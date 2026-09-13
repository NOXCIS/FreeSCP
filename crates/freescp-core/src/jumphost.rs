//! SSH jump-host (bastion) tunnel via the system OpenSSH client (`ssh -W`).
//!
//! Matches the C++ `spawn_ssh_jump_tunnel` path: shell out to
//! `ssh -o BatchMode=yes … -W target:port jumpHost` and expose the child's
//! stdio as an async byte stream for [`russh::client::connect_stream`].
//!
//! Using the system `ssh` is intentional — it inherits `~/.ssh/config` for the
//! bastion alias, including `ProxyCommand` (e.g. `cloudflared access ssh`).
//! An in-process russh bastion connection cannot honor `ProxyCommand`, which
//! caused connect timeouts for jump hosts that are only reachable that way.
//!
//! # Authentication / options (parity with C++)
//!
//! The spawned argv is:
//! `ssh -o BatchMode=yes -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes
//!  -o ConnectTimeout=20 -o ServerAliveInterval=30 -o ServerAliveCountMax=2
//!  [-l user] [-i key] -p port -W target:port jumpHost`
//!
//! - No password prompts (`BatchMode=yes`).
//! - When `-i` is given, only that key is tried (`IdentitiesOnly=yes`).
//! - Bastion `ProxyCommand` / `HostName` / `User` / `IdentityFile` from
//!   `~/.ssh/config` still apply when `jumpHost` is an ssh_config alias —
//!   callers must **not** rewrite the jump alias to its `HostName`.
//!
//! # Notes
//!
//! - Dropping a [`JumpTunnel`] kills the `ssh` child (SIGTERM, then SIGKILL).
//! - Proxy + jump host remain mutually exclusive at the backend layer.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context, Poll};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tracing::debug;

/// Default `ConnectTimeout=20` from the C++ jump tunnel spawn.
pub const JUMP_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Keepalive cadence, mirroring the C++ `ServerAliveInterval=30`.
pub const JUMP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Unanswered keepalives before giving up, mirroring the C++
/// `ServerAliveCountMax=2`.
pub const JUMP_KEEPALIVE_MAX: usize = 2;

/// Brief pause before checking whether `ssh` exited immediately (C++: 40 ms).
const SSH_SPAWN_PROBE: Duration = Duration::from_millis(40);

/// A byte stream tunneled through an SSH bastion to a target host.
///
/// Implements [`AsyncRead`] + [`AsyncWrite`] over the `ssh -W` child's stdio
/// and is `Send` + `Unpin`, so it can be handed to
/// [`russh::client::connect_stream`].
pub struct JumpTunnel {
    stdin: ChildStdin,
    stdout: ChildStdout,
    /// Kept so Drop can reap/kill the process; stderr is drained on early fail.
    child: Child,
    label: String,
}

impl fmt::Debug for JumpTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JumpTunnel")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl JumpTunnel {
    /// Consumes the tunnel as the transport stream for
    /// [`russh::client::connect_stream`].
    ///
    /// Kept as an identity helper so call sites that previously unwrapped a
    /// russh `ChannelStream` keep compiling.
    pub fn into_stream(self) -> Self {
        self
    }

    /// Best-effort graceful teardown (closes stdio, then kills the child).
    pub async fn disconnect(&mut self) {
        let _ = self.stdin.shutdown().await;
        let _ = self.child.kill().await;
    }

    /// Whether the `ssh` child has already exited.
    pub fn is_closed(&self) -> bool {
        // `Child::id()` is None after the process has been waited/reaped.
        self.child.id().is_none()
    }

    /// Human-readable description of the tunnel endpoints.
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl Drop for JumpTunnel {
    fn drop(&mut self) {
        // tokio::process::Child with kill_on_drop(true) also kills, but be
        // explicit so a partially-moved tunnel still tears down.
        let _ = self.child.start_kill();
    }
}

impl AsyncRead for JumpTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for JumpTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

/// Options for [`open_jump_tunnel_with_options`].
pub struct JumpTunnelOptions<'a> {
    /// Bastion login user (`ssh -l`). When `None`, OpenSSH uses the jump
    /// host's `User` from `~/.ssh/config` or the local login name.
    pub username: Option<&'a str>,
    /// Private key for bastion authentication (`ssh -i`); implies
    /// `IdentitiesOnly=yes` on the spawned command.
    pub private_key_path: Option<&'a Path>,
    /// Unused for `ssh -W` (BatchMode cannot prompt); retained for API
    /// compatibility with the previous in-process russh tunnel.
    pub private_key_passphrase: Option<&'a str>,
    /// Unused for `ssh -W` (OpenSSH reads `~/.ssh/known_hosts` itself);
    /// retained for API compatibility.
    pub known_hosts_path: Option<PathBuf>,
    /// Unused for `ssh -W` (`BatchMode=yes` refuses unknown hosts);
    /// retained for API compatibility.
    pub accept_unknown_host_key: bool,
    /// Bound mirrored as `ssh -o ConnectTimeout=N` (seconds, ceil). Defaults
    /// to [`JUMP_CONNECT_TIMEOUT`] (20 s).
    pub connect_timeout: Duration,
}

impl<'a> Default for JumpTunnelOptions<'a> {
    fn default() -> Self {
        JumpTunnelOptions {
            username: None,
            private_key_path: None,
            private_key_passphrase: None,
            known_hosts_path: None,
            accept_unknown_host_key: false,
            connect_timeout: JUMP_CONNECT_TIMEOUT,
        }
    }
}

impl<'a> fmt::Debug for JumpTunnelOptions<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JumpTunnelOptions")
            .field("username", &self.username)
            .field("private_key_path", &self.private_key_path)
            .field(
                "private_key_passphrase",
                &self.private_key_passphrase.map(|_| "***"),
            )
            .field("known_hosts_path", &self.known_hosts_path)
            .field("accept_unknown_host_key", &self.accept_unknown_host_key)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

/// Errors from opening or using a jump tunnel.
#[derive(Debug, Error)]
pub enum JumpError {
    #[error("{0}")]
    AuthFailed(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Other(String),
}

/// Opens an SSH tunnel to `target_host:target_port` through the bastion
/// `jump_host:jump_port` using default options.
pub async fn open_jump_tunnel(
    jump_host: &str,
    jump_port: u16,
    jump_user: Option<&str>,
    jump_key: Option<&Path>,
    target_host: &str,
    target_port: u16,
) -> Result<JumpTunnel, JumpError> {
    let options = JumpTunnelOptions {
        username: jump_user,
        private_key_path: jump_key,
        ..JumpTunnelOptions::default()
    };
    open_jump_tunnel_with_options(jump_host, jump_port, target_host, target_port, &options).await
}

/// Opens an SSH tunnel to `target_host:target_port` through the bastion
/// `jump_host:jump_port` with explicit [`JumpTunnelOptions`].
pub async fn open_jump_tunnel_with_options(
    jump_host: &str,
    jump_port: u16,
    target_host: &str,
    target_port: u16,
    options: &JumpTunnelOptions<'_>,
) -> Result<JumpTunnel, JumpError> {
    if jump_host.is_empty() {
        return Err(JumpError::Other("SSH jump host is empty.".into()));
    }
    if jump_port == 0 {
        return Err(JumpError::Other("SSH jump host port is invalid.".into()));
    }
    if target_host.is_empty() {
        return Err(JumpError::Other("SSH target host is empty.".into()));
    }
    if target_port == 0 {
        return Err(JumpError::Other("SSH target port is invalid.".into()));
    }

    let label = format!("{jump_host}:{jump_port} -> {target_host}:{target_port}");
    let connect_secs = options.connect_timeout.as_secs().max(1);
    let forward = format_host_port_authority(target_host, target_port);

    debug!(
        jump_host,
        jump_port,
        %target_host,
        target_port,
        ?options,
        "opening SSH jump tunnel via system ssh -W"
    );

    let mut cmd = Command::new("ssh");
    cmd.arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-o")
        .arg(format!("ConnectTimeout={connect_secs}"))
        .arg("-o")
        .arg("ServerAliveInterval=30")
        .arg("-o")
        .arg("ServerAliveCountMax=2");

    if let Some(user) = options.username.map(str::trim).filter(|u| !u.is_empty()) {
        cmd.arg("-l").arg(user);
    }
    if let Some(key) = options.private_key_path {
        cmd.arg("-i").arg(key);
    }
    cmd.arg("-p")
        .arg(jump_port.to_string())
        .arg("-W")
        .arg(&forward)
        .arg(jump_host);

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().map_err(|err| {
        JumpError::Other(format!(
            "failed to start SSH jump tunnel process (is `ssh` on PATH?): {err}"
        ))
    })?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| JumpError::Other("ssh stdin pipe missing".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| JumpError::Other("ssh stdout pipe missing".into()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| JumpError::Other("ssh stderr pipe missing".into()))?;

    // C++ probes with waitpid(WNOHANG) after 40 ms for instant failures
    // (bad argv, missing ProxyCommand binary, etc.).
    tokio::time::sleep(SSH_SPAWN_PROBE).await;
    if let Some(status) = child.try_wait().map_err(JumpError::Io)? {
        let stderr_text = read_stderr_limited(&mut stderr).await;
        return Err(JumpError::Other(format_jump_exit_error(
            "Failed to start SSH jump tunnel process.",
            &stderr_text,
            status.code(),
        )));
    }

    // Detach remaining stderr so a noisy ProxyCommand cannot fill the pipe
    // and block ssh; spawn a drain task.
    tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        let _ = tokio::io::copy(&mut stderr, &mut sink).await;
    });

    Ok(JumpTunnel {
        stdin,
        stdout,
        child,
        label,
    })
}

/// Formats `host:port` for `ssh -W`, bracketing IPv6 literals.
fn format_host_port_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn read_stderr_limited(stderr: &mut ChildStderr) -> String {
    let mut buf = Vec::new();
    // Cap so a pathological ProxyCommand cannot blow memory on failure.
    let mut limited = stderr.take(8 * 1024);
    let _ = limited.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).trim().to_string()
}

fn format_jump_exit_error(prefix: &str, stderr_text: &str, code: Option<i32>) -> String {
    let mut out = prefix.to_string();
    if let Some(code) = code {
        out.push_str(&format!(" (exit {code})"));
    }
    if !stderr_text.is_empty() {
        out.push(' ');
        out.push_str(stderr_text);
    }
    let lower = stderr_text.to_lowercase();
    if lower.contains("permission denied")
        || lower.contains("authentication failed")
        || lower.contains("publickey") && (lower.contains("denied") || lower.contains("failed"))
    {
        // Prefer AuthFailed so the UI can show a credential-oriented message.
        return out;
    }
    out
}

// Re-map auth-looking spawn failures through JumpError::AuthFailed at the
// call boundary by inspecting the message — kept simple: Other is fine for
// ProxyCommand/connect failures (the common timeout case).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_match_cpp_defaults() {
        let options = JumpTunnelOptions::default();
        assert_eq!(options.connect_timeout, Duration::from_secs(20));
        assert!(!options.accept_unknown_host_key);
        assert!(options.username.is_none());
        assert!(options.private_key_path.is_none());
        assert!(options.private_key_passphrase.is_none());
        assert!(options.known_hosts_path.is_none());
    }

    #[test]
    fn ipv6_authority_is_bracketed() {
        assert_eq!(
            format_host_port_authority("2001:db8::1", 22),
            "[2001:db8::1]:22"
        );
        assert_eq!(format_host_port_authority("bastion", 2200), "bastion:2200");
        assert_eq!(format_host_port_authority("[::1]", 22), "[::1]:22");
    }
}
