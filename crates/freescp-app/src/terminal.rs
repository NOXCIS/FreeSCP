//! Remote "Open in terminal" command builder.
//!
//! Port of the Qt helpers in `ui/MainWindowRemoteOps.cpp`
//! (`buildOpenSshProxyCommand`, `buildRemoteTerminalSshCommand`,
//! `buildRemoteSftpCliCommand`, `buildSshWithSftpFallbackCommand`,
//! `launchShellCommandInSystemTerminal`) plus the session gating of
//! `openRightRemoteTerminal`.
//!
//! The C++ builders emit one shell command line in which every argv element
//! is single-quoted ([`shell_join_quoted`]). OpenSSH's `ProxyCommand=` value
//! is itself such a quoted argv list, so it is quoted a second time when the
//! outer command is assembled; the tests pin those exact strings.

#![allow(dead_code)] // The main-window wiring lands separately from this port.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use freescp_core::{KnownHostsPolicy, Protocol, ProxyType, SessionOptions};

use crate::settings::Preferences;

// ---------------------------------------------------------------------------
// Shell quoting helpers (shellSingleQuote / shellJoinQuoted)
// ---------------------------------------------------------------------------

/// Port of `shellSingleQuote`: wraps `value` in single quotes, encoding any
/// embedded `'` as `'"'"'`.
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// Port of `shellJoinQuoted`: single-quotes every element and joins with
/// spaces.
fn shell_join_quoted<S: AsRef<str>>(args: &[S]) -> String {
    args.iter()
        .map(|arg| shell_single_quote(arg.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Port of `normalizeRemotePath`: ensure a non-empty absolute path with no
/// duplicate or trailing separators.
fn normalize_remote_path(raw: &str) -> String {
    let mut normalized = raw.trim().to_string();
    if normalized.is_empty() {
        normalized = "/".to_string();
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
    }
    if normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

/// Port of the `QDir::fromNativeSeparators(QDir::cleanPath(path))` pair the
/// C++ applies to key and known_hosts paths.
fn clean_path(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let mut out = PathBuf::new();
    for component in Path::new(raw).components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !out.pop() && !out.has_root() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    let text = out.to_string_lossy().into_owned();
    #[cfg(windows)]
    let text = text.replace('\\', "/");
    if text.is_empty() {
        ".".to_string()
    } else {
        text
    }
}

/// Port of `defaultKnownHostsPath` (`~/.ssh/known_hosts`).
fn default_known_hosts_path() -> String {
    let home = crate::local_fs::home_dir();
    if home.as_os_str().is_empty() {
        return String::new();
    }
    home.join(".ssh")
        .join("known_hosts")
        .to_string_lossy()
        .into_owned()
}

/// Port of `trimOptionalString`: `None`/blank values are the empty string.
fn trim_optional(value: &Option<String>) -> &str {
    value.as_deref().map(str::trim).unwrap_or("")
}

// ---------------------------------------------------------------------------
// PATH lookup (QStandardPaths::findExecutable)
// ---------------------------------------------------------------------------

/// First executable `name` found in `PATH` (or `name` itself when it already
/// contains a separator).
fn find_in_path(name: &str) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }
    if name.contains('/') || name.contains(std::path::MAIN_SEPARATOR) {
        let direct = Path::new(name);
        return is_executable(direct).then(|| direct.to_path_buf());
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
        #[cfg(windows)]
        for ext in ["exe", "cmd", "bat", "com"] {
            let candidate = dir.join(format!("{name}.{ext}"));
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

// ---------------------------------------------------------------------------
// Proxy command (buildOpenSshProxyCommand)
// ---------------------------------------------------------------------------

/// Proxy type and credentials needed by [`build_open_ssh_proxy_command`].
///
/// The endpoint (host/port) is passed to the builder separately, mirroring
/// the C++ helper which reads `proxy_host`/`proxy_port` next to the type and
/// credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxySettings {
    pub proxy_type: ProxyType,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxySettings {
    /// Extracts the proxy type and credentials from a session.
    pub fn from_session(session: &SessionOptions) -> Self {
        ProxySettings {
            proxy_type: session.proxy_type,
            username: session.proxy_username.clone(),
            password: session.proxy_password.clone(),
        }
    }
}

/// Port of `buildOpenSshProxyCommand`: builds the `nc`/`ncat` command used as
/// an OpenSSH `ProxyCommand` value.
pub fn build_open_ssh_proxy_command(
    proxy: &ProxySettings,
    host: &str,
    port: u16,
) -> Result<String, String> {
    build_open_ssh_proxy_command_with(proxy, host, port, &find_in_path)
}

fn build_open_ssh_proxy_command_with(
    proxy: &ProxySettings,
    host: &str,
    port: u16,
    find: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<String, String> {
    if proxy.proxy_type == ProxyType::None {
        return Err("Proxy command requested without proxy settings.".to_string());
    }

    let host = host.trim();
    if host.is_empty() || port == 0 {
        return Err("Proxy host/port is missing for terminal command.".to_string());
    }

    let user = trim_optional(&proxy.username);
    let password = trim_optional(&proxy.password);
    let wants_auth = !user.is_empty() || !password.is_empty();
    if wants_auth && user.is_empty() {
        return Err("Proxy authentication requires a username.".to_string());
    }

    if wants_auth {
        let ncat = find("ncat").ok_or_else(|| {
            "Proxy authentication in terminal mode requires 'ncat' (with --proxy-auth support)."
                .to_string()
        })?;
        let proxy_type = ncat_proxy_type(proxy.proxy_type)?;
        let args = vec![
            ncat.to_string_lossy().into_owned(),
            "--proxy".to_string(),
            format!("{host}:{port}"),
            "--proxy-type".to_string(),
            proxy_type.to_string(),
            "--proxy-auth".to_string(),
            format!("{user}:{password}"),
            "%h".to_string(),
            "%p".to_string(),
        ];
        return Ok(shell_join_quoted(&args));
    }

    if let Some(nc) = find("nc") {
        let mut args = vec![
            nc.to_string_lossy().into_owned(),
            "-x".to_string(),
            format!("{host}:{port}"),
        ];
        match proxy.proxy_type {
            ProxyType::Socks5 => {
                args.push("-X".to_string());
                args.push("5".to_string());
            }
            ProxyType::HttpConnect => {
                args.push("-X".to_string());
                args.push("connect".to_string());
            }
            ProxyType::None => {
                return Err("Unsupported proxy type for terminal command.".to_string());
            }
        }
        args.push("%h".to_string());
        args.push("%p".to_string());
        return Ok(shell_join_quoted(&args));
    }

    if let Some(ncat) = find("ncat") {
        let proxy_type = ncat_proxy_type(proxy.proxy_type)?;
        let args = vec![
            ncat.to_string_lossy().into_owned(),
            "--proxy".to_string(),
            format!("{host}:{port}"),
            "--proxy-type".to_string(),
            proxy_type.to_string(),
            "%h".to_string(),
            "%p".to_string(),
        ];
        return Ok(shell_join_quoted(&args));
    }

    Err("Could not find a proxy helper for terminal mode (tried: nc, ncat).".to_string())
}

/// `ncatTypeForProxy`: `--proxy-type` value for the supported proxy types.
fn ncat_proxy_type(proxy_type: ProxyType) -> Result<&'static str, String> {
    match proxy_type {
        ProxyType::Socks5 => Ok("socks5"),
        ProxyType::HttpConnect => Ok("http"),
        ProxyType::None => Err("Unsupported proxy type for terminal command.".to_string()),
    }
}

// ---------------------------------------------------------------------------
// SSH / SFTP command builders
// ---------------------------------------------------------------------------

/// Port of `buildRemoteTerminalSshCommand`: `ssh -tt` into the session host
/// running the remote login shell at `remote_path`.
pub fn build_remote_terminal_ssh_command(
    session: &SessionOptions,
    prefs: &Preferences,
    remote_path: &str,
) -> Result<String, String> {
    build_remote_terminal_ssh_command_with(session, prefs, remote_path, &find_in_path)
}

fn build_remote_terminal_ssh_command_with(
    session: &SessionOptions,
    prefs: &Preferences,
    remote_path: &str,
    find: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<String, String> {
    let ssh = find("ssh").ok_or_else(|| "OpenSSH client was not found in PATH.".to_string())?;
    let host = session.host.trim();
    let user = session.username.trim();
    if host.is_empty() || user.is_empty() {
        return Err("Session is missing host or username information.".to_string());
    }

    let mut args = vec![
        ssh.to_string_lossy().into_owned(),
        "-tt".to_string(),
        "-p".to_string(),
        session.port.to_string(),
    ];
    append_security_args(&mut args, session, prefs, find)?;
    args.push(format!("{user}@{host}"));
    args.push(remote_login_command(remote_path));
    Ok(shell_join_quoted(&args))
}

/// Port of `buildRemoteSftpCliCommand`: `sftp -P` into the session host at
/// `remote_path`.
pub fn build_remote_sftp_cli_command(
    session: &SessionOptions,
    prefs: &Preferences,
    remote_path: &str,
) -> Result<String, String> {
    build_remote_sftp_cli_command_with(session, prefs, remote_path, &find_in_path)
}

fn build_remote_sftp_cli_command_with(
    session: &SessionOptions,
    prefs: &Preferences,
    remote_path: &str,
    find: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<String, String> {
    let sftp =
        find("sftp").ok_or_else(|| "OpenSSH sftp client was not found in PATH.".to_string())?;
    let host = session.host.trim();
    let user = session.username.trim();
    if host.is_empty() || user.is_empty() {
        return Err("Session is missing host or username information.".to_string());
    }

    let mut args = vec![
        sftp.to_string_lossy().into_owned(),
        "-P".to_string(),
        session.port.to_string(),
    ];
    append_security_args(&mut args, session, prefs, find)?;
    args.push(format!(
        "{user}@{host}:{}",
        normalize_remote_path(remote_path)
    ));
    Ok(shell_join_quoted(&args))
}

/// Known-hosts, authentication, jump-host and proxy arguments shared by the
/// `ssh` and `sftp` builders (the C++ duplicates this block in both).
fn append_security_args(
    args: &mut Vec<String>,
    session: &SessionOptions,
    prefs: &Preferences,
    find: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<(), String> {
    if session.known_hosts_policy == KnownHostsPolicy::Off {
        args.push("-o".to_string());
        args.push("StrictHostKeyChecking=no".to_string());
        args.push("-o".to_string());
        args.push("UserKnownHostsFile=/dev/null".to_string());
    } else {
        let strict = if session.known_hosts_policy == KnownHostsPolicy::AcceptNew {
            "accept-new"
        } else {
            "yes"
        };
        args.push("-o".to_string());
        args.push(format!("StrictHostKeyChecking={strict}"));

        let known_hosts = match trim_optional(&session.known_hosts_path) {
            "" => default_known_hosts_path(),
            path => clean_path(path),
        };
        if !known_hosts.is_empty() {
            args.push("-o".to_string());
            args.push(format!("UserKnownHostsFile={known_hosts}"));
        }
    }

    if prefs.terminal_force_interactive_login {
        args.push("-o".to_string());
        args.push("PubkeyAuthentication=no".to_string());
        args.push("-o".to_string());
        args.push("PreferredAuthentications=keyboard-interactive,password".to_string());
    } else {
        let key = trim_optional(&session.private_key_path);
        if !key.is_empty() {
            args.push("-i".to_string());
            args.push(clean_path(key));
            args.push("-o".to_string());
            args.push("IdentitiesOnly=yes".to_string());
        }
    }

    let jump_host = trim_optional(&session.jump_host);
    let use_jump = !jump_host.is_empty();
    let use_proxy = session.proxy_type != ProxyType::None;
    if use_jump && use_proxy {
        return Err(
            "Proxy and SSH jump host cannot be used together in the same terminal command."
                .to_string(),
        );
    }

    if use_jump {
        let jump_user = trim_optional(&session.jump_username);
        let jump_key = trim_optional(&session.jump_private_key_path);
        let jump_port = if session.jump_port == 0 {
            22
        } else {
            session.jump_port
        };
        if jump_key.is_empty() {
            let mut spec = jump_host.to_string();
            if !jump_user.is_empty() {
                spec = format!("{jump_user}@{spec}");
            }
            if jump_port != 22 {
                spec = format!("{spec}:{jump_port}");
            }
            args.push("-J".to_string());
            args.push(spec);
        } else {
            let mut jump_cmd = vec![
                "ssh".to_string(),
                "-W".to_string(),
                "%h:%p".to_string(),
                "-p".to_string(),
                jump_port.to_string(),
            ];
            if !jump_user.is_empty() {
                jump_cmd.push("-l".to_string());
                jump_cmd.push(jump_user.to_string());
            }
            jump_cmd.push("-i".to_string());
            jump_cmd.push(clean_path(jump_key));
            jump_cmd.push("-o".to_string());
            jump_cmd.push("IdentitiesOnly=yes".to_string());
            jump_cmd.push(jump_host.to_string());
            args.push("-o".to_string());
            args.push(format!("ProxyCommand={}", shell_join_quoted(&jump_cmd)));
        }
    } else if use_proxy {
        let proxy_command = build_open_ssh_proxy_command_with(
            &ProxySettings::from_session(session),
            &session.proxy_host,
            session.proxy_port,
            find,
        )?;
        args.push("-o".to_string());
        args.push(format!("ProxyCommand={proxy_command}"));
    }

    Ok(())
}

/// Remote init command run by the login shell after `cd`-ing to the path.
fn remote_login_command(remote_path: &str) -> String {
    format!(
        "cd -- {} 2>/dev/null || cd /; exec ${{SHELL:-/bin/sh}} -l",
        shell_single_quote(&normalize_remote_path(remote_path))
    )
}

// ---------------------------------------------------------------------------
// SSH with SFTP fallback (buildSshWithSftpFallbackCommand)
// ---------------------------------------------------------------------------

/// Port of `buildSshWithSftpFallbackCommand`: runs `ssh_cmd`, and when
/// OpenSSH exits with 255 (transport/session error, e.g. PTY denied) prints a
/// notice and runs the SFTP CLI command instead.
pub fn build_ssh_with_sftp_fallback_command(ssh_cmd: &str, sftp_cmd: &str) -> String {
    if sftp_cmd.trim().is_empty() {
        return ssh_cmd.to_string();
    }
    let notice =
        shell_single_quote("FreeSCP: SSH shell was not available. Falling back to SFTP CLI.");
    format!(
        "{ssh_cmd}; _freescp_ssh_status=$?; \
         if [ \"$_freescp_ssh_status\" -eq 255 ]; then \
         printf '%s\\n' {notice}; {sftp_cmd}; \
         fi"
    )
}

// ---------------------------------------------------------------------------
// System terminal launcher (launchShellCommandInSystemTerminal)
// ---------------------------------------------------------------------------

/// Port of `appleScriptStringLiteral`.
fn apple_script_literal(raw: &str) -> String {
    format!("\"{}\"", raw.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Port of `launchShellCommandInSystemTerminal`: opens `command` in the
/// platform terminal emulator without blocking.
// `return` is required by the cfg-block dispatch below (each block is a
// statement, so the function cannot simply end with a cfg'd tail expression).
#[allow(clippy::needless_return)]
pub fn launch_command_in_system_terminal(command: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        return launch_macos(command);
    }
    #[cfg(target_os = "linux")]
    {
        return launch_linux(command);
    }
    #[cfg(target_os = "windows")]
    {
        return launch_windows(command);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("Open in terminal action is not supported on this platform.".to_string())
    }
}

/// `QProcess::startDetached` equivalent: spawn without blocking the caller
/// and reap the child on a helper thread.
fn spawn_detached(program: &Path, args: &[&str]) -> std::io::Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

#[cfg(target_os = "macos")]
fn launch_macos(command: &str) -> Result<(), String> {
    let osascript =
        find_in_path("osascript").ok_or_else(|| "Could not locate osascript.".to_string())?;
    let activate = "tell application \"Terminal\" to activate";
    let script = format!(
        "tell application \"Terminal\" to do script {}",
        apple_script_literal(command)
    );
    spawn_detached(&osascript, &["-e", activate, "-e", &script])
        .map_err(|_| "Could not launch Terminal.app.".to_string())
}

#[cfg(target_os = "linux")]
fn launch_linux(command: &str) -> Result<(), String> {
    if try_launch("x-terminal-emulator", &["-e", "sh", "-lc", command]) {
        return Ok(());
    }
    if try_launch("gnome-terminal", &["--", "sh", "-lc", command]) {
        return Ok(());
    }
    if try_launch("konsole", &["-e", "sh", "-lc", command]) {
        return Ok(());
    }
    let xfce_command = format!("sh -lc {}", shell_single_quote(command));
    if try_launch("xfce4-terminal", &["--command", &xfce_command]) {
        return Ok(());
    }
    if try_launch("xterm", &["-e", "sh", "-lc", command]) {
        return Ok(());
    }
    if try_launch("alacritty", &["-e", "sh", "-lc", command]) {
        return Ok(());
    }
    if try_launch("kitty", &["sh", "-lc", command]) {
        return Ok(());
    }
    Err("No compatible terminal emulator was found.".to_string())
}

#[cfg(target_os = "linux")]
fn try_launch(program: &str, args: &[&str]) -> bool {
    match find_in_path(program) {
        Some(exe) => spawn_detached(&exe, args).is_ok(),
        None => false,
    }
}

#[cfg(target_os = "windows")]
fn launch_windows(command: &str) -> Result<(), String> {
    spawn_detached(Path::new("cmd"), &["/C", "start", "cmd", "/K", command])
        .map_err(|_| "Could not launch the system terminal.".to_string())
}

// ---------------------------------------------------------------------------
// Open remote terminal (openRightRemoteTerminal)
// ---------------------------------------------------------------------------

/// Whether the session protocol is carried over SSH (the C++ action is only
/// meaningful for SFTP/SCP sessions).
fn protocol_supports_ssh_transport(protocol: Protocol) -> bool {
    matches!(protocol, Protocol::Sftp | Protocol::Scp)
}

fn has_saved_password(session: &SessionOptions) -> bool {
    session.password.as_deref().is_some_and(|p| !p.is_empty())
        && trim_optional(&session.private_key_path).is_empty()
}

/// Status-bar suffix mirroring the flags appended by the C++
/// `openRightRemoteTerminal`.
///
/// `sftp_fallback_active` must be `true` only when the SFTP CLI command was
/// actually built (the C++ `hasSftpFallback`), not merely enabled.
pub fn status_suffix(
    session: &SessionOptions,
    prefs: &Preferences,
    sftp_fallback_active: bool,
) -> String {
    let mut suffix = String::new();
    if prefs.terminal_force_interactive_login {
        suffix.push_str(" (interactive login required)");
    } else if has_saved_password(session) {
        suffix.push_str(" (password may be requested by OpenSSH for security)");
    }
    if sftp_fallback_active {
        suffix.push_str(" (auto-fallback to SFTP CLI enabled)");
    }
    suffix
}

struct PreparedTerminal {
    command: String,
    status_message: String,
}

/// Builds the launch command and the status message without launching.
fn prepare_remote_terminal_with(
    session: &SessionOptions,
    prefs: &Preferences,
    remote_path: &str,
    find: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<PreparedTerminal, String> {
    let ssh_command = build_remote_terminal_ssh_command_with(session, prefs, remote_path, find)?;
    let sftp_command = if prefs.terminal_enable_sftp_cli_fallback {
        build_remote_sftp_cli_command_with(session, prefs, remote_path, find).ok()
    } else {
        None
    };
    let command = match &sftp_command {
        Some(sftp) => build_ssh_with_sftp_fallback_command(&ssh_command, sftp),
        None => ssh_command,
    };
    let mut status_message = format!(
        "Opening remote terminal at {}",
        normalize_remote_path(remote_path)
    );
    status_message.push_str(&status_suffix(session, prefs, sftp_command.is_some()));
    Ok(PreparedTerminal {
        command,
        status_message,
    })
}

/// Port of `openRightRemoteTerminal`: builds the SSH terminal command (with
/// optional SFTP CLI fallback), opens it in the system terminal and returns
/// the status message for the status bar.
pub fn open_remote_terminal(
    session: &SessionOptions,
    prefs: &Preferences,
    remote_path: &str,
) -> Result<String, String> {
    if !protocol_supports_ssh_transport(session.protocol) {
        return Err(
            "Open in terminal requires an SSH transport (SFTP or SCP session).".to_string(),
        );
    }
    let prepared = prepare_remote_terminal_with(session, prefs, remote_path, &find_in_path)?;
    launch_command_in_system_terminal(&prepared.command)?;
    Ok(prepared.status_message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSH: &str = "/usr/bin/ssh";
    const SFTP: &str = "/usr/bin/sftp";
    const NC: &str = "/usr/bin/nc";
    const NCAT: &str = "/usr/bin/ncat";

    fn tools_lookup<'a>(tools: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<PathBuf> + 'a {
        move |name: &str| {
            tools
                .iter()
                .find(|(tool, _)| *tool == name)
                .map(|(_, path)| PathBuf::from(*path))
        }
    }

    fn base_session() -> SessionOptions {
        SessionOptions {
            host: "example.com".into(),
            port: 2222,
            username: "alice".into(),
            known_hosts_path: Some("/home/alice/.ssh/known_hosts".into()),
            ..SessionOptions::default()
        }
    }

    fn ssh_command_with_tools(
        session: &SessionOptions,
        prefs: &Preferences,
        remote_path: &str,
        tools: &[(&str, &str)],
    ) -> String {
        let lookup = tools_lookup(tools);
        build_remote_terminal_ssh_command_with(session, prefs, remote_path, &lookup)
            .expect("ssh command")
    }

    fn sftp_command_with_tools(
        session: &SessionOptions,
        prefs: &Preferences,
        remote_path: &str,
        tools: &[(&str, &str)],
    ) -> String {
        let lookup = tools_lookup(tools);
        build_remote_sftp_cli_command_with(session, prefs, remote_path, &lookup)
            .expect("sftp command")
    }

    // -- quoting / path helpers -------------------------------------------

    #[test]
    fn shell_single_quote_escapes_apostrophes() {
        assert_eq!(shell_single_quote("plain"), "'plain'");
        assert_eq!(shell_single_quote("a b'c"), r#"'a b'"'"'c'"#);
    }

    #[test]
    fn shell_join_quoted_quotes_every_argument() {
        assert_eq!(
            shell_join_quoted(&["-o", "StrictHostKeyChecking=yes"]),
            "'-o' 'StrictHostKeyChecking=yes'"
        );
        assert_eq!(shell_join_quoted(&["".to_string()]), "''");
    }

    #[test]
    fn normalize_remote_path_matches_cpp() {
        assert_eq!(normalize_remote_path(""), "/");
        assert_eq!(normalize_remote_path("home/alice"), "/home/alice");
        assert_eq!(normalize_remote_path("//home///alice//"), "/home/alice");
        assert_eq!(normalize_remote_path("  /a/b/  "), "/a/b");
        assert_eq!(normalize_remote_path("/"), "/");
    }

    #[test]
    fn clean_path_matches_qdir_clean_path() {
        assert_eq!(clean_path("/a//b/../c"), "/a/c");
        assert_eq!(clean_path("/a/./b/"), "/a/b");
        assert_eq!(clean_path("~/.ssh/known_hosts"), "~/.ssh/known_hosts");
        assert_eq!(clean_path("a/../b"), "b");
    }

    // -- proxy command -----------------------------------------------------

    #[test]
    fn proxy_command_without_proxy_settings_is_rejected() {
        let proxy = ProxySettings::default();
        let err = build_open_ssh_proxy_command_with(&proxy, "p.example", 1080, &tools_lookup(&[]))
            .expect_err("must reject");
        assert_eq!(err, "Proxy command requested without proxy settings.");
    }

    #[test]
    fn proxy_command_requires_host_and_port() {
        let proxy = ProxySettings {
            proxy_type: ProxyType::Socks5,
            ..ProxySettings::default()
        };
        let err = build_open_ssh_proxy_command_with(&proxy, "  ", 1080, &tools_lookup(&[]))
            .expect_err("must reject host");
        assert_eq!(err, "Proxy host/port is missing for terminal command.");
        let err = build_open_ssh_proxy_command_with(&proxy, "p.example", 0, &tools_lookup(&[]))
            .expect_err("must reject port");
        assert_eq!(err, "Proxy host/port is missing for terminal command.");
    }

    #[test]
    fn proxy_command_auth_requires_username() {
        let proxy = ProxySettings {
            proxy_type: ProxyType::Socks5,
            password: Some("secret".into()),
            ..ProxySettings::default()
        };
        let err = build_open_ssh_proxy_command_with(
            &proxy,
            "p.example",
            1080,
            &tools_lookup(&[("ncat", NCAT)]),
        )
        .expect_err("must reject");
        assert_eq!(err, "Proxy authentication requires a username.");
    }

    #[test]
    fn proxy_command_prefers_nc_without_auth() {
        let proxy = ProxySettings {
            proxy_type: ProxyType::Socks5,
            ..ProxySettings::default()
        };
        let command = build_open_ssh_proxy_command_with(
            &proxy,
            "p.example",
            1080,
            &tools_lookup(&[("nc", NC), ("ncat", NCAT)]),
        )
        .expect("proxy command");
        assert_eq!(
            command,
            "'/usr/bin/nc' '-x' 'p.example:1080' '-X' '5' '%h' '%p'"
        );
    }

    #[test]
    fn proxy_command_uses_ncat_when_nc_is_missing() {
        let proxy = ProxySettings {
            proxy_type: ProxyType::Socks5,
            ..ProxySettings::default()
        };
        let command = build_open_ssh_proxy_command_with(
            &proxy,
            "p.example",
            1080,
            &tools_lookup(&[("ncat", NCAT)]),
        )
        .expect("proxy command");
        assert_eq!(
            command,
            "'/usr/bin/ncat' '--proxy' 'p.example:1080' '--proxy-type' 'socks5' '%h' '%p'"
        );
    }

    #[test]
    fn proxy_command_http_connect_uses_connect_flag() {
        let proxy = ProxySettings {
            proxy_type: ProxyType::HttpConnect,
            ..ProxySettings::default()
        };
        let command = build_open_ssh_proxy_command_with(
            &proxy,
            "p.example",
            8080,
            &tools_lookup(&[("nc", NC)]),
        )
        .expect("proxy command");
        assert_eq!(
            command,
            "'/usr/bin/nc' '-x' 'p.example:8080' '-X' 'connect' '%h' '%p'"
        );
    }

    #[test]
    fn proxy_command_auth_requires_ncat() {
        let proxy = ProxySettings {
            proxy_type: ProxyType::Socks5,
            username: Some("u".into()),
            password: Some("p".into()),
        };
        let err = build_open_ssh_proxy_command_with(
            &proxy,
            "p.example",
            1080,
            &tools_lookup(&[("nc", NC)]),
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            "Proxy authentication in terminal mode requires 'ncat' (with --proxy-auth support)."
        );
    }

    #[test]
    fn proxy_command_auth_builds_ncat_with_proxy_auth() {
        let proxy = ProxySettings {
            proxy_type: ProxyType::Socks5,
            username: Some(" u ".into()),
            password: Some(" p ".into()),
        };
        let command = build_open_ssh_proxy_command_with(
            &proxy,
            "p.example",
            1080,
            &tools_lookup(&[("ncat", NCAT)]),
        )
        .expect("proxy command");
        assert_eq!(
            command,
            "'/usr/bin/ncat' '--proxy' 'p.example:1080' '--proxy-type' 'socks5' \
             '--proxy-auth' 'u:p' '%h' '%p'"
        );
    }

    #[test]
    fn proxy_command_reports_missing_helpers() {
        let proxy = ProxySettings {
            proxy_type: ProxyType::HttpConnect,
            ..ProxySettings::default()
        };
        let err = build_open_ssh_proxy_command_with(&proxy, "p.example", 8080, &tools_lookup(&[]))
            .expect_err("must reject");
        assert_eq!(
            err,
            "Could not find a proxy helper for terminal mode (tried: nc, ncat)."
        );
    }

    // -- SSH command -------------------------------------------------------

    #[test]
    fn ssh_command_basic_shape_and_quoting() {
        let command = ssh_command_with_tools(
            &base_session(),
            &Preferences::default(),
            "/home/alice",
            &[("ssh", SSH)],
        );
        let expected = concat!(
            "'/usr/bin/ssh' '-tt' '-p' '2222' ",
            "'-o' 'StrictHostKeyChecking=yes' ",
            "'-o' 'UserKnownHostsFile=/home/alice/.ssh/known_hosts' ",
            "'alice@example.com' ",
            "'cd -- '\"'\"'/home/alice'\"'\"' 2>/dev/null || cd /; ",
            "exec ${SHELL:-/bin/sh} -l'"
        );
        assert_eq!(command, expected);
    }

    #[test]
    fn ssh_command_requires_ssh_binary() {
        let err = build_remote_terminal_ssh_command_with(
            &base_session(),
            &Preferences::default(),
            "/",
            &tools_lookup(&[]),
        )
        .expect_err("must reject");
        assert_eq!(err, "OpenSSH client was not found in PATH.");
    }

    #[test]
    fn ssh_command_requires_host_and_username() {
        let session = SessionOptions {
            host: "  ".into(),
            ..base_session()
        };
        let err = ssh_err(&session);
        assert_eq!(err, "Session is missing host or username information.");

        let session = SessionOptions {
            username: "".into(),
            ..base_session()
        };
        let err = ssh_err(&session);
        assert_eq!(err, "Session is missing host or username information.");
    }

    fn ssh_err(session: &SessionOptions) -> String {
        let lookup = tools_lookup(&[("ssh", SSH)]);
        build_remote_terminal_ssh_command_with(session, &Preferences::default(), "/", &lookup)
            .expect_err("must reject")
    }

    #[test]
    fn ssh_command_known_hosts_off_disables_verification() {
        let session = SessionOptions {
            known_hosts_policy: KnownHostsPolicy::Off,
            ..base_session()
        };
        let command =
            ssh_command_with_tools(&session, &Preferences::default(), "/", &[("ssh", SSH)]);
        assert!(command.contains("'-o' 'StrictHostKeyChecking=no'"));
        assert!(command.contains("'-o' 'UserKnownHostsFile=/dev/null'"));
        assert!(!command.contains("/home/alice/.ssh/known_hosts"));
    }

    #[test]
    fn ssh_command_known_hosts_strict_uses_configured_path() {
        let command = ssh_command_with_tools(
            &base_session(),
            &Preferences::default(),
            "/",
            &[("ssh", SSH)],
        );
        assert!(command.contains("'-o' 'StrictHostKeyChecking=yes'"));
        assert!(command.contains("'-o' 'UserKnownHostsFile=/home/alice/.ssh/known_hosts'"));
    }

    #[test]
    fn ssh_command_known_hosts_accept_new() {
        let session = SessionOptions {
            known_hosts_policy: KnownHostsPolicy::AcceptNew,
            ..base_session()
        };
        let command =
            ssh_command_with_tools(&session, &Preferences::default(), "/", &[("ssh", SSH)]);
        assert!(command.contains("'-o' 'StrictHostKeyChecking=accept-new'"));
        assert!(command.contains("'-o' 'UserKnownHostsFile=/home/alice/.ssh/known_hosts'"));
    }

    #[test]
    fn ssh_command_known_hosts_defaults_to_home() {
        let session = SessionOptions {
            known_hosts_path: None,
            ..base_session()
        };
        let command =
            ssh_command_with_tools(&session, &Preferences::default(), "/", &[("ssh", SSH)]);
        let expected = format!(
            "'-o' 'UserKnownHostsFile={}'",
            crate::local_fs::home_dir()
                .join(".ssh")
                .join("known_hosts")
                .display()
        );
        assert!(command.contains(&expected), "command was {command}");
    }

    #[test]
    fn ssh_command_interactive_login_disables_key_auth() {
        let session = SessionOptions {
            private_key_path: Some("/keys/id_ed25519".into()),
            ..base_session()
        };
        let prefs = Preferences {
            terminal_force_interactive_login: true,
            ..Preferences::default()
        };
        let command = ssh_command_with_tools(&session, &prefs, "/", &[("ssh", SSH)]);
        assert!(command.contains("'-o' 'PubkeyAuthentication=no'"));
        assert!(command.contains("'-o' 'PreferredAuthentications=keyboard-interactive,password'"));
        assert!(!command.contains("'-i'"));
        assert!(!command.contains("IdentitiesOnly"));
    }

    #[test]
    fn ssh_command_uses_configured_private_key() {
        let session = SessionOptions {
            private_key_path: Some("/keys/../keys/id_ed25519".into()),
            ..base_session()
        };
        let command =
            ssh_command_with_tools(&session, &Preferences::default(), "/", &[("ssh", SSH)]);
        assert!(command.contains("'-i' '/keys/id_ed25519'"));
        assert!(command.contains("'-o' 'IdentitiesOnly=yes'"));
        assert!(!command.contains("PubkeyAuthentication"));
    }

    #[test]
    fn ssh_command_jump_host_uses_dash_j() {
        let session = SessionOptions {
            jump_host: Some(" bastion.example ".into()),
            ..base_session()
        };
        let command =
            ssh_command_with_tools(&session, &Preferences::default(), "/", &[("ssh", SSH)]);
        assert!(command.contains("'-J' 'bastion.example'"));

        let session = SessionOptions {
            jump_host: Some("bastion.example".into()),
            jump_port: 2200,
            jump_username: Some("juser".into()),
            ..base_session()
        };
        let command =
            ssh_command_with_tools(&session, &Preferences::default(), "/", &[("ssh", SSH)]);
        assert!(command.contains("'-J' 'juser@bastion.example:2200'"));
    }

    #[test]
    fn ssh_command_jump_host_with_key_uses_proxy_command() {
        let session = SessionOptions {
            jump_host: Some("bastion.example".into()),
            jump_port: 2200,
            jump_username: Some("juser".into()),
            jump_private_key_path: Some("/keys/jump".into()),
            ..base_session()
        };
        let command =
            ssh_command_with_tools(&session, &Preferences::default(), "/", &[("ssh", SSH)]);
        let jump_cmd = shell_join_quoted(&[
            "ssh",
            "-W",
            "%h:%p",
            "-p",
            "2200",
            "-l",
            "juser",
            "-i",
            "/keys/jump",
            "-o",
            "IdentitiesOnly=yes",
            "bastion.example",
        ]);
        let expected = format!(
            "'-o' {}",
            shell_single_quote(&format!("ProxyCommand={jump_cmd}"))
        );
        assert!(command.contains(&expected), "command was {command}");
        assert!(!command.contains("'-J'"));
    }

    #[test]
    fn ssh_command_proxy_and_jump_host_are_mutually_exclusive() {
        let session = SessionOptions {
            jump_host: Some("bastion.example".into()),
            proxy_type: ProxyType::Socks5,
            proxy_host: "p.example".into(),
            proxy_port: 1080,
            ..base_session()
        };
        let err = ssh_err(&session);
        assert_eq!(
            err,
            "Proxy and SSH jump host cannot be used together in the same terminal command."
        );
    }

    #[test]
    fn ssh_command_proxy_uses_proxy_command() {
        let session = SessionOptions {
            proxy_type: ProxyType::Socks5,
            proxy_host: "p.example".into(),
            proxy_port: 1080,
            ..base_session()
        };
        let command = ssh_command_with_tools(
            &session,
            &Preferences::default(),
            "/",
            &[("ssh", SSH), ("nc", NC)],
        );
        let proxy_cmd = "'/usr/bin/nc' '-x' 'p.example:1080' '-X' '5' '%h' '%p'";
        let expected = format!(
            "'-o' {}",
            shell_single_quote(&format!("ProxyCommand={proxy_cmd}"))
        );
        assert!(command.contains(&expected), "command was {command}");
        assert!(command.contains("'alice@example.com'"));
    }

    #[test]
    fn ssh_command_quotes_remote_path_with_spaces_and_quotes() {
        let command = ssh_command_with_tools(
            &base_session(),
            &Preferences::default(),
            "  /home/o'brien/my dir/  ",
            &[("ssh", SSH)],
        );
        assert!(command.ends_with(
            r#"'cd -- '"'"'/home/o'"'"'"'"'"'"'"'"'brien/my dir'"'"' 2>/dev/null || cd /; exec ${SHELL:-/bin/sh} -l'"#
        ), "command was {command}");
    }

    // -- SFTP CLI command --------------------------------------------------

    #[test]
    fn sftp_command_basic_shape() {
        let command = sftp_command_with_tools(
            &base_session(),
            &Preferences::default(),
            "/home/alice",
            &[("sftp", SFTP)],
        );
        let expected = concat!(
            "'/usr/bin/sftp' '-P' '2222' ",
            "'-o' 'StrictHostKeyChecking=yes' ",
            "'-o' 'UserKnownHostsFile=/home/alice/.ssh/known_hosts' ",
            "'alice@example.com:/home/alice'"
        );
        assert_eq!(command, expected);
    }

    #[test]
    fn sftp_command_requires_sftp_binary() {
        let lookup = tools_lookup(&[]);
        let err = build_remote_sftp_cli_command_with(
            &base_session(),
            &Preferences::default(),
            "/",
            &lookup,
        )
        .expect_err("must reject");
        assert_eq!(err, "OpenSSH sftp client was not found in PATH.");
    }

    #[test]
    fn sftp_command_applies_security_options() {
        let session = SessionOptions {
            known_hosts_policy: KnownHostsPolicy::Off,
            private_key_path: Some("/keys/id_ed25519".into()),
            ..base_session()
        };
        let command =
            sftp_command_with_tools(&session, &Preferences::default(), "/", &[("sftp", SFTP)]);
        assert!(command.contains("'-P' '2222'"));
        assert!(command.contains("'-o' 'StrictHostKeyChecking=no'"));
        assert!(command.contains("'-o' 'UserKnownHostsFile=/dev/null'"));
        assert!(command.contains("'-i' '/keys/id_ed25519'"));
        assert!(command.contains("'-o' 'IdentitiesOnly=yes'"));

        let prefs = Preferences {
            terminal_force_interactive_login: true,
            ..Preferences::default()
        };
        let command = sftp_command_with_tools(&session, &prefs, "/", &[("sftp", SFTP)]);
        assert!(command.contains("'-o' 'PubkeyAuthentication=no'"));
        assert!(!command.contains("'-i'"));
    }

    // -- fallback wrapper --------------------------------------------------

    #[test]
    fn ssh_with_sftp_fallback_wrapper_is_exact() {
        let wrapper = build_ssh_with_sftp_fallback_command("SSHCMD", "SFTPCMD");
        assert_eq!(
            wrapper,
            r#"SSHCMD; _freescp_ssh_status=$?; if [ "$_freescp_ssh_status" -eq 255 ]; then printf '%s\n' 'FreeSCP: SSH shell was not available. Falling back to SFTP CLI.'; SFTPCMD; fi"#
        );
    }

    #[test]
    fn ssh_with_sftp_fallback_keeps_plain_ssh_without_sftp() {
        assert_eq!(build_ssh_with_sftp_fallback_command("SSHCMD", ""), "SSHCMD");
        assert_eq!(
            build_ssh_with_sftp_fallback_command("SSHCMD", "   "),
            "SSHCMD"
        );
    }

    // -- status / integration ---------------------------------------------

    #[test]
    fn status_suffix_reports_enabled_flags() {
        let mut session = base_session();
        let mut prefs = Preferences::default();

        assert_eq!(status_suffix(&session, &prefs, false), "");
        assert_eq!(
            status_suffix(&session, &prefs, true),
            " (auto-fallback to SFTP CLI enabled)"
        );

        prefs.terminal_force_interactive_login = true;
        assert_eq!(
            status_suffix(&session, &prefs, true),
            " (interactive login required) (auto-fallback to SFTP CLI enabled)"
        );

        prefs.terminal_force_interactive_login = false;
        session.password = Some("secret".into());
        assert_eq!(
            status_suffix(&session, &prefs, false),
            " (password may be requested by OpenSSH for security)"
        );

        session.private_key_path = Some("/keys/id_ed25519".into());
        assert_eq!(status_suffix(&session, &prefs, false), "");

        prefs.terminal_force_interactive_login = true;
        assert_eq!(
            status_suffix(&session, &prefs, false),
            " (interactive login required)"
        );
    }

    #[test]
    fn prepare_remote_terminal_wraps_fallback_and_builds_status() {
        let session = base_session();
        let prefs = Preferences::default();
        let lookup = tools_lookup(&[("ssh", SSH), ("sftp", SFTP)]);
        let prepared =
            prepare_remote_terminal_with(&session, &prefs, "/home/alice", &lookup).expect("plan");

        let ssh_cmd =
            build_remote_terminal_ssh_command_with(&session, &prefs, "/home/alice", &lookup)
                .expect("ssh command");
        let sftp_cmd = build_remote_sftp_cli_command_with(&session, &prefs, "/home/alice", &lookup)
            .expect("sftp command");
        assert_eq!(
            prepared.command,
            build_ssh_with_sftp_fallback_command(&ssh_cmd, &sftp_cmd)
        );
        assert_eq!(
            prepared.status_message,
            "Opening remote terminal at /home/alice (auto-fallback to SFTP CLI enabled)"
        );
    }

    #[test]
    fn prepare_remote_terminal_skips_fallback_when_disabled() {
        let session = base_session();
        let prefs = Preferences {
            terminal_enable_sftp_cli_fallback: false,
            ..Preferences::default()
        };
        let lookup = tools_lookup(&[("ssh", SSH), ("sftp", SFTP)]);
        let prepared = prepare_remote_terminal_with(&session, &prefs, "/", &lookup).expect("plan");

        let ssh_cmd = build_remote_terminal_ssh_command_with(&session, &prefs, "/", &lookup)
            .expect("ssh command");
        assert_eq!(prepared.command, ssh_cmd);
        assert_eq!(prepared.status_message, "Opening remote terminal at /");
    }

    #[test]
    fn prepare_remote_terminal_ignores_fallback_when_sftp_is_missing() {
        let session = base_session();
        let prefs = Preferences::default();
        let lookup = tools_lookup(&[("ssh", SSH)]);
        let prepared = prepare_remote_terminal_with(&session, &prefs, "/", &lookup).expect("plan");
        assert_eq!(
            prepared.command,
            build_remote_terminal_ssh_command_with(&session, &prefs, "/", &lookup)
                .expect("ssh command")
        );
        assert!(!prepared.command.contains("_freescp_ssh_status"));
        assert_eq!(prepared.status_message, "Opening remote terminal at /");
    }

    #[test]
    fn open_remote_terminal_rejects_non_ssh_protocols() {
        for protocol in [Protocol::Ftp, Protocol::Ftps, Protocol::WebDav] {
            let session = SessionOptions {
                protocol,
                ..base_session()
            };
            let err = open_remote_terminal(&session, &Preferences::default(), "/")
                .expect_err("must reject");
            assert_eq!(
                err,
                "Open in terminal requires an SSH transport (SFTP or SCP session)."
            );
        }
    }

    // -- launcher helper ---------------------------------------------------

    #[test]
    fn apple_script_literal_escapes_quotes_and_backslashes() {
        assert_eq!(apple_script_literal(r#"a"b\c"#), r#""a\"b\\c""#);
    }
}
