//! Shared SSH transport and authentication.
//!
//! Both SSH consumers in this crate dial the same way: the SFTP/SCP
//! filesystem backends ([`crate::backends::sftp`]) and the embedded terminal
//! workspace ([`crate::shell`]). This module owns that path — proxy or SSH
//! jump tunnel, TCP connect, host-key verification through [`SshHandler`],
//! and the C++-ordered authentication chain — so the two cannot drift.
//!
//! The code is the connect half of `backends/sftp.rs` lifted out unchanged;
//! callers open their own channel on the returned [`Handle`] (`sftp`
//! subsystem, or a PTY shell).
//!
//! # Host-key verification
//!
//! [`SshHandler`] ports the host-key verification block of
//! `Libssh2SftpClient.cpp` (`sshHandshakeAuth`): known_hosts `Strict` /
//! `AcceptNew` (TOFU) / `Off` policies, fingerprint presentation,
//! `hostkey_confirm_cb` and `hostkey_status_cb`. Parsing/matching/saving is
//! delegated to [`crate::known_hosts`].
//!
//! # russh semantics differ from libssh2 here
//!
//! * `Handler::check_server_key` receives `&PublicKeyOrCertificate` (russh
//!   0.63, which supports OpenSSH host certificates). The C++ client only
//!   dealt with plain keys, so we extract `PublicKeyOrCertificate::public_key()`
//!   and verify that (certificate keys are compared by their embedded
//!   public key).
//! * Returning `Ok(true)` accepts the key; `Ok(false)` rejects it with a
//!   generic message; `Err(SshHandlerError::HostKeyRejected(msg))` rejects
//!   it with *our* message, which `connect_stream` propagates verbatim and
//!   [`map_handler_error`] turns into `ClientError::HostKeyRejected`.
//! * The handler runs during key exchange, i.e. before authentication —
//!   matching libssh2's ordering.
//! * Keyboard-interactive is NOT handler-driven in russh 0.63: the
//!   `authenticate_keyboard_interactive_start` / `_respond` methods on
//!   `Handle` expose the prompt/response loop directly.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::AgentClient;
use russh::keys::{
    load_secret_key, Algorithm, EcdsaCurve, HashAlg, PrivateKeyWithHashAlg, PublicKey,
    PublicKeyOrCertificate,
};
use tracing::{debug, info};

use crate::client::ClientError;
use crate::jumphost::{JumpError, JumpTunnelOptions};
use crate::known_hosts::{
    default_known_hosts_path, fingerprint_sha256, hostkey_bits, load_known_hosts,
    load_known_hosts_strict, save_host, verify_host, KnownHostVerdict,
};
use crate::types::{KbdIntPromptResult, KnownHostsPolicy, ProxyType, SessionOptions};

/// Error type of [`SshHandler`]. `russh::client::Handler::Error` must
/// implement `From<russh::Error>`; the `HostKeyRejected` variant carries the
/// reason shown to the user.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SshHandlerError {
    /// Host key was not accepted under the configured known_hosts policy.
    #[error("{0}")]
    HostKeyRejected(String),
    /// Transparent wrapper so russh transport errors can flow through the
    /// handler error type.
    #[error(transparent)]
    Russh(#[from] russh::Error),
}

/// Client handler for the target SSH connection. Host-key policy and TOFU
/// callbacks come from the [`SessionOptions`] clone the caller hands over.
pub(crate) struct SshHandler {
    pub(crate) opts: SessionOptions,
}

impl SshHandler {
    pub(crate) fn new(opts: SessionOptions) -> Self {
        Self { opts }
    }

    fn status_cb(&self, message: &str) {
        if let Some(cb) = &self.opts.hostkey_status_cb {
            cb(message);
        }
    }

    fn confirm(&self, alg: &str, fp: &str, can_save: bool) -> crate::types::HostKeyDecision {
        match &self.opts.hostkey_confirm_cb {
            Some(cb) => cb(&self.opts.host, self.opts.port, alg, fp, can_save),
            None => crate::types::HostKeyDecision::Reject,
        }
    }
}

/// Resolve the known_hosts file path from options: explicit path if set,
/// otherwise `~/.ssh/known_hosts` (`default_known_hosts_path`).
pub(crate) fn resolved_known_hosts_path(opts: &SessionOptions) -> Option<PathBuf> {
    match opts.known_hosts_path.as_deref() {
        Some(p) if !p.is_empty() => Some(PathBuf::from(p)),
        _ => default_known_hosts_path(),
    }
}

/// SSH algorithm display name for the TOFU prompt. Matches the `algDisplay`
/// values of the C++ client: ssh-ed25519 / ssh-rsa / ecdsa-sha2-nistp{256,384,521}.
fn algorithm_name(key: &PublicKey) -> &'static str {
    match key.algorithm() {
        Algorithm::Ed25519 => "ssh-ed25519",
        Algorithm::Ecdsa { curve } => match curve {
            EcdsaCurve::NistP256 => "ecdsa-sha2-nistp256",
            EcdsaCurve::NistP384 => "ecdsa-sha2-nistp384",
            EcdsaCurve::NistP521 => "ecdsa-sha2-nistp521",
        },
        Algorithm::Rsa { .. } => "ssh-rsa",
        _ => "unknown",
    }
}

impl russh::client::Handler for SshHandler {
    type Error = SshHandlerError;

    /// Host-key verification: ports the known_hosts policy block of
    /// `sshHandshakeAuth`.
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = server_public_key.public_key();
        let opts = &self.opts;
        let policy = opts.known_hosts_policy;

        if policy == KnownHostsPolicy::Off {
            debug!(host = %opts.host, "known_hosts policy Off: accepting any host key");
            return Ok(true);
        }

        let kh_path = resolved_known_hosts_path(opts);

        // Strict requires a usable known_hosts file (C++: "known_hosts
        // unavailable or unreadable (strict policy)").
        let entries = match kh_path.as_deref() {
            None => {
                let msg = "known_hosts unavailable or unreadable (strict policy)".to_string();
                return Err(SshHandlerError::HostKeyRejected(msg));
            }
            Some(path) if policy == KnownHostsPolicy::Strict => {
                if !path.exists() {
                    let msg = "known_hosts unavailable or unreadable (strict policy)".to_string();
                    return Err(SshHandlerError::HostKeyRejected(msg));
                }
                match load_known_hosts_strict(path) {
                    Ok(e) => e,
                    Err(e) => {
                        let msg =
                            format!("known_hosts unavailable or unreadable (strict policy): {e}");
                        return Err(SshHandlerError::HostKeyRejected(msg));
                    }
                }
            }
            Some(path) => match load_known_hosts(path) {
                Ok(e) => e,
                Err(e) => {
                    // AcceptNew with an unreadable file degrades to TOFU (the
                    // file is empty for all practical purposes).
                    self.status_cb(&format!("Could not read known_hosts: {e}"));
                    Vec::new()
                }
            },
        };

        let fingerprint = fingerprint_sha256(&key, opts.show_fp_hex)
            .unwrap_or_else(|_| "SHA256:<unavailable>".to_string());
        let alg_display = format!("{} ({}-bit)", algorithm_name(&key), hostkey_bits(&key));

        match verify_host(&entries, policy, &opts.host, opts.port, &key) {
            KnownHostVerdict::Accepted { line_no } => {
                debug!(host = %opts.host, port = opts.port, line_no, "known_hosts MATCH");
                Ok(true)
            }
            KnownHostVerdict::Mismatch => {
                let msg = match policy {
                    KnownHostsPolicy::Strict => "Host key does not match known_hosts".to_string(),
                    _ => "Host key does not match known_hosts (TOFU rejects changed keys)"
                        .to_string(),
                };
                self.status_cb(&msg);
                info!(host = %opts.host, "host key mismatch rejected");
                Err(SshHandlerError::HostKeyRejected(msg))
            }
            KnownHostVerdict::Missing => {
                if policy == KnownHostsPolicy::Strict {
                    let msg = "Unknown host in known_hosts".to_string();
                    return Err(SshHandlerError::HostKeyRejected(msg));
                }

                // AcceptNew / TOFU: confirm with the user, then optionally persist.
                let can_save = kh_path.is_some();
                debug!(
                    host = %opts.host, port = opts.port, alg = %alg_display, fp = %fingerprint,
                    can_save, "TOFU: asking user to confirm unknown host key"
                );
                match self.confirm(&alg_display, &fingerprint, can_save) {
                    crate::types::HostKeyDecision::Reject => {
                        let msg = "Unknown host: fingerprint not confirmed by user".to_string();
                        info!(host = %opts.host, "TOFU: user rejected unknown host key");
                        return Err(SshHandlerError::HostKeyRejected(msg));
                    }
                    crate::types::HostKeyDecision::AcceptOnce => {
                        self.status_cb("Fingerprint accepted for this connection only");
                        return Ok(true);
                    }
                    crate::types::HostKeyDecision::AcceptAndSave => {}
                }

                let Some(path) = kh_path.as_deref() else {
                    // One-time connection, like C++ when !can_save.
                    self.status_cb("Fingerprint cannot be saved: known_hosts path is not set");
                    return Ok(true);
                };

                if let Err(e) = save_host(
                    path,
                    &opts.host,
                    opts.port,
                    &key,
                    opts.known_hosts_hash_names,
                ) {
                    // Persist failed: ask again with can_save=false; reject
                    // unless the user explicitly accepts one-time.
                    self.status_cb(&format!("Could not save known_hosts: {e}"));
                    match self.confirm(&alg_display, &fingerprint, false) {
                        crate::types::HostKeyDecision::Reject => {
                            let msg = "Could not save fingerprint in known_hosts".to_string();
                            return Err(SshHandlerError::HostKeyRejected(msg));
                        }
                        crate::types::HostKeyDecision::AcceptOnce
                        | crate::types::HostKeyDecision::AcceptAndSave => {}
                    }
                } else {
                    info!(host = %opts.host, port = opts.port, "TOFU: saved new host key");
                }
                Ok(true)
            }
        }
    }
}

/// russh client config shared by every SSH connection (keepalives match the
/// C++ client's libssh2 keepalive settings).
pub(crate) fn client_config() -> Arc<client::Config> {
    Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 6,
        ..Default::default()
    })
}

/// TCP stream for the SSH transport: proxy tunnel or plain connect.
async fn open_tcp_stream(opt: &SessionOptions) -> Result<tokio::net::TcpStream, ClientError> {
    if opt.proxy_type != ProxyType::None {
        if opt.proxy_host.is_empty() {
            return Err(ClientError::Other("proxy host is required".into()));
        }
        debug!(?opt.proxy_type, proxy_host = %opt.proxy_host, proxy_port = opt.proxy_port,
            target = %opt.host, target_port = opt.port, "connecting via proxy");
        crate::proxy::connect_via_proxy(
            opt.proxy_type,
            &opt.proxy_host,
            opt.proxy_port,
            opt.proxy_username.as_deref(),
            opt.proxy_password.as_deref(),
            &opt.host,
            opt.port,
        )
        .await
        .map_err(ClientError::Io)
    } else {
        tokio::net::TcpStream::connect((opt.host.as_str(), opt.port))
            .await
            .map_err(ClientError::Io)
    }
}

fn map_handler_error(e: SshHandlerError) -> ClientError {
    match e {
        SshHandlerError::HostKeyRejected(msg) => ClientError::HostKeyRejected(msg),
        SshHandlerError::Russh(r) => ClientError::Other(r.to_string()),
    }
}

fn map_jump_error(e: JumpError) -> ClientError {
    match e {
        JumpError::AuthFailed(msg) => ClientError::AuthFailed(msg),
        JumpError::Io(io) => ClientError::Io(io),
        JumpError::Other(msg) => {
            let lower = msg.to_lowercase();
            if lower.contains("host key") || lower.contains("hostkey") {
                ClientError::HostKeyRejected(msg)
            } else {
                ClientError::Other(msg)
            }
        }
    }
}

/// Builds the SSH transport for `opt` (proxy, SSH jump tunnel or plain TCP)
/// and authenticates. The returned handle is live; the caller opens its
/// channel on it (SFTP subsystem or a PTY shell) and must keep the handle
/// alive for as long as the channel is in use.
pub(crate) async fn connect_and_auth(
    opt: &SessionOptions,
) -> Result<Handle<SshHandler>, ClientError> {
    // C++: "Proxy and SSH jump host cannot be used together."
    if opt.proxy_type != ProxyType::None && opt.jump_host.is_some() {
        return Err(ClientError::Unsupported(
            "Proxy and SSH jump host cannot be used together.".into(),
        ));
    }

    let handler = SshHandler::new(opt.clone());
    let config = client_config();

    let mut handle = match opt.jump_host.as_deref().filter(|h| !h.is_empty()) {
        Some(jump_host) => {
            let tunnel = crate::jumphost::open_jump_tunnel_with_options(
                jump_host,
                opt.jump_port,
                &opt.host,
                opt.port,
                &JumpTunnelOptions {
                    username: opt.jump_username.as_deref(),
                    private_key_path: opt
                        .jump_private_key_path
                        .as_deref()
                        .map(std::path::Path::new),
                    private_key_passphrase: opt.private_key_passphrase.as_deref(),
                    known_hosts_path: resolved_known_hosts_path(opt),
                    accept_unknown_host_key: opt.known_hosts_policy != KnownHostsPolicy::Strict,
                    ..JumpTunnelOptions::default()
                },
            )
            .await
            .map_err(map_jump_error)?;
            info!(jump_host, target = %opt.host, "connecting through SSH jump tunnel (ssh -W)");
            client::connect_stream(config, tunnel, handler)
                .await
                .map_err(map_handler_error)?
        }
        None => {
            let stream = open_tcp_stream(opt).await?;
            client::connect_stream(config, stream, handler)
                .await
                .map_err(map_handler_error)?
        }
    };

    authenticate(&mut handle, opt).await?;
    Ok(handle)
}

// ---------------------------------------------------------------------------
// Authentication (ports `authenticateSession` from the C++ client)
// ---------------------------------------------------------------------------

/// Try methods in the C++ order: keyboard-interactive, password, key file,
/// then ssh-agent identities.
async fn authenticate(
    handle: &mut Handle<SshHandler>,
    opt: &SessionOptions,
) -> Result<(), ClientError> {
    let mut tried: Vec<&'static str> = Vec::new();

    // 1. Keyboard-interactive (attempted when a callback exists, or when a
    //    password is available for the heuristic fallback).
    let can_kbd = opt.keyboard_interactive_cb.is_some() || opt.password.is_some();
    if can_kbd {
        match try_keyboard_interactive(handle, opt).await {
            Ok(true) => {
                info!(user = %opt.username, "authenticated via keyboard-interactive");
                return Ok(());
            }
            Ok(false) => tried.push("keyboard-interactive"),
            Err(e) => return Err(e), // Cancelled or transport failure
        }
    }

    // 2. Password.
    if let Some(password) = opt.password.as_deref() {
        match handle
            .authenticate_password(opt.username.clone(), password)
            .await
        {
            Ok(AuthResult::Success) => {
                info!(user = %opt.username, "authenticated via password");
                return Ok(());
            }
            Ok(AuthResult::Failure { .. }) => tried.push("password"),
            Err(e) => {
                debug!(error = %e, "password auth transport error");
                tried.push("password");
            }
        }
    }

    // 3. Explicit private key file.
    if let Some(key_path) = opt.private_key_path.as_deref() {
        match try_private_key(handle, opt, key_path).await {
            Ok(true) => return Ok(()),
            Ok(false) => tried.push("publickey"),
            Err(e) => return Err(e), // unusable key file
        }
    }

    // 4. ssh-agent identities (always consulted as a last resort; the C++
    //    client did the same when agent support was compiled in).
    match try_agent(handle, &opt.username).await {
        Ok(true) => {
            info!(user = %opt.username, "authenticated via ssh-agent");
            return Ok(());
        }
        Ok(false) => tried.push("ssh-agent"),
        Err(e) => {
            debug!(error = %e, "ssh-agent auth failed");
            tried.push("ssh-agent");
        }
    }

    Err(ClientError::AuthFailed(format!(
        "all authentication methods failed (tried: {})",
        tried.join(", ")
    )))
}

/// Keyboard-interactive loop. On `Unhandled` (or no callback) the C++
/// heuristic fallback answers every prompt with the password; `Cancelled`
/// aborts the whole connection attempt.
async fn try_keyboard_interactive(
    handle: &mut Handle<SshHandler>,
    opt: &SessionOptions,
) -> Result<bool, ClientError> {
    let mut state = handle
        .authenticate_keyboard_interactive_start(opt.username.clone(), None::<String>)
        .await
        .map_err(|e| ClientError::Other(format!("keyboard-interactive failed: {e}")))?;

    loop {
        match state {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let prompt_texts: Vec<String> = prompts.iter().map(|p| p.prompt.clone()).collect();
                let mut responses: Vec<String> = Vec::new();
                let result = match &opt.keyboard_interactive_cb {
                    Some(cb) => cb(&name, &instructions, &prompt_texts, &mut responses),
                    None => KbdIntPromptResult::Unhandled,
                };
                match result {
                    KbdIntPromptResult::Cancelled => {
                        return Err(ClientError::AuthFailed(
                            "keyboard-interactive cancelled by user".into(),
                        ));
                    }
                    KbdIntPromptResult::Unhandled => {
                        let Some(password) = opt.password.clone() else {
                            return Err(ClientError::AuthFailed(
                                "keyboard-interactive prompts unhandled and no password for fallback"
                                    .into(),
                            ));
                        };
                        responses = prompt_texts.iter().map(|_| password.clone()).collect();
                    }
                    KbdIntPromptResult::Handled => {
                        // Pad short answers with empty strings (the C++
                        // client did the same for LIBSSH2_KBDINT_RESPONSE).
                        responses.resize(prompts.len(), String::new());
                    }
                }
                state = handle
                    .authenticate_keyboard_interactive_respond(responses)
                    .await
                    .map_err(|e| ClientError::Other(format!("keyboard-interactive failed: {e}")))?;
            }
        }
    }
}

/// Load `key_path` and attempt public-key authentication with it.
async fn try_private_key(
    handle: &mut Handle<SshHandler>,
    opt: &SessionOptions,
    key_path: &str,
) -> Result<bool, ClientError> {
    let key = load_secret_key(key_path, opt.private_key_passphrase.as_deref()).map_err(|e| {
        ClientError::AuthFailed(format!("failed to load private key {key_path}: {e}"))
    })?;
    // OpenSSH servers commonly reject SHA-1 `ssh-rsa` signatures; negotiate
    // rsa-sha2 when the server advertises its signature algorithms (same
    // fallback policy as crate::jumphost).
    let hash_alg = if matches!(key.public_key().algorithm(), Algorithm::Rsa { .. }) {
        let negotiated = handle.best_supported_rsa_hash().await.unwrap_or(None);
        Some(negotiated.flatten().unwrap_or(HashAlg::Sha256))
    } else {
        None
    };
    let pair = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
    match handle
        .authenticate_publickey(opt.username.clone(), pair)
        .await
    {
        Ok(AuthResult::Success) => {
            info!(user = %opt.username, key = key_path, "authenticated via private key");
            Ok(true)
        }
        Ok(AuthResult::Failure { .. }) => Ok(false),
        Err(e) => {
            debug!(error = %e, "publickey auth transport error");
            Ok(false)
        }
    }
}

/// Try every identity offered by the ssh-agent.
async fn try_agent(handle: &mut Handle<SshHandler>, username: &str) -> Result<bool, ClientError> {
    #[cfg(unix)]
    let mut agent = match AgentClient::connect_env().await {
        Ok(a) => a,
        Err(e) => {
            debug!("ssh-agent unavailable: {e}");
            return Ok(false);
        }
    };
    #[cfg(windows)]
    let mut agent = match AgentClient::connect_pageant().await {
        Ok(a) => a,
        Err(e) => {
            debug!("ssh-agent (Pageant) unavailable: {e}");
            return Ok(false);
        }
    };

    let identities = match agent.request_identities().await {
        Ok(v) => v,
        Err(e) => {
            debug!("ssh-agent request_identities failed: {e}");
            return Ok(false);
        }
    };
    for identity in identities {
        let key = identity.public_key().into_owned();
        match handle
            .authenticate_publickey_with(username.to_string(), key, None, &mut agent)
            .await
        {
            Ok(AuthResult::Success) => return Ok(true),
            Ok(AuthResult::Failure { .. }) => continue,
            Err(e) => {
                debug!(error = %e, "ssh-agent identity rejected");
                continue;
            }
        }
    }
    Ok(false)
}
