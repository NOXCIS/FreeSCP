//! SCP backend: classic SCP protocol implemented over `russh` channels.
//!
//! This is a port of `core/src/libssh2/Libssh2ScpClient.cpp` onto pure-Rust
//! russh. The C++ client used libssh2's high-level `scp_send64` / `scp_recv2`
//! helpers; those do not exist for russh, so this module speaks the classic
//! SCP wire protocol itself:
//!
//! * Upload (`put`): open a session channel and
//!   `exec "scp -t <path>"` (single file) or `exec "scp -r -t <path>"`
//!   (recursive directory). The client drives the "sink" side:
//!   `C{mode:04o} {size} {name}\n` for files, `D{mode:04o} 0 {name}\n` ...
//!   `E\n` for directories, optional `T{mtime} 0 {atime} 0\n` time records,
//!   NUL (`\x00`) terminators after file data, and 1-byte ACKs read from the
//!   remote after every record.
//! * Download (`get`): `exec "scp -r -f <path>"` and parse the "source" mode
//!   control stream (`C`, `D`, `E`, `T`, `\x01` error, `\x02` fatal error).
//!
//! Wire-protocol decisions (deviations from the C++ client, which delegated
//! the protocol to libssh2):
//!
//! * Downloads always run with `-r` (`scp -r -f`). The legacy SCP protocol has
//!   no remote stat, and `exists()`/`stat()` are unsupported by this backend,
//!   so there is no way to know in advance whether the remote path is a file
//!   or a directory. `-r` makes the remote source send `C` records for plain
//!   files and `D`/`E` records for directories — a strict superset of `-f`
//!   behavior on every legacy server. This enables recursive download
//!   (requested feature; the C++ client was single-file only).
//! * Recursive uploads (`local` is a directory) exec `scp -r -t <path>` and
//!   send `D`/`E`/`T` records, preserving file/dir modes and mtimes. Plain
//!   single-file uploads keep exact C++ parity: `scp -t`, mode `0644`, no `T`
//!   record.
//! * OpenSSH >= 9.0 servers negotiate "SFTP-mode scp" over the exec channel.
//!   Negotiation is initiated by a first-write escape byte; a legacy client
//!   like this one never sends it, so servers must fall back to the legacy
//!   protocol. Defensively, if the first control byte received on download is
//!   not a legacy control byte (`C`/`D`/`T`/`\x01`/`\x02`), we treat the
//!   transfer as an open failure — which routes to the SFTP fallback in
//!   `ScpTransferMode::Auto`, exactly where an SFTP-speaking server belongs.
//! * `T` records received on download are parsed and ignored: applying remote
//!   mtimes to local files needs the `filetime` crate, which is not declared
//!   in `crates/freescp-core`'s dependencies, and the C++ client did not set
//!   local times either.
//! * Symlinks are skipped during recursive uploads (avoids cycles; the C++
//!   client could not upload directories at all).
//! * SCP paths are passed through the remote shell; we single-quote them
//!   (`'...'` with embedded quotes escaped as `'\''`). File names containing
//!   newlines cannot be represented in the SCP wire format and will be
//!   truncated/mangled — a protocol limitation, documented here.
//! * `interrupt()` sets a flag observed via `tokio::select!` in every
//!   read/write of the transfer engine and aborts with
//!   `ClientError::Cancelled`. This is cooperative-hard cancellation (the
//!   running read/write future is dropped immediately); the C++ equivalent
//!   (`shutdown(sock, SHUT_RDWR)`) killed the whole session, so this is
//!   strictly gentler. Interrupt during `connect()` is only checked between
//!   phases (no handle exists yet to disconnect).
//!
//! The C++ client delegated the SSH transport (TCP connect, proxy, jump host,
//! known_hosts, auth) to `Libssh2SftpClient::connectTransportOnly`; this
//! module embeds its own equivalent transport setup. See
//! [`ScpSession::connect`].

// ===========================================================================
// CROSS-AGENT CONTRACTS — what this file assumes from sibling workstreams.
// If your workstream owns one of these modules, keep it in sync with this.
// ===========================================================================
//
// crate::types (core-types) — mirrors core/include/freescp/SftpTypes.hpp:
//     pub struct SessionOptions {
//         pub protocol: Protocol,                       // set to Protocol::Scp on connect
//         pub scp_transfer_mode: ScpTransferMode,       // Auto | ScpOnly
//         pub host: String,
//         pub port: u16,
//         pub username: String,
//         pub password: Option<String>,
//         pub private_key_path: Option<String>,
//         pub private_key_passphrase: Option<String>,
//         pub known_hosts_path: Option<String>,         // default ~/.ssh/known_hosts
//         pub known_hosts_policy: KnownHostsPolicy,     // Strict | AcceptNew | Off
//         pub known_hosts_hash_names: bool,
//         pub transfer_integrity_policy: TransferIntegrityPolicy, // unused here (C++ SCP had none)
//         pub proxy_type: ProxyType,                    // None | Socks5 | HttpConnect
//         pub proxy_host: String,
//         pub proxy_port: u16,
//         pub proxy_username: Option<String>,
//         pub proxy_password: Option<String>,
//         pub jump_host: Option<String>,
//         pub jump_port: u16,
//         pub jump_username: Option<String>,
//         pub jump_private_key_path: Option<String>,
//         pub hostkey_confirm_cb: Option<HostKeyConfirmCb>,
//         pub hostkey_status_cb: Option<HostKeyStatusCb>,
//         pub keyboard_interactive_cb: Option<KbdIntPromptsCb>,
//     }
//     pub enum KbdIntPromptResult { Handled, Unhandled, Cancelled }
//     pub enum Protocol { Sftp, Scp, Ftp, Ftps, WebDav }
//     pub enum ScpTransferMode { Auto, ScpOnly }
//     pub enum KnownHostsPolicy { Strict, AcceptNew, Off }
//     pub enum ProxyType { None, Socks5, HttpConnect }
//     pub fn capabilities_for_protocol(p: Protocol) -> ProtocolCapabilities;
//     SessionOptions must derive Clone (the SFTP fallback copies it and flips
//     `protocol` to Sftp, mirroring the C++ `SessionOptions sftpOpt = *sessionOptions_`).
//     KnownHostsPolicy, ProxyType and ScpTransferMode must derive Clone +
//     PartialEq (this file clones/compares them); Protocol must derive Clone +
//     PartialEq.
//     Callback aliases:
//     pub type HostKeyConfirmCb = Arc<dyn Fn(&str, u16, &str, &str, bool) -> bool + Send + Sync>;
//     pub type HostKeyStatusCb  = Arc<dyn Fn(&str) + Send + Sync>;
//     pub type KbdIntPromptsCb  = Arc<dyn Fn(&str, &str, &[String], &mut Vec<String>)
//                                         -> KbdIntPromptResult + Send + Sync>;
//
// crate::client (core-api) — the trait this module implements:
//     pub type ProgressCb = Arc<dyn Fn(u64, u64) + Send + Sync>;
//     pub type CancelCb    = Arc<dyn Fn() -> bool + Send + Sync>;
//
// crate::known_hosts (sftp-helper) — expected API (used by host_key_gate below):
//     pub enum KnownHostsMatch { Match, Mismatch, NotFound }
//     pub fn lookup(host: &str, port: u16, key: &russh::keys::PublicKey,
//                   file: &std::path::Path) -> Result<KnownHostsMatch, ClientError>;
//         // Missing file => Ok(KnownHostsMatch::NotFound).
//     pub fn persist(host: &str, port: u16, key: &russh::keys::PublicKey,
//                    file: &std::path::Path, hash_names: bool) -> Result<(), ClientError>;
//     pub fn default_path() -> std::path::PathBuf;   // ~/.ssh/known_hosts (HOME, then USERPROFILE)
//
// crate::proxy (proxy-jumphost) — exact contract given to this workstream:
//     pub async fn connect_via_proxy(proxy_type: ProxyType, proxy_host: &str,
//         proxy_port: u16, proxy_user: Option<&str>, proxy_pass: Option<&str>,
//         target_host: &str, target_port: u16) -> io::Result<tokio::net::TcpStream>;
//
// crate::jumphost (proxy-jumphost) — expected API (russh direct-tcpip tunnel,
// replaces the C++ `ssh -W` stdio tunnel):
//     pub async fn open_tunnel(jump_host: &str, jump_port: u16,
//         jump_username: Option<&str>, jump_private_key_path: Option<&std::path::Path>,
//         target_host: &str, target_port: u16)
//         -> io::Result<Box<dyn tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>>;
//
// crate::backends::sftp (sftp-backend) — fallback client:
//     pub struct RusshSftpClient;  // pub fn new() -> Self; impl crate::client::SftpClient
//
// Version note: this file targets the workspace-pinned `russh = "0.63"` API
// (e.g. `check_server_key(&PublicKeyOrCertificate)`, `exec(impl Into<Vec<u8>>)`,
// `russh::keys::load_secret_key`, `russh::keys::PrivateKeyWithHashAlg`).
// ===========================================================================

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use russh::client::{self, Handle, Handler as ClientHandler, Msg};
use russh::keys as rkeys;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tracing::{debug, trace, warn};

use crate::client::{CancelCb, ClientError, ProgressCb, SftpClient};
use crate::types::{
    HostKeyConfirmCb, HostKeyStatusCb, KbdIntPromptResult, KbdIntPromptsCb, KnownHostsPolicy,
    Protocol, ProtocolCapabilities, ProxyType, ScpTransferMode, SessionOptions,
};

/// Data chunk size, mirrors `kScpChunkSize` in Libssh2ScpClient.cpp.
const SCP_CHUNK_SIZE: usize = 64 * 1024;

/// Keepalive interval for the SSH session. The C++ transport enables
/// libssh2 keepalive; russh supports it via `Config::keepalive_interval`.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// russh `Handle` is not `Clone`, so `interrupt()` cannot own a copy. It
/// instead flips an `AtomicBool` observed by `tokio::select!` in every
/// transfer-engine read/write via a `watch` channel.
struct Shared {
    host: String,
    port: u16,
    password: Option<String>,
    known_hosts_path: Option<PathBuf>,
    known_hosts_policy: KnownHostsPolicy,
    known_hosts_hash_names: bool,
    hostkey_confirm: Option<HostKeyConfirmCb>,
    hostkey_status: Option<HostKeyStatusCb>,
    kbdint_cb: Option<KbdIntPromptsCb>,
    interrupted: AtomicBool,
    /// Set by `check_server_key` on rejection; consumed by `connect` to
    /// produce `ClientError::HostKeyRejected` with a useful message.
    hostkey_rejected: tokio::sync::Mutex<Option<String>>,
    interrupt_tx: tokio::sync::watch::Sender<bool>,
}

impl Shared {
    fn new(opt: &SessionOptions) -> Self {
        let (interrupt_tx, _) = tokio::sync::watch::channel(false);
        Self {
            host: opt.host.clone(),
            port: opt.port,
            password: opt.password.clone(),
            known_hosts_path: opt.known_hosts_path.as_ref().map(PathBuf::from),
            known_hosts_policy: opt.known_hosts_policy,
            known_hosts_hash_names: opt.known_hosts_hash_names,
            hostkey_confirm: opt.hostkey_confirm_cb.clone(),
            hostkey_status: opt.hostkey_status_cb.clone(),
            kbdint_cb: opt.keyboard_interactive_cb.clone(),
            interrupted: AtomicBool::new(false),
            hostkey_rejected: tokio::sync::Mutex::new(None),
            interrupt_tx,
        }
    }

    fn interrupt(&self) {
        self.interrupted.store(true, Ordering::SeqCst);
        self.interrupt_tx.send_replace(true);
    }

    fn interrupted(&self) -> bool {
        self.interrupted.load(Ordering::SeqCst)
    }

    fn status(&self, message: &str) {
        if let Some(cb) = &self.hostkey_status {
            cb(message);
        }
    }
}

/// russh client handler. In russh the handler carries no auth callbacks
/// (auth is driven through `Handle::authenticate_*`); the only mandatory
/// method is `check_server_key`.
struct ScpHandler {
    shared: Arc<Shared>,
}

impl ClientHandler for ScpHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &rkeys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // russh 0.63 may hand us a host certificate instead of a plain key.
        // The C++ client never saw certificates (libssh2), so we verify the
        // certificate's embedded subject public key against known_hosts.
        let key: rkeys::PublicKey = match server_public_key {
            rkeys::PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            rkeys::PublicKeyOrCertificate::Certificate(cert) => cert.public_key().clone().into(),
        };
        match self.shared.verify_host_key(&key) {
            Ok(()) => Ok(true),
            Err(msg) => {
                warn!(host = %self.shared.host, "host key rejected: {msg}");
                *self.shared.hostkey_rejected.lock().await = Some(msg);
                Ok(false)
            }
        }
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        debug!(%banner, "auth banner received");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Host-key gate (known_hosts policy logic, mirroring Libssh2SftpClient.cpp
// lines ~1994-2427). Calls into crate::known_hosts — see the contract block.
// ---------------------------------------------------------------------------

impl Shared {
    fn verify_host_key(&self, key: &rkeys::PublicKey) -> Result<(), String> {
        if self.known_hosts_policy == KnownHostsPolicy::Off {
            warn!(host = %self.host, "host key verification disabled by policy");
            return Ok(());
        }

        let file = self
            .known_hosts_path
            .clone()
            .or_else(crate::known_hosts::default_known_hosts_path)
            .ok_or_else(|| "could not determine the known_hosts path".to_string())?;

        if !file.exists() && self.known_hosts_policy == KnownHostsPolicy::Strict {
            self.status("known_hosts unavailable or unreadable (strict policy)");
            return Err("known_hosts unavailable or unreadable (strict policy)".into());
        }

        let entries = match self.known_hosts_policy {
            KnownHostsPolicy::Strict => crate::known_hosts::load_known_hosts_strict(&file),
            _ => crate::known_hosts::load_known_hosts(&file),
        }
        .map_err(|e| format!("known_hosts lookup failed: {e}"))?;

        let verdict = crate::known_hosts::verify_host(
            &entries,
            self.known_hosts_policy,
            &self.host,
            self.port,
            key,
        );

        match verdict {
            crate::known_hosts::KnownHostVerdict::Accepted { line_no } => {
                debug!(host = %self.host, port = self.port, line_no, "host key matched known_hosts");
                Ok(())
            }
            crate::known_hosts::KnownHostVerdict::Mismatch => match self.known_hosts_policy {
                KnownHostsPolicy::Strict => Err("Host key does not match known_hosts".into()),
                KnownHostsPolicy::AcceptNew => {
                    self.status("Host key does not match known_hosts (TOFU rejects changed keys)");
                    Err("Host key does not match known_hosts (TOFU rejects changed keys)".into())
                }
                KnownHostsPolicy::Off => unreachable!("handled above"),
            },
            crate::known_hosts::KnownHostVerdict::Missing => match self.known_hosts_policy {
                KnownHostsPolicy::Strict => Err("Unknown host in known_hosts".into()),
                KnownHostsPolicy::AcceptNew => {
                    let (algorithm, fingerprint) = host_key_info(key);
                    let can_save = !file.as_os_str().is_empty();
                    let confirmed = self.hostkey_confirm.as_ref().is_some_and(|cb| {
                        cb(&self.host, self.port, &algorithm, &fingerprint, can_save)
                    });
                    if !confirmed {
                        return Err("Unknown host: fingerprint not confirmed by user".into());
                    }
                    match crate::known_hosts::save_host(
                        &file,
                        &self.host,
                        self.port,
                        key,
                        self.known_hosts_hash_names,
                    ) {
                        Ok(()) => Ok(()),
                        Err(e) => {
                            // C++ continues connecting after a persist failure;
                            // it only notifies the status callback.
                            let msg = format!("Could not save known_hosts: {e}");
                            warn!(host = %self.host, "{msg}");
                            self.status(&msg);
                            Ok(())
                        }
                    }
                }
                KnownHostsPolicy::Off => unreachable!("handled above"),
            },
        }
    }
}

/// `(algorithm, fingerprint)` for the TOFU confirm callback. The C++ client
/// passed a display name like "ECDSA (256-bit)" and a SHA256/Base64
/// fingerprint; we pass the OpenSSH algorithm name and the ssh-key crate's
/// standard `SHA256:...` fingerprint.
fn host_key_info(key: &rkeys::PublicKey) -> (String, String) {
    let algorithm = key.algorithm().to_string();
    let fingerprint = key.fingerprint(rkeys::HashAlg::Sha256).to_string();
    (algorithm, fingerprint)
}

// ---------------------------------------------------------------------------
// Transport (TCP / SOCKS5+HTTP-CONNECT proxy / SSH jump host). Isolated so the
// proxy-jumphost workstream can plug its helpers in without touching the rest.
// ---------------------------------------------------------------------------

/// Auto-trait alias for the byte streams accepted by
/// [`Transport::Streamed`]: a single non-auto trait is required in trait
/// objects, so this bundles `AsyncRead + AsyncWrite + Unpin + Send`.
trait StreamIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> StreamIo for T {}

enum Transport {
    Direct,
    Streamed(Box<dyn StreamIo>),
}

/// Open the raw byte transport to `opt.host:opt.port` according to
/// `proxy_type` / `jump_host` in `SessionOptions`. Mirrors the C++ `tcpConnect`.
async fn open_transport(opt: &SessionOptions) -> io::Result<Transport> {
    if let Some(jump) = &opt.jump_host {
        debug!(jump_host = %jump, "opening SSH jump-host tunnel");
        let tunnel = crate::jumphost::open_jump_tunnel(
            jump,
            opt.jump_port,
            opt.jump_username.as_deref(),
            opt.jump_private_key_path.as_deref().map(Path::new),
            &opt.host,
            opt.port,
        )
        .await
        .map_err(io::Error::other)?;
        return Ok(Transport::Streamed(Box::new(tunnel)));
    }
    if opt.proxy_type != ProxyType::None {
        debug!(
            proxy = ?opt.proxy_type,
            proxy_host = %opt.proxy_host,
            "opening proxy tunnel"
        );
        let stream = crate::proxy::connect_via_proxy(
            opt.proxy_type,
            &opt.proxy_host,
            opt.proxy_port,
            opt.proxy_username.as_deref(),
            opt.proxy_password.as_deref(),
            &opt.host,
            opt.port,
        )
        .await?;
        return Ok(Transport::Streamed(Box::new(stream)));
    }
    Ok(Transport::Direct)
}

// ---------------------------------------------------------------------------
// SSH session + authentication (port of the connectTransportOnly flow)
// ---------------------------------------------------------------------------

struct ScpSession {
    handle: Handle<ScpHandler>,
    shared: Arc<Shared>,
}

impl ScpSession {
    async fn connect(opt: &SessionOptions) -> Result<Self, ClientError> {
        let shared = Arc::new(Shared::new(opt));
        if shared.interrupted() {
            return Err(ClientError::Cancelled);
        }

        let transport = open_transport(opt)
            .await
            .map_err(|e| ClientError::OperationFailed(format!("TCP connect failed: {e}")))?;
        if shared.interrupted() {
            return Err(ClientError::Cancelled);
        }

        let config = Arc::new(client::Config {
            keepalive_interval: Some(KEEPALIVE_INTERVAL),
            ..Default::default()
        });
        let handler = ScpHandler {
            shared: shared.clone(),
        };

        let mut handle = match transport {
            Transport::Direct => {
                client::connect(config, (opt.host.as_str(), opt.port), handler).await
            }
            Transport::Streamed(stream) => client::connect_stream(config, stream, handler).await,
        };
        if let Err(e) = &mut handle {
            if let Some(msg) = shared.hostkey_rejected.lock().await.take() {
                return Err(ClientError::HostKeyRejected(msg));
            }
            return Err(ClientError::OperationFailed(format!(
                "SSH handshake failed: {e:#}"
            )));
        }
        let mut handle = handle.unwrap();
        if shared.interrupted() {
            return Err(ClientError::Cancelled);
        }

        authenticate(&mut handle, &shared, opt).await?;
        Ok(Self { handle, shared })
    }

    fn is_alive(&self) -> bool {
        !self.handle.is_closed()
    }

    fn interrupt(&self) {
        self.shared.interrupt();
    }
}

/// Authentication, mirroring Libssh2SftpClient.cpp lines 2430-2674:
///
/// 1) explicit private key (fail hard), 2) password then keyboard-interactive
///    if the server still allows it, then ssh-agent as a last resort (agent auth
///    is NOT ported — see MISSING-DEP below), 3) no credentials: keyboard-
///    interactive when a callback is supplied, otherwise fail.
///
// MISSING-DEP: ssh-agent (last-resort ssh-agent auth fallback of the C++
// password/kbdint path). russh 0.63 bundles an agent client
// (`russh::keys::agent::client::AgentClient`, Signer impl for
// `authenticate_publickey_with`), so no external crate is strictly required —
// but the flow (SSH_AUTH_SOCK discovery, request_identities, per-key sign
// attempts) is not implemented here. If a dedicated helper lands in a sibling
// crate, plug it into the two `// MISSING-DEP` call sites below.
async fn authenticate(
    handle: &mut Handle<ScpHandler>,
    shared: &Arc<Shared>,
    opt: &SessionOptions,
) -> Result<(), ClientError> {
    // 1) Private key.
    if let Some(path) = &opt.private_key_path {
        let passphrase = opt.private_key_passphrase.as_deref();
        let key = rkeys::load_secret_key(path, passphrase)
            .map_err(|e| ClientError::AuthFailed(format!("Key authentication failed — {e}")))?;
        let hash_alg = rsa_hash_alg(handle, &key).await;
        let key = rkeys::PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
        match handle.authenticate_publickey(&opt.username, key).await {
            Ok(client::AuthResult::Success) => return Ok(()),
            Ok(client::AuthResult::Failure { .. }) | Err(_) => {
                return Err(ClientError::AuthFailed(
                    "Key authentication failed".to_string(),
                ));
            }
        }
    }

    // 2) Password, then keyboard-interactive if the server still allows it.
    if let Some(password) = &opt.password {
        match handle.authenticate_password(&opt.username, password).await {
            Ok(client::AuthResult::Success) => return Ok(()),
            Ok(client::AuthResult::Failure {
                remaining_methods,
                partial_success: _,
            }) => {
                // Mirrors the C++ userauth_list + hasMethod("keyboard-interactive") check.
                let kbdint_allowed =
                    remaining_methods.contains(&russh::MethodKind::KeyboardInteractive);
                if kbdint_allowed && run_keyboard_interactive(handle, shared, opt).await? {
                    return Ok(());
                }
                return Err(ClientError::AuthFailed(
                    "Password/kbdint authentication failed".to_string(),
                ));
            }
            Err(e) => {
                return Err(ClientError::AuthFailed(format!(
                    "Password authentication failed — {e}"
                )));
            }
        }
    }

    // 3) No credentials: keyboard-interactive only if a callback can answer it.
    //    (The C++ client tried ssh-agent here; see MISSING-DEP above.)
    if opt.keyboard_interactive_cb.is_some() {
        if run_keyboard_interactive(handle, shared, opt).await? {
            return Ok(());
        }
        return Err(ClientError::AuthFailed(
            "Keyboard-interactive authentication failed".to_string(),
        ));
    }

    // Mirrors "Sin credenciales: clave/agent/password no disponibles".
    Err(ClientError::AuthFailed(
        "No credentials: key/agent/password not available".to_string(),
    ))
}

/// For RSA keys, pick the strongest hash the server supports
/// (`rsa-sha2-512` default; legacy `ssh-rsa` only when the server explicitly
/// rejects rsa-sha2). Non-RSA keys ignore the hash.
async fn rsa_hash_alg(
    handle: &Handle<ScpHandler>,
    key: &rkeys::PrivateKey,
) -> Option<rkeys::HashAlg> {
    if !key.algorithm().is_rsa() {
        return None;
    }
    match handle.best_supported_rsa_hash().await {
        Ok(Some(Some(hash))) => Some(hash),
        Ok(Some(None)) => None, // server only allows legacy ssh-rsa (SHA-1)
        Ok(None) | Err(_) => Some(rkeys::HashAlg::Sha512),
    }
}

/// Drive the russh keyboard-interactive flow, answering prompts through
/// `SessionOptions::keyboard_interactive_cb` (Handled) or the C++ heuristic
/// (Unhandled: first prompt gets the password, the rest are empty).
async fn run_keyboard_interactive(
    handle: &mut Handle<ScpHandler>,
    shared: &Arc<Shared>,
    opt: &SessionOptions,
) -> Result<bool, ClientError> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(&opt.username, None::<String>)
        .await
        .map_err(|e| ClientError::AuthFailed(format!("Keyboard-interactive start failed — {e}")))?;

    loop {
        match response {
            client::KeyboardInteractiveAuthResponse::Success => return Ok(true),
            client::KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            client::KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                if shared.interrupted() {
                    return Err(ClientError::Cancelled);
                }
                let mut answers = Vec::with_capacity(prompts.len());
                let handled = match &shared.kbdint_cb {
                    Some(cb) => {
                        let prompt_texts: Vec<String> =
                            prompts.iter().map(|p| p.prompt.clone()).collect();
                        let mut responses: Vec<String> = Vec::new();
                        let result = cb(&name, &instructions, &prompt_texts, &mut responses);
                        match result {
                            KbdIntPromptResult::Handled => {
                                answers = responses;
                                true
                            }
                            KbdIntPromptResult::Unhandled => false,
                            KbdIntPromptResult::Cancelled => {
                                return Err(ClientError::AuthFailed(
                                    "Keyboard-interactive authentication canceled by user"
                                        .to_string(),
                                ));
                            }
                        }
                    }
                    None => false,
                };
                if !handled {
                    // C++ heuristic: password answers the first prompt.
                    for (i, _) in prompts.iter().enumerate() {
                        if i == 0 {
                            answers.push(shared.password.clone().unwrap_or_default());
                        } else {
                            answers.push(String::new());
                        }
                    }
                }
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(|e| {
                        ClientError::AuthFailed(format!(
                            "Keyboard-interactive response failed — {e}"
                        ))
                    })?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SCP wire-protocol stream: byte-level view of a `scp -t` / `scp -f` channel.
// ---------------------------------------------------------------------------

/// Every read/write races against the interrupt watch; on interrupt the
/// pending IO future is dropped and the transfer unwinds with
/// `ClientError::Cancelled`.
struct ScpStream {
    inner: tokio::io::BufReader<russh::ChannelStream<Msg>>,
    shared: Arc<Shared>,
}

enum StreamError {
    Io(io::Error),
    /// Channel EOF / closed: no more data will ever arrive.
    Eof,
    /// `interrupt()` fired while blocked.
    Interrupted,
}

impl From<io::Error> for StreamError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            StreamError::Eof
        } else {
            StreamError::Io(e)
        }
    }
}

impl ScpStream {
    fn new(stream: russh::ChannelStream<Msg>, shared: Arc<Shared>) -> Self {
        Self {
            inner: tokio::io::BufReader::new(stream),
            shared,
        }
    }

    async fn read_u8(&mut self) -> Result<u8, StreamError> {
        let mut buf = [0u8; 1];
        self.read_exact_into(&mut buf).await?;
        Ok(buf[0])
    }

    /// Read one `\n`-terminated protocol line (the trailing `\n` is kept).
    async fn read_line(&mut self) -> Result<Vec<u8>, StreamError> {
        let mut line = Vec::new();
        let mut rx = self.shared.interrupt_tx.subscribe();
        tokio::select! {
            n = self.inner.read_until(b'\n', &mut line) => {
                let n = n?;
                if n == 0 && line.is_empty() {
                    return Err(StreamError::Eof);
                }
                Ok(line) // may be an unterminated final line
            }
            _ = rx.changed() => Err(StreamError::Interrupted),
        }
    }

    async fn read_exact_into(&mut self, buf: &mut [u8]) -> Result<(), StreamError> {
        let mut rx = self.shared.interrupt_tx.subscribe();
        tokio::select! {
            r = self.inner.read_exact(buf) => r.map(|_| ()).map_err(StreamError::from),
            _ = rx.changed() => Err(StreamError::Interrupted),
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        let mut rx = self.shared.interrupt_tx.subscribe();
        tokio::select! {
            r = self.inner.write_all(bytes) => r.map_err(StreamError::from),
            _ = rx.changed() => Err(StreamError::Interrupted),
        }
    }

    /// Send the 1-byte SCP ACK (`\x00`).
    async fn ack(&mut self) -> Result<(), StreamError> {
        self.write_all(b"\x00").await
    }

    /// Graceful close, mirroring C++ `closeScpChannel(channel, true)`
    /// (send_eof → wait_eof → wait_closed). Abrupt close is simply dropping
    /// the stream: `ChannelStream`'s `Drop` sends `ChannelMsg::Close`, which
    /// is exactly the C++ `closeScpChannel(channel, false)` / `channel_free`
    /// semantics.
    async fn graceful_close(&mut self) {
        let _ = self.inner.shutdown().await;
        let mut sink = [0u8; 4096];
        loop {
            match self.inner.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Record parsing
// ---------------------------------------------------------------------------

/// Parse the payload of a `C`/`D` control line: `"0644 13 name with spaces\n"`
/// (control byte already consumed by the caller). Returns (mode, size, name).
/// SCP cannot represent names containing `\n`; non-UTF-8 names are lossily
/// converted.
fn parse_ctl_line(ctl: u8, line: &[u8]) -> Result<(u32, u64, String), TransferError> {
    let payload = line;
    let text = std::str::from_utf8(payload)
        .map_err(|_| TransferError::Protocol(format!("{ctl} record is not UTF-8")))?;
    let text = text.trim_end_matches(['\n', '\r']);
    let mut parts = text.splitn(3, ' ');
    let mode_tok = parts
        .next()
        .ok_or_else(|| TransferError::Protocol(format!("{ctl} record missing mode")))?;
    let size_tok = parts
        .next()
        .ok_or_else(|| TransferError::Protocol(format!("{ctl} record missing size")))?;
    let name = parts.next().unwrap_or("").to_string();
    let mode = u32::from_str_radix(mode_tok, 8).map_err(|_| {
        TransferError::Protocol(format!("{ctl} record has invalid mode {mode_tok:?}"))
    })?;
    let size = size_tok.parse::<u64>().map_err(|_| {
        TransferError::Protocol(format!("{ctl} record has invalid size {size_tok:?}"))
    })?;
    Ok((mode, size, name))
}

/// Format a `C`/`D` control line: `C{mode:04o} {size} {name}\n`.
fn fmt_ctl_line(ctl: char, mode: u32, size: u64, name: &str) -> Vec<u8> {
    format!("{ctl}{mode:04o} {size} {name}\n").into_bytes()
}

/// Format a `T` record: `T{mtime} 0 {atime} 0\n`.
fn fmt_t_record(mtime: u64, atime: u64) -> Vec<u8> {
    format!("T{mtime} 0 {atime} 0\n").into_bytes()
}

/// Parse the mtime from a `T` record payload ("1612345678 0 1612345678 0\n").
/// The caller has already consumed the leading `T` control byte.
fn parse_t_line(line: &[u8]) -> Result<u64, TransferError> {
    let text = std::str::from_utf8(line)
        .map_err(|_| TransferError::Protocol("T record is not UTF-8".into()))?;
    let mtime = text
        .split_whitespace()
        .next()
        .and_then(|t| t.parse::<u64>().ok())
        .ok_or_else(|| TransferError::Protocol("T record has invalid mtime".into()))?;
    Ok(mtime)
}

// ---------------------------------------------------------------------------
// Transfer error classification (mirrors the C++ fallback conditions)
// ---------------------------------------------------------------------------

/// Failures are classified exactly like the C++ client:
/// * channel-open / pre-first-record failures → `Open` (SFTP-fallback eligible)
/// * mid-stream channel failures → `Mid` (SFTP-fallback eligible)
/// * local file-system failures → `Local` (never falls back)
/// * user cancel / interrupt → `Cancelled` (never falls back)
enum TransferError {
    Open(String),
    Mid(String),
    Local(String),
    Protocol(String),
    Cancelled,
}

impl TransferError {
    fn from_stream(e: StreamError, records_seen: u64, context: &str) -> Self {
        match e {
            StreamError::Interrupted => TransferError::Cancelled,
            StreamError::Eof => {
                let detail = format!("{context}: remote closed the connection unexpectedly");
                if records_seen == 0 {
                    TransferError::Open(detail)
                } else {
                    TransferError::Mid(detail)
                }
            }
            StreamError::Io(e) => {
                let detail = format!("{context}: {e}");
                if records_seen == 0 {
                    TransferError::Open(detail)
                } else {
                    TransferError::Mid(detail)
                }
            }
        }
    }
}

/// Progress reporting mirrors C++: only when `total > 0`, plus one final
/// report after the transfer completes.
fn report_progress(progress: &Option<ProgressCb>, done: u64, total: u64) {
    if total == 0 {
        return;
    }
    if let Some(p) = progress {
        p(done, total);
    }
}

fn cancel_requested(shared: &Shared, cancel: &Option<CancelCb>) -> bool {
    if shared.interrupted() {
        return true;
    }
    cancel.as_ref().is_some_and(|c| c())
}

/// Single-quote a path for the remote shell (`scp` paths go through `/bin/sh`).
fn shell_quote(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 2);
    out.push('\'');
    for ch in path.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn unix_mode(meta: &std::fs::Metadata, _default: u32) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        _default
    }
}

fn unix_timestamp(system_time: std::time::SystemTime) -> u64 {
    system_time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Download engine (SCP source mode)
// ---------------------------------------------------------------------------

struct DownloadState {
    done: u64,
    /// Running total: the sum of every `C` record size seen so far. The SCP
    /// protocol has no upfront total for recursive transfers, so this grows
    /// as records arrive; for single files it is exactly the file size the
    /// C++ client obtained from libssh2's `st_size`.
    total: u64,
    records_seen: u64,
}

impl DownloadState {
    fn new() -> Self {
        Self {
            done: 0,
            total: 0,
            records_seen: 0,
        }
    }
}

async fn download_data(
    stream: &mut ScpStream,
    state: &mut DownloadState,
    local_path: &Path,
    size: u64,
    progress: &Option<ProgressCb>,
    cancel: &Option<CancelCb>,
) -> Result<(), TransferError> {
    let mut file = tokio::fs::File::create(local_path)
        .await
        .map_err(|e| TransferError::Local(format!("Could not open local file for writing: {e}")))?;

    // C++ parity: on cancel, read failure, or local write failure the partial
    // local file is always removed before the error (or SFTP fallback)
    // propagates.
    let result = download_data_loop(stream, state, size, progress, cancel, &mut file).await;
    if result.is_err() {
        drop(file);
        let _ = tokio::fs::remove_file(local_path).await;
    }
    result
}

async fn download_data_loop(
    stream: &mut ScpStream,
    state: &mut DownloadState,
    size: u64,
    progress: &Option<ProgressCb>,
    cancel: &Option<CancelCb>,
    file: &mut tokio::fs::File,
) -> Result<(), TransferError> {
    let mut remaining = size;
    let mut buf = vec![0u8; SCP_CHUNK_SIZE];
    while remaining > 0 {
        if cancel_requested(&stream.shared, cancel) {
            return Err(TransferError::Cancelled);
        }
        let want = remaining.min(buf.len() as u64) as usize;
        stream
            .read_exact_into(&mut buf[..want])
            .await
            .map_err(|e| {
                let ctx = "SCP read failed";
                match e {
                    StreamError::Interrupted => TransferError::Cancelled,
                    other => TransferError::from_stream(other, state.records_seen, ctx),
                }
            })?;
        file.write_all(&buf[..want])
            .await
            .map_err(|e| TransferError::Local(format!("Local write failed: {e}")))?;
        remaining -= want as u64;
        state.done += want as u64;
        report_progress(progress, state.done, state.total);
    }
    Ok(())
}

/// Download the records of one directory level. `dir` is the directory the
/// remote `scp` process has descended into (created by the caller or by a
/// `D` record). Returns when the matching `E` record arrives.
async fn download_dir_level(
    stream: &mut ScpStream,
    state: &mut DownloadState,
    dir: &Path,
    progress: &Option<ProgressCb>,
    cancel: &Option<CancelCb>,
) -> Result<(), TransferError> {
    loop {
        if cancel_requested(&stream.shared, cancel) {
            return Err(TransferError::Cancelled);
        }
        let ctl = stream.read_u8().await.map_err(|e| {
            if matches!(e, StreamError::Interrupted) {
                TransferError::Cancelled
            } else {
                TransferError::from_stream(e, state.records_seen, "SCP read failed")
            }
        })?;
        match ctl {
            b'C' => {
                let line = stream.read_line().await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, state.records_seen, "SCP read failed")
                    }
                })?;
                let (_mode, size, name) = parse_ctl_line(b'C', &line)?;
                state.records_seen += 1;
                state.total += size;
                stream.ack().await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, state.records_seen, "SCP read failed")
                    }
                })?;
                let local_path = dir.join(name);
                download_data(stream, state, &local_path, size, progress, cancel).await?;
                stream.ack().await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, state.records_seen, "SCP read failed")
                    }
                })?;
            }
            b'D' => {
                let line = stream.read_line().await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, state.records_seen, "SCP read failed")
                    }
                })?;
                let (_mode, _size, name) = parse_ctl_line(b'D', &line)?;
                state.records_seen += 1;
                let subdir = dir.join(name);
                tokio::fs::create_dir_all(&subdir).await.map_err(|e| {
                    TransferError::Local(format!("Could not create directory: {e}"))
                })?;
                stream.ack().await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, state.records_seen, "SCP read failed")
                    }
                })?;
                trace!(dir = %subdir.display(), "descending into remote directory");
                Box::pin(download_dir_level(stream, state, &subdir, progress, cancel)).await?;
            }
            b'E' => {
                // Ends the current level; consume the (optional) directory
                // name line and ACK it, like OpenSSH's source().
                let _line = stream.read_line().await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, state.records_seen, "SCP read failed")
                    }
                })?;
                stream.ack().await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, state.records_seen, "SCP read failed")
                    }
                })?;
                return Ok(());
            }
            b'T' => {
                // mtime/atime record; parsed and deliberately ignored
                // (see module docs).
                let line = stream.read_line().await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, state.records_seen, "SCP read failed")
                    }
                })?;
                if let Ok(mtime) = parse_t_line(&line) {
                    trace!(mtime, "ignoring remote T record");
                }
            }
            0x01 | 0x02 => {
                let line = stream.read_line().await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, state.records_seen, "SCP read failed")
                    }
                })?;
                let msg = String::from_utf8_lossy(&line);
                let detail = format!("remote scp reported: {}", msg.trim());
                if state.records_seen == 0 {
                    return Err(TransferError::Open(detail));
                }
                return Err(TransferError::Mid(detail));
            }
            other => {
                // Not a legacy control byte: most likely an OpenSSH >= 9.0
                // server attempting SFTP-mode scp negotiation (see module
                // docs). Treat as open failure so Auto mode falls back to
                // the real SFTP client.
                let detail = format!(
                    "unexpected SCP control byte 0x{other:02x} \
                     (possible SFTP-mode scp negotiation)"
                );
                if state.records_seen == 0 {
                    return Err(TransferError::Open(detail));
                }
                return Err(TransferError::Mid(detail));
            }
        }
    }
}

/// Full download: open the channel, `exec "scp -r -f <remote>"`, and drive
/// the source-mode state machine. `local` is the local file path (for `C`)
/// or the local directory root (for `D`), decided by the first record.
async fn scp_download(
    session: &ScpSession,
    remote: &str,
    local: &str,
    progress: &Option<ProgressCb>,
    cancel: &Option<CancelCb>,
) -> Result<(), TransferError> {
    let channel = session
        .handle
        .channel_open_session()
        .await
        .map_err(|e| TransferError::Open(format!("Could not open channel: {e}")))?;
    let command = format!("scp -r -f {}", shell_quote(remote));
    channel
        .exec(true, command.as_bytes())
        .await
        .map_err(|e| TransferError::Open(format!("Could not exec remote scp: {e}")))?;
    let stream = channel.into_stream();
    let mut stream = ScpStream::new(stream, session.shared.clone());
    let local = PathBuf::from(local);
    let mut state = DownloadState::new();

    // First record decides file vs directory download. Stray `T` records
    // (some servers send one with `-p` even when not requested) are skipped.
    let first = loop {
        let ctl = stream.read_u8().await.map_err(|e| {
            if matches!(e, StreamError::Interrupted) {
                TransferError::Cancelled
            } else {
                TransferError::from_stream(e, 0, "Could not open remote file for SCP download")
            }
        })?;
        if ctl == b'T' {
            let line = stream.read_line().await.map_err(|e| {
                if matches!(e, StreamError::Interrupted) {
                    TransferError::Cancelled
                } else {
                    TransferError::from_stream(e, 0, "Could not open remote file for SCP download")
                }
            })?;
            let _ = parse_t_line(&line);
            continue;
        }
        break ctl;
    };
    match first {
        b'C' => {
            let line = stream.read_line().await.map_err(|e| {
                if matches!(e, StreamError::Interrupted) {
                    TransferError::Cancelled
                } else {
                    TransferError::from_stream(e, 0, "Could not open remote file for SCP download")
                }
            })?;
            let (_mode, size, _name) = parse_ctl_line(b'C', &line)?;
            state.records_seen += 1;
            state.total += size;
            stream.ack().await.map_err(|e| {
                if matches!(e, StreamError::Interrupted) {
                    TransferError::Cancelled
                } else {
                    TransferError::from_stream(e, 1, "SCP read failed")
                }
            })?;
            download_data(&mut stream, &mut state, &local, size, progress, cancel).await?;
            stream.ack().await.map_err(|e| {
                if matches!(e, StreamError::Interrupted) {
                    TransferError::Cancelled
                } else {
                    TransferError::from_stream(e, 1, "SCP read failed")
                }
            })?;
        }
        b'D' => {
            let line = stream.read_line().await.map_err(|e| {
                if matches!(e, StreamError::Interrupted) {
                    TransferError::Cancelled
                } else {
                    TransferError::from_stream(e, 0, "Could not open remote file for SCP download")
                }
            })?;
            let (_mode, _size, _name) = parse_ctl_line(b'D', &line)?;
            state.records_seen += 1;
            tokio::fs::create_dir_all(&local)
                .await
                .map_err(|e| TransferError::Local(format!("Could not create directory: {e}")))?;
            stream.ack().await.map_err(|e| {
                if matches!(e, StreamError::Interrupted) {
                    TransferError::Cancelled
                } else {
                    TransferError::from_stream(e, 1, "SCP read failed")
                }
            })?;
            Box::pin(download_dir_level(
                &mut stream,
                &mut state,
                &local,
                progress,
                cancel,
            ))
            .await?;
        }
        0x01 | 0x02 => {
            let line = stream.read_line().await.map_err(|e| {
                if matches!(e, StreamError::Interrupted) {
                    TransferError::Cancelled
                } else {
                    TransferError::from_stream(e, 0, "Could not open remote file for SCP download")
                }
            })?;
            let msg = String::from_utf8_lossy(&line);
            return Err(TransferError::Open(format!(
                "remote scp reported: {}",
                msg.trim()
            )));
        }
        other => {
            return Err(TransferError::Open(format!(
                "unexpected SCP control byte 0x{other:02x} \
                 (possible SFTP-mode scp negotiation)"
            )));
        }
    }

    // OpenSSH end-of-stream handshake: the source sends a final NUL byte
    // ("send 0") and waits for the sink's last ACK. All payload data has
    // already been received at this point, so any anomaly here is logged and
    // tolerated rather than failing the transfer.
    match stream.read_u8().await {
        Ok(0) | Ok(1) => {
            let _ = stream.write_all(b"\x00").await;
        }
        Ok(2) => {
            let line = stream.read_line().await.unwrap_or_default();
            warn!(
                "remote scp reported an error after transfer completion: {}",
                String::from_utf8_lossy(&line).trim()
            );
            let _ = stream.write_all(b"\x00").await;
        }
        Ok(other) => {
            warn!("unexpected final SCP control byte 0x{other:02x}; ignoring");
            let _ = stream.write_all(b"\x00").await;
        }
        Err(_) => {
            // Channel EOF / closed or interrupt: the data is already on
            // disk, nothing further to do.
        }
    }

    // C++ reports a final progress tick after the transfer.
    report_progress(progress, state.done, state.total);
    stream.graceful_close().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Upload engine (SCP sink mode)
// ---------------------------------------------------------------------------

enum EntryKind {
    File,
    Dir,
}

struct LocalEntry {
    name: String,
    kind: EntryKind,
    mode: u32,
    size: u64,
    mtime: u64,
    atime: u64,
    children: Vec<LocalEntry>,
}

/// Walk the local tree (depth-first, deterministic order). Symlinks are
/// skipped. `total` accumulates the byte count of every regular file.
fn walk_local(dir: &Path, total: &mut u64) -> io::Result<Vec<LocalEntry>> {
    let mut entries = Vec::new();
    for item in std::fs::read_dir(dir)? {
        let item = item?;
        let path = item.path();
        let meta = match item.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let name = item.file_name().to_string_lossy().into_owned();
        if meta.is_dir() {
            let children = walk_local(&path, total)?;
            entries.push(LocalEntry {
                name,
                kind: EntryKind::Dir,
                mode: unix_mode(&meta, 0o755),
                size: 0,
                mtime: unix_timestamp(meta.modified().unwrap_or(UNIX_EPOCH)),
                atime: unix_timestamp(meta.accessed().unwrap_or(UNIX_EPOCH)),
                children,
            });
        } else if meta.is_file() {
            *total += meta.len();
            entries.push(LocalEntry {
                name,
                kind: EntryKind::File,
                mode: unix_mode(&meta, 0o644),
                size: meta.len(),
                mtime: unix_timestamp(meta.modified().unwrap_or(UNIX_EPOCH)),
                atime: unix_timestamp(meta.accessed().unwrap_or(UNIX_EPOCH)),
                children: Vec::new(),
            });
        }
        // anything else (symlinks, devices) is skipped
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

struct UploadState {
    done: u64,
    total: u64,
}

/// Read one remote ACK byte after a `C`/`D`/`E` record:
/// `0` ok, `1` warning (log + continue), `2` fatal (read message, fail).
async fn expect_ack(stream: &mut ScpStream, context: &str) -> Result<(), TransferError> {
    match stream.read_u8().await {
        Ok(0) => Ok(()),
        Ok(1) => {
            let line = stream.read_line().await.unwrap_or_default();
            warn!(
                "remote scp warning after {context}: {}",
                String::from_utf8_lossy(&line).trim()
            );
            Ok(())
        }
        Ok(2) => {
            let line = stream.read_line().await.unwrap_or_default();
            Err(TransferError::Mid(format!(
                "{context}: remote rejected the transfer: {}",
                String::from_utf8_lossy(&line).trim()
            )))
        }
        Ok(other) => Err(TransferError::Mid(format!(
            "{context}: unexpected ACK byte {other}"
        ))),
        Err(e) => match e {
            StreamError::Interrupted => Err(TransferError::Cancelled),
            other => Err(TransferError::from_stream(other, 1, context)),
        },
    }
}

async fn upload_file_data(
    stream: &mut ScpStream,
    state: &mut UploadState,
    local_path: &Path,
    size: u64,
    progress: &Option<ProgressCb>,
    cancel: &Option<CancelCb>,
) -> Result<(), TransferError> {
    let mut file = tokio::fs::File::open(local_path)
        .await
        .map_err(|e| TransferError::Local(format!("Could not open local file for reading: {e}")))?;
    let mut buf = vec![0u8; SCP_CHUNK_SIZE];
    let mut remaining = size;
    while remaining > 0 {
        if cancel_requested(&stream.shared, cancel) {
            return Err(TransferError::Cancelled);
        }
        let want = remaining.min(buf.len() as u64) as usize;
        let n = file
            .read(&mut buf[..want])
            .await
            .map_err(|e| TransferError::Local(format!("Local read failed: {e}")))?;
        if n == 0 {
            return Err(TransferError::Local(
                "Local read failed: unexpected EOF".into(),
            ));
        }
        stream.write_all(&buf[..n]).await.map_err(|e| {
            if matches!(e, StreamError::Interrupted) {
                TransferError::Cancelled
            } else {
                TransferError::from_stream(e, 1, "SCP write failed")
            }
        })?;
        remaining -= n as u64;
        state.done += n as u64;
        report_progress(progress, state.done, state.total);
    }
    // NUL terminator for the file data, then the final ACK.
    stream.write_all(b"\x00").await.map_err(|e| {
        if matches!(e, StreamError::Interrupted) {
            TransferError::Cancelled
        } else {
            TransferError::from_stream(e, 1, "SCP write failed")
        }
    })?;
    Ok(())
}

/// Upload the entries of one directory level; the remote sink has already
/// chdir'd into this level (top level: the command argument; nested levels:
/// the `D` record we just sent).
async fn upload_dir_level(
    stream: &mut ScpStream,
    state: &mut UploadState,
    root: &Path,
    entries: &[LocalEntry],
    progress: &Option<ProgressCb>,
    cancel: &Option<CancelCb>,
) -> Result<(), TransferError> {
    for entry in entries {
        if cancel_requested(&stream.shared, cancel) {
            return Err(TransferError::Cancelled);
        }
        match entry.kind {
            EntryKind::Dir => {
                let d = fmt_ctl_line('D', entry.mode, 0, &entry.name);
                stream.write_all(&d).await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, 1, "SCP write failed")
                    }
                })?;
                expect_ack(stream, "D record").await?;
                Box::pin(upload_dir_level(
                    stream,
                    state,
                    &root.join(&entry.name),
                    &entry.children,
                    progress,
                    cancel,
                ))
                .await?;
                stream.write_all(b"E\n").await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, 1, "SCP write failed")
                    }
                })?;
                expect_ack(stream, "E record").await?;
            }
            EntryKind::File => {
                // T record first (no ACK for T in the SCP protocol).
                let t = fmt_t_record(entry.mtime, entry.atime);
                stream.write_all(&t).await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, 1, "SCP write failed")
                    }
                })?;
                let c = fmt_ctl_line('C', entry.mode, entry.size, &entry.name);
                stream.write_all(&c).await.map_err(|e| {
                    if matches!(e, StreamError::Interrupted) {
                        TransferError::Cancelled
                    } else {
                        TransferError::from_stream(e, 1, "SCP write failed")
                    }
                })?;
                expect_ack(stream, "C record").await?;
                let local_path = root.join(&entry.name);
                upload_file_data(stream, state, &local_path, entry.size, progress, cancel).await?;
                expect_ack(stream, "file data").await?;
            }
        }
    }
    Ok(())
}

/// Full upload: walk/stat the local path first (C++ parity: local errors
/// surface before any channel is opened), then exec `scp [-r] -t <remote>`
/// and drive the sink-mode state machine.
async fn scp_upload(
    session: &ScpSession,
    local: &str,
    remote: &str,
    progress: &Option<ProgressCb>,
    cancel: &Option<CancelCb>,
) -> Result<(), TransferError> {
    let local_path = PathBuf::from(local);
    let meta = std::fs::metadata(&local_path)
        .map_err(|e| TransferError::Local(format!("Could not determine local file size: {e}")))?;

    let (is_dir, total, entries) = if meta.is_dir() {
        let mut total = 0u64;
        let entries =
            walk_local(&local_path, &mut total).map_err(|e| TransferError::Local(e.to_string()))?;
        (true, total, Some(entries))
    } else if meta.is_file() {
        (false, meta.len(), None)
    } else {
        return Err(TransferError::Local(
            "Could not open local file for reading: not a regular file".into(),
        ));
    };
    // Empty directory tree: C++ reports progress only when total > 0.
    let mut state = UploadState { done: 0, total };

    let channel = session
        .handle
        .channel_open_session()
        .await
        .map_err(|e| TransferError::Open(format!("Could not open channel: {e}")))?;
    let command = if is_dir {
        format!("scp -r -t {}", shell_quote(remote))
    } else {
        format!("scp -t {}", shell_quote(remote))
    };
    channel
        .exec(true, command.as_bytes())
        .await
        .map_err(|e| TransferError::Open(format!("Could not exec remote scp: {e}")))?;
    let stream = channel.into_stream();
    let mut stream = ScpStream::new(stream, session.shared.clone());

    if let Some(entries) = entries {
        Box::pin(upload_dir_level(
            &mut stream,
            &mut state,
            &local_path,
            &entries,
            progress,
            cancel,
        ))
        .await?;
    } else {
        // Single-file upload, exact C++ parity: mode 0644, no T record.
        let size = total;
        let name = local_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| local_path.to_string_lossy().into_owned());
        let c = fmt_ctl_line('C', 0o644, size, &name);
        stream.write_all(&c).await.map_err(|e| {
            if matches!(e, StreamError::Interrupted) {
                TransferError::Cancelled
            } else {
                TransferError::from_stream(e, 0, "SCP write failed")
            }
        })?;
        expect_ack(&mut stream, "C record").await?;
        upload_file_data(&mut stream, &mut state, &local_path, size, progress, cancel).await?;
        expect_ack(&mut stream, "file data").await?;
    }

    // OpenSSH end-of-stream handshake: the source sends a final NUL byte
    // ("send 0") and waits for the sink's last ACK. Some servers close the
    // channel without the final ACK; that is tolerated.
    stream.write_all(b"\x00").await.map_err(|e| {
        if matches!(e, StreamError::Interrupted) {
            TransferError::Cancelled
        } else {
            TransferError::from_stream(e, 1, "SCP write failed")
        }
    })?;
    match stream.read_u8().await {
        Ok(0) => {}
        Ok(1) => {
            let line = stream.read_line().await.unwrap_or_default();
            warn!(
                "remote scp warning after transfer completion: {}",
                String::from_utf8_lossy(&line).trim()
            );
        }
        Ok(2) => {
            let line = stream.read_line().await.unwrap_or_default();
            return Err(TransferError::Mid(format!(
                "remote scp rejected the transfer: {}",
                String::from_utf8_lossy(&line).trim()
            )));
        }
        Ok(other) => {
            warn!("unexpected final ACK byte {other}; ignoring");
        }
        Err(StreamError::Interrupted) => return Err(TransferError::Cancelled),
        Err(_) => {
            // Channel EOF / closed without the final ACK: tolerated.
        }
    }

    // C++ reports a final progress tick after the transfer.
    report_progress(progress, state.done, total);
    stream.graceful_close().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// SFTP fallback (ScpTransferMode::Auto), port of transferViaSftpFallbackGet/
// Put: fresh SFTP connection from a copy of the session options with
// protocol switched to Sftp, transfer with resume=false, then disconnect.
// ---------------------------------------------------------------------------

async fn sftp_fallback_get(
    opts: &SessionOptions,
    remote: &str,
    local: &str,
    progress: Option<ProgressCb>,
    cancel: Option<CancelCb>,
) -> Result<(), ClientError> {
    let mut sftp_opts = opts.clone();
    sftp_opts.protocol = Protocol::Sftp;
    let mut client = crate::backends::sftp::RusshSftpClient::new();
    client.connect(&sftp_opts).await?;
    let result = client.get(remote, local, progress, cancel, false).await;
    let _ = client.disconnect().await;
    result
}

async fn sftp_fallback_put(
    opts: &SessionOptions,
    local: &str,
    remote: &str,
    progress: Option<ProgressCb>,
    cancel: Option<CancelCb>,
) -> Result<(), ClientError> {
    let mut sftp_opts = opts.clone();
    sftp_opts.protocol = Protocol::Sftp;
    let mut client = crate::backends::sftp::RusshSftpClient::new();
    client.connect(&sftp_opts).await?;
    let result = client.put(local, remote, progress, cancel, false).await;
    let _ = client.disconnect().await;
    result
}

// ---------------------------------------------------------------------------
// ScpClient
// ---------------------------------------------------------------------------

/// Classic SCP client over an SSH session, port of `Libssh2ScpClient`.
pub struct ScpClient {
    session: Option<ScpSession>,
    opts: Option<SessionOptions>,
}

impl ScpClient {
    pub fn new() -> Self {
        Self {
            session: None,
            opts: None,
        }
    }

    /// Mirrors `Libssh2ScpClient::sftpFallbackEnabled()`: true when no
    /// session options are stored (defensive) or the mode is Auto.
    fn sftp_fallback_enabled(&self) -> bool {
        match &self.opts {
            None => true,
            Some(o) => o.scp_transfer_mode == ScpTransferMode::Auto,
        }
    }

    fn connected(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.is_alive())
    }

    /// Apply the C++ fallback decision to a failed SCP get:
    /// `ScpOnly` → plain error; `Auto` → try SFTP and compose errors.
    async fn handle_get_failure(
        &self,
        base: String,
        remote: &str,
        local: &str,
        progress: Option<ProgressCb>,
        cancel: Option<CancelCb>,
    ) -> Result<(), ClientError> {
        if !self.sftp_fallback_enabled() {
            return Err(ClientError::OperationFailed(format!(
                "{base} (SFTP fallback is disabled by the selected SCP mode)"
            )));
        }
        if cancel_requested_opt(self, &cancel) {
            return Err(ClientError::Cancelled);
        }
        let opts = self
            .opts
            .clone()
            .ok_or_else(|| ClientError::OperationFailed("missing session options".into()))?;
        match sftp_fallback_get(&opts, remote, local, progress, cancel).await {
            Ok(()) => Ok(()),
            Err(ClientError::Cancelled) => Err(ClientError::Cancelled),
            Err(e) => Err(ClientError::OperationFailed(format!(
                "{base} | SFTP fallback failed: {e}"
            ))),
        }
    }

    async fn handle_put_failure(
        &self,
        base: String,
        local: &str,
        remote: &str,
        progress: Option<ProgressCb>,
        cancel: Option<CancelCb>,
    ) -> Result<(), ClientError> {
        if !self.sftp_fallback_enabled() {
            return Err(ClientError::OperationFailed(format!(
                "{base} (SFTP fallback is disabled by the selected SCP mode)"
            )));
        }
        if cancel_requested_opt(self, &cancel) {
            return Err(ClientError::Cancelled);
        }
        let opts = self
            .opts
            .clone()
            .ok_or_else(|| ClientError::OperationFailed("missing session options".into()))?;
        match sftp_fallback_put(&opts, local, remote, progress, cancel).await {
            Ok(()) => Ok(()),
            Err(ClientError::Cancelled) => Err(ClientError::Cancelled),
            Err(e) => Err(ClientError::OperationFailed(format!(
                "{base} | SFTP fallback failed: {e}"
            ))),
        }
    }
}

fn cancel_requested_opt(client: &ScpClient, cancel: &Option<CancelCb>) -> bool {
    if let Some(s) = &client.session {
        if s.shared.interrupted() {
            return true;
        }
    }
    cancel.as_ref().is_some_and(|c| c())
}

#[async_trait]
impl SftpClient for ScpClient {
    fn protocol(&self) -> Protocol {
        Protocol::Scp
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        crate::types::capabilities_for_protocol(self.protocol())
    }

    async fn connect(&mut self, opt: &SessionOptions) -> Result<(), ClientError> {
        if self.connected() {
            return Err(ClientError::OperationFailed("Already connected".into()));
        }
        // Defensive: clear leftover state from a previous partial attempt
        // (mirrors the C++ connectInternal).
        self.session = None;

        let mut copy = opt.clone();
        copy.protocol = Protocol::Scp;

        let session = ScpSession::connect(&copy).await?;
        self.session = Some(session);
        self.opts = Some(copy);
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
        if let Some(session) = self.session.take() {
            let _ = session
                .handle
                .disconnect(russh::Disconnect::ByApplication, "client disconnect", "")
                .await;
        }
        self.opts = None;
        Ok(())
    }

    fn interrupt(&self) {
        if let Some(session) = &self.session {
            session.interrupt();
        }
    }

    fn is_connected(&self) -> bool {
        self.connected()
    }

    async fn list(
        &mut self,
        _remote_path: &str,
    ) -> Result<Vec<crate::types::FileInfo>, ClientError> {
        Err(ClientError::Unsupported(
            "SCP backend does not support directory listing.".into(),
        ))
    }

    async fn get(
        &mut self,
        remote: &str,
        local: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError> {
        if resume {
            return Err(ClientError::Unsupported(
                "SCP downloads do not support resume.".into(),
            ));
        }
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| ClientError::OperationFailed("Not connected".into()))?;
        if !session.is_alive() {
            return Err(ClientError::OperationFailed("Not connected".into()));
        }

        match scp_download(session, remote, local, &progress, &should_cancel).await {
            Ok(()) => Ok(()),
            Err(TransferError::Cancelled) => Err(ClientError::Cancelled),
            Err(TransferError::Local(msg)) => Err(ClientError::OperationFailed(msg)),
            Err(TransferError::Protocol(msg)) => {
                // Malformed protocol: the channel is unusable. Treat like a
                // mid-transfer channel failure (fallback-eligible).
                self.handle_get_failure(
                    format!("SCP read failed: {msg}"),
                    remote,
                    local,
                    progress,
                    should_cancel,
                )
                .await
            }
            Err(TransferError::Open(detail)) => {
                let base = if detail.is_empty() {
                    "Could not open remote file for SCP download".to_string()
                } else {
                    format!("Could not open remote file for SCP download: {detail}")
                };
                self.handle_get_failure(base, remote, local, progress, should_cancel)
                    .await
            }
            Err(TransferError::Mid(detail)) => {
                let base = if detail.is_empty() {
                    "SCP read failed".to_string()
                } else {
                    format!("SCP read failed: {detail}")
                };
                // The partial local file is removed by download_data before
                // returning (C++ parity).
                self.handle_get_failure(base, remote, local, progress, should_cancel)
                    .await
            }
        }
    }

    async fn put(
        &mut self,
        local: &str,
        remote: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError> {
        if resume {
            return Err(ClientError::Unsupported(
                "SCP uploads do not support resume.".into(),
            ));
        }
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| ClientError::OperationFailed("Not connected".into()))?;
        if !session.is_alive() {
            return Err(ClientError::OperationFailed("Not connected".into()));
        }

        match scp_upload(session, local, remote, &progress, &should_cancel).await {
            Ok(()) => Ok(()),
            Err(TransferError::Cancelled) => Err(ClientError::Cancelled),
            Err(TransferError::Local(msg)) => Err(ClientError::OperationFailed(msg)),
            Err(TransferError::Protocol(msg)) => {
                self.handle_put_failure(
                    format!("SCP write failed: {msg}"),
                    local,
                    remote,
                    progress,
                    should_cancel,
                )
                .await
            }
            Err(TransferError::Open(detail)) => {
                let base = if detail.is_empty() {
                    "Could not open remote file for SCP upload".to_string()
                } else {
                    format!("Could not open remote file for SCP upload: {detail}")
                };
                self.handle_put_failure(base, local, remote, progress, should_cancel)
                    .await
            }
            Err(TransferError::Mid(detail)) => {
                let base = if detail.is_empty() {
                    "SCP write failed".to_string()
                } else {
                    format!("SCP write failed: {detail}")
                };
                self.handle_put_failure(base, local, remote, progress, should_cancel)
                    .await
            }
        }
    }

    async fn exists(&mut self, _remote_path: &str) -> Result<Option<bool>, ClientError> {
        Err(ClientError::Unsupported(
            "SCP backend does not support path existence checks.".into(),
        ))
    }

    async fn stat(&mut self, _remote_path: &str) -> Result<crate::types::FileInfo, ClientError> {
        Err(ClientError::Unsupported(
            "SCP backend does not support metadata stat.".into(),
        ))
    }

    async fn chmod(&mut self, _remote_path: &str, _mode: u32) -> Result<(), ClientError> {
        Err(ClientError::Unsupported(
            "SCP backend does not support chmod.".into(),
        ))
    }

    async fn chown(&mut self, _remote_path: &str, _uid: u32, _gid: u32) -> Result<(), ClientError> {
        Err(ClientError::Unsupported(
            "SCP backend does not support chown.".into(),
        ))
    }

    async fn set_times(
        &mut self,
        _remote_path: &str,
        _atime: u64,
        _mtime: u64,
    ) -> Result<(), ClientError> {
        Err(ClientError::Unsupported(
            "SCP backend does not support timestamp updates.".into(),
        ))
    }

    async fn mkdir(&mut self, _remote_dir: &str, _mode: u32) -> Result<(), ClientError> {
        Err(ClientError::Unsupported(
            "SCP backend does not support mkdir.".into(),
        ))
    }

    async fn remove_file(&mut self, _remote_path: &str) -> Result<(), ClientError> {
        Err(ClientError::Unsupported(
            "SCP backend does not support file deletion.".into(),
        ))
    }

    async fn remove_dir(&mut self, _remote_dir: &str) -> Result<(), ClientError> {
        Err(ClientError::Unsupported(
            "SCP backend does not support directory deletion.".into(),
        ))
    }

    async fn rename(
        &mut self,
        _from: &str,
        _to: &str,
        _overwrite: bool,
    ) -> Result<(), ClientError> {
        Err(ClientError::Unsupported(
            "SCP backend does not support rename.".into(),
        ))
    }

    async fn new_connection_like(
        &self,
        opt: &SessionOptions,
    ) -> Result<Box<dyn SftpClient>, ClientError> {
        let mut client = ScpClient::new();
        client.connect(opt).await?;
        Ok(Box::new(client))
    }
}

impl Default for ScpClient {
    fn default() -> Self {
        Self::new()
    }
}
