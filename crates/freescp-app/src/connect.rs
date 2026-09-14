//! Connection dialog wiring and async connect orchestration.
//!
//! Rust port of the connect-related paths of `ui/ConnectionDialog.cpp` and
//! `ui/MainWindowConnection.cpp`: dialog defaults and protocol-dependent
//! port logic, transport validation, TOFU host-key confirmation,
//! keyboard-interactive prompts, "no verification" double confirmation,
//! quick-connect site persistence decisions, and session indicators.
//!
//! Cross-workstream contracts:
//! - `main-window` (owns `main.rs`): must declare `mod connect;` (and
//!   `mod state;`) and call [`open`] with its `crate::ui::main_window::MainWindow`.
//! - `state` (owns `crates/freescp-app/src/state.rs`): provides the
//!   `AppState` surface documented below (satisfied by `src/state.rs`).
//! - `site-manager` (owns `crates/freescp-app/src/site_manager.rs`): see
//!   [`maybe_persist_site`] for the persistence hand-off.
//!
//! # AppState integration contract
//!
//! ```text
//! #[derive(Clone)]                       // Clone + Send + Sync required:
//! pub struct AppState { /* internals */ } // open() hands it to tokio tasks.
//!
//! impl AppState {
//!     /// Status-bar message (mirrors QStatusBar::showMessage).
//!     pub fn set_status(&self, message: &str);
//!     /// Show/hide the "Connecting…" progress affordance.
//!     pub fn set_connect_progress(&self, active: bool);
//!     /// Install a freshly connected session into `tab` (the active tab / a
//!     /// fresh tab when `None`); the main window switches that tab's right
//!     /// pane into remote mode (port of applyRemoteConnectedUI).
//!     pub fn install_session(&self, tab: Option<u64>, opt: SessionOptions, client: Box<dyn SftpClient>);
//!     /// Clear a reserved tab's "Connecting…" state after a failed attempt.
//!     pub fn connect_failed(&self, tab: Option<u64>);
//! }
//! ```
//!
//! [`open`] and [`start_connect`] spawn network work on
//! [`AppState::runtime_handle`], so callers must pass an `AppState` whose
//! multi-thread runtime is still alive for the lifetime of the Slint event
//! loop (created in [`AppState::new`]).

use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use slint::ComponentHandle;

use crate::state::AppState;
use crate::ui::connection_dialog;
use crate::ui::main_window;

use freescp_core::client::ClientError;
use freescp_core::client_factory;
use freescp_core::ssh_config::{self, ResolvedSshParams};
use freescp_core::{
    capabilities_for_protocol, default_port_for_protocol, default_port_for_proxy_type,
    default_port_for_telnet, default_port_for_webdav_scheme, protocol_display_name,
    HostKeyConfirmCb, KbdIntPromptResult, KbdIntPromptsCb, KnownHostsPolicy, Protocol, ProxyType,
    ScpTransferMode, SessionOptions, SftpClient, TransferIntegrityPolicy, WebDavScheme,
};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Error surfaced by the connect flow to the UI layer.
#[derive(Debug)]
pub enum ConnectError {
    /// Connection failed; the `String` is already user-facing (see
    /// [`friendly_error`], mirroring the C++ `shortRemoteError` wording).
    Failed(String),
    /// The user explicitly cancelled the connect attempt.
    Cancelled,
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Failed(msg) => write!(f, "{msg}"),
            ConnectError::Cancelled => write!(f, "Connection canceled"),
        }
    }
}

impl std::error::Error for ConnectError {}

// ---------------------------------------------------------------------------
// Integer <-> enum mapping (dialog contract values)
// ---------------------------------------------------------------------------

fn protocol_from_int(v: i32) -> Protocol {
    match v {
        0 => Protocol::Sftp,
        1 => Protocol::Scp,
        2 => Protocol::Ftp,
        3 => Protocol::Ftps,
        4 => Protocol::WebDav,
        5 => Protocol::Smb,
        6 => Protocol::Telnet,
        _ => Protocol::Sftp,
    }
}

/// Dialog index for a protocol (inverse of `protocol_from_int`); used to
/// apply the default protocol from the settings store when the dialog opens.
pub fn protocol_to_int(p: Protocol) -> i32 {
    match p {
        Protocol::Sftp => 0,
        Protocol::Scp => 1,
        Protocol::Ftp => 2,
        Protocol::Ftps => 3,
        Protocol::WebDav => 4,
        Protocol::Smb => 5,
        Protocol::Telnet => 6,
    }
}

fn scp_mode_from_int(v: i32) -> ScpTransferMode {
    if v == 1 {
        ScpTransferMode::ScpOnly
    } else {
        ScpTransferMode::Auto
    }
}

/// Dialog index for an SCP transfer mode (inverse of `scp_mode_from_int`).
pub fn scp_mode_to_int(m: ScpTransferMode) -> i32 {
    match m {
        ScpTransferMode::ScpOnly => 1,
        ScpTransferMode::Auto => 0,
    }
}

fn known_hosts_policy_from_int(v: i32) -> KnownHostsPolicy {
    match v {
        1 => KnownHostsPolicy::AcceptNew,
        2 => KnownHostsPolicy::Off,
        _ => KnownHostsPolicy::Strict,
    }
}

fn integrity_from_int(v: i32) -> TransferIntegrityPolicy {
    match v {
        0 => TransferIntegrityPolicy::Off,
        2 => TransferIntegrityPolicy::Required,
        _ => TransferIntegrityPolicy::Optional,
    }
}

fn proxy_type_from_int(v: i32) -> ProxyType {
    match v {
        1 => ProxyType::Socks5,
        2 => ProxyType::HttpConnect,
        _ => ProxyType::None,
    }
}

// ---------------------------------------------------------------------------
// Error message translation
// ---------------------------------------------------------------------------

/// Port of `shortRemoteError` (MainWindowConnection.cpp): collapse raw
/// transport errors into short user-facing sentences.
pub fn friendly_error(raw: &str, fallback: &str) -> String {
    let msg = raw.trim();
    if msg.is_empty() {
        return fallback.to_string();
    }
    let lower = msg.to_lowercase();
    if lower.contains("permission denied") {
        return "Permission denied.".to_string();
    }
    if lower.contains("read-only") {
        return "Location is read-only.".to_string();
    }
    if lower.contains("no such file") || lower.contains("not found") {
        return "File or folder does not exist.".to_string();
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return "Connection timed out.".to_string();
    }
    if lower.contains("could not resolve")
        || lower.contains("name or service not known")
        || lower.contains("nodename nor servname")
    {
        return "Could not resolve the server hostname.".to_string();
    }
    if lower.contains("connection refused") {
        return "Connection refused by the server.".to_string();
    }
    if lower.contains("network is unreachable") || lower.contains("host is unreachable") {
        return "Network unavailable or host unreachable.".to_string();
    }
    if lower.contains("authentication failed") || lower.contains("auth fail") {
        return "Authentication failed.".to_string();
    }
    // First line, collapsed whitespace, truncated like QString::simplified +
    // left(93) + "...".
    let first_line = msg.lines().next().unwrap_or("").trim();
    let simplified: String = first_line.split_whitespace().collect::<Vec<_>>().join(" ");
    if simplified.chars().count() > 96 {
        let mut cut: String = simplified.chars().take(93).collect();
        cut.push_str("...");
        return cut;
    }
    simplified
}

fn translate_client_error(err: ClientError) -> ConnectError {
    match err {
        ClientError::Io(io) => ConnectError::Failed(friendly_error(
            &io.to_string(),
            "Check host, port, and credentials.",
        )),
        ClientError::AuthFailed(msg) => {
            ConnectError::Failed(friendly_error(&msg, "Authentication failed."))
        }
        ClientError::HostKeyRejected(msg) => {
            ConnectError::Failed(friendly_error(&msg, "Host key verification failed."))
        }
        ClientError::OperationFailed(msg) => {
            ConnectError::Failed(friendly_error(&msg, "Operation failed."))
        }
        ClientError::Cancelled => ConnectError::Cancelled,
        ClientError::Unsupported(msg) => {
            ConnectError::Failed(friendly_error(&msg, "Operation not supported."))
        }
        ClientError::Other(msg) => {
            ConnectError::Failed(friendly_error(&msg, "Check host, port, and credentials."))
        }
    }
}

// ---------------------------------------------------------------------------
// Dialog -> SessionOptions mapping
// ---------------------------------------------------------------------------

/// Map the dialog fields onto [`SessionOptions`], porting
/// `ConnectionDialog::options()` (including the protocol-dependent resets for
/// SCP mode, FTPS and WebDAV fields, and the proxy/jump transport rules).
pub fn session_options_from_dialog(dlg: &connection_dialog::ConnectionDialog) -> SessionOptions {
    let protocol = protocol_from_int(dlg.get_protocol());
    let caps = capabilities_for_protocol(protocol);

    let mut opt = SessionOptions {
        protocol,
        scp_transfer_mode: if protocol == Protocol::Scp {
            scp_mode_from_int(dlg.get_scp_mode())
        } else {
            ScpTransferMode::Auto
        },
        host: dlg.get_host().trim().to_string(),
        port: dlg.get_port().clamp(1, 65535) as u16,
        username: dlg.get_username().to_string(),
        ..SessionOptions::default()
    };

    let password = dlg.get_password().to_string();
    if !password.is_empty() {
        opt.password = Some(password);
    }
    let key_path = dlg.get_private_key_path().trim().to_string();
    if !key_path.is_empty() {
        opt.private_key_path = Some(key_path);
    }
    let key_passphrase = dlg.get_private_key_passphrase().to_string();
    if !key_passphrase.is_empty() {
        opt.private_key_passphrase = Some(key_passphrase);
    }

    // SSH security (advanced).
    let kh_path = dlg.get_known_hosts_path().trim().to_string();
    if !kh_path.is_empty() {
        opt.known_hosts_path = Some(kh_path);
    }
    opt.known_hosts_policy = known_hosts_policy_from_int(dlg.get_known_hosts_policy());
    opt.transfer_integrity_policy = integrity_from_int(dlg.get_integrity());

    // FTPS settings only apply to FTPS (C++ resets them otherwise).
    if protocol == Protocol::Ftps {
        opt.ftps_verify_peer = dlg.get_ftps_verify_peer();
        let ca = dlg.get_ftps_ca_path().trim().to_string();
        if !ca.is_empty() {
            opt.ftps_ca_cert_path = Some(ca);
        }
    }

    // WebDAV scheme + TLS settings (HTTP scheme forces no verification).
    if protocol == Protocol::WebDav {
        opt.webdav_scheme = if dlg.get_webdav_https() {
            WebDavScheme::Https
        } else {
            WebDavScheme::Http
        };
        if opt.webdav_scheme == WebDavScheme::Http {
            opt.webdav_verify_peer = false;
            opt.webdav_ca_cert_path = None;
        } else {
            opt.webdav_verify_peer = dlg.get_webdav_verify_peer();
            let ca = dlg.get_webdav_ca_path().trim().to_string();
            if !ca.is_empty() {
                opt.webdav_ca_cert_path = Some(ca);
            }
        }
    }

    // SMB workgroup/domain for NTLM authentication.
    if protocol == Protocol::Smb {
        let domain = dlg.get_smb_domain().trim().to_string();
        if !domain.is_empty() {
            opt.smb_domain = Some(domain);
        }
    }

    // Telnet console settings (TLS + auto-login). Plain telnet ignores the
    // TLS fields, mirroring the plain-HTTP WebDAV reset above.
    if protocol == Protocol::Telnet {
        opt.telnet_tls = dlg.get_telnet_tls();
        if opt.telnet_tls {
            opt.telnet_verify_peer = dlg.get_telnet_verify_peer();
            let ca = dlg.get_telnet_ca_path().trim().to_string();
            if !ca.is_empty() {
                opt.telnet_ca_cert_path = Some(ca);
            }
        } else {
            opt.telnet_verify_peer = true;
            opt.telnet_ca_cert_path = None;
        }
        opt.telnet_auto_login = dlg.get_telnet_auto_login();
    }

    // Transport: jump host wins over proxy; both must not be combined
    // (mirrors ConnectionDialog::options()).
    let jump_enabled = dlg.get_jump_enabled();
    let jump_host = dlg.get_jump_host().trim().to_string();
    let use_jump = caps.supports_jump_host && jump_enabled && !jump_host.is_empty();
    let proxy_type = proxy_type_from_int(dlg.get_proxy_type());
    let use_proxy = caps.supports_proxy && proxy_type != ProxyType::None && !use_jump;

    if use_jump {
        opt.proxy_type = ProxyType::None;
        opt.jump_host = Some(jump_host);
        opt.jump_port = if dlg.get_jump_port() > 0 {
            dlg.get_jump_port() as u16
        } else {
            22
        };
        let jump_user = dlg.get_jump_username().to_string();
        if !jump_user.is_empty() {
            opt.jump_username = Some(jump_user);
        }
        let jump_key = dlg.get_jump_key_path().trim().to_string();
        if !jump_key.is_empty() {
            opt.jump_private_key_path = Some(jump_key);
        }
    }

    if use_proxy {
        opt.proxy_type = proxy_type;
        opt.proxy_host = dlg.get_proxy_host().trim().to_string();
        opt.proxy_port = {
            let p = dlg.get_proxy_port();
            if p > 0 {
                p as u16
            } else {
                default_port_for_proxy_type(proxy_type)
            }
        };
        let proxy_user = dlg.get_proxy_username().to_string();
        if !proxy_user.is_empty() {
            opt.proxy_username = Some(proxy_user);
        }
        let proxy_pass = dlg.get_proxy_password().to_string();
        if !proxy_pass.is_empty() {
            opt.proxy_password = Some(proxy_pass);
        }
    }

    if !caps.supports_proxy {
        opt.proxy_type = ProxyType::None;
        opt.proxy_host.clear();
        opt.proxy_port = 0;
        opt.proxy_username = None;
        opt.proxy_password = None;
    }

    // Global security preferences, read from the settings store (port of
    // the C++ QSettings reads "Security/knownHostsHashed" and
    // "Security/fpHex").
    let prefs = crate::settings::Preferences::load();
    opt.known_hosts_hash_names = prefs.known_hosts_hashed;
    opt.show_fp_hex = prefs.fp_hex;

    opt
}

/// `true` when a session requests both a proxy and an SSH jump host
/// (port of `hasTransportSelectionConflict`).
pub fn has_transport_conflict(opt: &SessionOptions) -> bool {
    opt.proxy_type != ProxyType::None
        && opt
            .jump_host
            .as_deref()
            .is_some_and(|h| !h.trim().is_empty())
}

// ---------------------------------------------------------------------------
// Async connect
// ---------------------------------------------------------------------------

/// Create a client for `opt.protocol` and connect it (port of the C++
/// `startSftpConnect` worker thread + `CreateConnectedClient`).
///
/// Runs entirely on the tokio runtime; the Slint event loop must not be
/// blocked on this future. The callbacks inside `opt` (TOFU /
/// keyboard-interactive) may block a tokio worker thread while waiting for
/// user input, which is fine.
pub async fn run_connect(mut opt: SessionOptions) -> Result<Box<dyn SftpClient>, ConnectError> {
    // Resolve Host / HostName / Port / User / IdentityFile / ProxyJump from
    // ~/.ssh/config when the UI left those fields at their defaults.
    freescp_core::ssh_config::apply_user_config(&mut opt);
    let mut client = client_factory::create_client(opt.protocol).map_err(translate_client_error)?;
    client.connect(&opt).await.map_err(translate_client_error)?;
    Ok(client)
}

/// What a finished connect attempt produced.
pub enum ConnectOutcome {
    /// A filesystem session (`SftpClient`), installed through
    /// `AppState::install_session`.
    Session(Box<dyn SftpClient>),
    /// A Telnet console: the transport handle plus its event stream, installed
    /// through `AppState::install_console_session`. Telnet has no filesystem,
    /// so it never becomes an `SftpClient`.
    Console(
        freescp_core::telnet::TelnetSession,
        tokio::sync::mpsc::UnboundedReceiver<freescp_core::telnet::TelnetEvent>,
    ),
}

/// Connects `opt`, picking the transport its protocol needs: everything with a
/// filesystem goes through [`run_connect`], Telnet opens a console session.
pub async fn run_any_connect(opt: SessionOptions) -> Result<ConnectOutcome, ConnectError> {
    if opt.protocol == Protocol::Telnet {
        let (session, events) = freescp_core::telnet::connect(&opt)
            .await
            .map_err(translate_client_error)?;
        return Ok(ConnectOutcome::Console(session, events));
    }
    run_connect(opt).await.map(ConnectOutcome::Session)
}

/// Connect with a fully prepared [`SessionOptions`] (no dialog): spawns the
/// network work on tokio, then applies the result on the UI thread via
/// `spawn_local` (port of `startSftpConnect` + `finalizeSftpConnect`).
///
/// `tab` is the tab the session should install into (the tab a dialog connect
/// reserved, or the tab that asked for it). `None` lets the UI event loop pick:
/// the active tab when it is idle, else a fresh tab.
///
/// Used by the Site Manager's connect action and by the quick-connect flow
/// in [`open`]; the caller is responsible for validation, callback
/// attachment, and any cancel handling.
pub fn start_connect(state: &AppState, tab: Option<u64>, opt: SessionOptions) {
    let state = state.clone();
    let host_display = opt.host.clone();
    let protocol_display = protocol_display_name(opt.protocol).to_string();
    let mut opt = opt;
    // ~/.ssh/config resolution (Rust-only feature): sites and quick-connect
    // entries store the alias; the resolved values drive the session only, so
    // a saved site keeps working when the config changes.
    apply_ssh_config_defaults(&mut opt);
    let opt_for_install = opt.clone();
    state.set_connect_progress(true);

    let connect_state = state.clone();
    // UI callbacks are not inside a Tokio context; use AppState's runtime.
    let task = state
        .runtime_handle()
        .spawn(async move { run_any_connect(opt).await });

    let _ = slint::spawn_local(async move {
        let outcome = task.await.unwrap_or_else(|join_error| {
            tracing::error!("connection task panicked: {join_error}");
            Err(ConnectError::Failed("Connection task crashed.".to_string()))
        });
        connect_state.set_connect_progress(false);
        match outcome {
            Ok(ConnectOutcome::Session(client)) => {
                start_indicators(&connect_state);
                connect_state
                    .set_status(&format!("Connected ({protocol_display}) to {host_display}"));
                connect_state.install_session(tab, opt_for_install, client);
            }
            Ok(ConnectOutcome::Console(session, events)) => {
                start_indicators(&connect_state);
                connect_state
                    .set_status(&format!("Connected ({protocol_display}) to {host_display}"));
                connect_state.install_console_session(tab, opt_for_install, session, events);
            }
            Err(ConnectError::Cancelled) => {
                connect_state.set_status("Connection canceled");
                connect_state.connect_failed(tab);
            }
            Err(ConnectError::Failed(msg)) => {
                connect_state.connect_failed(tab);
                show_alert(
                    "Connection error",
                    &tr(
                        "Could not connect to the server.\n%1",
                        std::slice::from_ref(&msg),
                    ),
                );
            }
        }
    });
}

// ---------------------------------------------------------------------------
// ~/.ssh/config resolution (Rust-only feature; no C++ counterpart)
// ---------------------------------------------------------------------------

/// Applies `~/.ssh/config` defaults to a prepared [`SessionOptions`] right
/// before connecting, like the OpenSSH client would:
///
/// - `HostName` resolves host aliases to their real address;
/// - `User` fills an empty username;
/// - `Port` overrides the protocol default (22) — an explicitly typed 22 is
///   indistinguishable from the default, so it is treated as "not set";
/// - `IdentityFile` fills an empty key path (first identity, `~` expanded);
/// - `ProxyJump` configures the jump host when neither proxy nor jump is set;
/// - jump-host user/port/key are filled from the bastion's Host block, but the
///   jump alias itself is kept so `ssh -W` can still apply `ProxyCommand`.
///
/// Non-SSH protocols and a missing config are no-ops. Called from
/// [`start_connect`] only, after quick-connect site persistence, so saved
/// sites keep the alias as typed.
pub(crate) fn apply_ssh_config_defaults(opt: &mut SessionOptions) {
    if !matches!(opt.protocol, Protocol::Sftp | Protocol::Scp) {
        return;
    }
    let Some(config) = ssh_config::SshConfig::load_user_config() else {
        return;
    };
    apply_resolved_params(&config.resolve(&opt.host), opt);

    // Fill jump user/port/key from the bastion's Host block, but keep the
    // jump *alias* as typed. The system `ssh -W` tunnel inherits
    // ProxyCommand/HostName from ~/.ssh/config only when the argv host still
    // matches that Host pattern (rewriting to HostName broke cloudflared jumps).
    if let Some(alias) = opt.jump_host.clone().filter(|a| !a.is_empty()) {
        let r = config.resolve(&alias);
        if opt.jump_port == 22 {
            opt.jump_port = r.port.unwrap_or(22);
        }
        if opt.jump_username.is_none() {
            opt.jump_username = r.user.clone();
        }
        if opt.jump_private_key_path.is_none() {
            opt.jump_private_key_path = r.identity_files.first().cloned();
        }
    }
    tracing::debug!(
        host = %opt.host,
        port = opt.port,
        user = %opt.username,
        "session options after ~/.ssh/config resolution"
    );
}

/// Pure mapping of resolved parameters onto the fields left at their
/// defaults. Split out of [`apply_ssh_config_defaults`] so the OpenSSH-style
/// precedence is unit-testable without a real `~/.ssh/config`.
fn apply_resolved_params(r: &ResolvedSshParams, opt: &mut SessionOptions) {
    if let Some(host_name) = &r.host_name {
        if !host_name.is_empty() && *host_name != opt.host {
            tracing::info!("ssh config: host alias {} -> {}", opt.host, host_name);
            opt.host = host_name.clone();
        }
    }
    if opt.username.trim().is_empty() {
        if let Some(user) = r.user.as_deref().filter(|u| !u.is_empty()) {
            opt.username = user.to_string();
        }
    }
    if opt.port == default_port_for_protocol(opt.protocol) {
        if let Some(port) = r.port {
            opt.port = port;
        }
    }
    if opt.private_key_path.is_none() {
        opt.private_key_path = r.identity_files.first().cloned();
    }
    if opt.jump_host.is_none() && opt.proxy_type == ProxyType::None {
        if let Some(spec) = r.proxy_jump.as_deref().filter(|p| !p.is_empty()) {
            let (user, host, port) = ssh_config::parse_proxy_jump(spec);
            opt.jump_host = Some(host);
            opt.jump_username = user;
            opt.jump_port = port.unwrap_or(22);
        }
    }
}

// ---------------------------------------------------------------------------
// Fingerprint formatting
// ---------------------------------------------------------------------------

/// Present the fingerprint exactly as the SSH backend formatted it.
///
/// The backends format according to `SessionOptions::show_fp_hex` (hex-colon
/// when true, OpenSSH `SHA256:<base64>` otherwise) before invoking the
/// host-key callback — the same split as the C++ code, where the string
/// reaching the dialog was already formatted. `show_hex` is accepted for
/// parity with the C++ display helpers but must not re-encode the digest
/// (an OpenSSH SHA256 base64 digest cannot be losslessly converted to the
/// legacy MD5 hex-colon form).
pub fn format_fingerprint(fingerprint: &str, _show_hex: bool) -> String {
    fingerprint.to_string()
}

// ---------------------------------------------------------------------------
// TOFU host-key confirmation
// ---------------------------------------------------------------------------

/// Outcome of a blocking sub-dialog prompt.
pub enum PromptOutcome {
    Answered(String),
    Cancelled,
    Unavailable,
}

/// Blocking single-field prompt shown on the UI thread while the caller
/// (a tokio worker) waits on the returned receiver — port of the C++
/// `QInputDialog::getText` + `Qt::BlockingQueuedConnection` pattern.
///
/// `secret` masks the input (C++ passes `QLineEdit::Password` for password,
/// passphrase, and OTP/code/token prompts, and `QLineEdit::Normal` for the
/// generic "Information required" case).
///
/// Must be called from a non-UI thread: the caller blocks on the receiver
/// while the dialog is answered on the event loop.
pub fn prompt_user_sync(
    title: &str,
    name: &str,
    instruction: &str,
    prompt: &str,
    initial: &str,
    secret: bool,
) -> PromptOutcome {
    let (tx, rx) = mpsc::sync_channel::<PromptOutcome>(1);
    let title_s = title.to_string();
    let name_s = name.to_string();
    let instruction_s = instruction.to_string();
    let prompt_s = prompt.to_string();
    let initial_s = initial.to_string();

    let posted = slint::invoke_from_event_loop(move || {
        let Ok(dlg) = connection_dialog::KbdIntPromptDialog::new() else {
            let _ = tx.send(PromptOutcome::Unavailable);
            return;
        };
        dlg.set_title_text(title_s.into());
        dlg.set_name(name_s.into());
        dlg.set_instruction(instruction_s.into());
        dlg.set_prompt(prompt_s.into());
        dlg.set_answer(initial_s.into());
        dlg.set_mask_input(secret);
        let weak = dlg.as_weak();
        dlg.on_accepted({
            let tx = tx.clone();
            let weak = weak.clone();
            move || {
                let answer = weak
                    .upgrade()
                    .map(|d| d.get_answer().to_string())
                    .unwrap_or_default();
                let _ = tx.send(PromptOutcome::Answered(answer));
                if let Some(d) = weak.upgrade() {
                    let _ = d.hide(); // answered; closing is cosmetic
                }
            }
        });
        dlg.on_rejected({
            let tx = tx.clone();
            let weak = weak.clone();
            move || {
                let _ = tx.send(PromptOutcome::Cancelled);
                if let Some(d) = weak.upgrade() {
                    let _ = d.hide(); // cancelled; closing is cosmetic
                }
            }
        });
        let _ = dlg.show(); // showing the prompt is best-effort
    });
    if posted.is_err() {
        return PromptOutcome::Unavailable;
    }
    rx.recv_timeout(Duration::from_secs(120))
        .unwrap_or(PromptOutcome::Unavailable)
}

/// Host-key confirmation callback for the AcceptNew (TOFU) policy.
///
/// Runs on a tokio worker thread; posts the [`HostKeyDialog`] to the Slint
/// event loop and blocks on an mpsc channel until the user answers (mirror
/// of the C++ condition-variable wait in `MainWindow::confirmHostKeyUI`).
/// The C++ waited indefinitely; a 120 s timeout rejects the key so a dead
/// event loop cannot hang a connect forever (deviation, documented).
fn tofu_confirm_callback(state: AppState) -> HostKeyConfirmCb {
    Arc::new(
        move |host: &str, _port: u16, algorithm: &str, fingerprint: &str, can_save: bool| {
            let (tx, rx) = mpsc::sync_channel::<bool>(1);
            let host_s = host.to_string();
            let algorithm_s = algorithm.to_string();
            // C++ passed settings "Security/fpHex" to the display helper.
            let fp_hex = crate::settings::Preferences::load().fp_hex;
            let fingerprint_s = format_fingerprint(fingerprint, fp_hex);

            let posted = slint::invoke_from_event_loop({
                let tx = tx.clone();
                move || {
                    let Ok(dlg) = connection_dialog::HostKeyDialog::new() else {
                        let _ = tx.send(false);
                        return;
                    };
                    dlg.set_host(host_s.into());
                    dlg.set_algorithm(algorithm_s.into());
                    dlg.set_fingerprint(fingerprint_s.into());
                    dlg.set_can_save(can_save);
                    let weak = dlg.as_weak();
                    let close = {
                        let weak = weak.clone();
                        move || {
                            if let Some(d) = weak.upgrade() {
                                let _ = d.hide(); // answered; closing is cosmetic
                            }
                        }
                    };
                    dlg.on_accept_save({
                        let tx = tx.clone();
                        let close = close.clone();
                        move || {
                            let _ = tx.send(true);
                            close();
                        }
                    });
                    dlg.on_accept_once({
                        let tx = tx.clone();
                        let close = close.clone();
                        move || {
                            let _ = tx.send(true);
                            close();
                        }
                    });
                    dlg.on_reject({
                        let tx = tx.clone();
                        let close = close.clone();
                        move || {
                            let _ = tx.send(false);
                            close();
                        }
                    });
                    let _ = dlg.show(); // showing the prompt is best-effort
                }
            });
            if posted.is_err() {
                return false;
            }
            let accepted = rx.recv_timeout(Duration::from_secs(120)).unwrap_or(false);
            // Status wording mirrors MainWindow::onTofuFinished.
            if !can_save && accepted {
                state.set_status("Could not save fingerprint; allowing one-time connection");
            } else if !accepted {
                state.set_status("Connection cancelled: fingerprint not accepted");
            }
            accepted
        },
    )
}

// ---------------------------------------------------------------------------
// Keyboard-interactive prompts
// ---------------------------------------------------------------------------

/// Port of the `keyboard_interactive_cb` in MainWindowConnection.cpp:
/// auto-fill username/password prompts from the saved credentials, ask the
/// user for OTP/codes/generic info, cancel on user cancel, `Unhandled` when
/// the dialog cannot be shown.
fn keyboard_interactive_callback(username: String, password: String) -> KbdIntPromptsCb {
    Arc::new(
        move |name: &str,
              instruction: &str,
              prompts: &[String],
              responses: &mut Vec<String>|
              -> KbdIntPromptResult {
            responses.clear();
            let suffix = if instruction.is_empty() {
                String::new()
            } else {
                format!(" — {instruction}")
            };
            for prompt in prompts {
                let lower = prompt.to_lowercase();
                if lower.contains("user") || lower.contains("name:") {
                    responses.push(username.clone());
                    continue;
                }
                let password_like = lower.contains("password")
                    || lower.contains("passphrase")
                    || lower.contains("passcode");
                if password_like && !password.is_empty() {
                    responses.push(password.clone());
                    continue;
                }
                let otp_like = lower.contains("verification")
                    || lower.contains("verify")
                    || lower.contains("otp")
                    || lower.contains("code")
                    || lower.contains("token");
                let title = if otp_like {
                    format!("Verification code required{suffix}")
                } else if password_like {
                    format!("Password required{suffix}")
                } else {
                    format!("Information required{suffix}")
                };
                match prompt_user_sync(
                    &title,
                    name,
                    instruction,
                    prompt,
                    "",
                    password_like || otp_like,
                ) {
                    PromptOutcome::Answered(answer) => responses.push(answer),
                    PromptOutcome::Cancelled => return KbdIntPromptResult::Cancelled,
                    PromptOutcome::Unavailable => return KbdIntPromptResult::Unhandled,
                }
            }
            if responses.len() == prompts.len() {
                KbdIntPromptResult::Handled
            } else {
                KbdIntPromptResult::Unhandled
            }
        },
    )
}

/// Attach TOFU, host-key status, and keyboard-interactive callbacks for the
/// SSH protocols (port of the callback injection in `startSftpConnect`).
pub fn attach_session_callbacks(mut opt: SessionOptions, state: &AppState) -> SessionOptions {
    let caps = capabilities_for_protocol(opt.protocol);
    if caps.supports_known_hosts {
        if opt.known_hosts_policy == KnownHostsPolicy::AcceptNew {
            opt.hostkey_confirm_cb = Some(tofu_confirm_callback(state.clone()));
        }
        let status_state = state.clone();
        opt.hostkey_status_cb = Some(Arc::new(move |msg: &str| {
            let status_state = status_state.clone();
            let message = msg.to_string();
            let _ = slint::invoke_from_event_loop(move || {
                status_state.set_status(&message);
            });
        }));
        opt.keyboard_interactive_cb = Some(keyboard_interactive_callback(
            opt.username.clone(),
            opt.password.clone().unwrap_or_default(),
        ));
    }
    opt
}

// ---------------------------------------------------------------------------
// "No verification" (known_hosts Off) double confirmation
// ---------------------------------------------------------------------------

static NO_VERIFY_CONFIRMED_UNTIL: OnceLock<Mutex<HashMap<(String, u16), u64>>> = OnceLock::new();

// The C++ persisted the 15-minute exception per host:port in QSettings
// (`Security/noHostVerificationConfirmedUntilUtc/<host>:<port>`, TTL from
// `prefNoHostVerificationTtlMin_`); the exception map is kept in memory
// only (deviation, documented), while the TTL itself comes from the
// settings store.

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Port of `MainWindow::confirmInsecureHostPolicyForSession`: double
/// confirmation with exact-token typing for the Off policy.
pub fn confirm_insecure_host_policy(state: &AppState, opt: &SessionOptions) -> bool {
    if opt.known_hosts_policy != KnownHostsPolicy::Off {
        return true;
    }
    let ttl_min = crate::settings::Preferences::load()
        .no_host_verification_ttl_min
        .clamp(1, 1440) as u64;
    let key = (opt.host.trim().to_lowercase(), opt.port);
    let now = now_epoch_secs();
    let cache = NO_VERIFY_CONFIRMED_UNTIL.get_or_init(|| Mutex::new(HashMap::new()));
    let already_allowed = cache
        .lock()
        .map(|g| g.get(&key).map(|until| *until > now).unwrap_or(false))
        .unwrap_or(false);
    if already_allowed {
        return true;
    }

    let (tx, rx) = mpsc::sync_channel::<bool>(1);
    let posted = slint::invoke_from_event_loop({
        let tx = tx.clone();
        move || {
            let Ok(dlg) = connection_dialog::ConfirmTextDialog::new() else {
                let _ = tx.send(false);
                return;
            };
            dlg.set_title_text(translate_alert_text("Critical security risk").into());
            dlg.set_message(
                tr(
                    "You are about to connect using the \"No verification\" policy.\nThis allows MITM attacks and server impersonation.\n\nDo you want to continue at your own risk?\n\nTo confirm, type exactly %1",
                    &["UNSAFE".to_string()],
                )
                .into(),
            );
            dlg.set_confirm_token("UNSAFE".into());
            let weak = dlg.as_weak();
            dlg.on_confirmed({
                let tx = tx.clone();
                let weak = weak.clone();
                move || {
                    let _ = tx.send(true);
                    if let Some(d) = weak.upgrade() {
                        let _ = d.hide(); // answered; closing is cosmetic
                    }
                }
            });
            dlg.on_rejected({
                let tx = tx.clone();
                let weak = weak.clone();
                move || {
                    let _ = tx.send(false);
                    if let Some(d) = weak.upgrade() {
                        let _ = d.hide(); // answered; closing is cosmetic
                    }
                }
            });
            let _ = dlg.show(); // showing the prompt is best-effort
        }
    });
    if posted.is_err() {
        return false;
    }
    if !rx.recv_timeout(Duration::from_secs(120)).unwrap_or(false) {
        show_alert(
            "Connection canceled",
            "Risk confirmation was not completed correctly.",
        );
        return false;
    }
    if let Ok(mut g) = cache.lock() {
        g.insert(key, now + ttl_min * 60);
    }
    state.set_status(&format!(
        "Temporary \"no verification\" exception active for {ttl_min} minutes"
    ));
    true
}

// ---------------------------------------------------------------------------
// Alert box helper
// ---------------------------------------------------------------------------

/// Gettext contexts of the C++ alert call sites, tried in order; the first
/// catalog hit wins. Rust-built alert text needs this lookup because Slint's
/// `@tr` only covers strings written in `.slint` files, while the Qt `.ts`
/// catalogs contain every `tr()` from the C++ dialogs. The contexts are the
/// plain Qt context names: the pipes Qt's PO writer adds (`MainWindow|`) are
/// stripped when the catalogs are generated, because Slint (and the plain
/// gettext lookup here) uses the bare name.
const ALERT_CONTEXTS: &[&str] = &[
    "MainWindow",
    "ConnectionDialog",
    "SiteManagerDialog",
    "SettingsDialog",
    "AboutDialog",
    "TransferQueueDialog",
    "PermissionsDialog",
    "HistoryDialog",
    "SearchDialog",
    "RemoteModel",
    "DragAwareTreeView",
    "TransferManager",
    // Entries without a `msgctxt` (Qt's `QObject::tr` context).
    "QObject",
    "",
];

/// Best-effort gettext lookup for Rust-built dialog text; returns `text`
/// unchanged when no catalog carries the msgid (the source-language fallback,
/// and what happens in tests where no catalog is installed). Must run on the
/// UI thread: Slint keeps its translator in a thread-local.
pub fn translate_alert_text(text: &str) -> String {
    lookup_translation(text).unwrap_or_else(|| text.to_string())
}

/// Translates a catalog msgid and substitutes the Qt-style `%1`, `%2`… arguments
/// — the Rust equivalent of `tr("…").arg(…)` at the C++ call sites. The msgid is
/// returned with the arguments substituted when no catalog carries it.
pub fn tr(msgid: &str, args: &[String]) -> String {
    let mut text = lookup_translation(msgid).unwrap_or_else(|| msgid.to_string());
    for (index, arg) in args.iter().enumerate() {
        text = text.replace(&format!("%{}", index + 1), arg);
    }
    text
}

/// First catalog hit for `msgid` across the Qt contexts of the C++ call sites.
fn lookup_translation(msgid: &str) -> Option<String> {
    if msgid.is_empty() {
        return None;
    }
    for context in ALERT_CONTEXTS {
        let translated = slint::private_unstable_api::translate(
            msgid.into(),
            (*context).into(),
            "freescp-app".into(),
            Default::default(),
            1,
            Default::default(),
        );
        if translated.as_str() != msgid {
            return Some(translated.to_string());
        }
    }
    None
}

/// Show a modal-ish alert window (port of `UiAlerts::critical/warning/
/// information` usage in the connect path). Safe to call from any thread.
pub fn show_alert(title: &str, message: &str) {
    let title_s = title.to_string();
    let message_s = message.to_string();
    let posted = slint::invoke_from_event_loop(move || {
        let Ok(dlg) = connection_dialog::AlertDialog::new() else {
            return;
        };
        dlg.set_title_text(translate_alert_text(&title_s).into());
        dlg.set_message(translate_alert_text(&message_s).into());
        let weak = dlg.as_weak();
        dlg.on_ok(move || {
            if let Some(d) = weak.upgrade() {
                let _ = d.hide(); // dismissed; closing is cosmetic
            }
        });
        let _ = dlg.show(); // showing the alert is best-effort
    });
    if posted.is_err() {
        tracing::error!(%title, "alert could not be posted to the UI event loop");
    }
}

/// Blocking yes/no confirmation posted to the event loop (port of the
/// `QMessageBox::question` calls made from worker threads). Returns `false`
/// when the dialog cannot be shown or the user picks the secondary button.
///
/// Call only from a non-UI thread: the caller blocks while the event loop
/// displays the dialog.
pub fn confirm_sync(title: &str, message: &str, yes_label: &str, no_label: &str) -> bool {
    let (tx, rx) = mpsc::sync_channel::<bool>(1);
    let title_s = title.to_string();
    let message_s = message.to_string();
    let yes_s = yes_label.to_string();
    let no_s = no_label.to_string();
    let posted = slint::invoke_from_event_loop(move || {
        let Ok(dlg) = connection_dialog::AlertDialog::new() else {
            let _ = tx.send(false);
            return;
        };
        dlg.set_title_text(translate_alert_text(&title_s).into());
        dlg.set_message(translate_alert_text(&message_s).into());
        dlg.set_confirm_mode(true);
        dlg.set_yes_text(translate_alert_text(&yes_s).into());
        dlg.set_no_text(translate_alert_text(&no_s).into());
        let weak = dlg.as_weak();
        dlg.on_ok({
            let tx = tx.clone();
            let weak = weak.clone();
            move || {
                let _ = tx.send(true);
                if let Some(d) = weak.upgrade() {
                    let _ = d.hide();
                }
            }
        });
        dlg.on_cancel({
            let tx = tx.clone();
            let weak = weak.clone();
            move || {
                let _ = tx.send(false);
                if let Some(d) = weak.upgrade() {
                    let _ = d.hide();
                }
            }
        });
        let _ = dlg.show();
    });
    if posted.is_err() {
        return false;
    }
    rx.recv_timeout(Duration::from_secs(120)).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Quick-connect site persistence
// ---------------------------------------------------------------------------

/// Normalized identity comparison used to detect "site already exists"
/// (port of `sameSavedSiteIdentity`).
pub fn same_saved_site_identity(a: &SessionOptions, b: &SessionOptions) -> bool {
    let norm_host = |s: &str| s.trim().to_lowercase();
    let norm_path = |p: &Option<String>| {
        p.as_deref()
            .map(str::trim)
            .map(str::to_string)
            .filter(|s| !s.is_empty())
    };
    let scp_mode = |o: &SessionOptions| {
        if o.protocol == Protocol::Scp {
            o.scp_transfer_mode
        } else {
            ScpTransferMode::Auto
        }
    };
    let compare_webdav_tls = (a.protocol != Protocol::WebDav)
        || (a.webdav_scheme == b.webdav_scheme
            && a.webdav_verify_peer == b.webdav_verify_peer
            && norm_path(&a.webdav_ca_cert_path) == norm_path(&b.webdav_ca_cert_path));
    // SMB domains identify distinct logins on the same host; Telnet TLS
    // options identify distinct transports. Neither was part of the C++
    // comparison (those protocols are Rust-only), so they are gated by
    // protocol to keep the ported behavior for the shared protocols.
    let norm_domain = |d: &Option<String>| {
        d.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase())
    };
    let compare_smb_domain =
        (a.protocol != Protocol::Smb) || norm_domain(&a.smb_domain) == norm_domain(&b.smb_domain);
    let compare_telnet = (a.protocol != Protocol::Telnet)
        || (a.telnet_tls == b.telnet_tls
            && a.telnet_verify_peer == b.telnet_verify_peer
            && norm_path(&a.telnet_ca_cert_path) == norm_path(&b.telnet_ca_cert_path)
            && a.telnet_auto_login == b.telnet_auto_login);
    // Host-key verification decides whether an SSH connection may proceed, so
    // an SFTP/SCP site that differs only in known_hosts policy or file must
    // not be treated as the same saved site: the quick-connect choice would
    // otherwise be silently dropped instead of persisted. The C++ comparison
    // omitted these fields; the deviation is deliberate.
    let uses_known_hosts = |p: Protocol| matches!(p, Protocol::Sftp | Protocol::Scp);
    let compare_known_hosts = !uses_known_hosts(a.protocol)
        || (norm_path(&a.known_hosts_path) == norm_path(&b.known_hosts_path)
            && a.known_hosts_policy == b.known_hosts_policy
            && a.known_hosts_hash_names == b.known_hosts_hash_names);

    a.protocol == b.protocol
        && scp_mode(a) == scp_mode(b)
        && norm_host(&a.host) == norm_host(&b.host)
        && a.port == b.port
        && a.username.trim() == b.username.trim()
        && a.proxy_type == b.proxy_type
        && norm_host(&a.proxy_host) == norm_host(&b.proxy_host)
        && a.proxy_port == b.proxy_port
        && norm_path(&a.proxy_username) == norm_path(&b.proxy_username)
        && norm_path(&a.jump_host).map(|h| h.to_lowercase())
            == norm_path(&b.jump_host).map(|h| h.to_lowercase())
        && a.jump_port == b.jump_port
        && norm_path(&a.jump_username) == norm_path(&b.jump_username)
        && norm_path(&a.jump_private_key_path) == norm_path(&b.jump_private_key_path)
        && norm_path(&a.private_key_path) == norm_path(&b.private_key_path)
        && a.ftps_verify_peer == b.ftps_verify_peer
        && norm_path(&a.ftps_ca_cert_path) == norm_path(&b.ftps_ca_cert_path)
        && compare_webdav_tls
        && compare_smb_domain
        && compare_telnet
        && compare_known_hosts
}

/// Default "user@host[:port] (protocol)" site name (port of
/// `defaultQuickSiteName`).
pub fn default_quick_site_name(opt: &SessionOptions) -> String {
    let user = opt.username.trim();
    let host = opt.host.trim().to_lowercase();
    let mut out = if !user.is_empty() && !host.is_empty() {
        format!("{user}@{host}")
    } else if !host.is_empty() {
        host.clone()
    } else if !user.is_empty() {
        user.to_string()
    } else {
        "New site".to_string()
    };
    if !host.is_empty() && opt.port != default_port_for_protocol(opt.protocol) {
        out.push_str(&format!(":{}", opt.port));
    }
    if opt.protocol != Protocol::Sftp {
        out = format!("{out} ({})", protocol_display_name(opt.protocol));
    }
    out
}

/// Quick-connect site persistence (port of `maybePersistQuickConnectSite`).
///
/// Decision logic (identity comparison, default naming) lives here; the
/// actual store is delegated to [`crate::site_manager::save_site`], which
/// consults [`same_saved_site_identity`] for the "Site already exists."
/// vs. "Site saved." status wording.
pub async fn maybe_persist_site(
    state: &AppState,
    opt: &SessionOptions,
    save: bool,
    save_credentials: bool,
    site_name: &str,
) {
    if !save {
        return;
    }
    let preferred = site_name.trim();
    let name = if preferred.is_empty() {
        default_quick_site_name(opt)
    } else {
        preferred.to_string()
    };

    // Port of C++ maybePersistQuickConnectSite: passwords / passphrases are
    // only persisted when "Save passwords/passphrases" was checked; the
    // secrets themselves go to the keyring via save_site (which strips or
    // keeps them depending on which fields are Some here).
    let mut sanitized = opt.clone();
    if !save_credentials {
        sanitized.password = None;
        sanitized.private_key_passphrase = None;
        sanitized.proxy_password = None;
    }
    sanitized.hostkey_confirm_cb = None;
    sanitized.hostkey_status_cb = None;
    sanitized.keyboard_interactive_cb = None;

    // Port of the duplicate check in `maybePersistQuickConnectSite`: a site
    // with the same connection identity under a different name is not saved.
    let duplicate = crate::site_manager::load_sites().into_iter().find(|e| {
        !e.name.eq_ignore_ascii_case(&name)
            && same_saved_site_identity(&sanitized, &e.to_session_options())
    });
    if let Some(existing) = duplicate {
        state.set_status(&format!(
            "Site already exists: {existing}",
            existing = existing.name
        ));
        return;
    }

    match crate::site_manager::save_site(state, &name, &sanitized) {
        Ok(()) => {
            let msg = if save_credentials {
                format!("Site and credentials saved: {name}")
            } else {
                format!("Site saved: {name}")
            };
            state.set_status(&msg);
        }
        Err(e) => tracing::warn!(site = %name, "could not persist site: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Session indicators
// ---------------------------------------------------------------------------
//
// The elapsed indicator is driven per session from `SessionRecord::started_at`
// (the main window's 1 s timer renders it), so only the "a session just
// started" hook remains here — it is the port of
// `startConnectionSessionIndicators` for the connection paths that run before
// the session is installed.

/// Start the session timer (port of `startConnectionSessionIndicators`);
/// call when a session is installed.
pub fn start_indicators(state: &AppState) {
    let _ = state;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

thread_local! {
    /// True while a dialog-driven connect attempt is in flight. Mirrors
    /// `m_connectInProgress_` in `ui/MainWindow.cpp`: it guards against a
    /// second attempt and disables the main window's Connect action.
    static CONNECT_IN_FLIGHT: Cell<bool> = const { Cell::new(false) };
}

/// Whether a dialog-driven connection attempt is currently running.
pub fn connect_in_progress() -> bool {
    CONNECT_IN_FLIGHT.with(Cell::get)
}

/// Whether the Connect dialog may start a session for `protocol`: either a
/// file-transfer protocol, or the console-only Telnet transport that
/// [`run_any_connect`] routes to [`crate::console`].
///
/// Telnet is `implemented` but has no file-transfer capabilities, so the
/// `supports_file_transfers` guard alone would reject it.
fn protocol_can_start_connect(protocol: Protocol) -> bool {
    let caps = capabilities_for_protocol(protocol);
    caps.implemented && (caps.supports_file_transfers || protocol == Protocol::Telnet)
}

/// Open the connection dialog and run the full connect flow on
/// connect-requested (port of `openConnectDialogWithPreset` +
/// `startSftpConnect` + `finalizeSftpConnect`).
///
/// Never blocks the Slint thread: the network connect runs on
/// [`AppState::runtime_handle`], and the result is awaited back on the event
/// loop via `slint::spawn_local`.
///
/// The Site Manager's preset-based connect path goes through
/// [`start_connect`] instead of this dialog.
///
/// `tab` is the tab reserved by the caller (`main.rs` marks it `connecting`
/// and passes its id); a successful connect installs into exactly that tab.
pub fn open(win: &main_window::MainWindow, state: &AppState, tab: Option<u64>) {
    if connect_in_progress() {
        // The caller has already reserved `tab`; release it so the tab bar
        // does not stay on "Connecting…" for an attempt that never started.
        state.connect_failed(tab);
        show_alert(
            "Connection in progress",
            "Wait for the current connection attempt to finish or cancel it first.",
        );
        return;
    }
    let win_weak = win.as_weak();

    let Ok(dlg) = connection_dialog::ConnectionDialog::new() else {
        tracing::error!("failed to instantiate ConnectionDialog");
        state.connect_failed(tab);
        return;
    };
    let state = state.clone();

    // Center the dialog over the main window (port of parenting/modal
    // placement in the C++).
    if let Some(win) = win_weak.upgrade() {
        crate::remote::center_window_over(&win, dlg.window());
    }

    // Defaults come from the settings store (port of the QSettings reads in
    // ConnectionDialog::populateDefaultConnectionUi).
    {
        let prefs = crate::settings::Preferences::load();
        let protocol = prefs.default_protocol_enum();
        let scp_mode = prefs.default_scp_mode_enum();
        dlg.set_protocol(protocol_to_int(protocol));
        dlg.set_port(default_port_for_protocol(protocol).clamp(1, 65535) as i32);
        dlg.set_scp_mode(scp_mode_to_int(scp_mode));
        // The enum helpers mirror the C++ load path's fallback rules
        // (unknown stored values fall back to Strict / Optional).
        let known_hosts_index = match prefs.default_known_hosts_policy_enum() {
            KnownHostsPolicy::Strict => 0,
            KnownHostsPolicy::AcceptNew => 1,
            KnownHostsPolicy::Off => 2,
        };
        dlg.set_known_hosts_policy(known_hosts_index);
        let integrity_index = match prefs.default_transfer_integrity_policy_enum() {
            freescp_core::TransferIntegrityPolicy::Off => 0,
            freescp_core::TransferIntegrityPolicy::Optional => 1,
            freescp_core::TransferIntegrityPolicy::Required => 2,
        };
        dlg.set_integrity(integrity_index);
    }

    // Shared cancellation flag for the in-flight attempt (mirrors
    // m_connectCancelRequested_ / m_connectInProgress_ in the C++).
    let cancel = Arc::new(AtomicBool::new(false));

    // ---- protocol change: reset the port to the protocol default ----------
    {
        let d = dlg.as_weak();
        let last_webdav_https = Rc::new(Cell::new(true));
        let last_telnet_tls = Rc::new(Cell::new(false));
        dlg.on_protocol_changed({
            let d = d.clone();
            let last_webdav_https = last_webdav_https.clone();
            let last_telnet_tls = last_telnet_tls.clone();
            move || {
                let Some(d) = d.upgrade() else { return };
                let protocol = protocol_from_int(d.get_protocol());
                let default_port = if protocol == Protocol::WebDav {
                    default_port_for_webdav_scheme(if d.get_webdav_https() {
                        WebDavScheme::Https
                    } else {
                        WebDavScheme::Http
                    })
                } else if protocol == Protocol::Telnet {
                    default_port_for_telnet(d.get_telnet_tls())
                } else {
                    default_port_for_protocol(protocol)
                };
                d.set_port(default_port as i32);
                last_webdav_https.set(d.get_webdav_https());
                last_telnet_tls.set(d.get_telnet_tls());
            }
        });
        // WebDAV scheme switch only follows the port when it still equals
        // the previous scheme's default (port of updateProtocolUi + the
        // webDavScheme currentIndexChanged handler).
        dlg.on_webdav_scheme_changed({
            let d = d.clone();
            let last_webdav_https = last_webdav_https.clone();
            move || {
                let Some(d) = d.upgrade() else { return };
                let previous = if last_webdav_https.get() {
                    WebDavScheme::Https
                } else {
                    WebDavScheme::Http
                };
                let next = if d.get_webdav_https() {
                    WebDavScheme::Https
                } else {
                    WebDavScheme::Http
                };
                let previous_default = default_port_for_webdav_scheme(previous) as i32;
                let next_default = default_port_for_webdav_scheme(next) as i32;
                if protocol_from_int(d.get_protocol()) == Protocol::WebDav
                    && d.get_port() == previous_default
                    && previous_default != next_default
                {
                    d.set_port(next_default);
                }
                last_webdav_https.set(d.get_webdav_https());
            }
        });
        // Telnet TLS toggle: same follow-the-default rule for 23 <-> 992.
        dlg.on_telnet_tls_changed({
            let d = d.clone();
            let last_telnet_tls = last_telnet_tls.clone();
            move || {
                let Some(d) = d.upgrade() else { return };
                let previous_default = default_port_for_telnet(last_telnet_tls.get()) as i32;
                let next_default = default_port_for_telnet(d.get_telnet_tls()) as i32;
                if protocol_from_int(d.get_protocol()) == Protocol::Telnet
                    && d.get_port() == previous_default
                    && previous_default != next_default
                {
                    d.set_port(next_default);
                }
                last_telnet_tls.set(d.get_telnet_tls());
            }
        });
    }

    // ---- proxy selection: jump/proxy exclusion + proxy port defaults ------
    {
        let d = dlg.as_weak();
        let last_proxy_type = Rc::new(Cell::new(0i32));
        dlg.on_proxy_type_changed({
            let d = d.clone();
            let last_proxy_type = last_proxy_type.clone();
            move || {
                let Some(d) = d.upgrade() else { return };
                let proxy = proxy_type_from_int(d.get_proxy_type());
                if proxy != ProxyType::None && d.get_jump_enabled() {
                    d.set_jump_enabled(false);
                }
                let previous = proxy_type_from_int(last_proxy_type.get());
                let previous_default = default_port_for_proxy_type(previous) as i32;
                let next_default = default_port_for_proxy_type(proxy) as i32;
                let current_port = d.get_proxy_port();
                let first_selection = previous == ProxyType::None;
                let uses_previous_default =
                    previous_default != 0 && current_port == previous_default;
                if proxy != ProxyType::None
                    && next_default != 0
                    && (first_selection || uses_previous_default)
                    && current_port != next_default
                {
                    d.set_proxy_port(next_default);
                }
                last_proxy_type.set(d.get_proxy_type());
            }
        });
        dlg.on_jump_enabled_changed({
            let d = d.clone();
            move || {
                let Some(d) = d.upgrade() else { return };
                if d.get_jump_enabled() && d.get_proxy_type() != 0 {
                    d.set_proxy_type(0);
                }
            }
        });
    }

    // ---- "Choose…" file browse buttons ------------------------------------
    {
        let d = dlg.as_weak();
        dlg.on_browse_path_requested(move |field: slint::SharedString| {
            let Some(path) = pick_connection_file(field.as_str()) else {
                return;
            };
            let Some(d) = d.upgrade() else { return };
            let path_s: slint::SharedString = path.to_string_lossy().into_owned().into();
            match field.as_str() {
                "private-key" => d.set_private_key_path(path_s),
                "jump-key" => d.set_jump_key_path(path_s),
                "known-hosts" => d.set_known_hosts_path(path_s),
                "ftps-ca" => d.set_ftps_ca_path(path_s),
                "webdav-ca" => d.set_webdav_ca_path(path_s),
                "telnet-ca" => d.set_telnet_ca_path(path_s),
                other => tracing::warn!(field = %other, "unknown browse field"),
            }
        });
    }

    // ---- connect flow ------------------------------------------------------
    dlg.on_connect_requested({
        let d = dlg.as_weak();
        let state = state.clone();
        let cancel = cancel.clone();
        let win = win_weak.clone();
        move || {
            let Some(d) = d.upgrade() else { return };
            let mut opt = session_options_from_dialog(&d);
            if opt.host.trim().is_empty() {
                state.set_status("Please enter a server host.");
                return;
            }

            // Pre-flight validation (port of the startSftpConnect guards).
            // Console-only protocols (Telnet) pass: `run_any_connect` routes
            // them to the terminal transport instead of a file session.
            if !protocol_can_start_connect(opt.protocol) {
                let name = protocol_display_name(opt.protocol);
                show_alert(
                    "Protocol not available",
                    &tr(
                        "%1 support is not implemented yet.",
                        std::slice::from_ref(&name.to_string()),
                    ),
                );
                state.set_status(&format!("Connection canceled: unsupported protocol {name}"));
                return;
            }
            let caps = capabilities_for_protocol(opt.protocol);
            if opt.jump_host.is_some() && !caps.supports_jump_host {
                let name = protocol_display_name(opt.protocol);
                show_alert(
                    "Unsupported transport",
                    &tr(
                        "SSH jump host is not available for %1.",
                        std::slice::from_ref(&name.to_string()),
                    ),
                );
                state.set_status(&format!(
                    "Connection canceled: SSH jump host is not supported for {name}"
                ));
                return;
            }
            if opt.proxy_type != ProxyType::None && !caps.supports_proxy {
                let name = protocol_display_name(opt.protocol);
                show_alert(
                    "Unsupported transport",
                    &tr(
                        "Proxy settings are not available for %1.",
                        std::slice::from_ref(&name.to_string()),
                    ),
                );
                state.set_status(&format!("Connection canceled: proxy is not supported for {name}"));
                return;
            }
            if has_transport_conflict(&opt) {
                show_alert(
                    "Invalid transport configuration",
                    "Proxy and SSH jump host cannot be used together in the same connection.\nChoose only one transport method.",
                );
                state.set_status("Connection canceled: invalid transport configuration");
                return;
            }
            if !confirm_insecure_host_policy(&state, &opt) {
                state.set_status("Connection canceled: no-verification policy not confirmed");
                return;
            }

            // Inject TOFU / status / keyboard-interactive callbacks.
            opt = attach_session_callbacks(opt, &state);

            // Quick-connect persistence happens before connecting (C++
            // persisted on dialog accept: "Already persisted on request").
            let save_site = d.get_save_site();
            let save_credentials = d.get_save_credentials();
            let site_name = d.get_site_name().to_string();

            // Switch the dialog into "connecting" state.
            cancel.store(false, Ordering::SeqCst);
            CONNECT_IN_FLIGHT.with(|flag| flag.set(true));
            if let Some(win) = win.upgrade() {
                win.set_connect_in_progress(true);
            }
            d.set_connecting(true);
            d.set_status_message(translate_alert_text("Connecting…").into());
            state.set_connect_progress(true);

            let host_display = opt.host.clone();
            let protocol_display = protocol_display_name(opt.protocol).to_string();
            let opt_for_persist = opt.clone();
            let opt_for_install = opt.clone();

            let persist_state = state.clone();
            let ui_state = state.clone();
            let ui_dlg = d.as_weak();
            let ui_win = win.clone();
            let task_cancel = cancel.clone();

            // UI callbacks are not inside a Tokio context; use AppState's runtime.
            let task = state.runtime_handle().spawn(async move {
                if task_cancel.load(Ordering::SeqCst) {
                    return Err(ConnectError::Cancelled);
                }
                maybe_persist_site(
                    &persist_state,
                    &opt_for_persist,
                    save_site,
                    save_credentials,
                    &site_name,
                )
                .await;
                let result = run_any_connect(opt).await;
                if task_cancel.load(Ordering::SeqCst) {
                    if let Ok(ConnectOutcome::Session(client)) = &result {
                        client.interrupt();
                    }
                    return Err(ConnectError::Cancelled);
                }
                result
            });

            let _ = slint::spawn_local(async move {
                let outcome = task.await.unwrap_or_else(|join_error| {
                    tracing::error!("connection task panicked: {join_error}");
                    Err(ConnectError::Failed("Connection task crashed.".to_string()))
                });
                if let Some(ui_dlg) = ui_dlg.upgrade() {
                    ui_dlg.set_connecting(false);
                }
                CONNECT_IN_FLIGHT.with(|flag| flag.set(false));
                if let Some(win) = ui_win.upgrade() {
                    win.set_connect_in_progress(false);
                }
                ui_state.set_connect_progress(false);
                match outcome {
                    Ok(ConnectOutcome::Session(client)) => {
                        if let Some(ui_dlg) = ui_dlg.upgrade() {
                            let _ = ui_dlg.hide(); // connected; closing is cosmetic
                        }
                        start_indicators(&ui_state);
                        ui_state.set_status(&format!(
                            "Connected ({protocol_display}) to {host_display}"
                        ));
                        ui_state.install_session(tab, opt_for_install, client);
                    }
                    Ok(ConnectOutcome::Console(session, events)) => {
                        if let Some(ui_dlg) = ui_dlg.upgrade() {
                            let _ = ui_dlg.hide(); // connected; closing is cosmetic
                        }
                        start_indicators(&ui_state);
                        ui_state.set_status(&format!(
                            "Connected ({protocol_display}) to {host_display}"
                        ));
                        ui_state.install_console_session(tab, opt_for_install, session, events);
                    }
                    Err(ConnectError::Cancelled) => {
                        ui_state.set_status("Connection canceled");
                        ui_state.connect_failed(tab);
                    }
                    Err(ConnectError::Failed(msg)) => {
                        ui_state.connect_failed(tab);
                        show_alert(
                            "Connection error",
                            &tr(
                                "Could not connect to the server.\n%1",
                                std::slice::from_ref(&msg),
                            ),
                        );
                    }
                }
            });
        }
    });

    // ---- cancel the in-flight connect --------------------------------------
    dlg.on_cancel_requested({
        let d = dlg.as_weak();
        let state = state.clone();
        let cancel = cancel.clone();
        move || {
            let Some(d) = d.upgrade() else { return };
            cancel.store(true, Ordering::SeqCst);
            state.set_status("Canceling connection…");
            d.set_status_message("Canceling…".into());
        }
    });

    // ---- dialog closed by the user ----------------------------------------
    dlg.on_close_requested({
        let d = dlg.as_weak();
        let state = state.clone();
        let cancel = cancel.clone();
        move || {
            let Some(d) = d.upgrade() else { return };
            if d.get_connecting() {
                cancel.store(true, Ordering::SeqCst);
                state.set_status("Connection canceled");
            }
            // The reserved tab goes back to idle (no-op when a session
            // installed in the meantime).
            state.connect_failed(tab);
            let _ = d.hide(); // closed by the user; closing is cosmetic
        }
    });

    if let Err(err) = dlg.show() {
        // A dialog that never appeared has no close handler, so the reserved
        // tab would stay on "Connecting…" for the rest of the session.
        tracing::error!(%err, "failed to show the ConnectionDialog");
        state.connect_failed(tab);
    }
}

/// Opens the native file picker for one of the connection-editor file fields
/// (`private-key`, `jump-key`, `known-hosts`, `ftps-ca`, `webdav-ca`), porting
/// the C++ `ConnectionDialog` browse handlers: a per-field dialog title and a
/// starting directory — the user's `~/.ssh` for keys and known_hosts (where
/// the C++ `QFileDialog::getOpenFileName` calls start), the home directory
/// for TLS CA bundles. Falls back to the picker default when the directory
/// does not exist.
pub(crate) fn pick_connection_file(field: &str) -> Option<std::path::PathBuf> {
    let ssh_dir = || dirs::home_dir().map(|home| home.join(".ssh"));
    let home_dir = dirs::home_dir;
    let (title, start_dir) = match field {
        "private-key" => ("Select private key", ssh_dir()),
        "jump-key" => ("Select jump private key", ssh_dir()),
        "known-hosts" => ("Select known_hosts", ssh_dir()),
        "ftps-ca" => ("Select FTPS CA bundle", home_dir()),
        "webdav-ca" => ("Select WebDAV CA bundle", home_dir()),
        "telnet-ca" => ("Select Telnet CA bundle", home_dir()),
        _ => ("Select file", None),
    };
    let mut picker = rfd::FileDialog::new().set_title(title);
    if let Some(dir) = start_dir.filter(|dir| dir.is_dir()) {
        picker = picker.set_directory(dir);
    }
    picker.pick_file()
}

#[cfg(test)]
mod alert_i18n_tests {
    use super::translate_alert_text;

    /// With no catalog installed (the test process never calls
    /// `init_translations!`) the lookup must be a pass-through, and Rust-built
    /// text carrying braces must survive Slint's format pass untouched.
    #[test]
    fn alert_text_falls_back_to_the_source_string() {
        assert_eq!(
            translate_alert_text("No entries selected in the left panel."),
            "No entries selected in the left panel."
        );
        assert_eq!(translate_alert_text(""), "");
        assert_eq!(
            translate_alert_text("{not a placeholder}"),
            "{not a placeholder}"
        );
    }

    /// Temporary probe: verifies the catalogs really are reachable by the
    /// Rust-side lookup *and* by the context Slint's generated `@tr` calls use,
    /// including the C-locale case the startup path fixes (gettext is
    /// process-global, so this test is `#[ignore]`d and run explicitly with
    /// `--ignored --test-threads=1`).
    #[test]
    #[ignore = "mutates the process-global gettext locale; run explicitly"]
    fn catalogs_resolve_rust_and_slint_contexts() {
        std::env::set_var("LANGUAGE", "fr");
        crate::install_ui_locale("fr");
        slint::init_translations!(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("translations")
        );
        assert_eq!(
            translate_alert_text("Folder does not exist."),
            "Le dossier n'existe pas."
        );
        // The context `site-manager.slint`'s @tr calls are compiled with.
        let site_manager = slint::private_unstable_api::translate(
            "Site Manager".into(),
            "SiteManagerDialog".into(),
            "freescp-app".into(),
            Default::default(),
            1,
            Default::default(),
        );
        assert_eq!(site_manager.as_str(), "Gestionnaire de sites");
        // Rust-built dialogs: the `%1` templates the port reuses from the Qt
        // catalogs, the newest Rust-only entries, and Qt's standard buttons.
        assert_eq!(
            super::tr(
                "Could not connect to the server.\n%1",
                &["timeout".to_string()]
            ),
            "Impossible de se connecter au serveur.\ntimeout"
        );
        assert_eq!(
            super::tr("The pattern is not valid.\n%1", &["bad (".to_string()]),
            "Le motif n'est pas valide.\nbad ("
        );
        assert_eq!(
            super::tr(
                "Could not save site \"%1\".\n%2",
                &["prod".to_string(), "io".to_string()]
            ),
            "Impossible d'enregistrer le site « prod ».\nio"
        );
        assert_eq!(translate_alert_text("Yes"), "Oui");
        assert_eq!(translate_alert_text("No"), "Non");
        assert_eq!(
            translate_alert_text("No entries selected in the right panel."),
            "Aucune entrée sélectionnée dans le panneau droit."
        );
        assert_eq!(
            translate_alert_text("Permissions are not supported for the active protocol."),
            "Les autorisations ne sont pas prises en charge pour le protocole actif."
        );
        // A left-pane header, resolved through the `MainWindow` @tr context.
        for header in [
            "Kind",
            "Date Modified",
            "(empty folder)",
            "Search",
            "Pattern:",
        ] {
            let translated = slint::private_unstable_api::translate(
                header.into(),
                if header == "Search" || header == "Pattern:" {
                    "SearchDialog".into()
                } else {
                    "MainWindow".into()
                },
                "freescp-app".into(),
                Default::default(),
                1,
                Default::default(),
            );
            assert_ne!(translated.as_str(), header, "{header} stayed in English");
        }
    }
}

#[cfg(test)]
mod ssh_config_resolution_tests {
    use super::apply_resolved_params;
    use freescp_core::ssh_config::ResolvedSshParams;
    use freescp_core::{Protocol, ProxyType, SessionOptions};

    fn base() -> SessionOptions {
        SessionOptions {
            protocol: Protocol::Sftp,
            host: "myserver".into(),
            ..Default::default()
        }
    }

    fn resolved() -> ResolvedSshParams {
        ResolvedSshParams {
            host_name: Some("203.0.113.5".into()),
            port: Some(2222),
            user: Some("deploy".into()),
            identity_files: vec!["/home/test/.ssh/id_deploy".into()],
            proxy_jump: Some("bastion.example.com:2200".into()),
        }
    }

    #[test]
    fn fills_fields_left_at_their_defaults() {
        let mut opt = base(); // port 22 (default), no user/key/jump
        apply_resolved_params(&resolved(), &mut opt);
        assert_eq!(opt.host, "203.0.113.5");
        assert_eq!(opt.username, "deploy");
        assert_eq!(opt.port, 2222);
        assert_eq!(
            opt.private_key_path.as_deref(),
            Some("/home/test/.ssh/id_deploy")
        );
        assert_eq!(opt.jump_host.as_deref(), Some("bastion.example.com"));
        assert_eq!(opt.jump_port, 2200);
        assert_eq!(opt.jump_username, None);
    }

    #[test]
    fn explicit_values_win_over_the_config() {
        let mut opt = SessionOptions {
            username: "root".into(),
            port: 2222,
            private_key_path: Some("/keys/mine".into()),
            jump_host: Some("own-bastion".into()),
            jump_port: 2200,
            ..base()
        };
        apply_resolved_params(&resolved(), &mut opt);
        assert_eq!(opt.username, "root");
        assert_eq!(opt.port, 2222);
        assert_eq!(opt.private_key_path.as_deref(), Some("/keys/mine"));
        assert_eq!(opt.jump_host.as_deref(), Some("own-bastion"));
        assert_eq!(opt.jump_port, 2200);
    }

    #[test]
    fn proxy_sessions_do_not_get_a_config_jump_host() {
        let mut opt = SessionOptions {
            proxy_type: ProxyType::Socks5,
            ..base()
        };
        apply_resolved_params(&resolved(), &mut opt);
        // The alias still resolves, but the proxy is never combined with a
        // config jump host (transport exclusivity, like the dialogs).
        assert_eq!(opt.host, "203.0.113.5");
        assert_eq!(opt.jump_host, None);
    }

    #[test]
    fn empty_resolution_is_a_noop() {
        let mut opt = base();
        apply_resolved_params(&ResolvedSshParams::default(), &mut opt);
        assert_eq!(opt.host, "myserver");
        assert_eq!(opt.port, 22);
        assert_eq!(opt.username, "");
        assert_eq!(opt.private_key_path, None);
        assert_eq!(opt.jump_host, None);
    }
}

#[cfg(test)]
mod protocol_index_tests {
    use super::{protocol_from_int, protocol_to_int};
    use freescp_core::Protocol;

    #[test]
    fn dialog_indices_round_trip() {
        let pairs = [
            (0, Protocol::Sftp),
            (1, Protocol::Scp),
            (2, Protocol::Ftp),
            (3, Protocol::Ftps),
            (4, Protocol::WebDav),
            (5, Protocol::Smb),
            (6, Protocol::Telnet),
        ];
        for (index, protocol) in pairs {
            assert_eq!(protocol_from_int(index), protocol, "index {index}");
            assert_eq!(protocol_to_int(protocol), index, "{protocol:?}");
        }
        // Unknown indices fall back to SFTP, mirroring the C++.
        assert_eq!(protocol_from_int(7), Protocol::Sftp);
        assert_eq!(protocol_from_int(-1), Protocol::Sftp);
    }
}

#[cfg(test)]
mod connect_gate_tests {
    use super::{protocol_can_start_connect, same_saved_site_identity};
    use freescp_core::{KnownHostsPolicy, Protocol, SessionOptions};

    #[test]
    fn console_only_telnet_can_start_a_connect() {
        // Regression: the dialog's `supports_file_transfers` guard used to
        // reject Telnet even though `run_any_connect` routes it to the console.
        assert!(protocol_can_start_connect(Protocol::Telnet));
        for protocol in [
            Protocol::Sftp,
            Protocol::Scp,
            Protocol::Ftp,
            Protocol::Ftps,
            Protocol::WebDav,
            Protocol::Smb,
        ] {
            assert!(protocol_can_start_connect(protocol), "{protocol:?}");
        }
    }

    #[test]
    fn smb_domain_participates_in_site_identity() {
        let base = SessionOptions {
            protocol: Protocol::Smb,
            host: "files.example.com".into(),
            ..Default::default()
        };
        let mut other_domain = base.clone();
        other_domain.smb_domain = Some("WORKGROUP".into());
        assert!(!same_saved_site_identity(&base, &other_domain));
        // An empty domain normalizes to "no domain", i.e. the same site.
        other_domain.smb_domain = Some("   ".into());
        assert!(same_saved_site_identity(&base, &other_domain));
    }

    #[test]
    fn telnet_tls_options_participate_in_site_identity() {
        let base = SessionOptions {
            protocol: Protocol::Telnet,
            host: "console.example.com".into(),
            ..Default::default()
        };
        let mut tls = base.clone();
        tls.telnet_tls = true;
        assert!(!same_saved_site_identity(&base, &tls));
        let mut no_verify = base.clone();
        no_verify.telnet_verify_peer = !base.telnet_verify_peer;
        assert!(!same_saved_site_identity(&base, &no_verify));
        let mut auto_login = base.clone();
        auto_login.telnet_auto_login = !base.telnet_auto_login;
        assert!(!same_saved_site_identity(&base, &auto_login));
        let mut ca = base.clone();
        ca.telnet_ca_cert_path = Some("/tmp/ca.pem".into());
        assert!(!same_saved_site_identity(&base, &ca));
        // A whitespace-only path normalizes to "no path", i.e. the same site.
        let mut blank_ca = base.clone();
        blank_ca.telnet_ca_cert_path = Some("   ".into());
        assert!(same_saved_site_identity(&base, &blank_ca));
    }

    #[test]
    fn known_hosts_settings_participate_in_site_identity() {
        let base = SessionOptions {
            protocol: Protocol::Sftp,
            host: "ssh.example.com".into(),
            ..Default::default()
        };
        let mut policy = base.clone();
        policy.known_hosts_policy = KnownHostsPolicy::Off;
        assert!(!same_saved_site_identity(&base, &policy));
        let mut hashing = base.clone();
        hashing.known_hosts_hash_names = !base.known_hosts_hash_names;
        assert!(!same_saved_site_identity(&base, &hashing));
        let mut path = base.clone();
        path.known_hosts_path = Some("/tmp/known_hosts".into());
        assert!(!same_saved_site_identity(&base, &path));
        // Protocols without host keys ignore these fields.
        let mut ftp_a = base.clone();
        ftp_a.protocol = Protocol::Ftp;
        let mut ftp_b = ftp_a.clone();
        ftp_b.known_hosts_policy = KnownHostsPolicy::Off;
        ftp_b.known_hosts_path = Some("/tmp/known_hosts".into());
        assert!(same_saved_site_identity(&ftp_a, &ftp_b));
    }
}
