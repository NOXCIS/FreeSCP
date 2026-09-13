//! Basic types shared between UI and core for SFTP sessions and metadata.
//!
//! Rust port of `core/include/freescp/SftpTypes.hpp`. Keeping these
//! structures simple and serializable makes them easy to use in the UI.

use std::sync::Arc;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// known_hosts validation policy for the server host key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KnownHostsPolicy {
    /// Requires exact match with known_hosts.
    #[default]
    Strict,
    /// TOFU: accept and save new hosts; reject key changes.
    AcceptNew,
    /// No verification (not recommended).
    Off,
}

/// Transfer integrity policy.
///
/// - [`Off`](TransferIntegrityPolicy::Off): no hash verification.
/// - [`Optional`](TransferIntegrityPolicy::Optional): verify when possible;
///   fail on detected mismatch.
/// - [`Required`](TransferIntegrityPolicy::Required): verification is
///   mandatory; fail if verification cannot be completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransferIntegrityPolicy {
    Off,
    #[default]
    Optional,
    Required,
}

/// Optional TCP proxy tunnel type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyType {
    #[default]
    None,
    Socks5,
    HttpConnect,
}

/// Remote access protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    Sftp,
    Scp,
    Ftp,
    Ftps,
    WebDav,
}

/// HTTP transport scheme for WebDAV.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WebDavScheme {
    #[default]
    Https,
    Http,
}

/// How SCP transfers are performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScpTransferMode {
    /// Try native SCP first and fall back to SFTP transfers if needed.
    #[default]
    Auto,
    /// Enforce classic SCP transfers only (no SFTP fallback).
    ScpOnly,
}

/// Result for keyboard-interactive prompt handling.
///
/// - [`Handled`](KbdIntPromptResult::Handled): callback provided answers in
///   `responses`.
/// - [`Unhandled`](KbdIntPromptResult::Unhandled): callback could not answer;
///   backend may use heuristic fallback.
/// - [`Cancelled`](KbdIntPromptResult::Cancelled): user explicitly cancelled;
///   backend must not use fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KbdIntPromptResult {
    Handled,
    Unhandled,
    Cancelled,
}

// ---------------------------------------------------------------------------
// Enum validation / normalization helpers
// ---------------------------------------------------------------------------

/// Returns `true` when `proxy_type` is a defined, valid variant.
pub const fn is_valid_proxy_type(proxy_type: ProxyType) -> bool {
    match proxy_type {
        ProxyType::None | ProxyType::Socks5 | ProxyType::HttpConnect => true,
    }
}

/// Coerces any out-of-range proxy value back to [`ProxyType::None`].
pub const fn normalize_proxy_type(proxy_type: ProxyType) -> ProxyType {
    if is_valid_proxy_type(proxy_type) {
        proxy_type
    } else {
        ProxyType::None
    }
}

/// Returns `true` when `scheme` is a defined, valid variant.
pub const fn is_valid_webdav_scheme(scheme: WebDavScheme) -> bool {
    match scheme {
        WebDavScheme::Https | WebDavScheme::Http => true,
    }
}

/// Coerces any out-of-range scheme value back to [`WebDavScheme::Https`].
pub const fn normalize_webdav_scheme(scheme: WebDavScheme) -> WebDavScheme {
    if is_valid_webdav_scheme(scheme) {
        scheme
    } else {
        WebDavScheme::Https
    }
}

/// Restores a [`ProxyType`] from a persisted integer (storage format).
///
/// Discriminants match the C++ enum order: `0 = None`, `1 = Socks5`,
/// `2 = HttpConnect`. Anything else normalizes to [`ProxyType::None`].
pub fn proxy_type_from_storage_value(raw: i32) -> ProxyType {
    match raw {
        0 => ProxyType::None,
        1 => ProxyType::Socks5,
        2 => ProxyType::HttpConnect,
        _ => ProxyType::None,
    }
}

// ---------------------------------------------------------------------------
// Default ports
// ---------------------------------------------------------------------------

/// Default TCP port for a proxy tunnel (`0` when no proxy is configured).
pub const fn default_port_for_proxy_type(proxy_type: ProxyType) -> u16 {
    match proxy_type {
        ProxyType::Socks5 => 1080,
        ProxyType::HttpConnect => 8080,
        ProxyType::None => 0,
    }
}

/// Default port for the WebDAV HTTP transport scheme.
pub const fn default_port_for_webdav_scheme(scheme: WebDavScheme) -> u16 {
    match normalize_webdav_scheme(scheme) {
        WebDavScheme::Http => 80,
        WebDavScheme::Https => 443,
    }
}

/// Default TCP port for a protocol (SFTP/SCP 22, FTP 21, FTPS 990, WebDAV 443).
pub const fn default_port_for_protocol(protocol: Protocol) -> u16 {
    match protocol {
        Protocol::Sftp | Protocol::Scp => 22,
        Protocol::Ftp => 21,
        Protocol::Ftps => 990,
        Protocol::WebDav => 443,
    }
}

// ---------------------------------------------------------------------------
// Storage-name conversion helpers
// ---------------------------------------------------------------------------

/// Storage name for a WebDAV scheme (`"http"` / `"https"`).
pub const fn webdav_scheme_storage_name(scheme: WebDavScheme) -> &'static str {
    match normalize_webdav_scheme(scheme) {
        WebDavScheme::Http => "http",
        WebDavScheme::Https => "https",
    }
}

/// Parses a WebDAV scheme from a persisted string.
///
/// Case-insensitive; empty or unrecognized values fall back to
/// [`WebDavScheme::Https`], matching the C++ implementation.
pub fn webdav_scheme_from_storage_name(raw: &str) -> WebDavScheme {
    if raw.is_empty() {
        return WebDavScheme::Https;
    }
    if raw.eq_ignore_ascii_case("http") {
        return WebDavScheme::Http;
    }
    WebDavScheme::Https
}

/// Storage name for a protocol (`"sftp"`, `"scp"`, `"ftp"`, `"ftps"`,
/// `"webdav"`).
pub const fn protocol_storage_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Sftp => "sftp",
        Protocol::Scp => "scp",
        Protocol::Ftp => "ftp",
        Protocol::Ftps => "ftps",
        Protocol::WebDav => "webdav",
    }
}

/// Human-readable display name for a protocol (`"SFTP"`, `"SCP"`, ...).
pub const fn protocol_display_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Sftp => "SFTP",
        Protocol::Scp => "SCP",
        Protocol::Ftp => "FTP",
        Protocol::Ftps => "FTPS",
        Protocol::WebDav => "WebDAV",
    }
}

/// Parses a protocol from a persisted string.
///
/// Case-insensitive; empty or unrecognized values fall back to
/// [`Protocol::Sftp`], matching the C++ implementation.
pub fn protocol_from_storage_name(raw: &str) -> Protocol {
    if raw.is_empty() {
        return Protocol::Sftp;
    }
    if raw.eq_ignore_ascii_case("scp") {
        return Protocol::Scp;
    }
    if raw.eq_ignore_ascii_case("ftp") {
        return Protocol::Ftp;
    }
    if raw.eq_ignore_ascii_case("ftps") {
        return Protocol::Ftps;
    }
    if raw.eq_ignore_ascii_case("webdav") {
        return Protocol::WebDav;
    }
    Protocol::Sftp
}

/// Storage name for an SCP transfer mode (`"auto"` / `"scp-only"`).
pub const fn scp_transfer_mode_storage_name(mode: ScpTransferMode) -> &'static str {
    match mode {
        ScpTransferMode::Auto => "auto",
        ScpTransferMode::ScpOnly => "scp-only",
    }
}

/// Parses an SCP transfer mode from a persisted string.
///
/// Case-insensitive; empty or unrecognized values fall back to
/// [`ScpTransferMode::Auto`], matching the C++ implementation.
pub fn scp_transfer_mode_from_storage_name(raw: &str) -> ScpTransferMode {
    if raw.is_empty() {
        return ScpTransferMode::Auto;
    }
    if raw.eq_ignore_ascii_case("scp-only") {
        return ScpTransferMode::ScpOnly;
    }
    ScpTransferMode::Auto
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// Feature matrix describing what a protocol backend can do.
///
/// All five protocols report `implemented = true`: the pure-Rust backends
/// replace the C++ compile-time gates (`FREESCP_HAS_CURL_FTP` /
/// `FREESCP_HAS_CURL_WEBDAV`) and always ship.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtocolCapabilities {
    pub implemented: bool,
    pub supports_listing: bool,
    pub supports_file_transfers: bool,
    pub supports_resume: bool,
    pub supports_metadata: bool,
    pub supports_permissions: bool,
    pub supports_ownership: bool,
    pub supports_timestamps: bool,
    pub supports_proxy: bool,
    pub supports_jump_host: bool,
    pub supports_known_hosts: bool,
    pub supports_transfer_integrity: bool,
}

/// Per-protocol capability matrix.
///
/// Matches the C++ table with both curl feature gates enabled; the
/// pure-Rust backends always ship, so `implemented` is `true` for every
/// protocol.
pub fn capabilities_for_protocol(protocol: Protocol) -> ProtocolCapabilities {
    let mut caps = ProtocolCapabilities::default();
    match protocol {
        Protocol::Sftp => {
            caps.implemented = true;
            caps.supports_listing = true;
            caps.supports_file_transfers = true;
            caps.supports_resume = true;
            caps.supports_metadata = true;
            caps.supports_permissions = true;
            caps.supports_ownership = true;
            caps.supports_timestamps = true;
            caps.supports_proxy = true;
            caps.supports_jump_host = true;
            caps.supports_known_hosts = true;
            caps.supports_transfer_integrity = true;
        }
        Protocol::Scp => {
            caps.implemented = true;
            caps.supports_file_transfers = true;
            caps.supports_proxy = true;
            caps.supports_jump_host = true;
            caps.supports_known_hosts = true;
        }
        // The C++ build gates these behind FREESCP_HAS_CURL_FTP; the
        // pure-Rust backend always ships, so both are always implemented.
        Protocol::Ftp | Protocol::Ftps => {
            caps.implemented = true;
            caps.supports_listing = true;
            caps.supports_file_transfers = true;
            caps.supports_proxy = true;
        }
        // C++ gated by FREESCP_HAS_CURL_WEBDAV; the pure-Rust backend always
        // ships, so WebDAV is always implemented.
        Protocol::WebDav => {
            caps.implemented = true;
            caps.supports_listing = true;
            caps.supports_file_transfers = true;
            caps.supports_metadata = true;
            caps.supports_proxy = true;
        }
    }
    caps
}

/// Metadata for a single remote directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileInfo {
    /// Base name of the entry.
    pub name: String,
    pub is_dir: bool,
    /// Size in bytes (`0` is valid when `has_size == true`).
    pub size: u64,
    /// `true` if the size is known (`ATTR_SIZE` present).
    pub has_size: bool,
    /// Modification time as Unix epoch seconds.
    pub mtime: u64,
    /// POSIX bits (permissions/type).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

// ---------------------------------------------------------------------------
// Callback aliases
// ---------------------------------------------------------------------------

/// Host key confirmation (TOFU) callback invoked when known_hosts lacks an
/// entry.
///
/// Arguments: `host`, `port`, `algorithm`, `fingerprint`, `can_save`.
/// Return `true` to accept (and save when `can_save`) the key, `false` to
/// reject the connection. `can_save` being `false` means the client cannot
/// persist the key and the user must explicitly allow a one-time connection
/// without saving.
pub type HostKeyConfirmCb = Arc<dyn Fn(&str, u16, &str, &str, bool) -> bool + Send + Sync>;

/// Backend status message callback (e.g., persist errors/reasons).
pub type HostKeyStatusCb = Arc<dyn Fn(&str) + Send + Sync>;

/// Callback to answer keyboard-interactive prompts.
///
/// Arguments: `name`, `instruction`, `prompts`, `responses` (answers filled
/// in-place).
pub type KbdIntPromptsCb =
    Arc<dyn Fn(&str, &str, &[String], &mut Vec<String>) -> KbdIntPromptResult + Send + Sync>;

/// All connection/session options for a remote endpoint.
///
/// Defaults match the C++ in-class initializers: `port = 22`,
/// `known_hosts_policy = Strict`, `known_hosts_hash_names = true`,
/// `transfer_integrity_policy = Optional`, `ftps_verify_peer = true`,
/// `webdav_scheme = Https`, `webdav_verify_peer = true`, `jump_port = 22`,
/// `scp_transfer_mode = Auto`.
#[derive(Clone)]
pub struct SessionOptions {
    pub protocol: Protocol,
    pub scp_transfer_mode: ScpTransferMode,
    pub host: String,
    pub port: u16,
    pub username: String,

    pub password: Option<String>,
    pub private_key_path: Option<String>,
    pub private_key_passphrase: Option<String>,

    /// SSH security. Default path: `~/.ssh/known_hosts`.
    pub known_hosts_path: Option<String>,
    pub known_hosts_policy: KnownHostsPolicy,
    /// Whether to hash hostnames when saving to known_hosts (OpenSSH hashed
    /// hosts).
    pub known_hosts_hash_names: bool,
    /// Visual preference: show fingerprint in HEX colon format (UI only).
    pub show_fp_hex: bool,
    /// Transfer integrity checks for resume and final content verification.
    pub transfer_integrity_policy: TransferIntegrityPolicy,

    /// FTPS security.
    pub ftps_verify_peer: bool,
    pub ftps_ca_cert_path: Option<String>,

    /// WebDAV HTTP/TLS transport settings.
    pub webdav_scheme: WebDavScheme,
    pub webdav_verify_peer: bool,
    pub webdav_ca_cert_path: Option<String>,

    /// Optional TCP proxy tunnel for the transport.
    pub proxy_type: ProxyType,
    pub proxy_host: String,
    pub proxy_port: u16,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,

    /// Optional SSH jump host (bastion) tunnel.
    pub jump_host: Option<String>,
    pub jump_port: u16,
    pub jump_username: Option<String>,
    pub jump_private_key_path: Option<String>,

    /// Host key confirmation (TOFU) when known_hosts lacks an entry.
    pub hostkey_confirm_cb: Option<HostKeyConfirmCb>,
    /// Backend status messages (e.g., persist errors/reasons).
    pub hostkey_status_cb: Option<HostKeyStatusCb>,
    /// Custom handling for keyboard-interactive (e.g., OTP/2FA).
    pub keyboard_interactive_cb: Option<KbdIntPromptsCb>,
}

impl Default for SessionOptions {
    fn default() -> Self {
        SessionOptions {
            protocol: Protocol::Sftp,
            scp_transfer_mode: ScpTransferMode::Auto,
            host: String::new(),
            port: default_port_for_protocol(Protocol::Sftp),
            username: String::new(),
            password: None,
            private_key_path: None,
            private_key_passphrase: None,
            known_hosts_path: None,
            known_hosts_policy: KnownHostsPolicy::Strict,
            known_hosts_hash_names: true,
            show_fp_hex: false,
            transfer_integrity_policy: TransferIntegrityPolicy::Optional,
            ftps_verify_peer: true,
            ftps_ca_cert_path: None,
            webdav_scheme: WebDavScheme::Https,
            webdav_verify_peer: true,
            webdav_ca_cert_path: None,
            proxy_type: ProxyType::None,
            proxy_host: String::new(),
            proxy_port: 0,
            proxy_username: None,
            proxy_password: None,
            jump_host: None,
            jump_port: 22,
            jump_username: None,
            jump_private_key_path: None,
            hostkey_confirm_cb: None,
            hostkey_status_cb: None,
            keyboard_interactive_cb: None,
        }
    }
}

// `Arc<dyn Fn>` does not implement `Debug`, so the derive would not compile;
// format the callback slots as presence markers instead.
impl std::fmt::Debug for SessionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionOptions")
            .field("protocol", &self.protocol)
            .field("scp_transfer_mode", &self.scp_transfer_mode)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password)
            .field("private_key_path", &self.private_key_path)
            .field("private_key_passphrase", &self.private_key_passphrase)
            .field("known_hosts_path", &self.known_hosts_path)
            .field("known_hosts_policy", &self.known_hosts_policy)
            .field("known_hosts_hash_names", &self.known_hosts_hash_names)
            .field("show_fp_hex", &self.show_fp_hex)
            .field("transfer_integrity_policy", &self.transfer_integrity_policy)
            .field("ftps_verify_peer", &self.ftps_verify_peer)
            .field("ftps_ca_cert_path", &self.ftps_ca_cert_path)
            .field("webdav_scheme", &self.webdav_scheme)
            .field("webdav_verify_peer", &self.webdav_verify_peer)
            .field("webdav_ca_cert_path", &self.webdav_ca_cert_path)
            .field("proxy_type", &self.proxy_type)
            .field("proxy_host", &self.proxy_host)
            .field("proxy_port", &self.proxy_port)
            .field("proxy_username", &self.proxy_username)
            .field("proxy_password", &self.proxy_password)
            .field("jump_host", &self.jump_host)
            .field("jump_port", &self.jump_port)
            .field("jump_username", &self.jump_username)
            .field("jump_private_key_path", &self.jump_private_key_path)
            .field(
                "hostkey_confirm_cb",
                &self
                    .hostkey_confirm_cb
                    .as_ref()
                    .map(|_| "<HostKeyConfirmCb>"),
            )
            .field(
                "hostkey_status_cb",
                &self.hostkey_status_cb.as_ref().map(|_| "<HostKeyStatusCb>"),
            )
            .field(
                "keyboard_interactive_cb",
                &self
                    .keyboard_interactive_cb
                    .as_ref()
                    .map(|_| "<KbdIntPromptsCb>"),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_options_defaults_match_cpp() {
        let opts = SessionOptions::default();
        assert_eq!(opts.protocol, Protocol::Sftp);
        assert_eq!(opts.scp_transfer_mode, ScpTransferMode::Auto);
        assert_eq!(opts.port, 22);
        assert_eq!(opts.known_hosts_policy, KnownHostsPolicy::Strict);
        assert!(opts.known_hosts_hash_names);
        assert!(!opts.show_fp_hex);
        assert_eq!(
            opts.transfer_integrity_policy,
            TransferIntegrityPolicy::Optional
        );
        assert!(opts.ftps_verify_peer);
        assert_eq!(opts.webdav_scheme, WebDavScheme::Https);
        assert!(opts.webdav_verify_peer);
        assert_eq!(opts.proxy_type, ProxyType::None);
        assert_eq!(opts.proxy_port, 0);
        assert_eq!(opts.jump_port, 22);
        assert!(opts.password.is_none());
        assert!(opts.hostkey_confirm_cb.is_none());
    }

    #[test]
    fn default_ports_match_cpp() {
        assert_eq!(default_port_for_protocol(Protocol::Sftp), 22);
        assert_eq!(default_port_for_protocol(Protocol::Scp), 22);
        assert_eq!(default_port_for_protocol(Protocol::Ftp), 21);
        assert_eq!(default_port_for_protocol(Protocol::Ftps), 990);
        assert_eq!(default_port_for_protocol(Protocol::WebDav), 443);
        assert_eq!(default_port_for_proxy_type(ProxyType::None), 0);
        assert_eq!(default_port_for_proxy_type(ProxyType::Socks5), 1080);
        assert_eq!(default_port_for_proxy_type(ProxyType::HttpConnect), 8080);
        assert_eq!(default_port_for_webdav_scheme(WebDavScheme::Http), 80);
        assert_eq!(default_port_for_webdav_scheme(WebDavScheme::Https), 443);
    }

    #[test]
    fn storage_name_round_trips() {
        for proto in [
            Protocol::Sftp,
            Protocol::Scp,
            Protocol::Ftp,
            Protocol::Ftps,
            Protocol::WebDav,
        ] {
            assert_eq!(
                protocol_from_storage_name(protocol_storage_name(proto)),
                proto
            );
        }
        assert_eq!(protocol_from_storage_name(""), Protocol::Sftp);
        assert_eq!(protocol_from_storage_name("SFTP"), Protocol::Sftp);
        assert_eq!(protocol_from_storage_name("WebDav"), Protocol::WebDav);
        assert_eq!(protocol_from_storage_name("bogus"), Protocol::Sftp);
        assert_eq!(protocol_display_name(Protocol::WebDav), "WebDAV");

        assert_eq!(webdav_scheme_from_storage_name("http"), WebDavScheme::Http);
        assert_eq!(
            webdav_scheme_from_storage_name("HTTPS"),
            WebDavScheme::Https
        );
        assert_eq!(webdav_scheme_from_storage_name(""), WebDavScheme::Https);
        assert_eq!(
            webdav_scheme_from_storage_name("bogus"),
            WebDavScheme::Https
        );
        assert_eq!(webdav_scheme_storage_name(WebDavScheme::Http), "http");

        assert_eq!(
            scp_transfer_mode_from_storage_name("scp-only"),
            ScpTransferMode::ScpOnly
        );
        assert_eq!(
            scp_transfer_mode_from_storage_name("SCP-ONLY"),
            ScpTransferMode::ScpOnly
        );
        assert_eq!(
            scp_transfer_mode_from_storage_name("auto"),
            ScpTransferMode::Auto
        );
        assert_eq!(
            scp_transfer_mode_from_storage_name(""),
            ScpTransferMode::Auto
        );
        assert_eq!(
            scp_transfer_mode_storage_name(ScpTransferMode::ScpOnly),
            "scp-only"
        );
    }

    #[test]
    fn proxy_storage_values() {
        assert_eq!(proxy_type_from_storage_value(0), ProxyType::None);
        assert_eq!(proxy_type_from_storage_value(1), ProxyType::Socks5);
        assert_eq!(proxy_type_from_storage_value(2), ProxyType::HttpConnect);
        assert_eq!(proxy_type_from_storage_value(-1), ProxyType::None);
        assert_eq!(proxy_type_from_storage_value(99), ProxyType::None);
        assert_eq!(normalize_proxy_type(ProxyType::Socks5), ProxyType::Socks5);
    }

    #[test]
    fn capabilities_always_implemented() {
        for proto in [
            Protocol::Sftp,
            Protocol::Scp,
            Protocol::Ftp,
            Protocol::Ftps,
            Protocol::WebDav,
        ] {
            assert!(
                capabilities_for_protocol(proto).implemented,
                "{proto:?} must report implemented=true"
            );
        }
        let sftp = capabilities_for_protocol(Protocol::Sftp);
        assert!(sftp.supports_listing);
        assert!(sftp.supports_resume);
        assert!(sftp.supports_permissions);
        assert!(sftp.supports_ownership);
        assert!(sftp.supports_timestamps);
        assert!(sftp.supports_jump_host);
        assert!(sftp.supports_known_hosts);
        assert!(sftp.supports_transfer_integrity);
        let scp = capabilities_for_protocol(Protocol::Scp);
        assert!(!scp.supports_listing);
        assert!(scp.supports_file_transfers);
        let ftp = capabilities_for_protocol(Protocol::Ftp);
        assert!(ftp.supports_listing);
        assert!(!ftp.supports_known_hosts);
        let webdav = capabilities_for_protocol(Protocol::WebDav);
        assert!(webdav.supports_metadata);
        assert!(!webdav.supports_resume);
    }

    #[test]
    fn callbacks_are_callable_through_arc() {
        let opts = SessionOptions {
            hostkey_confirm_cb: Some(Arc::new(
                |host: &str, port: u16, _algo: &str, _fp: &str, can_save: bool| {
                    host == "example.com" && port == 22 && can_save
                },
            )),
            keyboard_interactive_cb: Some(Arc::new(
                |_name: &str, _instr: &str, prompts: &[String], responses: &mut Vec<String>| {
                    if prompts.len() == 1 {
                        responses.push("answer".to_string());
                        KbdIntPromptResult::Handled
                    } else {
                        KbdIntPromptResult::Unhandled
                    }
                },
            )),
            ..SessionOptions::default()
        };
        let confirm = opts.hostkey_confirm_cb.as_ref().unwrap();
        assert!(confirm("example.com", 22, "ssh-ed25519", "fp", true));
        assert!(!confirm("other", 22, "ssh-ed25519", "fp", false));
        let kbd = opts.keyboard_interactive_cb.as_ref().unwrap();
        let mut responses = Vec::new();
        assert_eq!(
            kbd("n", "i", &["otp?".to_string()], &mut responses),
            KbdIntPromptResult::Handled
        );
        assert_eq!(responses, vec!["answer".to_string()]);
        let _ = format!("{opts:?}");
    }
}
