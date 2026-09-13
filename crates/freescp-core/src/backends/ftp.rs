//! FTP/FTPS backend — pure-Rust port of `core/src/curl/CurlFtpClient.cpp`
//! onto [suppaftp] (sync, bridged to async via `tokio::task::spawn_blocking`).
//!
//! # C++ → Rust feature mapping
//!
//! | libcurl option / C++ behavior                | suppaftp / this module                       |
//! |----------------------------------------------|----------------------------------------------|
//! | `CURLOPT_CONNECTTIMEOUT` (15s)               | `TcpStream::connect_timeout(.., 15s)`        |
//! | `CURLOPT_FTP_RESPONSE_TIMEOUT` (30s)         | control-channel `set_read_timeout(30s)`      |
//! | `CURLOPT_USE_SSL = CURLUSESSL_ALL` (FTPS)    | `into_secure(...)` → AUTH TLS + PBSZ/PROT P  |
//! | `CURLOPT_FTPSSLAUTH = CURLFTPAUTH_TLS`       | implicit in `into_secure` (AUTH TLS)         |
//! | `CURLOPT_SSL_VERIFYPEER/VERIFYHOST = 0`      | rustls custom `ServerCertVerifier` that      |
//! | (i.e. `ftps_verify_peer == false`)           | accepts every cert AND skips hostname checks |
//! | `CURLOPT_CAINFO` (`ftps_ca_cert_path`)       | `RootCertStore` filled from the given PEM    |
//! |                                              | bundle (`CertificateDer::pem_file_iter`)     |
//! | default system CA store                      | first readable candidate from a list of      |
//! |                                              | well-known system CA bundle paths            |
//! | `CURLOPT_PROXY` + `CURLPROXY_SOCKS5_HOSTNAME`| control channel via `connect_with_stream`,   |
//! | `CURLOPT_PROXY` + `CURLPROXY_HTTP` +         | data channels via `passive_stream_builder`;  |
//! | `CURLOPT_HTTPPROXYTUNNEL`                    | both dial through a hand-rolled sync SOCKS5  |
//! |                                              | or HTTP-CONNECT tunnel (FTP data connections |
//! |                                              | are dialed per `PASV`/`EPSV` reply)          |
//! | `CURLOPT_CUSTOMREQUEST MLSD` → `LIST`        | `mlsd(..)` with fallback to `list(..)`       |
//! | `CURLOPT_DIRLISTONLY=1` connect probe        | `nlst(Some("/"))` probe in `connect`         |
//! | `CURLOPT_XFERINFOFUNCTION` progress          | per-chunk progress callback calls            |
//! | `CURLOPT_UPLOAD` + `CURLOPT_INFILESIZE_LARGE`| `put_with_stream` + `finalize_put_stream`    |
//! | `CURLOPT_FTP_CREATE_MISSING_DIRS` (RETRY)    | on STOR 550: create parent dirs, retry once  |
//! | `CURLOPT_RESUME_FROM` (not used by C++)      | implemented: REST for downloads and          |
//! |                                              | REST+STOR for uploads (see deviations)       |
//!
//! # TLS flag mapping (rustls)
//!
//! suppaftp uses **rustls** here (workspace enables the `rustls` feature).
//! * `ftps_verify_peer == true`  → `ClientConfig` built with
//!   `with_root_certificates(root_store)`: server certificate is validated
//!   against the CA bundle (`ftps_ca_cert_path` if set, otherwise the first
//!   loadable system bundle) AND the hostname is validated against the cert
//!   (equivalent to libcurl `CURLOPT_SSL_VERIFYPEER=1, CURLOPT_SSL_VERIFYHOST=2`).
//! * `ftps_verify_peer == false` → custom `ServerCertVerifier` that accepts
//!   every certificate and performs no hostname validation (equivalent to
//!   `CURLOPT_SSL_VERIFYPEER=0, CURLOPT_SSL_VERIFYHOST=0`).
//!
//! # Explicit vs implicit FTPS
//!
//! Mirrors the C++ decision: `Protocol::Ftps` on the default FTPS port (990)
//! selects *implicit* FTPS, any other port selects *explicit* FTPS (AUTH TLS).
//!
//! // MISSING-DEP: suppaftp `deprecated` feature — implicit FTPS needs
//! // `ImplFtpStream::connect_secure_implicit`, which is gated behind
//! // `#[cfg(all(feature = "secure", feature = "deprecated"))]`. The workspace
//! // declares `suppaftp = { version = "6", features = ["rustls"] }` only.
//! // Until `"deprecated"` is added, implicit FTPS connections return
//! // `ClientError::Unsupported` with an explanatory message (see `connect`).
//!
//! # Deviations from the C++ implementation
//!
//! * The C++ file rejects `resume`; this port implements it via
//!   `resume_transfer` (REST) for downloads and REST+STOR for uploads.
//! * The C++ file returns "not supported" for `exists`/`stat`/`mkdir`/
//!   `removeFile`/`removeDir`/`rename`/`chmod`/`setTimes`; this port
//!   implements them via MLST/SIZE/MDTM + listing lookup, `mkdir`/`rm`/`rmdir`,
//!   RNFR/RNTO, `SITE CHMOD` and `MFMT` (all best-effort). `chown` stays
//!   unsupported (no FTP mechanism exists).
//! * `connect` adopts any FTP-family protocol from `SessionOptions` instead of
//!   hard-failing on a protocol mismatch, so factories only need `FtpClient::new()`.
//! * `interrupt` aborts the data connection (`ABOR`) between 64 KiB chunks;
//!   a fully stalled server can delay it indefinitely (blocking suppaftp).
//! * C++ `LIST` parsing (unix + DOS) is preserved as fallback behind
//!   suppaftp's `list::File` parsers; LIST entries also expose `mtime`,
//!   `uid`/`gid` when suppaftp parses them (C++ left them zero).
//! * Like the C++ backend, every operation opens a fresh control connection
//!   (libcurl created a new easy handle per operation) and `is_connected()`
//!   only reflects the state of the last successful connect probe.

use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use suppaftp::list::{File as SuppaftpFile, PosixPexQuery};
use suppaftp::types::{FileType, Response};
use suppaftp::{FtpError, FtpResult, FtpStream, Mode, RustlsConnector, RustlsFtpStream, Status};
use tracing::{debug, info, warn};

use crate::client::{CancelCb, ClientError, ProgressCb, SftpClient};
use crate::types::{FileInfo, Protocol, ProxyType, SessionOptions};

/// Mirrors libcurl `CURLOPT_CONNECTTIMEOUT` (seconds).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Mirrors libcurl `CURLOPT_FTP_RESPONSE_TIMEOUT` (seconds).
const CONTROL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout for SOCKS5 / HTTP-CONNECT proxy handshakes.
const PROXY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Transfer chunk size used for progress and cancellation checks.
const TRANSFER_CHUNK: usize = 64 * 1024;
/// Safety cap for recursive `remove_dir` depth.
const MAX_REMOVE_DEPTH: usize = 128;

/// Well-known system CA bundle locations (equivalent to libcurl's default
/// CAINFO discovery). The first readable bundle is used when
/// `ftps_ca_cert_path` is not set.
const SYSTEM_CA_BUNDLE_CANDIDATES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL alt
    "/etc/ssl/ca-bundle.pem",             // SUSE
    "/etc/ssl/cert.pem",                  // macOS / FreeBSD
    "/usr/local/etc/openssl/cert.pem",    // Homebrew OpenSSL (macOS)
    "/usr/local/share/certs/ca-root-nss.crt", // FreeBSD
];

/// Proxy flavor after normalizing `crate::types::ProxyType` (an own copy type
/// so this module does not depend on derives of sibling types).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyKind {
    Socks5,
    HttpConnect,
}

/// Everything needed to (re)open an FTP control connection for an operation.
/// Mirrors the C++ practice of keeping `SessionOptions` in the client and
/// building a fresh libcurl handle per operation.
#[derive(Clone)]
struct FtpSessionConfig {
    protocol: Protocol,
    host: String,
    port: u16,
    /// Resolved from `SessionOptions.username` (anonymous fallback).
    username: String,
    /// Resolved from `SessionOptions.password` (anonymous fallback).
    password: String,
    ftps_verify_peer: bool,
    ftps_ca_cert_path: Option<String>,
    proxy: Option<ProxyDialer>,
}

/// Synchronous proxy dialer for control and data connections.
#[derive(Clone)]
struct ProxyDialer {
    kind: ProxyKind,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl ProxyDialer {
    /// Connect a TCP stream to `target` through the proxy.
    fn dial(&self, target: SocketAddr) -> std::io::Result<TcpStream> {
        let proxy_addr = resolve_first(&self.host, self.port)?;
        let mut stream = TcpStream::connect_timeout(&proxy_addr, CONNECT_TIMEOUT)?;
        stream.set_read_timeout(Some(PROXY_HANDSHAKE_TIMEOUT))?;
        stream.set_write_timeout(Some(PROXY_HANDSHAKE_TIMEOUT))?;
        match self.kind {
            ProxyKind::Socks5 => {
                socks5_connect(&mut stream, target, &self.username, &self.password)?
            }
            ProxyKind::HttpConnect => {
                http_connect(&mut stream, target, &self.username, &self.password)?
            }
        }
        // The caller resets timeouts: 30s read for the control channel,
        // blocking reads for data channels.
        Ok(stream)
    }
}

/// Client state guarded by a mutex (mirrors `CurlFtpClient::stateMutex_`).
struct ClientState {
    connected: bool,
    options: Option<FtpSessionConfig>,
}

/// FTP/FTPS client implementing [`SftpClient`].
pub struct FtpClient {
    protocol: Protocol,
    state: Mutex<ClientState>,
    interrupted: Arc<AtomicBool>,
}

impl Default for FtpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl FtpClient {
    /// Creates a plain FTP client (mirrors `CurlFtpClient()`).
    pub fn new() -> Self {
        Self::with_protocol(Protocol::Ftp)
    }

    /// Creates a client for the given protocol (mirrors
    /// `CurlFtpClient(Protocol)`); non-FTP protocols fall back to FTP.
    pub fn with_protocol(protocol: Protocol) -> Self {
        let protocol = if matches!(&protocol, Protocol::Ftp | Protocol::Ftps) {
            protocol
        } else {
            Protocol::Ftp
        };
        Self {
            protocol,
            state: Mutex::new(ClientState {
                connected: false,
                options: None,
            }),
            interrupted: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns the stored session config, or "Not connected." (mirrors C++).
    fn require_config(&self) -> Result<FtpSessionConfig, ClientError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ClientError::Other("FTP state lock poisoned".into()))?;
        if !state.connected {
            return Err(ClientError::Other("Not connected.".into()));
        }
        state
            .options
            .clone()
            .ok_or_else(|| ClientError::Other("Not connected.".into()))
    }
}

fn protocol_label(protocol: &Protocol) -> &'static str {
    if matches!(protocol, Protocol::Ftps) {
        "FTPS"
    } else {
        "FTP"
    }
}

fn default_port(protocol: &Protocol) -> u16 {
    if matches!(protocol, Protocol::Ftps) {
        990
    } else {
        21
    }
}

fn is_ftp_family(protocol: &Protocol) -> bool {
    matches!(protocol, Protocol::Ftp | Protocol::Ftps)
}

/// Mirrors the C++ decision: FTPS on the default FTPS port is implicit.
fn use_implicit_ftps(protocol: &Protocol, port: u16) -> bool {
    matches!(protocol, Protocol::Ftps) && port == default_port(&Protocol::Ftps)
}

fn unsupported(what: &str) -> ClientError {
    ClientError::Unsupported(format!("FTP/FTPS backend does not support {what}."))
}

/// Mirrors `CurlFtpClient::connect` normalization of credentials: anonymous
/// users get the conventional `anonymous@freescp.local` password.
fn config_from_options(
    protocol: Protocol,
    opt: &SessionOptions,
) -> Result<FtpSessionConfig, ClientError> {
    if opt.host.is_empty() {
        return Err(ClientError::Other("Host is required.".into()));
    }
    let port = if opt.port == 0 {
        default_port(&protocol)
    } else {
        opt.port
    };
    let username = if opt.username.is_empty() {
        "anonymous".to_string()
    } else {
        opt.username.clone()
    };
    let password = if opt.username.is_empty() && opt.password.as_deref().unwrap_or("").is_empty() {
        "anonymous@freescp.local".to_string()
    } else {
        opt.password.clone().unwrap_or_default()
    };
    let proxy = match &opt.proxy_type {
        ProxyType::None => None,
        ProxyType::Socks5 | ProxyType::HttpConnect => {
            if opt.proxy_host.is_empty() || opt.proxy_port == 0 {
                return Err(ClientError::Other(
                    "FTP proxy requires host and port.".into(),
                ));
            }
            Some(ProxyDialer {
                kind: if matches!(&opt.proxy_type, ProxyType::Socks5) {
                    ProxyKind::Socks5
                } else {
                    ProxyKind::HttpConnect
                },
                host: opt.proxy_host.clone(),
                port: opt.proxy_port,
                username: opt.proxy_username.clone(),
                password: opt.proxy_password.clone(),
            })
        }
    };
    Ok(FtpSessionConfig {
        protocol,
        host: opt.host.clone(),
        port,
        username,
        password,
        ftps_verify_peer: opt.ftps_verify_peer,
        ftps_ca_cert_path: opt.ftps_ca_cert_path.clone(),
        proxy,
    })
}

fn resolve_first(host: &str, port: u16) -> std::io::Result<SocketAddr> {
    let mut addrs = (host, port).to_socket_addrs()?;
    addrs.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no address for '{host}'"),
        )
    })
}

fn map_ftp_error(e: FtpError) -> ClientError {
    match e {
        FtpError::ConnectionError(io) => ClientError::Io(io),
        FtpError::SecureError(msg) => ClientError::Other(format!("Secure error: {msg}")),
        FtpError::UnexpectedResponse(resp) => {
            if resp.status == Status::NotLoggedIn || resp.status == Status::InvalidCredentials {
                ClientError::AuthFailed(resp.to_string())
            } else {
                ClientError::OperationFailed(resp.to_string())
            }
        }
        FtpError::BadResponse => {
            ClientError::OperationFailed("Response contains an invalid syntax".into())
        }
        FtpError::InvalidAddress(e) => {
            ClientError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy dialing (sync SOCKS5 / HTTP-CONNECT)
// ---------------------------------------------------------------------------

fn socks5_connect(
    stream: &mut TcpStream,
    target: SocketAddr,
    username: &Option<String>,
    password: &Option<String>,
) -> std::io::Result<()> {
    // Greeting: offer no-auth and, when credentials exist, user/pass auth.
    let methods: &[u8] = if username.is_some() || password.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting)?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS5 proxy replied with an invalid version",
        ));
    }
    match reply[1] {
        0x00 => {}
        0x02 => {
            let user = username.as_deref().unwrap_or("");
            let pass = password.as_deref().unwrap_or("");
            if user.len() > 255 || pass.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "SOCKS5 proxy credentials too long",
                ));
            }
            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.push(0x01);
            auth.push(user.len() as u8);
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth)?;
            let mut auth_reply = [0u8; 2];
            stream.read_exact(&mut auth_reply)?;
            if auth_reply[1] != 0x00 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "SOCKS5 proxy authentication failed",
                ));
            }
        }
        0xFF => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "SOCKS5 proxy: no acceptable authentication method",
            ));
        }
        method => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("SOCKS5 proxy selected unsupported auth method {method}"),
            ));
        }
    }
    // CONNECT request. Data connections only know the IP the server reported
    // in PASV/EPSV, so the address is sent by IP family (SOCKS5_HOSTNAME
    // semantics from the proxy's point of view: the proxy does the routing).
    let mut request = Vec::with_capacity(22);
    request.push(0x05);
    request.push(0x01);
    request.push(0x00);
    match target {
        SocketAddr::V4(v4) => {
            request.push(0x01);
            request.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            request.push(0x04);
            request.extend_from_slice(&v6.ip().octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT rejected with code {}", head[1]),
        ));
    }
    // Consume the variable-length bound address.
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            len[0] as usize + 2
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("SOCKS5 replied with unknown address type {other}"),
            ));
        }
    };
    let mut junk = vec![0u8; skip];
    stream.read_exact(&mut junk)?;
    Ok(())
}

fn http_connect(
    stream: &mut TcpStream,
    target: SocketAddr,
    username: &Option<String>,
    password: &Option<String>,
) -> std::io::Result<()> {
    let host_port = format!("{}:{}", target.ip(), target.port());
    let mut request = format!("CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n");
    if username.is_some() || password.is_some() {
        use base64::Engine;
        let creds = format!(
            "{}:{}",
            username.as_deref().unwrap_or(""),
            password.as_deref().unwrap_or("")
        );
        request.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64::engine::general_purpose::STANDARD.encode(creds.as_bytes())
        ));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;
    // Read the status line byte-by-byte so no bytes past the header (e.g. the
    // FTP greeting) are consumed from the underlying stream.
    let mut header: Vec<u8> = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte)?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
        if header.len() > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP CONNECT proxy response too large",
            ));
        }
    }
    let text = String::from_utf8_lossy(&header);
    let status_line = text.lines().next().unwrap_or("");
    if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("HTTP CONNECT proxy rejected: {status_line}"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// FTPS (rustls) configuration
// ---------------------------------------------------------------------------

/// Accepts every server certificate and skips hostname verification.
/// Equivalent to libcurl `CURLOPT_SSL_VERIFYPEER=0` + `CURLOPT_SSL_VERIFYHOST=0`
/// when the user disables peer verification.
#[derive(Debug)]
struct NoCertificateVerifier;

impl suppaftp::rustls::client::danger::ServerCertVerifier for NoCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &suppaftp::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[suppaftp::rustls::pki_types::CertificateDer<'_>],
        _server_name: &suppaftp::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: suppaftp::rustls::pki_types::UnixTime,
    ) -> Result<suppaftp::rustls::client::danger::ServerCertVerified, suppaftp::rustls::Error> {
        Ok(suppaftp::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &suppaftp::rustls::pki_types::CertificateDer<'_>,
        _dss: &suppaftp::rustls::DigitallySignedStruct,
    ) -> Result<suppaftp::rustls::client::danger::HandshakeSignatureValid, suppaftp::rustls::Error>
    {
        Ok(suppaftp::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &suppaftp::rustls::pki_types::CertificateDer<'_>,
        _dss: &suppaftp::rustls::DigitallySignedStruct,
    ) -> Result<suppaftp::rustls::client::danger::HandshakeSignatureValid, suppaftp::rustls::Error>
    {
        Ok(suppaftp::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<suppaftp::rustls::SignatureScheme> {
        use suppaftp::rustls::SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ED25519,
            ED448,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
        ]
    }
}

/// Loads PEM certificates from a bundle file into the root store, tolerating
/// unparsable entries (libcurl behaves the same). Returns the cert count.
fn load_ca_bundle_into(
    roots: &mut suppaftp::rustls::RootCertStore,
    path: &Path,
) -> std::io::Result<usize> {
    use suppaftp::rustls::pki_types::pem::PemObject;
    let mut count = 0usize;
    for cert in suppaftp::rustls::pki_types::CertificateDer::pem_file_iter(path)
        .map_err(|e| std::io::Error::other(e.to_string()))?
    {
        match cert {
            Ok(der) => match roots.add(der) {
                Ok(()) => count += 1,
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "skipping invalid CA certificate")
                }
            },
            Err(e) => warn!(path = %path.display(), error = %e, "skipping unparsable CA entry"),
        }
    }
    Ok(count)
}

fn build_tls_config(
    cfg: &FtpSessionConfig,
) -> Result<Arc<suppaftp::rustls::ClientConfig>, ClientError> {
    use suppaftp::rustls;
    let provider = rustls::crypto::ring::default_provider();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError::Other(format!("could not build TLS config: {e}")))?;
    if !cfg.ftps_verify_peer {
        // Mirror CURLOPT_SSL_VERIFYPEER=0 + CURLOPT_SSL_VERIFYHOST=0.
        let dangerous = builder.dangerous();
        let config = dangerous
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerifier))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca_path) = cfg.ftps_ca_cert_path.as_deref() {
        // Mirror CURLOPT_CAINFO.
        let count = load_ca_bundle_into(&mut roots, Path::new(ca_path)).map_err(|e| {
            ClientError::Io(std::io::Error::new(
                e.kind(),
                format!("Could not read FTPS CA certificate bundle '{ca_path}': {e}"),
            ))
        })?;
        if count == 0 {
            return Err(ClientError::Other(format!(
                "FTPS CA certificate bundle '{ca_path}' contains no usable certificates"
            )));
        }
    } else {
        let mut loaded = false;
        for candidate in SYSTEM_CA_BUNDLE_CANDIDATES {
            match load_ca_bundle_into(&mut roots, Path::new(candidate)) {
                Ok(n) if n > 0 => {
                    loaded = true;
                    debug!(bundle = candidate, certs = n, "loaded system CA bundle");
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }
        if !loaded {
            return Err(ClientError::Other(
                "FTPS certificate verification is enabled but no system CA certificates could be found".into(),
            ));
        }
    }
    let config = builder.with_root_certificates(roots).with_no_client_auth();
    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// Connection management
// ---------------------------------------------------------------------------

/// A live FTP control connection, either plain or TLS-upgraded.
/// Concrete `DataStream<T>` types cannot be named outside suppaftp (the
/// `TlsStream` bound is private), so transfer code is duplicated per arm via
/// macros; simple commands are forwarded through this enum.
enum FtpConnection {
    Plain(FtpStream),
    Tls(RustlsFtpStream),
}

impl FtpConnection {
    fn login(&mut self, user: &str, password: &str) -> FtpResult<()> {
        match self {
            FtpConnection::Plain(c) => c.login(user, password),
            FtpConnection::Tls(c) => c.login(user, password),
        }
    }

    fn set_mode(&mut self, mode: Mode) {
        match self {
            FtpConnection::Plain(c) => c.set_mode(mode),
            FtpConnection::Tls(c) => c.set_mode(mode),
        }
    }

    fn transfer_type(&mut self, file_type: FileType) -> FtpResult<()> {
        match self {
            FtpConnection::Plain(c) => c.transfer_type(file_type),
            FtpConnection::Tls(c) => c.transfer_type(file_type),
        }
    }

    fn nlst(&mut self, pathname: Option<&str>) -> FtpResult<Vec<String>> {
        match self {
            FtpConnection::Plain(c) => c.nlst(pathname),
            FtpConnection::Tls(c) => c.nlst(pathname),
        }
    }

    fn list(&mut self, pathname: Option<&str>) -> FtpResult<Vec<String>> {
        match self {
            FtpConnection::Plain(c) => c.list(pathname),
            FtpConnection::Tls(c) => c.list(pathname),
        }
    }

    fn mlsd(&mut self, pathname: Option<&str>) -> FtpResult<Vec<String>> {
        match self {
            FtpConnection::Plain(c) => c.mlsd(pathname),
            FtpConnection::Tls(c) => c.mlsd(pathname),
        }
    }

    fn mlst(&mut self, pathname: Option<&str>) -> FtpResult<String> {
        match self {
            FtpConnection::Plain(c) => c.mlst(pathname),
            FtpConnection::Tls(c) => c.mlst(pathname),
        }
    }

    fn mdtm(&mut self, pathname: &str) -> FtpResult<chrono::NaiveDateTime> {
        match self {
            FtpConnection::Plain(c) => c.mdtm(pathname),
            FtpConnection::Tls(c) => c.mdtm(pathname),
        }
    }

    fn size(&mut self, pathname: &str) -> FtpResult<usize> {
        match self {
            FtpConnection::Plain(c) => c.size(pathname),
            FtpConnection::Tls(c) => c.size(pathname),
        }
    }

    fn site(&mut self, command: &str) -> FtpResult<Response> {
        match self {
            FtpConnection::Plain(c) => c.site(command),
            FtpConnection::Tls(c) => c.site(command),
        }
    }

    fn custom_command(&mut self, command: &str, expected_code: &[Status]) -> FtpResult<Response> {
        match self {
            FtpConnection::Plain(c) => c.custom_command(command, expected_code),
            FtpConnection::Tls(c) => c.custom_command(command, expected_code),
        }
    }

    fn mkdir(&mut self, pathname: &str) -> FtpResult<()> {
        match self {
            FtpConnection::Plain(c) => c.mkdir(pathname),
            FtpConnection::Tls(c) => c.mkdir(pathname),
        }
    }

    fn rm(&mut self, pathname: &str) -> FtpResult<()> {
        match self {
            FtpConnection::Plain(c) => c.rm(pathname),
            FtpConnection::Tls(c) => c.rm(pathname),
        }
    }

    fn rmdir(&mut self, pathname: &str) -> FtpResult<()> {
        match self {
            FtpConnection::Plain(c) => c.rmdir(pathname),
            FtpConnection::Tls(c) => c.rmdir(pathname),
        }
    }

    fn rename(&mut self, from: &str, to: &str) -> FtpResult<()> {
        match self {
            FtpConnection::Plain(c) => c.rename(from, to),
            FtpConnection::Tls(c) => c.rename(from, to),
        }
    }
}

/// Dial the control connection (through the proxy when configured).
fn dial_control(cfg: &FtpSessionConfig, target: SocketAddr) -> Result<TcpStream, ClientError> {
    let stream = match cfg.proxy.as_ref() {
        Some(dialer) => dialer.dial(target).map_err(ClientError::Io)?,
        None => TcpStream::connect_timeout(&target, CONNECT_TIMEOUT).map_err(ClientError::Io)?,
    };
    // Mirror CURLOPT_FTP_RESPONSE_TIMEOUT on the control channel.
    stream
        .set_read_timeout(Some(CONTROL_RESPONSE_TIMEOUT))
        .map_err(ClientError::Io)?;
    stream.set_write_timeout(None).map_err(ClientError::Io)?;
    Ok(stream)
}

/// Dial a passive-mode data connection (through the proxy when configured).
fn dial_data(dialer: &Option<ProxyDialer>, addr: SocketAddr) -> FtpResult<TcpStream> {
    let stream = match dialer {
        Some(d) => d.dial(addr).map_err(FtpError::ConnectionError)?,
        None => {
            TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(FtpError::ConnectionError)?
        }
    };
    // Data channels use blocking reads (no timeout), matching the C++
    // backend; cancellation is cooperative, checked between chunks.
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
    Ok(stream)
}

/// Opens a fresh control connection: TCP dial (+TLS for FTPS explicit),
/// login, binary transfer type. Every operation gets its own connection,
/// mirroring the C++ per-operation libcurl handle.
fn open_connection(cfg: &FtpSessionConfig) -> Result<FtpConnection, ClientError> {
    let target = resolve_first(&cfg.host, cfg.port).map_err(ClientError::Io)?;
    let tls_config = if matches!(&cfg.protocol, Protocol::Ftps) {
        Some(build_tls_config(cfg)?)
    } else {
        None
    };
    let tcp = dial_control(cfg, target)?;
    let data_dialer = cfg.proxy.clone();
    let mut conn = match &tls_config {
        None => {
            let ftp = FtpStream::connect_with_stream(tcp).map_err(map_ftp_error)?;
            let ftp = ftp.passive_stream_builder(move |addr| dial_data(&data_dialer, addr));
            FtpConnection::Plain(ftp)
        }
        Some(tls_cfg) => {
            let ftp = RustlsFtpStream::connect_with_stream(tcp).map_err(map_ftp_error)?;
            let ftp = ftp.passive_stream_builder(move |addr| dial_data(&data_dialer, addr));
            let connector = RustlsConnector::from(Arc::clone(tls_cfg));
            let ftp = ftp
                .into_secure(connector, &cfg.host)
                .map_err(|e| ClientError::OperationFailed(format!("FTPS TLS setup failed: {e}")))?;
            FtpConnection::Tls(ftp)
        }
    };
    // EPSV is required for IPv6 (PASV is IPv4-only); libcurl prefers EPSV.
    if target.is_ipv6() {
        conn.set_mode(Mode::ExtendedPassive);
    }
    conn.login(&cfg.username, &cfg.password)
        .map_err(map_ftp_error)?;
    conn.transfer_type(FileType::Binary)
        .map_err(map_ftp_error)?;
    Ok(conn)
}

// ---------------------------------------------------------------------------
// Directory listing parsing (ports of the C++ parsers)
// ---------------------------------------------------------------------------

/// Port of `parseUnsignedDec`.
fn parse_u64(token: &str) -> Option<u64> {
    if token.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for ch in token.bytes() {
        if !ch.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((ch - b'0') as u64)?;
    }
    Some(value)
}

fn parse_octal_u32(token: &str) -> Option<u32> {
    if token.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for ch in token.bytes() {
        if !(b'0'..=b'7').contains(&ch) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add((ch - b'0') as u32)?;
    }
    Some(value)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// civil-date algorithm); port of the `timegm` usage in
/// `parseMlsdUtcTimestamp`.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = ((m as i64) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + (d as i64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Port of `parseMlsdUtcTimestamp`: `YYYYMMDDHHMMSS` → epoch seconds.
fn parse_mlsd_utc_timestamp(raw: &str) -> Option<u64> {
    if raw.len() < 14 {
        return None;
    }
    let year = parse_u64(&raw[0..4])?;
    let month = parse_u64(&raw[4..6])?;
    let day = parse_u64(&raw[6..8])?;
    let hour = parse_u64(&raw[8..10])?;
    let minute = parse_u64(&raw[10..12])?;
    let second = parse_u64(&raw[12..14])?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
        || !(1970..=9999).contains(&year)
    {
        return None;
    }
    let days = days_from_civil(year as i64, month as u32, day as u32);
    if days < 0 {
        return None;
    }
    Some((days as u64) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Port of `parseUnixPermBits`.
fn parse_unix_perm_bits(perm: &str) -> u32 {
    let bytes = perm.as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    let mut mode: u32 = match bytes[0] {
        b'd' => 0o040000,
        b'l' => 0o120000,
        b'-' => 0o100000,
        _ => 0,
    };
    if bytes.len() < 10 {
        return mode;
    }
    let bits: [u32; 9] = [
        0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001,
    ];
    for (i, bit) in bits.iter().enumerate() {
        let c = bytes.get(1 + i).copied().unwrap_or(0);
        if c != b'-' && c != 0 {
            mode |= bit;
        }
    }
    mode
}

/// Port of `parseMlsdLine`. Returns false when the line cannot be parsed
/// (mirrors the all-or-nothing MLSD behavior of the C++ backend).
fn parse_mlsd_line(raw: &str, out: &mut Vec<FileInfo>) -> bool {
    let line = raw.trim_end_matches('\r').trim().to_string();
    if line.is_empty() {
        return true;
    }
    let Some(sep) = line.find([' ', '\t']) else {
        return false;
    };
    let facts_part = &line[..sep];
    let name = line[sep + 1..].trim_start().to_string();
    if name.is_empty() {
        return false;
    }
    if name == "." || name == ".." {
        return true;
    }

    let mut info = FileInfo {
        name,
        is_dir: false,
        size: 0,
        has_size: false,
        mtime: 0,
        mode: 0,
        uid: 0,
        gid: 0,
    };
    let mut type_str = String::new();
    for fact in facts_part.split(';') {
        if fact.is_empty() {
            continue;
        }
        let Some(eq) = fact.find('=') else { continue };
        let key = fact[..eq].to_ascii_lowercase();
        let value = &fact[eq + 1..];
        match key.as_str() {
            "type" => type_str = value.to_ascii_lowercase(),
            "size" => {
                if let Some(sz) = parse_u64(value) {
                    info.size = sz;
                    info.has_size = true;
                }
            }
            "modify" => {
                if let Some(ts) = parse_mlsd_utc_timestamp(value) {
                    info.mtime = ts;
                }
            }
            "unix.mode" => {
                if let Some(mode) = parse_octal_u32(value) {
                    info.mode = mode & 0o7777;
                }
            }
            "unix.uid" => {
                if let Some(uid) = parse_u64(value) {
                    info.uid = uid.min(u32::MAX as u64) as u32;
                }
            }
            "unix.gid" => {
                if let Some(gid) = parse_u64(value) {
                    info.gid = gid.min(u32::MAX as u64) as u32;
                }
            }
            _ => {}
        }
    }

    if type_str.is_empty() {
        return false;
    }
    if type_str == "cdir" || type_str == "pdir" {
        return true;
    }
    info.is_dir = type_str == "dir";
    if info.is_dir {
        info.has_size = false;
        info.size = 0;
        if info.mode & 0o170000 == 0 {
            info.mode |= 0o040000;
        }
    } else if info.mode & 0o170000 == 0 {
        info.mode |= 0o100000;
    }
    out.push(info);
    true
}

enum LineOutcome {
    Emitted,
    Skipped,
    Failed,
}

/// Port of `parseUnixListLine`.
fn parse_unix_list_line(line: &str, out: &mut Vec<FileInfo>) -> LineOutcome {
    let mut it = line.split_whitespace();
    let (
        Some(perm),
        Some(_links),
        Some(_owner),
        Some(_group),
        Some(size_tok),
        Some(_month),
        Some(_day),
        Some(_time_or_year),
    ) = (
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
    )
    else {
        return LineOutcome::Failed;
    };
    let rest: Vec<&str> = it.collect();
    if rest.is_empty() {
        return LineOutcome::Failed;
    }
    let mut name = rest.join(" ").trim().to_string();
    if let Some(pos) = name.find(" -> ") {
        name.truncate(pos);
    }
    if name.is_empty() {
        return LineOutcome::Failed;
    }
    if name == "." || name == ".." {
        return LineOutcome::Skipped;
    }
    let is_dir = perm.starts_with('d');
    let mut info = FileInfo {
        name,
        is_dir,
        size: 0,
        has_size: false,
        mtime: 0,
        mode: parse_unix_perm_bits(perm),
        uid: 0,
        gid: 0,
    };
    if !is_dir {
        if let Some(sz) = parse_u64(size_tok) {
            info.size = sz;
            info.has_size = true;
        }
    }
    out.push(info);
    LineOutcome::Emitted
}

/// Port of `parseDosListLine`.
fn parse_dos_list_line(line: &str, out: &mut Vec<FileInfo>) -> LineOutcome {
    let mut it = line.split_whitespace();
    let (Some(_date_tok), Some(_time_tok), Some(size_or_dir)) = (it.next(), it.next(), it.next())
    else {
        return LineOutcome::Failed;
    };
    let rest: Vec<&str> = it.collect();
    if rest.is_empty() {
        return LineOutcome::Failed;
    }
    let name = rest.join(" ").trim().to_string();
    if name.is_empty() {
        return LineOutcome::Failed;
    }
    if name == "." || name == ".." {
        return LineOutcome::Skipped;
    }
    let kind = size_or_dir.to_ascii_lowercase();
    let mut info = FileInfo {
        name,
        is_dir: false,
        size: 0,
        has_size: false,
        mtime: 0,
        mode: 0,
        uid: 0,
        gid: 0,
    };
    if kind == "<dir>" {
        info.is_dir = true;
        info.mode = 0o040000;
    } else {
        let normalized: String = size_or_dir.chars().filter(|c| *c != ',').collect();
        let Some(sz) = parse_u64(&normalized) else {
            return LineOutcome::Failed;
        };
        info.size = sz;
        info.has_size = true;
        info.mode = 0o100000;
    }
    out.push(info);
    LineOutcome::Emitted
}

/// Converts a suppaftp-parsed LIST/MLSx entry into `FileInfo`.
fn file_info_from_suppaftp(file: &SuppaftpFile) -> FileInfo {
    let mut mode: u32 = if file.is_directory() {
        0o040000
    } else if file.is_symlink() {
        0o120000
    } else {
        0o100000
    };
    for (who, shift) in [
        (PosixPexQuery::Owner, 6),
        (PosixPexQuery::Group, 3),
        (PosixPexQuery::Others, 0),
    ] {
        if file.can_read(who) {
            mode |= 0o4 << shift;
        }
        if file.can_write(who) {
            mode |= 0o2 << shift;
        }
        if file.can_execute(who) {
            mode |= 0o1 << shift;
        }
    }
    let mtime = file
        .modified()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let is_dir = file.is_directory();
    FileInfo {
        name: file.name().to_string(),
        is_dir,
        size: if is_dir { 0 } else { file.size() as u64 },
        has_size: !is_dir,
        mtime,
        mode,
        uid: file.uid().unwrap_or(0),
        gid: file.gid().unwrap_or(0),
    }
}

/// Port of `parseListListing`: suppaftp parsers first, C++ parsers as
/// fallback. Returns the entries and the C++ success condition
/// (`parsedAny || !sawUnparsedLine`).
fn parse_list_listing(lines: &[String]) -> (Vec<FileInfo>, bool) {
    let mut out = Vec::new();
    let mut saw_content = false;
    let mut parsed_any = false;
    let mut saw_unparsed = false;
    for line in lines {
        let normalized = line.trim();
        if normalized.is_empty() {
            continue;
        }
        let lowered = normalized.to_ascii_lowercase();
        if lowered.starts_with("total ") {
            continue;
        }
        saw_content = true;
        let first = normalized.chars().next().unwrap_or(' ');
        let mut ok = false;
        let mut emitted = false;
        if matches!(first, 'd' | '-' | 'l' | 'c' | 'b' | 's' | 'p') {
            if matches!(first, 'd' | '-' | 'l') {
                if let Ok(file) = SuppaftpFile::from_posix_line(normalized) {
                    out.push(file_info_from_suppaftp(&file));
                    ok = true;
                    emitted = true;
                }
            }
            if !ok {
                match parse_unix_list_line(normalized, &mut out) {
                    LineOutcome::Emitted => {
                        ok = true;
                        emitted = true;
                    }
                    LineOutcome::Skipped => ok = true,
                    LineOutcome::Failed => {}
                }
            }
        }
        if !ok {
            match parse_dos_list_line(normalized, &mut out) {
                LineOutcome::Emitted => {
                    ok = true;
                    emitted = true;
                }
                LineOutcome::Skipped => ok = true,
                LineOutcome::Failed => {
                    if let Ok(file) = SuppaftpFile::from_dos_line(normalized) {
                        out.push(file_info_from_suppaftp(&file));
                        ok = true;
                        emitted = true;
                    }
                }
            }
        }
        if !ok {
            saw_unparsed = true;
        } else if emitted {
            parsed_any = true;
        }
    }
    if !saw_content {
        return (out, true);
    }
    (out, parsed_any || !saw_unparsed)
}

/// Port of `CurlFtpClient::list`: MLSD first with fallback to LIST, and the
/// same error messages.
fn list_impl(
    conn: &mut FtpConnection,
    remote_path: &str,
    label: &'static str,
) -> Result<Vec<FileInfo>, ClientError> {
    let path = normalize_remote_path(remote_path);
    enum Attempt {
        Ok(Vec<FileInfo>),
        ParseFailed,
        CommandFailed(String),
    }
    let mlsd = match conn.mlsd(Some(&path)) {
        Ok(lines) => {
            let mut out = Vec::new();
            let mut ok = true;
            for line in &lines {
                if !parse_mlsd_line(line, &mut out) {
                    ok = false;
                    break;
                }
            }
            if ok {
                Attempt::Ok(out)
            } else {
                Attempt::ParseFailed
            }
        }
        Err(e) => Attempt::CommandFailed(e.to_string()),
    };
    match mlsd {
        Attempt::Ok(out) => Ok(out),
        Attempt::ParseFailed => {
            debug!("MLSD listing could not be parsed; falling back to LIST");
            match conn.list(Some(&path)) {
                Ok(lines) => {
                    let (out, success) = parse_list_listing(&lines);
                    if success {
                        Ok(out)
                    } else {
                        Err(ClientError::OperationFailed(format!(
                            "{label} directory listing parse failed for MLSD and LIST output."
                        )))
                    }
                }
                Err(list_err) => Err(ClientError::OperationFailed(format!(
                    "{label} directory listing parse failed for MLSD output, and LIST fallback failed: {list_err}"
                ))),
            }
        }
        Attempt::CommandFailed(mlsd_err) => {
            debug!(error = %mlsd_err, "MLSD failed; falling back to LIST");
            match conn.list(Some(&path)) {
                Ok(lines) => {
                    let (out, success) = parse_list_listing(&lines);
                    if success {
                        Ok(out)
                    } else {
                        Err(ClientError::OperationFailed(format!(
                            "{label} directory listing parse failed for MLSD and LIST output."
                        )))
                    }
                }
                Err(list_err) => Err(ClientError::OperationFailed(format!(
                    "{label} directory listing failed. MLSD: {mlsd_err} | LIST: {list_err}"
                ))),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Metadata / file operations
// ---------------------------------------------------------------------------

fn normalize_remote_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn strip_trailing_slash(path: &str) -> &str {
    if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    }
}

fn base_name(path: &str) -> String {
    let trimmed = strip_trailing_slash(path);
    match trimmed.rfind('/') {
        Some(idx) => trimmed[idx + 1..].to_string(),
        None => trimmed.to_string(),
    }
}

fn join_remote(base: &str, name: &str) -> String {
    if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

fn split_parent(path: &str) -> Option<(String, String)> {
    let trimmed = strip_trailing_slash(path);
    let idx = trimmed.rfind('/')?;
    let name = &trimmed[idx + 1..];
    if name.is_empty() {
        return None;
    }
    let parent = if idx == 0 {
        "/".to_string()
    } else {
        trimmed[..idx].to_string()
    };
    Some((parent, name.to_string()))
}

fn mdtm_to_epoch(dt: &chrono::NaiveDateTime) -> u64 {
    dt.and_utc().timestamp().max(0) as u64
}

fn copy_file_info(info: &FileInfo) -> FileInfo {
    FileInfo {
        name: info.name.clone(),
        is_dir: info.is_dir,
        size: info.size,
        has_size: info.has_size,
        mtime: info.mtime,
        mode: info.mode,
        uid: info.uid,
        gid: info.gid,
    }
}

/// `exists`: MLST first, then SIZE, then a parent-directory listing lookup,
/// then MDTM as a last resort (unknown type → file).
fn exists_impl(
    conn: &mut FtpConnection,
    remote_path: &str,
    label: &'static str,
) -> Result<Option<bool>, ClientError> {
    let path = strip_trailing_slash(remote_path);
    if let Ok(line) = conn.mlst(Some(path)) {
        let mut out = Vec::new();
        if parse_mlsd_line(&line, &mut out) {
            if let Some(info) = out.first() {
                return Ok(Some(info.is_dir));
            }
        }
    }
    if conn.size(path).is_ok() {
        return Ok(Some(false));
    }
    if let Some((parent, name)) = split_parent(path) {
        if let Ok(entries) = list_impl(conn, &parent, label) {
            return Ok(entries.iter().find(|f| f.name == name).map(|f| f.is_dir));
        }
    }
    if conn.mdtm(path).is_ok() {
        return Ok(Some(false));
    }
    Ok(None)
}

/// `stat`: MLST first, then parent-directory listing lookup, then
/// SIZE+MDTM for plain files.
fn stat_impl(
    conn: &mut FtpConnection,
    remote_path: &str,
    label: &'static str,
) -> Result<FileInfo, ClientError> {
    let path = strip_trailing_slash(remote_path);
    if let Ok(line) = conn.mlst(Some(path)) {
        let mut out = Vec::new();
        if parse_mlsd_line(&line, &mut out) {
            if let Some(mut info) = out.into_iter().next() {
                info.name = base_name(path);
                return Ok(info);
            }
        }
    }
    if let Some((parent, name)) = split_parent(path) {
        let entries = list_impl(conn, &parent, label)?;
        if let Some(info) = entries.iter().find(|f| f.name == name) {
            return Ok(copy_file_info(info));
        }
        return Err(ClientError::OperationFailed(format!(
            "{label} stat failed: '{path}' not found in '{parent}'"
        )));
    }
    let size = conn.size(path).ok().map(|s| s as u64);
    let mtime = conn.mdtm(path).ok().map(|dt| mdtm_to_epoch(&dt));
    match (size, mtime) {
        (Some(sz), mtime) => Ok(FileInfo {
            name: base_name(path),
            is_dir: false,
            size: sz,
            has_size: true,
            mtime: mtime.unwrap_or(0),
            mode: 0o100000,
            uid: 0,
            gid: 0,
        }),
        (None, Some(mtime)) => Ok(FileInfo {
            name: base_name(path),
            is_dir: false,
            size: 0,
            has_size: false,
            mtime,
            mode: 0,
            uid: 0,
            gid: 0,
        }),
        (None, None) => Err(ClientError::OperationFailed(format!(
            "{label} stat failed: '{path}' not found"
        ))),
    }
}

fn mkdir_impl(conn: &mut FtpConnection, remote_dir: &str, mode: u32) -> Result<(), ClientError> {
    // FTP MKD has no permission argument; mode is accepted for trait parity.
    debug!(
        dir = remote_dir,
        mode, "FTP mkdir (mode ignored by the FTP protocol)"
    );
    conn.mkdir(strip_trailing_slash(remote_dir))
        .map_err(map_ftp_error)
}

fn remove_file_impl(conn: &mut FtpConnection, remote_path: &str) -> Result<(), ClientError> {
    conn.rm(remote_path).map_err(map_ftp_error)
}

/// Recursive directory removal: descend the listing and delete bottom-up.
fn remove_dir_impl(
    conn: &mut FtpConnection,
    remote_dir: &str,
    label: &'static str,
) -> Result<(), ClientError> {
    fn remove_recursive(
        conn: &mut FtpConnection,
        dir: &str,
        depth: usize,
        label: &'static str,
    ) -> Result<(), ClientError> {
        if depth > MAX_REMOVE_DEPTH {
            return Err(ClientError::Other(format!(
                "{label} removeDir failed: recursion limit exceeded at '{dir}'"
            )));
        }
        let entries = list_impl(conn, dir, label)?;
        for entry in &entries {
            let child = join_remote(dir, &entry.name);
            if entry.is_dir {
                remove_recursive(conn, &child, depth + 1, label)?;
            } else {
                conn.rm(&child).map_err(map_ftp_error)?;
            }
        }
        conn.rmdir(dir).map_err(map_ftp_error)
    }
    remove_recursive(conn, strip_trailing_slash(remote_dir), 0, label)
}

/// RNFR/RNTO with overwrite semantics: a missing source errors; when
/// `overwrite` is set the destination is removed first (some servers refuse
/// to replace an existing target).
fn rename_impl(
    conn: &mut FtpConnection,
    from: &str,
    to: &str,
    overwrite: bool,
    label: &'static str,
) -> Result<(), ClientError> {
    if !overwrite && exists_impl(conn, to, label)?.is_some() {
        return Err(ClientError::OperationFailed(format!(
            "{label} rename failed: destination '{to}' already exists"
        )));
    }
    match conn.rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) if overwrite => {
            let _ = conn.rm(to);
            conn.rename(from, to).map_err(map_ftp_error)
        }
        Err(e) => Err(map_ftp_error(e)),
    }
}

/// `SITE CHMOD <octal-mode> <path>` (best effort; servers without SITE CHMOD
/// return an error).
fn chmod_impl(
    conn: &mut FtpConnection,
    remote_path: &str,
    mode: u32,
    label: &'static str,
) -> Result<(), ClientError> {
    let command = format!(
        "CHMOD {:o} {}",
        mode & 0o7777,
        strip_trailing_slash(remote_path)
    );
    conn.site(&command).map(|_| ()).map_err(|e| {
        ClientError::OperationFailed(format!(
            "{label} SITE CHMOD failed (server may not support it): {e}"
        ))
    })
}

/// `MFMT <YYYYMMDDHHMMSS> <path>` (best effort). FTP has no standard way to
/// set atime, so `atime` is ignored.
fn set_times_impl(
    conn: &mut FtpConnection,
    remote_path: &str,
    atime: u64,
    mtime: u64,
    label: &'static str,
) -> Result<(), ClientError> {
    let stamp = chrono::DateTime::from_timestamp(mtime.min(i64::MAX as u64) as i64, 0)
        .map(|dt| dt.format("%Y%m%d%H%M%S").to_string())
        .ok_or_else(|| ClientError::Other("Invalid mtime".into()))?;
    let command = format!("MFMT {stamp} {}", strip_trailing_slash(remote_path));
    debug!(
        path = remote_path,
        atime, mtime, "FTP set_times (atime ignored)"
    );
    conn.custom_command(&command, &[Status::File])
        .map(|_| ())
        .map_err(|e| {
            ClientError::OperationFailed(format!(
                "{label} MFMT failed (server may not support timestamp updates): {e}"
            ))
        })
}

// ---------------------------------------------------------------------------
// Transfers
// ---------------------------------------------------------------------------

/// Download loop over a concrete `ImplFtpStream<T>` (duplicated per
/// connection flavor by macro expansion, because the `TlsStream` bound is
/// private in suppaftp). Mirrors `CurlFtpClient::get` progress/cancel
/// semantics plus REST-based resume.
macro_rules! download_transfer {
    ($ftp:ident, $remote:ident, $file:ident, $offset:ident, $progress:ident, $should_cancel:ident, $interrupted:ident, $label:ident) => {{
        let mut total: u64 = match $ftp.size($remote) {
            Ok(sz) => sz as u64,
            Err(_) => 0,
        };
        if $offset > 0 {
            if total > 0 && $offset > total {
                warn!(offset = $offset, total, "resume offset exceeds remote size; restarting download");
                $offset = 0;
                $file.set_len(0).map_err(ClientError::Io)?;
                $file.seek(SeekFrom::Start(0)).map_err(ClientError::Io)?;
            } else if total > 0 && $offset == total {
                debug!("download already complete (offset == remote size)");
                return Ok(());
            }
            $ftp.resume_transfer($offset as usize)
                .map_err(|e| ClientError::OperationFailed(format!("{} download failed: {}", $label, e)))?;
        }
        if total > 0 {
            total += $offset;
        }
        let mut stream = $ftp
            .retr_as_stream($remote)
            .map_err(|e| ClientError::OperationFailed(format!("{} download failed: {}", $label, e)))?;
        let mut buf = vec![0u8; TRANSFER_CHUNK];
        let mut done: u64 = $offset;
        loop {
            if $interrupted.load(Ordering::SeqCst) {
                debug!("download interrupted; aborting data connection");
                let _ = $ftp.abort(stream);
                return Err(ClientError::Other("Interrupted".into()));
            }
            if let Some(cb) = $should_cancel.as_ref() {
                if cb() {
                    debug!("download cancelled by user; aborting data connection");
                    let _ = $ftp.abort(stream);
                    return Err(ClientError::Cancelled);
                }
            }
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    $file.write_all(&buf[..n]).map_err(ClientError::Io)?;
                    done += n as u64;
                    if let Some(cb) = $progress.as_ref() {
                        cb(done, total);
                    }
                }
                Err(e) => {
                    debug!(error = %e, "download data read failed");
                    let _ = $ftp.abort(stream);
                    return Err(ClientError::Io(e));
                }
            }
        }
        $ftp.finalize_retr_stream(stream)
            .map_err(|e| ClientError::OperationFailed(format!("{} download failed: {}", $label, e)))?;
        if let Some(cb) = $progress.as_ref() {
            cb(done, total);
        }
        Ok(())
    }};
}

/// Upload loop; mirrors `CurlFtpClient::put` plus REST-based resume and the
/// `CURLOPT_FTP_CREATE_MISSING_DIRS` retry behavior.
macro_rules! upload_transfer {
    ($ftp:ident, $remote:ident, $file:ident, $offset:ident, $progress:ident, $should_cancel:ident, $interrupted:ident, $label:ident, $total:ident) => {{
        if $offset > 0 && $offset > $total {
            warn!(offset = $offset, total = $total, "remote file larger than local; restarting upload");
            $offset = 0;
        }
        if $offset > 0 && $offset < $total {
            $file.seek(SeekFrom::Start($offset)).map_err(ClientError::Io)?;
            $ftp.resume_transfer($offset as usize)
                .map_err(|e| ClientError::OperationFailed(format!("{} upload failed: {}", $label, e)))?;
        } else if $offset > 0 && $offset == $total {
            debug!("upload already complete (remote size == local size)");
            return Ok(());
        }
        let mut stream = match $ftp.put_with_stream($remote) {
            Ok(stream) => stream,
            Err(FtpError::UnexpectedResponse(resp)) if resp.status == Status::FileUnavailable => {
                // Mirror CURLOPT_FTP_CREATE_MISSING_DIRS (CURLFTP_CREATE_DIR_RETRY).
                debug!("upload rejected (550); creating missing parent directories and retrying once");
                {
                    let mut acc = String::new();
                    let path = normalize_remote_path($remote);
                    if let Some(slash) = path.rfind('/') {
                        if slash > 0 {
                            for dir in path[..slash].split('/').filter(|s| !s.is_empty()) {
                                acc.push('/');
                                acc.push_str(dir);
                                if $ftp.mkdir(acc.as_str()).is_ok() {
                                    debug!(dir = %acc, "created missing remote directory");
                                }
                            }
                        }
                    }
                }
                $ftp.put_with_stream($remote)
                    .map_err(|e| ClientError::OperationFailed(format!("{} upload failed: {}", $label, e)))?
            }
            Err(e) => {
                return Err(ClientError::OperationFailed(format!("{} upload failed: {}", $label, e)));
            }
        };
        let mut buf = vec![0u8; TRANSFER_CHUNK];
        let mut done: u64 = $offset;
        loop {
            if $interrupted.load(Ordering::SeqCst) {
                debug!("upload interrupted; aborting data connection");
                let _ = $ftp.abort(stream);
                return Err(ClientError::Other("Interrupted".into()));
            }
            if let Some(cb) = $should_cancel.as_ref() {
                if cb() {
                    debug!("upload cancelled by user; aborting data connection");
                    let _ = $ftp.abort(stream);
                    return Err(ClientError::Cancelled);
                }
            }
            if done >= $total {
                break;
            }
            let want = std::cmp::min(buf.len() as u64, $total - done) as usize;
            match $file.read(&mut buf[..want]) {
                Ok(0) => break,
                Ok(n) => {
                    stream.write_all(&buf[..n]).map_err(ClientError::Io)?;
                    done += n as u64;
                    if let Some(cb) = $progress.as_ref() {
                        cb(done, $total);
                    }
                }
                Err(e) => {
                    debug!(error = %e, "upload local read failed");
                    let _ = $ftp.abort(stream);
                    return Err(ClientError::Io(e));
                }
            }
        }
        $ftp.finalize_put_stream(stream)
            .map_err(|e| ClientError::OperationFailed(format!("{} upload failed: {}", $label, e)))?;
        if let Some(cb) = $progress.as_ref() {
            cb(done, $total);
        }
        Ok(())
    }};
}

#[allow(clippy::too_many_arguments)]
fn download_file(
    conn: &mut FtpConnection,
    remote: &str,
    local: &str,
    progress: Option<ProgressCb>,
    should_cancel: Option<CancelCb>,
    resume: bool,
    interrupted: Arc<AtomicBool>,
    label: &'static str,
) -> Result<(), ClientError> {
    let mut offset: u64 = 0;
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if resume {
        options.create(true).append(true);
        offset = std::fs::metadata(local).map(|m| m.len()).unwrap_or(0);
    } else {
        options.create(true).truncate(true);
    }
    let mut file = options.open(local).map_err(|e| {
        ClientError::Io(std::io::Error::new(
            e.kind(),
            format!("Could not open local file for writing: {e}"),
        ))
    })?;
    match conn {
        FtpConnection::Plain(c) => download_transfer!(
            c,
            remote,
            file,
            offset,
            progress,
            should_cancel,
            interrupted,
            label
        ),
        FtpConnection::Tls(c) => download_transfer!(
            c,
            remote,
            file,
            offset,
            progress,
            should_cancel,
            interrupted,
            label
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn upload_file(
    conn: &mut FtpConnection,
    local: &str,
    remote: &str,
    progress: Option<ProgressCb>,
    should_cancel: Option<CancelCb>,
    resume: bool,
    interrupted: Arc<AtomicBool>,
    label: &'static str,
) -> Result<(), ClientError> {
    let total = std::fs::metadata(local)
        .map_err(|e| {
            ClientError::Io(std::io::Error::new(
                e.kind(),
                format!("Could not determine local file size: {e}"),
            ))
        })?
        .len();
    let mut file = std::fs::File::open(local).map_err(|e| {
        ClientError::Io(std::io::Error::new(
            e.kind(),
            format!("Could not open local file for reading: {e}"),
        ))
    })?;
    let mut offset: u64 = 0;
    if resume {
        if let Ok(sz) = conn.size(remote) {
            offset = sz as u64;
        }
    }
    match conn {
        FtpConnection::Plain(c) => upload_transfer!(
            c,
            remote,
            file,
            offset,
            progress,
            should_cancel,
            interrupted,
            label,
            total
        ),
        FtpConnection::Tls(c) => upload_transfer!(
            c,
            remote,
            file,
            offset,
            progress,
            should_cancel,
            interrupted,
            label,
            total
        ),
    }
}

// ---------------------------------------------------------------------------
// SftpClient implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl SftpClient for FtpClient {
    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn interrupt(&self) {
        self.interrupted.store(true, Ordering::SeqCst);
    }

    fn is_connected(&self) -> bool {
        match self.state.lock() {
            Ok(state) => state.connected,
            Err(_) => false,
        }
    }

    async fn connect(&mut self, opt: &SessionOptions) -> Result<(), ClientError> {
        self.interrupted.store(false, Ordering::SeqCst);
        if !is_ftp_family(&opt.protocol) {
            return Err(ClientError::Unsupported(
                "FtpClient only supports FTP and FTPS protocols.".into(),
            ));
        }
        // The C++ client hard-fails on protocol mismatch; this port instead
        // adopts any FTP-family protocol so factories only need `new()`.
        if opt.protocol != self.protocol {
            self.protocol = opt.protocol;
        }
        if let Some(jump_host) = &opt.jump_host {
            if !jump_host.is_empty() {
                return Err(ClientError::Unsupported(
                    "FTP/FTPS backend does not support SSH jump host.".into(),
                ));
            }
        }
        let cfg = config_from_options(self.protocol, opt)?;
        if use_implicit_ftps(&cfg.protocol, cfg.port) {
            return Err(ClientError::Unsupported(
                "Implicit FTPS (TLS from the start of the connection on port 990) requires the \
                 suppaftp 'deprecated' feature (ImplFtpStream::connect_secure_implicit). Enable \
                 it in the workspace dependencies, or use explicit FTPS (AUTH TLS) on a \
                 non-990 port."
                    .into(),
            ));
        }
        let label = protocol_label(&cfg.protocol);
        let probe_cfg = cfg.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ClientError> {
            let mut conn = open_connection(&probe_cfg)?;
            // Mirrors the C++ connect probe (DIRLISTONLY=1 on "/").
            conn.nlst(Some("/")).map_err(|e| {
                ClientError::OperationFailed(format!("{label} connect probe failed: {e}"))
            })?;
            Ok(())
        })
        .await
        .map_err(|e| ClientError::Other(format!("FTP task join error: {e}")))??;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ClientError::Other("FTP state lock poisoned".into()))?;
        state.options = Some(cfg);
        state.connected = true;
        info!(protocol = label, host = %opt.host, port = opt.port, "FTP connection probe succeeded");
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
        self.interrupted.store(false, Ordering::SeqCst);
        let mut state = self
            .state
            .lock()
            .map_err(|_| ClientError::Other("FTP state lock poisoned".into()))?;
        state.connected = false;
        state.options = None;
        Ok(())
    }

    async fn list(&mut self, remote_path: &str) -> Result<Vec<FileInfo>, ClientError> {
        let cfg = self.require_config()?;
        let label = protocol_label(&cfg.protocol);
        let path = remote_path.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_connection(&cfg)?;
            list_impl(&mut conn, &path, label)
        })
        .await
        .map_err(|e| ClientError::Other(format!("FTP task join error: {e}")))?
    }

    async fn get(
        &mut self,
        remote: &str,
        local: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError> {
        let cfg = self.require_config()?;
        self.interrupted.store(false, Ordering::SeqCst);
        let label = protocol_label(&cfg.protocol);
        let interrupted = Arc::clone(&self.interrupted);
        let remote = remote.to_owned();
        let local = local.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_connection(&cfg)?;
            download_file(
                &mut conn,
                &remote,
                &local,
                progress,
                should_cancel,
                resume,
                interrupted,
                label,
            )
        })
        .await
        .map_err(|e| ClientError::Other(format!("FTP task join error: {e}")))?
    }

    async fn put(
        &mut self,
        local: &str,
        remote: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError> {
        let cfg = self.require_config()?;
        self.interrupted.store(false, Ordering::SeqCst);
        let label = protocol_label(&cfg.protocol);
        let interrupted = Arc::clone(&self.interrupted);
        let local = local.to_owned();
        let remote = remote.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_connection(&cfg)?;
            upload_file(
                &mut conn,
                &local,
                &remote,
                progress,
                should_cancel,
                resume,
                interrupted,
                label,
            )
        })
        .await
        .map_err(|e| ClientError::Other(format!("FTP task join error: {e}")))?
    }

    async fn exists(&mut self, remote_path: &str) -> Result<Option<bool>, ClientError> {
        let cfg = self.require_config()?;
        let label = protocol_label(&cfg.protocol);
        let path = remote_path.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_connection(&cfg)?;
            exists_impl(&mut conn, &path, label)
        })
        .await
        .map_err(|e| ClientError::Other(format!("FTP task join error: {e}")))?
    }

    async fn stat(&mut self, remote_path: &str) -> Result<FileInfo, ClientError> {
        let cfg = self.require_config()?;
        let label = protocol_label(&cfg.protocol);
        let path = remote_path.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_connection(&cfg)?;
            stat_impl(&mut conn, &path, label)
        })
        .await
        .map_err(|e| ClientError::Other(format!("FTP task join error: {e}")))?
    }

    async fn chmod(&mut self, remote_path: &str, mode: u32) -> Result<(), ClientError> {
        let cfg = self.require_config()?;
        let label = protocol_label(&cfg.protocol);
        let path = remote_path.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_connection(&cfg)?;
            chmod_impl(&mut conn, &path, mode, label)
        })
        .await
        .map_err(|e| ClientError::Other(format!("FTP task join error: {e}")))?
    }

    async fn chown(&mut self, _remote_path: &str, _uid: u32, _gid: u32) -> Result<(), ClientError> {
        // No FTP command exists to change file ownership (mirrors C++).
        Err(unsupported("chown"))
    }

    async fn set_times(
        &mut self,
        remote_path: &str,
        atime: u64,
        mtime: u64,
    ) -> Result<(), ClientError> {
        let cfg = self.require_config()?;
        let label = protocol_label(&cfg.protocol);
        let path = remote_path.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_connection(&cfg)?;
            set_times_impl(&mut conn, &path, atime, mtime, label)
        })
        .await
        .map_err(|e| ClientError::Other(format!("FTP task join error: {e}")))?
    }

    async fn mkdir(&mut self, remote_dir: &str, mode: u32) -> Result<(), ClientError> {
        let cfg = self.require_config()?;
        let path = remote_dir.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_connection(&cfg)?;
            mkdir_impl(&mut conn, &path, mode)
        })
        .await
        .map_err(|e| ClientError::Other(format!("FTP task join error: {e}")))?
    }

    async fn remove_file(&mut self, remote_path: &str) -> Result<(), ClientError> {
        let cfg = self.require_config()?;
        let path = remote_path.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_connection(&cfg)?;
            remove_file_impl(&mut conn, &path)
        })
        .await
        .map_err(|e| ClientError::Other(format!("FTP task join error: {e}")))?
    }

    async fn remove_dir(&mut self, remote_dir: &str) -> Result<(), ClientError> {
        let cfg = self.require_config()?;
        let label = protocol_label(&cfg.protocol);
        let path = remote_dir.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_connection(&cfg)?;
            remove_dir_impl(&mut conn, &path, label)
        })
        .await
        .map_err(|e| ClientError::Other(format!("FTP task join error: {e}")))?
    }

    async fn rename(&mut self, from: &str, to: &str, overwrite: bool) -> Result<(), ClientError> {
        let cfg = self.require_config()?;
        let label = protocol_label(&cfg.protocol);
        let from = from.to_owned();
        let to = to.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_connection(&cfg)?;
            rename_impl(&mut conn, &from, &to, overwrite, label)
        })
        .await
        .map_err(|e| ClientError::Other(format!("FTP task join error: {e}")))?
    }

    async fn new_connection_like(
        &self,
        opt: &SessionOptions,
    ) -> Result<Box<dyn SftpClient>, ClientError> {
        let next = if is_ftp_family(&opt.protocol) {
            opt.protocol
        } else {
            self.protocol
        };
        let mut client = FtpClient::with_protocol(next);
        client.connect(opt).await?;
        Ok(Box::new(client))
    }
}
