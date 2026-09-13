//! TCP proxy tunnels (SOCKS5 / HTTP CONNECT) for the SSH transports.
//!
//! Rust port of the SOCKS5 and HTTP CONNECT handshakes in
//! `core/src/libssh2/Libssh2SftpClient.cpp` (`establish_socks5_tunnel` /
//! `establish_http_connect_tunnel`). The SFTP/SCP backends call
//! [`connect_via_proxy`] to obtain a raw [`tokio::net::TcpStream`] that they
//! hand to [`russh::client::connect_stream`], so the SSH session runs through
//! the proxy.
//!
//! # Integration notes for the SFTP/SCP backend
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use freescp_core::proxy;
//! # use freescp_core::types::ProxyType;
//! # use russh::client;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let stream = proxy::connect_via_proxy(
//!     ProxyType::Socks5, "proxy.example.com", 1080,
//!     Some("user"), Some("pass"),
//!     "sftp.example.com", 22,
//! ).await?;
//! let config = Arc::new(client::Config::default());
//! let session = client::connect_stream(config, stream, SftpHandler).await?;
//! // ... authenticate and start the SFTP subsystem ...
//! # Ok(())
//! # }
//! # struct SftpHandler;
//! # impl client::Handler for SftpHandler {
//! #     type Error = russh::Error;
//! #     async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> { Ok(true) }
//! # }
//! ```
//!
//! # Notes and deviations from the C++ implementation
//!
//! - The C++ code applied a 20 s socket timeout to the proxy handshake only;
//!   here the whole "connect + handshake" sequence is bounded by the same
//!   20 s timeout (see [`PROXY_HANDSHAKE_TIMEOUT`]).
//! - SOCKS5 authentication uses [`tokio_socks::tcp::Socks5Stream`]
//!   (`connect_with_password`). When credentials are supplied the password
//!   method is *offered exclusively*, whereas the C++ greeting offered both
//!   "no auth" and "user/pass" and let the server pick. A proxy that only
//!   accepts unauthenticated connections will therefore reject credentialed
//!   clients here; callers can simply omit the credentials to fall back to
//!   unauthenticated SOCKS5.
//! - Combining a proxy with an SSH jump host is rejected by the C++
//!   `tcpConnect` (`"Proxy and SSH jump host cannot be used together."`); the
//!   backends should keep the same policy (see [`crate::jumphost`]).
//! - IPv6 literals are bracketed in HTTP CONNECT authorities (`[::1]:22`).
//!   For SOCKS5, `(&str, u16)` targets are parsed as IP addresses first and
//!   sent as domain names otherwise, which matches the C++ `inet_pton`
//!   behaviour.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use tracing::debug;

use crate::types::ProxyType;

/// Timeout for the proxy connect + handshake sequence.
///
/// Mirrors `kProxyHandshakeTimeoutMs = 20000` from the C++ client.
pub const PROXY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Upper bound on HTTP CONNECT response headers, mirrors the C++ 8192-byte
/// read cap in `socket_recv_until`.
const MAX_CONNECT_RESPONSE_BYTES: usize = 8192;

/// Connect to `target_host:target_port`, optionally tunnelling the TCP
/// connection through a proxy.
///
/// - [`ProxyType::None`]: plain [`TcpStream::connect`] to the target.
/// - [`ProxyType::Socks5`]: SOCKS5 `CONNECT` via `tokio-socks`; when
///   `proxy_user`/`proxy_pass` is provided, username/password authentication
///   (RFC 1929) is used and the inner [`TcpStream`] is returned.
/// - [`ProxyType::HttpConnect`]: hand-rolled HTTP `CONNECT` request; the raw
///   [`TcpStream`] is returned after the proxy answers `200`.
///
/// The returned stream is the *tunnelled* connection: the caller can run an
/// SSH session over it directly (e.g. via
/// [`russh::client::connect_stream`]).
///
/// `target_host` may be a hostname, an IPv4 literal or a (possibly bracketed)
/// IPv6 literal. Bracketed IPv6 literals are handled by the HTTP CONNECT
/// authority formatting; unbracketed IPv6 literals are bracketed
/// automatically.
///
/// # Errors
///
/// Returns an [`io::Error`] on connection failures, proxy handshake failures,
/// authentication rejections, non-200 CONNECT responses (the message carries
/// the proxy's status line) and timeouts.
pub async fn connect_via_proxy(
    proxy_type: crate::types::ProxyType,
    proxy_host: &str,
    proxy_port: u16,
    proxy_user: Option<&str>,
    proxy_pass: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> io::Result<TcpStream> {
    debug!(
        ?proxy_type,
        %proxy_host,
        proxy_port,
        %target_host,
        target_port,
        "opening (possibly proxied) TCP connection"
    );

    if target_host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Target host is empty.",
        ));
    }

    match proxy_type {
        ProxyType::None => {
            debug!(%target_host, target_port, "connecting directly");
            TcpStream::connect((target_host, target_port)).await
        }
        ProxyType::Socks5 => {
            validate_proxy_endpoint(proxy_host, proxy_port)?;
            tokio::time::timeout(
                PROXY_HANDSHAKE_TIMEOUT,
                connect_socks5(
                    proxy_host,
                    proxy_port,
                    proxy_user,
                    proxy_pass,
                    target_host,
                    target_port,
                ),
            )
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SOCKS5 proxy connect timed out after 20 seconds.",
                )
            })?
        }
        ProxyType::HttpConnect => {
            validate_proxy_endpoint(proxy_host, proxy_port)?;
            tokio::time::timeout(
                PROXY_HANDSHAKE_TIMEOUT,
                connect_http_connect(
                    proxy_host,
                    proxy_port,
                    proxy_user,
                    proxy_pass,
                    target_host,
                    target_port,
                ),
            )
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP CONNECT proxy handshake timed out after 20 seconds.",
                )
            })?
        }
    }
}

/// Rejects empty proxy hosts and zero proxy ports with messages matching the
/// C++ client.
fn validate_proxy_endpoint(proxy_host: &str, proxy_port: u16) -> io::Result<()> {
    if proxy_host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Proxy host is empty.",
        ));
    }
    if proxy_port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Proxy port is invalid.",
        ));
    }
    Ok(())
}

/// Formats a `host:port` authority for HTTP CONNECT, bracketing unbracketed
/// IPv6 literals. Hosts that are already bracketed (`[::1]`) pass through,
/// mirroring `format_host_port_authority` in the C++ client.
fn format_host_port_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.contains(']') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// SOCKS5 connect through `tokio-socks`.
async fn connect_socks5(
    proxy_host: &str,
    proxy_port: u16,
    proxy_user: Option<&str>,
    proxy_pass: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> io::Result<TcpStream> {
    debug!(
        %proxy_host,
        proxy_port,
        %target_host,
        target_port,
        authenticated = proxy_user.is_some() || proxy_pass.is_some(),
        "negotiating SOCKS5 tunnel"
    );

    let want_auth = proxy_user.is_some() || proxy_pass.is_some();
    let stream = if want_auth {
        // The C++ client required a non-empty username for user/pass auth.
        let user = proxy_user.unwrap_or("");
        if user.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 proxy authentication requires a username.",
            ));
        }
        if user.len() > 255 || proxy_pass.map_or(0, str::len) > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 proxy credentials are too long.",
            ));
        }
        let pass = proxy_pass.unwrap_or("");
        Socks5Stream::connect_with_password(
            (proxy_host, proxy_port),
            (target_host, target_port),
            user,
            pass,
        )
        .await
    } else {
        Socks5Stream::connect((proxy_host, proxy_port), (target_host, target_port)).await
    }
    .map_err(map_socks5_error)?;

    debug!(%target_host, target_port, "SOCKS5 tunnel established");
    Ok(stream.into_inner())
}

/// Maps `tokio-socks` errors onto [`io::Error`], preserving the underlying IO
/// error and giving the proxy-side failures a descriptive message.
fn map_socks5_error(err: tokio_socks::Error) -> io::Error {
    match err {
        tokio_socks::Error::Io(inner) => inner,
        other => io::Error::other(format!("SOCKS5 proxy error: {other}")),
    }
}

/// Hand-rolled HTTP CONNECT tunnel.
async fn connect_http_connect(
    proxy_host: &str,
    proxy_port: u16,
    proxy_user: Option<&str>,
    proxy_pass: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> io::Result<TcpStream> {
    debug!(
        %proxy_host,
        proxy_port,
        %target_host,
        target_port,
        "negotiating HTTP CONNECT tunnel"
    );

    let mut stream = TcpStream::connect((proxy_host, proxy_port)).await?;

    let authority = format_host_port_authority(target_host, target_port);
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Proxy-Connection: Keep-Alive\r\n\
         User-Agent: FreeSCP\r\n"
    );
    if proxy_user.is_some() || proxy_pass.is_some() {
        let user = proxy_user.unwrap_or("");
        let pass = proxy_pass.unwrap_or("");
        let credentials = format!("{user}:{pass}");
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let encoded = STANDARD.encode(credentials.as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let head = read_http_connect_response(&mut stream).await?;
    let status_line = head.split("\r\n").next().unwrap_or("");
    if !status_line.starts_with("HTTP/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP proxy returned invalid response to CONNECT.",
        ));
    }

    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status_code = parts.next().and_then(|code| code.parse::<u16>().ok());
    match status_code {
        Some(200) => {
            debug!(%target_host, target_port, "HTTP CONNECT tunnel established");
            Ok(stream)
        }
        Some(407) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTP proxy authentication required or failed (407).",
        )),
        Some(code) if code != 0 => Err(io::Error::other(format!(
            "HTTP CONNECT tunnel rejected: {status_line}"
        ))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP proxy returned malformed CONNECT status.",
        )),
    }
}

/// Reads the CONNECT response headers one byte at a time until the blank
/// line terminates them (or the size cap is hit).
///
/// Reading byte-at-a-time is deliberate: after the headers, the same stream
/// carries tunnelled payload (an SSH banner can arrive immediately), and any
/// buffered over-read would be lost when we return the raw [`TcpStream`].
async fn read_http_connect_response(stream: &mut TcpStream) -> io::Result<String> {
    let mut head: Vec<u8> = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while head.len() < MAX_CONNECT_RESPONSE_BYTES {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP proxy closed the connection before completing the CONNECT response.",
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&head).into_owned());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP CONNECT response headers exceed the 8192-byte limit.",
    ))
}

#[cfg(test)]
mod tests {
    use super::format_host_port_authority;

    #[test]
    fn ipv6_literals_are_bracketed() {
        assert_eq!(format_host_port_authority("::1", 22), "[::1]:22");
        assert_eq!(
            format_host_port_authority("fe80::1%en0", 22),
            "[fe80::1%en0]:22"
        );
        // Already-bracketed literals pass through unchanged.
        assert_eq!(format_host_port_authority("[::1]", 22), "[::1]:22");
    }

    #[test]
    fn hostnames_and_ipv4_pass_through() {
        assert_eq!(
            format_host_port_authority("example.com", 443),
            "example.com:443"
        );
        assert_eq!(format_host_port_authority("127.0.0.1", 22), "127.0.0.1:22");
    }
}
