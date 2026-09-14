//! In-process telnet session tests: a tokio mock server validates the IAC
//! negotiation round-trip, subnegotiation replies, auto-login prompt
//! matching and the telnet-over-TLS transport (with an `rcgen` self-signed
//! certificate). No external server is required.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use freescp_core::telnet::codec::{
    DO, DONT, IAC, OPT_ECHO, OPT_NAWS, OPT_SGA, OPT_TTYPE, SB, SE, WILL,
};
use freescp_core::telnet::{connect, TelnetEvent};
use freescp_core::types::{Protocol, SessionOptions};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Shorter timeout used to assert that nothing arrives (auto-login disarmed).
const QUIET_TIMEOUT: Duration = Duration::from_millis(500);

fn session_options(port: u16) -> SessionOptions {
    SessionOptions {
        protocol: Protocol::Telnet,
        host: "127.0.0.1".to_string(),
        port,
        telnet_terminal_type: "xterm-256color".to_string(),
        telnet_auto_login: true,
        username: "alice".to_string(),
        password: Some("s3cret".to_string()),
        ..SessionOptions::default()
    }
}

/// Reads up to `buf.len()` bytes with a timeout; `None` on timeout/EOF.
async fn read_some(stream: &mut TcpStream, buf: &mut [u8]) -> Option<usize> {
    match tokio::time::timeout(IO_TIMEOUT, stream.read(buf)).await {
        Ok(Ok(n)) => Some(n),
        Ok(Err(_)) | Err(_) => None,
    }
}

/// Reads bytes until `end` appears (inclusive); panics on timeout.
async fn read_until(stream: &mut TcpStream, end: &[u8]) -> Vec<u8> {
    let mut acc = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        if let Some(pos) = acc.windows(end.len()).position(|w| w == end) {
            return acc.drain(..pos + end.len()).collect();
        }
        let Some(n) = read_some(stream, &mut buf).await else {
            panic!("timed out waiting for {end:?}; got {acc:?}");
        };
        if n == 0 {
            panic!("stream closed waiting for {end:?}; got {acc:?}");
        }
        acc.extend_from_slice(&buf[..n]);
    }
}

/// Stateful reader that preserves bytes past an expected pattern (TCP
/// segments may carry several replies at once).
struct ByteReader {
    buf: Vec<u8>,
}

impl ByteReader {
    fn new() -> Self {
        ByteReader { buf: Vec::new() }
    }

    async fn expect(&mut self, stream: &mut TcpStream, expected: &[u8]) {
        let mut tmp = [0u8; 256];
        loop {
            if let Some(pos) = self.buf.windows(expected.len()).position(|w| w == expected) {
                let drained: Vec<u8> = self.buf.drain(..pos + expected.len()).collect();
                assert_eq!(drained, expected, "unexpected wire bytes before pattern");
                return;
            }
            let Some(n) = read_some(stream, &mut tmp).await else {
                panic!("timed out waiting for {expected:?}; got {:?}", self.buf);
            };
            assert!(
                n > 0,
                "stream closed waiting for {expected:?}; got {:?}",
                self.buf
            );
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }
}

/// Accumulates decoded data events until `expected` is contained in the
/// stream.
async fn collect_until(rx: &mut mpsc::UnboundedReceiver<TelnetEvent>, expected: &[u8]) -> Vec<u8> {
    let mut acc = Vec::new();
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    while !acc.windows(expected.len()).any(|w| w == expected) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            panic!("timed out waiting for data {expected:?}; got {acc:?}");
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(TelnetEvent::Data(data))) => acc.extend_from_slice(&data),
            Ok(Some(other)) => panic!("unexpected event: {other:?}"),
            Ok(None) => panic!("event channel closed"),
            Err(_) => panic!("timed out waiting for data {expected:?}; got {acc:?}"),
        }
    }
    acc
}

// ---------------------------------------------------------------------------
// Mock server helpers
// ---------------------------------------------------------------------------

/// Spawns a one-connection server running `handler`; returns the bound
/// address and the join handle. The handler runs to completion while the
/// test asserts on the client side.
async fn spawn_mock_server<F, Fut>(
    handler: F,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind mock server");
    let addr = listener.local_addr().expect("local addr");
    let join = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        handler(stream).await;
    });
    (addr, join)
}

async fn expect_bytes(stream: &mut TcpStream, expected: &[u8]) {
    // One-shot reads are fine when the peer sends exactly one reply at a
    // time (auto-login tests). Negotiation tests use `ByteReader`.
    let got = read_until(stream, expected).await;
    assert_eq!(got, expected);
}

async fn expect_silence(stream: &mut TcpStream) {
    let mut buf = [0u8; 256];
    let got = match tokio::time::timeout(QUIET_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(_)) | Err(_) => 0,
    };
    assert_eq!(got, 0, "expected silence, got {:?}", &buf[..got]);
}

// ---------------------------------------------------------------------------
// Negotiation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn negotiation_round_trip() {
    let (addr, server) = spawn_mock_server(|mut stream| async move {
        let mut wire = ByteReader::new();
        // TTYPE negotiation.
        stream.write_all(&[IAC, DO, OPT_TTYPE]).await.unwrap();
        wire.expect(&mut stream, &[IAC, WILL, OPT_TTYPE]).await;
        stream
            .write_all(&[IAC, SB, OPT_TTYPE, 1, IAC, SE])
            .await
            .unwrap();
        let mut expected = vec![IAC, SB, OPT_TTYPE, 0];
        expected.extend_from_slice(b"xterm-256color");
        expected.extend_from_slice(&[IAC, SE]);
        wire.expect(&mut stream, &expected).await;

        // NAWS negotiation announces the initial size.
        stream.write_all(&[IAC, DO, OPT_NAWS]).await.unwrap();
        let mut expected = vec![IAC, WILL, OPT_NAWS, IAC, SB, OPT_NAWS];
        expected.extend_from_slice(&80u16.to_be_bytes());
        expected.extend_from_slice(&24u16.to_be_bytes());
        expected.extend_from_slice(&[IAC, SE]);
        wire.expect(&mut stream, &expected).await;

        // Server-side ECHO is accepted.
        stream.write_all(&[IAC, WILL, OPT_ECHO]).await.unwrap();
        wire.expect(&mut stream, &[IAC, DO, OPT_ECHO]).await;

        // Signal that negotiation is complete; the client then resizes and
        // sends user data (negotiation replies precede them on the wire).
        stream.write_all(b"READY").await.unwrap();

        // A resize on the client becomes a NAWS subnegotiation.
        wire.expect(&mut stream, &[IAC, SB, OPT_NAWS, 0, 100, 0, 30, IAC, SE])
            .await;

        // Client user data arrives verbatim.
        wire.expect(&mut stream, b"hello").await;
    })
    .await;

    let (session, mut events) = connect(&session_options(addr.port())).await.unwrap();
    collect_until(&mut events, b"READY").await;
    session.resize(100, 30);
    session.send(b"hello");

    tokio::time::timeout(IO_TIMEOUT, server)
        .await
        .expect("server join timeout")
        .expect("mock server panicked");
    drop(session);
    drop(events);
}

// ---------------------------------------------------------------------------
// Data flow and IAC escaping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn data_flow_escapes_iac() {
    let (addr, server) = spawn_mock_server(|mut stream| async move {
        // Banner with an escaped literal 0xFF.
        stream
            .write_all(&[b'a', IAC, IAC, b'b', b'\r', IAC, DO, OPT_SGA])
            .await
            .unwrap();
        expect_bytes(&mut stream, &[IAC, WILL, OPT_SGA]).await;
        // Server data with commands interleaved.
        stream.write_all(b"c").await.unwrap();
        stream.write_all(&[IAC, WILL, 42]).await.unwrap();
        expect_bytes(&mut stream, &[IAC, DONT, 42]).await;
        stream.write_all(b"d").await.unwrap();
    })
    .await;

    let (session, mut events) = connect(&session_options(addr.port())).await.unwrap();
    let data = collect_until(&mut events, b"d").await;
    assert_eq!(data, &[b'a', 0xFF, b'b', b'\r', b'c', b'd']);
    drop(session);
    tokio::time::timeout(IO_TIMEOUT, server)
        .await
        .expect("server join timeout")
        .expect("mock server panicked");
}

#[tokio::test]
async fn eof_emits_closed() {
    let (addr, server) = spawn_mock_server(|mut stream| async move {
        stream.write_all(b"bye").await.unwrap();
        drop(stream);
    })
    .await;

    let (session, mut events) = connect(&session_options(addr.port())).await.unwrap();
    match tokio::time::timeout(IO_TIMEOUT, events.recv()).await {
        Ok(Some(TelnetEvent::Data(data))) => assert_eq!(data, b"bye"),
        other => panic!("expected data, got {other:?}"),
    }
    match tokio::time::timeout(IO_TIMEOUT, events.recv()).await {
        Ok(Some(TelnetEvent::Closed)) => {}
        other => panic!("expected Closed, got {other:?}"),
    }
    drop(session);
    let _ = server.await;
}

// ---------------------------------------------------------------------------
// Auto-login
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auto_login_answers_prompts_once() {
    let (addr, server) = spawn_mock_server(|mut stream| async move {
        stream.write_all(b"Welcome!\r\nlogin: ").await.unwrap();
        expect_bytes(&mut stream, b"alice\r\n").await;
        stream.write_all(b"Password: ").await.unwrap();
        expect_bytes(&mut stream, b"s3cret\r\n").await;
        // Disarmed after the password: a repeated prompt gets no reply.
        stream.write_all(b"Password: ").await.unwrap();
        expect_silence(&mut stream).await;
    })
    .await;

    let (session, mut events) = connect(&session_options(addr.port())).await.unwrap();
    collect_until(&mut events, b"Password: ").await;
    drop(session);
    tokio::time::timeout(IO_TIMEOUT, server)
        .await
        .expect("server join timeout")
        .expect("mock server panicked");
}

#[tokio::test]
async fn user_input_disarms_auto_login() {
    let (addr, server) = spawn_mock_server(|mut stream| async move {
        expect_bytes(&mut stream, b"x").await;
        stream.write_all(b"login: ").await.unwrap();
        expect_silence(&mut stream).await;
    })
    .await;

    let (session, mut events) = connect(&session_options(addr.port())).await.unwrap();
    session.send(b"x");
    collect_until(&mut events, b"login: ").await;
    drop(session);
    tokio::time::timeout(IO_TIMEOUT, server)
        .await
        .expect("server join timeout")
        .expect("mock server panicked");
}

#[tokio::test]
async fn auto_login_off_when_disabled() {
    let (addr, server) = spawn_mock_server(|mut stream| async move {
        stream.write_all(b"login: ").await.unwrap();
        expect_silence(&mut stream).await;
    })
    .await;

    let opts = SessionOptions {
        telnet_auto_login: false,
        ..session_options(addr.port())
    };
    let (session, mut events) = connect(&opts).await.unwrap();
    collect_until(&mut events, b"login: ").await;
    drop(session);
    tokio::time::timeout(IO_TIMEOUT, server)
        .await
        .expect("server join timeout")
        .expect("mock server panicked");
}

#[tokio::test]
async fn explicit_close_terminates_session() {
    let (addr, server) = spawn_mock_server(|mut stream| async move {
        // The server writes a banner; the client closes; expect EOF.
        stream.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 64];
        let n = match tokio::time::timeout(IO_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => 0,
        };
        assert_eq!(n, 0, "expected EOF after client close");
    })
    .await;

    let (session, mut events) = connect(&session_options(addr.port())).await.unwrap();
    match tokio::time::timeout(IO_TIMEOUT, events.recv()).await {
        Ok(Some(TelnetEvent::Data(data))) => assert_eq!(data, b"hello"),
        other => panic!("expected data, got {other:?}"),
    }
    session.close();
    // After close the reader emits no further events beyond the socket
    // winding down; the session handle drop must not panic.
    drop(session);
    tokio::time::timeout(IO_TIMEOUT, server)
        .await
        .expect("server join timeout")
        .expect("mock server panicked");
    // Drain whatever arrives (Data/Error/Closed) without asserting.
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100), events.recv()).await {}
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// Self-signed certificate for `127.0.0.1` plus its PEM path and the rustls
/// server config. RSA is used because rcgen's ring backend cannot generate
/// RSA keys (the `aws_lc_rs` feature provides keygen) and the client verifies
/// with ring, which accepts RSA SHA-256 signatures.
fn tls_fixture() -> (PathBuf, Arc<rustls::ServerConfig>) {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).expect("generate RSA key pair");
    let params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("certificate params");
    let cert = params
        .self_signed(&key_pair)
        .expect("self-sign certificate");
    let pem_path =
        std::env::temp_dir().join(format!("freescp_telnet_test_ca_{}.pem", std::process::id()));
    std::fs::write(&pem_path, cert.pem()).expect("write CA pem");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .expect("build server config");
    (pem_path, Arc::new(config))
}

async fn spawn_tls_server(
    config: Arc<rustls::ServerConfig>,
    handler: impl FnOnce(
            tokio_rustls::server::TlsStream<TcpStream>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + 'static,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind tls server");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let join = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(stream).await.expect("tls accept");
        handler(tls).await;
    });
    (addr, join)
}

/// A write to a socket whose peer has vanished must surface as
/// `TelnetEvent::Error`. Regression guard: the writer used to fail silently,
/// leaving a "live" session over a dead socket.
#[tokio::test]
async fn write_failure_is_reported_as_error() {
    let (addr, server) = spawn_mock_server(|stream| async move {
        // Linger 0 makes the close send an RST rather than a FIN, so the
        // client sees a hard connection error, not a clean EOF.
        socket2::SockRef::from(&stream)
            .set_linger(Some(Duration::ZERO))
            .expect("set linger on mock socket");
        drop(stream);
    })
    .await;

    let opts = SessionOptions {
        telnet_auto_login: false,
        ..session_options(addr.port())
    };
    let (session, mut events) = connect(&opts).await.unwrap();

    // Write until the socket fails; reader or writer notices the RST, and the
    // first terminal event must be an Error (a Closed would mean the session
    // looked like it ended cleanly).
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    let terminal = loop {
        session.send(b"payload");
        tokio::time::sleep(Duration::from_millis(25)).await;
        match events.try_recv() {
            Ok(event) => break Some(event),
            Err(mpsc::error::TryRecvError::Empty) => {}
            Err(mpsc::error::TryRecvError::Disconnected) => break None,
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no terminal event after repeated writes to a dead socket"
        );
    };
    match terminal {
        Some(TelnetEvent::Error(_)) => {}
        other => panic!("expected a terminal Error event, got {other:?}"),
    }

    drop(session);
    tokio::time::timeout(IO_TIMEOUT, server)
        .await
        .expect("server join timeout")
        .expect("mock server panicked");
}

#[tokio::test]
async fn tls_handshake_with_ca_verification() {
    let (ca_path, server_config) = tls_fixture();
    let (server, server_task) = spawn_tls_server(server_config.clone(), |mut tls| {
        Box::pin(async move {
            tls.write_all(b"secure").await.unwrap();
            let mut buf = [0u8; 32];
            let n = match tokio::time::timeout(IO_TIMEOUT, tls.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(_)) | Err(_) => panic!("tls read failed"),
            };
            assert_eq!(&buf[..n], b"ping");
        })
    })
    .await;

    let opts = SessionOptions {
        telnet_tls: true,
        telnet_verify_peer: true,
        telnet_ca_cert_path: Some(ca_path.display().to_string()),
        ..session_options(server.port())
    };
    let (session, mut events) = connect(&opts).await.unwrap();
    let data = collect_until(&mut events, b"secure").await;
    assert_eq!(data, b"secure");
    session.send(b"ping");
    drop(session);
    // Await the server so its assertion on the received bytes is not swallowed
    // by a detached task.
    tokio::time::timeout(IO_TIMEOUT, server_task)
        .await
        .expect("tls server join timeout")
        .expect("tls mock server panicked");
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn tls_no_peer_verification() {
    let (ca_path, server_config) = tls_fixture();
    let (server, server_task) = spawn_tls_server(server_config.clone(), |mut tls| {
        Box::pin(async move {
            tls.write_all(b"insecure").await.unwrap();
            let mut buf = [0u8; 32];
            let n = match tokio::time::timeout(IO_TIMEOUT, tls.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(_)) | Err(_) => panic!("tls read failed"),
            };
            assert_eq!(&buf[..n], b"pong");
        })
    })
    .await;

    let opts = SessionOptions {
        telnet_tls: true,
        telnet_verify_peer: false,
        ..session_options(server.port())
    };
    let (session, mut events) = connect(&opts).await.unwrap();
    let data = collect_until(&mut events, b"insecure").await;
    assert_eq!(data, b"insecure");
    session.send(b"pong");
    drop(session);
    tokio::time::timeout(IO_TIMEOUT, server_task)
        .await
        .expect("tls server join timeout")
        .expect("tls mock server panicked");
    let _ = std::fs::remove_file(&ca_path);
}
