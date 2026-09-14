//! Telnet interactive console transport (RFC 854) with IAC option
//! negotiation (RFC 855/857/858/1073/1091), telnet-over-TLS (RFC 854
//! `telnets`, default port 992) and optional prompt-based auto-login.
//!
//! Unlike the file-transfer backends, telnet is not expressed through the
//! [`SftpClient`](crate::SftpClient) trait: the session exposes a small
//! handle ([`TelnetSession`]) with `send`/`resize`/`close` and produces
//! decoded data events ([`TelnetEvent`]) on an unbounded channel.
//!
//! # Lifecycle
//!
//! * [`connect`] performs the TCP/TLS handshake and spawns two tasks: a
//!   reader (owns the [`codec::TelnetCodec`], strips IAC, answers
//!   negotiation, runs auto-login) and a writer (drains raw wire bytes).
//! * The reader exits on EOF, I/O error, an explicit `close`, or when every
//!   [`TelnetSession`] handle is dropped (all senders of the command channel
//!   are gone). Either way both socket halves are released.
//! * A socket *write* failure ends the session too: the writer reports
//!   [`TelnetEvent::Error`] instead of leaving a live-looking session on a
//!   dead socket. Reader and writer share one terminal-event slot, so
//!   consumers see at most one `Error`/`Closed` and may treat it as final.
//!
//! # Auto-login
//!
//! When `telnet_auto_login` is enabled and both `username` and `password`
//! are set, the reader matches the classic `login:`/`Username:` and
//! `Password:` prompts in the decoded output stream and sends the
//! credentials once. The matcher disarms after the password is sent, when
//! the user starts typing, or after 60 seconds — whichever comes first.
//! Credentials are never logged.
//!
//! # Backpressure
//!
//! The session's channels are unbounded: a server that produces output faster
//! than the consumer drains it grows the event queue without limit, as does
//! user input queued while the socket is stalled. Consumers must drain
//! [`TelnetEvent`]s promptly and drop the session when they stop reading; the
//! in-tree console forwarder does.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::debug;

use crate::client::ClientError;
use crate::types::SessionOptions;

pub mod codec;
pub mod tls;

/// Mirrors the other backends' connect timeout (libcurl
/// `CURLOPT_CONNECTTIMEOUT`).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Read buffer size per socket read.
const READ_BUF: usize = 8192;
/// Auto-login arms for this long after connect.
const AUTO_LOGIN_WINDOW: Duration = Duration::from_secs(60);
/// Rolling window (decoded bytes) used for prompt matching.
const PROMPT_WINDOW: usize = 1024;
/// Bound on the final `shutdown()` flush so a peer that stopped reading (a
/// stalled TLS peer in particular) cannot park the writer task forever.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Events produced by a live telnet session.
#[derive(Debug)]
pub enum TelnetEvent {
    /// Decoded data (IAC stripped) destined for the terminal emulator.
    Data(Vec<u8>),
    /// The server closed the connection cleanly.
    Closed,
    /// The connection failed mid-session (user-facing message).
    Error(String),
}

/// Message from the app side to the reader task.
enum ClientMsg {
    /// User input; escaped by the codec before hitting the wire.
    Data(Vec<u8>),
    /// Window resize; queues a NAWS reply when negotiated.
    Resize { cols: u16, rows: u16 },
    /// Close the session now.
    Close,
}

/// Handle to a connected telnet session.
///
/// Cloning is cheap (it clones the command-channel sender). Dropping every
/// clone also closes the session — `close()` is the explicit variant.
#[derive(Clone, Debug)]
pub struct TelnetSession {
    tx: mpsc::UnboundedSender<ClientMsg>,
}

impl TelnetSession {
    /// Queues user input for the socket (`0xFF` bytes are escaped as
    /// `IAC IAC` by the codec).
    pub fn send(&self, data: &[u8]) {
        let _ = self.tx.send(ClientMsg::Data(data.to_vec()));
    }

    /// Resizes the local window; sends `SB NAWS` when the server negotiated
    /// `DO NAWS`.
    pub fn resize(&self, cols: u16, rows: u16) {
        let _ = self.tx.send(ClientMsg::Resize { cols, rows });
    }

    /// Closes the session. Equivalent to dropping all handles.
    pub fn close(&self) {
        let _ = self.tx.send(ClientMsg::Close);
    }
}

/// Combined read+write trait object used to hold either a plain TCP stream
/// or a TLS stream.
trait ReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> ReadWrite for T {}

/// Connects a telnet session from [`SessionOptions`] and returns the handle
/// plus the event receiver.
pub async fn connect(
    opt: &SessionOptions,
) -> Result<(TelnetSession, mpsc::UnboundedReceiver<TelnetEvent>), ClientError> {
    let host = opt.host.trim().to_string();
    if host.is_empty() {
        return Err(ClientError::Other(
            "Cannot connect: the telnet host is empty".to_string(),
        ));
    }
    let port = opt.port;

    let addr = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| {
            ClientError::Io(std::io::Error::new(
                e.kind(),
                format!("Could not resolve telnet host '{host}': {e}"),
            ))
        })?
        .next()
        .ok_or_else(|| {
            ClientError::Other(format!(
                "Telnet host '{host}' did not resolve to any address"
            ))
        })?;

    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| {
            ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Telnet connection timed out",
            ))
        })?
        .map_err(|e| {
            ClientError::Io(std::io::Error::new(
                e.kind(),
                format!("Could not connect to {host}:{port}: {e}"),
            ))
        })?;
    let _ = tcp.set_nodelay(true);

    let stream: Box<dyn ReadWrite + Unpin + Send> = if opt.telnet_tls {
        let config =
            tls::build_tls_config(opt.telnet_verify_peer, opt.telnet_ca_cert_path.as_deref())?;
        let connector = tokio_rustls::TlsConnector::from(config);
        let server_name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| {
            ClientError::Other(format!("Invalid telnet TLS server name '{host}': {e}"))
        })?;
        let tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
            ClientError::Other(format!(
                "Telnet TLS handshake with {host}:{port} failed: {e}"
            ))
        })?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp)
    };

    let (reader, writer) = tokio::io::split(stream);
    let reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(reader);
    let writer: Box<dyn AsyncWrite + Unpin + Send> = Box::new(writer);

    let (client_tx, client_rx) = mpsc::unbounded_channel();
    let (writer_tx, writer_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (event_tx, event_rx) = mpsc::unbounded_channel();

    let codec = codec::TelnetCodec::new(opt.telnet_terminal_type.clone(), 80, 24);
    let auto_login = AutoLogin::new(opt);

    let terminal = TerminalSignal::new(event_tx.clone());
    tokio::spawn(reader_loop(
        client_rx,
        reader,
        writer_tx,
        event_tx,
        terminal.clone(),
        codec,
        auto_login,
    ));
    tokio::spawn(writer_loop(writer_rx, writer, terminal));

    debug!(host = %host, port, tls = opt.telnet_tls, "telnet session connected");
    Ok((TelnetSession { tx: client_tx }, event_rx))
}

/// Delivers the session's single terminal event (`Closed`/`Error`). The reader
/// and the writer can both observe the same socket failure; the first one wins
/// and later attempts are dropped, so consumers may treat the first terminal
/// event as final.
#[derive(Clone)]
struct TerminalSignal {
    sent: Arc<AtomicBool>,
    tx: mpsc::UnboundedSender<TelnetEvent>,
}

impl TerminalSignal {
    fn new(tx: mpsc::UnboundedSender<TelnetEvent>) -> Self {
        Self {
            sent: Arc::new(AtomicBool::new(false)),
            tx,
        }
    }

    fn emit(&self, event: TelnetEvent) {
        if !self.sent.swap(true, Ordering::SeqCst) {
            let _ = self.tx.send(event);
        }
    }
}

async fn reader_loop(
    mut client_rx: mpsc::UnboundedReceiver<ClientMsg>,
    mut reader: Box<dyn AsyncRead + Unpin + Send>,
    writer_tx: mpsc::UnboundedSender<Vec<u8>>,
    event_tx: mpsc::UnboundedSender<TelnetEvent>,
    terminal: TerminalSignal,
    mut codec: codec::TelnetCodec,
    mut auto_login: AutoLogin,
) {
    let mut buf = vec![0u8; READ_BUF];
    let mut decoded = Vec::new();
    loop {
        tokio::select! {
            msg = client_rx.recv() => {
                match msg {
                    Some(ClientMsg::Data(data)) => {
                        auto_login.note_user_input();
                        let mut encoded = Vec::with_capacity(data.len() + 8);
                        codec.encode(&data, &mut encoded);
                        if writer_tx.send(encoded).is_err() {
                            break;
                        }
                    }
                    Some(ClientMsg::Resize { cols, rows }) => {
                        codec.resize(cols, rows);
                        let reply = codec.drain_replies();
                        if !reply.is_empty() && writer_tx.send(reply).is_err() {
                            break;
                        }
                    }
                    Some(ClientMsg::Close) | None => break,
                }
            }
            read = reader.read(&mut buf) => {
                match read {
                    Ok(0) => {
                        terminal.emit(TelnetEvent::Closed);
                        break;
                    }
                    Ok(n) => {
                        decoded.clear();
                        codec.process(&buf[..n], &mut decoded);
                        let reply = codec.drain_replies();
                        if !reply.is_empty() && writer_tx.send(reply).is_err() {
                            break;
                        }
                        if !decoded.is_empty() {
                            if let Some(response) = auto_login.feed(&decoded) {
                                let mut encoded = Vec::with_capacity(response.len() + 8);
                                codec.encode(response.as_bytes(), &mut encoded);
                                if writer_tx.send(encoded).is_err() {
                                    break;
                                }
                            }
                            if event_tx
                                .send(TelnetEvent::Data(std::mem::take(&mut decoded)))
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        terminal.emit(TelnetEvent::Error(e.to_string()));
                        break;
                    }
                }
            }
        }
    }
}

async fn writer_loop(
    mut writer_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut writer: Box<dyn AsyncWrite + Unpin + Send>,
    terminal: TerminalSignal,
) {
    while let Some(bytes) = writer_rx.recv().await {
        if let Err(e) = writer.write_all(&bytes).await {
            // Without this the reader would only break on its next write and
            // the UI would keep showing a live session over a dead socket.
            terminal.emit(TelnetEvent::Error(format!(
                "Telnet connection lost while sending: {e}"
            )));
            break;
        }
    }
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, writer.shutdown()).await;
}

// ---------------------------------------------------------------------------
// Auto-login
// ---------------------------------------------------------------------------

/// Prompt-based auto-login: matches `login:`/`Username:` and `Password:`
/// prompts in the decoded stream and sends the stored credentials once.
struct AutoLogin {
    username: String,
    password: String,
    armed: bool,
    sent_user: bool,
    sent_pass: bool,
    deadline: tokio::time::Instant,
    window: Vec<u8>,
}

impl AutoLogin {
    fn new(opt: &SessionOptions) -> Self {
        let username = opt.username.trim().to_string();
        let has_password = opt.password.as_deref().is_some_and(|p| !p.is_empty());
        let armed = opt.telnet_auto_login && !username.is_empty() && has_password;
        AutoLogin {
            username,
            password: opt.password.clone().unwrap_or_default(),
            armed,
            sent_user: false,
            sent_pass: false,
            deadline: tokio::time::Instant::now() + AUTO_LOGIN_WINDOW,
            window: Vec::new(),
        }
    }

    /// The user typed something: they are handling login themselves.
    fn note_user_input(&mut self) {
        self.armed = false;
    }

    /// Feeds decoded output; returns the bytes to send when a prompt was
    /// matched.
    fn feed(&mut self, data: &[u8]) -> Option<String> {
        if !self.armed || self.sent_pass {
            return None;
        }
        if tokio::time::Instant::now() > self.deadline {
            self.armed = false;
            return None;
        }
        self.window.extend_from_slice(data);
        let excess = self.window.len().saturating_sub(PROMPT_WINDOW);
        if excess > 0 {
            self.window.drain(..excess);
        }
        let line = last_prompt_line(&self.window)?;
        if !self.sent_user && is_user_prompt(line) {
            self.sent_user = true;
            return Some(format!("{}\r\n", self.username));
        }
        if self.sent_user && is_password_prompt(line) {
            self.sent_pass = true;
            self.armed = false;
            return Some(format!("{}\r\n", self.password));
        }
        None
    }
}

/// Last non-empty line of the rolling window (prompts sit at the end of a
/// line).
fn last_prompt_line(window: &[u8]) -> Option<&[u8]> {
    let trimmed = trim_ascii_end(window);
    if trimmed.is_empty() {
        return None;
    }
    let start = trimmed
        .iter()
        .rposition(|&b| b == b'\n' || b == b'\r')
        .map(|i| i + 1)
        .unwrap_or(0);
    Some(&trimmed[start..])
}

fn trim_ascii_end(mut bytes: &[u8]) -> &[u8] {
    while let Some((&last, rest)) = bytes.split_last() {
        if matches!(last, b' ' | b'\t' | b'\r' | b'\n' | 0) {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

/// ASCII-lowercases `bytes`, keeping only letters (digits pass through too).
fn ascii_lower(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|&b| if b.is_ascii_uppercase() { b + 32 } else { b })
        .collect()
}

fn is_user_prompt(line: &[u8]) -> bool {
    let lower = ascii_lower(line);
    let lower = trim_ascii_end(&lower);
    if !lower.ends_with(b":") {
        return false;
    }
    let body = &lower[..lower.len() - 1];
    body.ends_with(b"login")
        || body.ends_with(b"username")
        || body.ends_with(b"user")
        || body.ends_with(b"login as")
}

fn is_password_prompt(line: &[u8]) -> bool {
    let lower = ascii_lower(line);
    let lower = trim_ascii_end(&lower);
    if !lower.ends_with(b":") {
        return false;
    }
    // "password:", "Password for user:", "passcode:" — any password mention
    // followed by the prompt colon.
    let body = &lower[..lower.len() - 1];
    body.windows(8).any(|w| w == b"password") || body.ends_with(b"passcode")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Writer stub whose writes always fail; flushing and shutdown succeed so
    /// the writer task can finish.
    struct FailingWriter;

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "peer went away",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// The writer must report a failed write instead of silently dropping the
    /// bytes, and must still terminate.
    #[tokio::test]
    async fn writer_failure_reports_error_and_exits() {
        let (writer_tx, writer_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        writer_tx.send(b"payload".to_vec()).expect("queue payload");
        drop(writer_tx);

        let writer_task = tokio::spawn(writer_loop(
            writer_rx,
            Box::new(FailingWriter),
            TerminalSignal::new(event_tx),
        ));

        match tokio::time::timeout(Duration::from_secs(5), event_rx.recv()).await {
            Ok(Some(TelnetEvent::Error(message))) => {
                assert!(
                    message.contains("sending"),
                    "error should name the failing direction: {message}"
                );
            }
            other => panic!("expected a write-failure error, got {other:?}"),
        }
        tokio::time::timeout(Duration::from_secs(5), writer_task)
            .await
            .expect("writer task must finish after a write failure")
            .expect("writer task panicked");
    }

    /// Reader and writer can both see the same socket failure; consumers see
    /// exactly one terminal event.
    #[tokio::test]
    async fn terminal_signal_delivers_only_the_first_event() {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let signal = TerminalSignal::new(event_tx);
        signal.emit(TelnetEvent::Error("first".to_string()));
        signal.clone().emit(TelnetEvent::Closed);

        match event_rx.try_recv() {
            Ok(TelnetEvent::Error(message)) => assert_eq!(message, "first"),
            other => panic!("expected the first terminal event, got {other:?}"),
        }
        assert!(
            event_rx.try_recv().is_err(),
            "later terminal events must be dropped"
        );
    }
}
