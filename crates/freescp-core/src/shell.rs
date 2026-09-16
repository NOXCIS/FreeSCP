//! SSH shell (PTY) sessions for the embedded terminal workspace.
//!
//! Unlike the file-transfer backends, a shell is not expressed through the
//! [`SftpClient`](crate::SftpClient) trait: the session exposes a small
//! handle ([`ShellSession`]) with `send`/`resize`/`close` and produces
//! decoded data events ([`ShellEvent`]) on an unbounded channel — the same
//! shape as [`crate::telnet::TelnetSession`], so the app's terminal view can
//! drive either transport.
//!
//! # Lifecycle
//!
//! * [`connect`] dials through [`crate::ssh_transport::connect_and_auth`]
//!   (proxy / jump tunnel / known-hosts policy / the full auth chain), opens
//!   a session channel, requests an `xterm-256color` PTY and the user's
//!   login shell.
//! * The channel is split: a reader task drains [`ChannelMsg`]s into
//!   [`ShellEvent`]s, a writer task forwards queued input and resize
//!   requests (`window_change`). The SSH handle lives in the reader task, so
//!   the connection stays up for as long as the session does.
//! * The reader exits on the server's EOF/Close, when the socket fails, or
//!   when every [`ShellSession`] handle is dropped. Either way the channel is
//!   released.
//! * The first terminal event (`Closed`/`Error`) wins; later ones are
//!   dropped, so consumers may treat it as final (mirrors the telnet
//!   transport).
//!
//! # Backpressure
//!
//! The channels are unbounded: a server that produces output faster than the
//! consumer drains it grows the event queue without limit, as does user input
//! queued while the socket is stalled. Consumers must drain [`ShellEvent`]s
//! promptly and drop the session when they stop reading; the in-tree console
//! forwarder does.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use russh::client::Handle;
use russh::ChannelMsg;
use tokio::sync::mpsc;
use tracing::debug;

use crate::client::ClientError;
use crate::ssh_transport::{self, SshHandler};
use crate::types::SessionOptions;

/// TERMINAL value requested for the remote PTY. Matches the terminal type the
/// Telnet transport advertises by default.
const TERMINAL_TYPE: &str = "xterm-256color";
/// Bound on the final `close()` flush so a peer that stopped reading cannot
/// park the writer task forever.
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Events produced by a live shell session.
#[derive(Debug)]
pub enum ShellEvent {
    /// Data from the remote shell (stdout and stderr are merged).
    Data(Vec<u8>),
    /// The remote side closed the session (EOF / channel close).
    Closed,
    /// The connection failed mid-session (user-facing message).
    Error(String),
}

/// Message from the app side to the writer task.
enum ClientMsg {
    /// User input; written straight to the channel.
    Data(Vec<u8>),
    /// Window resize; forwarded as an SSH `window-change` request.
    Resize { cols: u16, rows: u16 },
    /// Close the session now.
    Close,
}

/// Handle to a connected SSH shell session.
///
/// Cloning is cheap (it clones the command-channel sender). Dropping every
/// clone also closes the session — `close()` is the explicit variant.
#[derive(Clone, Debug)]
pub struct ShellSession {
    tx: mpsc::UnboundedSender<ClientMsg>,
}

impl ShellSession {
    /// Queues user input for the remote PTY.
    pub fn send(&self, data: &[u8]) {
        let _ = self.tx.send(ClientMsg::Data(data.to_vec()));
    }

    /// Resizes the terminal; sends an SSH `window-change` request.
    pub fn resize(&self, cols: u16, rows: u16) {
        let _ = self.tx.send(ClientMsg::Resize { cols, rows });
    }

    /// Closes the session. Equivalent to dropping all handles.
    pub fn close(&self) {
        let _ = self.tx.send(ClientMsg::Close);
    }
}

/// Connects an SSH shell session from [`SessionOptions`] and returns the
/// handle plus the event receiver. `cols`/`rows` size the initial PTY.
pub async fn connect(
    opt: &SessionOptions,
    cols: u16,
    rows: u16,
) -> Result<(ShellSession, mpsc::UnboundedReceiver<ShellEvent>), ClientError> {
    let host = opt.host.trim().to_string();
    if host.is_empty() {
        return Err(ClientError::Other(
            "Cannot connect: the host is empty".to_string(),
        ));
    }

    let handle: Handle<SshHandler> = ssh_transport::connect_and_auth(opt).await?;
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| ClientError::Other(format!("failed to open session channel: {e}")))?;
    let (read_half, write_half) = channel.split();

    write_half
        .request_pty(
            true,
            TERMINAL_TYPE,
            u32::from(cols.max(1)),
            u32::from(rows.max(1)),
            0,
            0,
            &[],
        )
        .await
        .map_err(|e| ClientError::Other(format!("failed to request a PTY: {e}")))?;
    write_half
        .request_shell(true)
        .await
        .map_err(|e| ClientError::Other(format!("failed to start the remote shell: {e}")))?;

    let (tx, rx) = mpsc::unbounded_channel();
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let terminal = TerminalSignal::new(event_tx.clone());

    debug!(host = %host, port = opt.port, cols, rows, "shell session connected");
    tokio::spawn(reader_loop(read_half, event_tx, terminal.clone(), handle));
    tokio::spawn(writer_loop(write_half, rx, terminal));

    Ok((ShellSession { tx }, event_rx))
}

/// Delivers the session's single terminal event (`Closed`/`Error`). The
/// reader and the writer can both observe the same channel failure; the first
/// one wins and later attempts are dropped, so consumers may treat the first
/// terminal event as final.
#[derive(Clone)]
struct TerminalSignal {
    sent: Arc<AtomicBool>,
    tx: mpsc::UnboundedSender<ShellEvent>,
}

impl TerminalSignal {
    fn new(tx: mpsc::UnboundedSender<ShellEvent>) -> Self {
        Self {
            sent: Arc::new(AtomicBool::new(false)),
            tx,
        }
    }

    fn emit(&self, event: ShellEvent) {
        if !self.sent.swap(true, Ordering::SeqCst) {
            let _ = self.tx.send(event);
        }
    }
}

/// Drains channel messages into [`ShellEvent`]s. `_handle` keeps the SSH
/// connection alive for as long as the session is being read.
async fn reader_loop(
    mut read_half: russh::ChannelReadHalf,
    event_tx: mpsc::UnboundedSender<ShellEvent>,
    terminal: TerminalSignal,
    _handle: Handle<SshHandler>,
) {
    loop {
        let Some(msg) = read_half.wait().await else {
            terminal.emit(ShellEvent::Closed);
            break;
        };
        match msg {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                if event_tx.send(ShellEvent::Data(data.to_vec())).is_err() {
                    break;
                }
            }
            ChannelMsg::Eof | ChannelMsg::Close => {
                terminal.emit(ShellEvent::Closed);
                break;
            }
            // PTY/shell replies and window bookkeeping: nothing to render.
            // A rejected PTY or shell request surfaces as an unusable
            // terminal, so report it instead of leaving a dead screen.
            ChannelMsg::Failure => {
                terminal.emit(ShellEvent::Error(
                    "the server rejected the PTY or shell request".to_string(),
                ));
                break;
            }
            _ => {}
        }
    }
    debug!("shell reader finished");
}

/// Forwards queued input and resize requests to the channel.
async fn writer_loop(
    write_half: russh::ChannelWriteHalf<russh::client::Msg>,
    mut client_rx: mpsc::UnboundedReceiver<ClientMsg>,
    terminal: TerminalSignal,
) {
    while let Some(msg) = client_rx.recv().await {
        match msg {
            ClientMsg::Data(data) => {
                if let Err(e) = write_half.data_bytes(data).await {
                    terminal.emit(ShellEvent::Error(format!("shell write failed: {e}")));
                    break;
                }
            }
            ClientMsg::Resize { cols, rows } => {
                if let Err(e) = write_half
                    .window_change(u32::from(cols.max(1)), u32::from(rows.max(1)), 0, 0)
                    .await
                {
                    // A resize on a session that is already gone is not fatal
                    // by itself; the reader reports the terminal event.
                    debug!("shell resize failed: {e}");
                }
            }
            ClientMsg::Close => {
                // `eof` then `close`: the server sees an orderly hangup and
                // typically exits the shell, which stops the reader too.
                let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
                    let _ = write_half.eof().await;
                    let _ = write_half.close().await;
                })
                .await;
                break;
            }
        }
    }
    debug!("shell writer finished");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_with_rx() -> (ShellSession, mpsc::UnboundedReceiver<ClientMsg>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (ShellSession { tx }, rx)
    }

    #[test]
    fn send_resize_close_queue_in_order() {
        let (session, mut rx) = session_with_rx();

        session.send(b"ls\n");
        session.resize(120, 40);
        session.close();

        match rx.try_recv().expect("data queued") {
            ClientMsg::Data(bytes) => assert_eq!(bytes, b"ls\n"),
            _ => panic!("expected data"),
        }
        match rx.try_recv().expect("resize queued") {
            ClientMsg::Resize { cols, rows } => assert_eq!((cols, rows), (120, 40)),
            _ => panic!("expected resize"),
        }
        assert!(matches!(
            rx.try_recv().expect("close queued"),
            ClientMsg::Close
        ));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn dropped_session_closes_the_command_channel() {
        let (session, mut rx) = session_with_rx();
        drop(session);
        // The writer loop treats a closed command channel as "session over".
        assert!(rx.blocking_recv().is_none());
    }

    #[test]
    fn terminal_signal_delivers_only_the_first_event() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let signal = TerminalSignal::new(tx);

        signal.emit(ShellEvent::Closed);
        signal.emit(ShellEvent::Error("late".into()));

        assert!(matches!(rx.try_recv(), Ok(ShellEvent::Closed)));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn empty_host_is_rejected_before_dialing() {
        let opt = SessionOptions {
            host: "  ".to_string(),
            ..SessionOptions::default()
        };
        let err = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(connect(&opt, 80, 24))
            .expect_err("empty host must fail");
        assert!(err.to_string().contains("host is empty"));
    }
}
