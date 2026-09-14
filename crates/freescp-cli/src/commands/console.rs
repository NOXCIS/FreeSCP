//! `freescp console` — interactive telnet console.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use freescp_core::telnet::{self, TelnetEvent, TelnetSession};
use freescp_core::Protocol;

use crate::cli::ConsoleArgs;
use crate::commands::CommonArgs;
use crate::session;

/// Ctrl-] — the classic telnet escape sequence that closes the session.
const ESCAPE_BYTE: u8 = 0x1d;

pub async fn run(common: &CommonArgs, args: &ConsoleArgs) -> Result<u8> {
    if let Some(protocol) = args.conn.protocol {
        if protocol.to_core() != Protocol::Telnet {
            bail!("console only uses the telnet protocol (drop --protocol)");
        }
    }

    let target = session::parse_target(&args.target)?;
    let options = session::prepare(&args.conn, &target, Protocol::Telnet)?;
    let (session, mut events) = telnet::connect(&options).await?;

    let guard = RawModeGuard::enable()?;
    if !common.quiet {
        eprintln!(
            "freescp: connected to {} — press Ctrl-] to disconnect",
            session::describe(&options)
        );
    }

    if let Ok((cols, rows)) = crossterm::terminal::size() {
        session.resize(cols, rows);
    }
    tokio::spawn(watch_resize(session.clone()));

    let interactive_input = std::io::stdin().is_terminal();
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    tokio::spawn(read_stdin(input_tx));

    let mut input_open = true;
    let mut stdout = tokio::io::stdout();
    let exit_code;
    loop {
        tokio::select! {
            chunk = input_rx.recv(), if input_open => match chunk {
                Some(bytes) => {
                    if let Some(index) = bytes.iter().position(|byte| *byte == ESCAPE_BYTE) {
                        if index > 0 {
                            session.send(&bytes[..index]);
                        }
                        exit_code = 0;
                        break;
                    }
                    session.send(&bytes);
                }
                None => {
                    input_open = false;
                    if !interactive_input {
                        // Piped input ended: give the server a moment to
                        // answer, then drop the session instead of hanging.
                        let session = session.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            session.close();
                        });
                    }
                }
            },
            event = events.recv() => match event {
                Some(TelnetEvent::Data(data)) => {
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
                Some(TelnetEvent::Closed) => { exit_code = 0; break; }
                Some(TelnetEvent::Error(message)) => {
                    eprintln!("\r\nfreescp: {message}");
                    exit_code = 1;
                    break;
                }
                None => { exit_code = 0; break; }
            },
        }
    }

    session.close();
    drop(guard);
    // Leave the terminal on a fresh line after raw-mode output.
    println!();
    Ok(exit_code)
}

/// Restores the terminal on every exit path, panics included.
struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> Result<Self> {
        // Piped stdin has no terminal settings to save; raw mode is only
        // meaningful (and only works) on an interactive terminal.
        if std::io::stdin().is_terminal() {
            crossterm::terminal::enable_raw_mode().context("could not enable raw terminal mode")?;
        }
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if std::io::stdin().is_terminal() {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

async fn read_stdin(tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
    let mut stdin = tokio::io::stdin();
    let mut buffer = [0u8; 4096];
    loop {
        match stdin.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if tx.send(buffer[..read].to_vec()).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// Sends NAWS updates when the terminal is resized (SIGWINCH on Unix; a
/// one-second poll elsewhere).
#[cfg(unix)]
async fn watch_resize(session: TelnetSession) {
    use tokio::signal::unix::{signal, SignalKind};

    let Ok(mut window_change) = signal(SignalKind::window_change()) else {
        return;
    };
    while window_change.recv().await.is_some() {
        if let Ok((cols, rows)) = crossterm::terminal::size() {
            session.resize(cols, rows);
        }
    }
}

#[cfg(not(unix))]
async fn watch_resize(session: TelnetSession) {
    let mut last = (0u16, 0u16);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Ok((cols, rows)) = crossterm::terminal::size() {
            if (cols, rows) != last {
                last = (cols, rows);
                session.resize(cols, rows);
            }
        }
    }
}
