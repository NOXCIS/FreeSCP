//! Subcommand dispatch and helpers shared by the one-shot commands.

pub mod chmod;
pub mod chown;
pub mod completions;
pub mod console;
pub mod exists;
pub mod get;
pub mod ls;
pub mod mkdir;
pub mod mv;
pub mod put;
pub mod rm;
pub mod shell;
pub mod stat;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};

use freescp_core::client::{CancelCb, ProgressCb};
use freescp_core::{client_factory, ClientError, SessionOptions, SftpClient};

use crate::cli::{Cli, Command};
use crate::session;

/// Flags shared by every subcommand.
pub struct CommonArgs {
    pub json: bool,
    pub quiet: bool,
}

/// Runs the parsed command, mapping failures to process exit codes
/// (0 success, 1 error, 2 cancelled).
pub async fn run(cli: Cli) -> u8 {
    let common = CommonArgs {
        json: cli.json,
        quiet: cli.quiet,
    };
    let result = match cli.command {
        Command::Ls(args) => ls::run(&common, &args).await,
        Command::Get(args) => get::run(&common, &args).await,
        Command::Put(args) => put::run(&common, &args).await,
        Command::Mkdir(args) => mkdir::run(&common, &args).await,
        Command::Rm(args) => rm::run(&common, &args).await,
        Command::Mv(args) => mv::run(&common, &args).await,
        Command::Stat(args) => stat::run(&common, &args).await,
        Command::Chmod(args) => chmod::run(&common, &args).await,
        Command::Chown(args) => chown::run(&common, &args).await,
        Command::Exists(args) => exists::run(&common, &args).await,
        Command::Shell(args) => shell::run(&common, &args).await,
        Command::Console(args) => console::run(&common, &args).await,
        Command::Completions(args) => completions::run(&args),
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            if is_cancelled(&err) {
                eprintln!("freescp: transfer cancelled");
                2
            } else {
                eprintln!("freescp: {err:#}");
                1
            }
        }
    }
}

/// True when the error chain contains [`ClientError::Cancelled`].
pub fn is_cancelled(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<ClientError>(),
            Some(ClientError::Cancelled)
        )
    })
}

/// Installs a Ctrl-C handler that flips the returned flag; transfers poll it
/// through [`cancel_cb`] and abort cleanly.
pub fn cancel_flag() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let signal_flag = flag.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_flag.store(true, Ordering::SeqCst);
        }
    });
    flag
}

/// The polling callback handed to `get`/`put`.
pub fn cancel_cb(flag: &Arc<AtomicBool>) -> CancelCb {
    let flag = flag.clone();
    Box::new(move || flag.load(Ordering::SeqCst))
}

/// Connects and returns the client, announcing the target unless quiet.
pub async fn connect(options: &SessionOptions, quiet: bool) -> Result<Box<dyn SftpClient>> {
    if !quiet {
        eprintln!("freescp: connecting to {}", session::describe(options));
    }
    let client = client_factory::create_connected_client(options).await?;
    Ok(client)
}

/// Progress bar wired to the core `ProgressCb` contract.
pub struct TransferProgress {
    bar: Option<ProgressBar>,
    started: Instant,
}

impl TransferProgress {
    pub fn new(label: &str, quiet: bool) -> Self {
        let bar = if quiet {
            None
        } else {
            let bar = ProgressBar::new(0);
            bar.set_style(
                ProgressStyle::with_template(
                    "{msg} [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec})",
                )
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("=>-"),
            );
            bar.set_message(label.to_string());
            Some(bar)
        };
        Self {
            bar,
            started: Instant::now(),
        }
    }

    /// The callback to pass to `get`/`put` (`None` when quiet).
    pub fn callback(&self) -> Option<ProgressCb> {
        let bar = self.bar.clone()?;
        Some(Box::new(move |done, total| {
            if total > 0 {
                bar.set_length(total);
            }
            bar.set_position(done);
        }))
    }

    /// Clears the bar and reports the elapsed time on stderr.
    pub fn finish(&self, quiet: bool, summary: &str) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
        if !quiet {
            eprintln!(
                "freescp: {summary} in {:.1}s",
                self.started.elapsed().as_secs_f64()
            );
        }
    }

    /// Clears the bar after a failure without printing a summary.
    pub fn abort(&self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
    }
}

/// Derives a file name from a remote path (`/a/b.txt` -> `b.txt`).
pub fn remote_file_name(path: &str) -> Result<String> {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((_, name)) if !name.is_empty() => Ok(name.to_string()),
        _ if !trimmed.is_empty() => Ok(trimmed.to_string()),
        _ => anyhow::bail!(
            "cannot derive a file name from remote path '{path}'; pass one explicitly"
        ),
    }
}

/// Parses permission bits (`644` or `0644`) as octal.
pub fn parse_mode(raw: &str) -> Result<u32> {
    let raw = raw.trim();
    let digits = raw.strip_prefix("0o").unwrap_or(raw);
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(8)) {
        anyhow::bail!("invalid permission mode '{raw}' (expected octal digits, e.g. 644)");
    }
    u32::from_str_radix(digits, 8)
        .map_err(|err| anyhow::anyhow!("invalid permission mode '{raw}': {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_octal_modes() {
        assert_eq!(parse_mode("644").unwrap(), 0o644);
        assert_eq!(parse_mode("0644").unwrap(), 0o644);
        assert_eq!(parse_mode("0o755").unwrap(), 0o755);
        assert_eq!(parse_mode(" 600 ").unwrap(), 0o600);
        assert!(parse_mode("abc").is_err());
        assert!(parse_mode("999").is_err());
        assert!(parse_mode("").is_err());
    }
}
