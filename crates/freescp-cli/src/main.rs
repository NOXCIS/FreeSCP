//! `freescp` command-line client entry point.

mod cli;
mod commands;
mod output;
mod session;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    init_tracing();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("freescp: could not start the async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    ExitCode::from(runtime.block_on(commands::run(cli)))
}

/// Diagnostics go to stderr; `RUST_LOG` selects the level (default: warn).
fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
