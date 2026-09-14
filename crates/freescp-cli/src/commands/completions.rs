//! `freescp completions` — generate a shell completion script.

use anyhow::Result;
use clap::CommandFactory;

use crate::cli::{Cli, CompletionsArgs};

pub fn run(args: &CompletionsArgs) -> Result<u8> {
    let mut command = Cli::command();
    clap_complete::generate(args.shell, &mut command, "freescp", &mut std::io::stdout());
    Ok(0)
}
