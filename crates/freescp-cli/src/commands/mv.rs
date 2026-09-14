//! `freescp mv` — rename or move a remote path.

use anyhow::Result;

use freescp_core::Protocol;

use crate::cli::MvArgs;
use crate::commands::{connect, CommonArgs};
use crate::session;

pub async fn run(common: &CommonArgs, args: &MvArgs) -> Result<u8> {
    let target = session::parse_target(&args.target)?;
    let protocol = session::resolved_protocol(&args.conn, Protocol::Sftp);
    session::require_file_protocol(protocol)?;

    let options = session::prepare(&args.conn, &target, protocol)?;
    let mut client = connect(&options, common.quiet).await?;
    let outcome = client
        .rename(&args.from, &args.to, !args.no_overwrite)
        .await;
    let _ = client.disconnect().await;
    outcome?;

    if !common.quiet {
        eprintln!("freescp: renamed {} -> {}", args.from, args.to);
    }
    Ok(0)
}
