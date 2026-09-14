//! `freescp chmod` — change remote permissions.

use anyhow::Result;

use freescp_core::Protocol;

use crate::cli::ChmodArgs;
use crate::commands::{connect, parse_mode, CommonArgs};
use crate::session;

pub async fn run(common: &CommonArgs, args: &ChmodArgs) -> Result<u8> {
    let target = session::parse_target(&args.target)?;
    let protocol = session::resolved_protocol(&args.conn, Protocol::Sftp);
    session::require_file_protocol(protocol)?;
    let mode = parse_mode(&args.mode)?;

    let options = session::prepare(&args.conn, &target, protocol)?;
    let mut client = connect(&options, common.quiet).await?;
    let outcome = async {
        for path in &args.paths {
            client.chmod(path, mode).await?;
        }
        Ok::<(), freescp_core::ClientError>(())
    }
    .await;
    let _ = client.disconnect().await;
    outcome?;
    Ok(0)
}
