//! `freescp ls` — list a remote directory.

use anyhow::Result;

use freescp_core::Protocol;

use crate::cli::LsArgs;
use crate::commands::{connect, CommonArgs};
use crate::output;
use crate::session;

pub async fn run(common: &CommonArgs, args: &LsArgs) -> Result<u8> {
    let target = session::parse_target(&args.target)?;
    let protocol = session::resolved_protocol(&args.conn, Protocol::Sftp);
    session::require_file_protocol(protocol)?;
    session::require_listing(protocol)?;

    let options = session::prepare(&args.conn, &target, protocol)?;
    let mut client = connect(&options, common.quiet).await?;
    let entries = client.list(&args.path).await;
    let _ = client.disconnect().await;

    output::print_listing(&entries?, common.json)?;
    Ok(0)
}
