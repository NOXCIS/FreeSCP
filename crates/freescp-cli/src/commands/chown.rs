//! `freescp chown` — change the remote owner/group.

use anyhow::Result;

use freescp_core::Protocol;

use crate::cli::ChownArgs;
use crate::commands::{connect, CommonArgs};
use crate::session;

pub async fn run(common: &CommonArgs, args: &ChownArgs) -> Result<u8> {
    let target = session::parse_target(&args.target)?;
    let protocol = session::resolved_protocol(&args.conn, Protocol::Sftp);
    session::require_file_protocol(protocol)?;

    let options = session::prepare(&args.conn, &target, protocol)?;
    let mut client = connect(&options, common.quiet).await?;
    let outcome = async {
        for path in &args.paths {
            client.chown(path, args.uid, args.gid).await?;
        }
        Ok::<(), freescp_core::ClientError>(())
    }
    .await;
    let _ = client.disconnect().await;
    outcome?;
    Ok(0)
}
