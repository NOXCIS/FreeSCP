//! `freescp get` — download a remote file.

use anyhow::Result;

use freescp_core::Protocol;

use crate::cli::GetArgs;
use crate::commands::{
    cancel_cb, cancel_flag, connect, remote_file_name, CommonArgs, TransferProgress,
};
use crate::session;

pub async fn run(common: &CommonArgs, args: &GetArgs) -> Result<u8> {
    let target = session::parse_target(&args.target)?;
    let protocol = session::resolved_protocol(&args.conn, Protocol::Sftp);
    session::require_file_protocol(protocol)?;
    session::require_transfers(protocol)?;

    let local = match &args.local {
        Some(local) => local.clone(),
        None => remote_file_name(&args.remote)?,
    };

    let options = session::prepare(&args.conn, &target, protocol)?;
    let mut client = connect(&options, common.quiet).await?;

    let progress = TransferProgress::new(&local, common.quiet);
    let flag = cancel_flag();
    let outcome = client
        .get(
            &args.remote,
            &local,
            progress.callback(),
            Some(cancel_cb(&flag)),
            args.resume,
        )
        .await;
    let _ = client.disconnect().await;

    match outcome {
        Ok(()) => {
            progress.finish(
                common.quiet,
                &format!("downloaded {} -> {}", args.remote, local),
            );
            Ok(0)
        }
        Err(err) => {
            progress.abort();
            Err(err.into())
        }
    }
}
