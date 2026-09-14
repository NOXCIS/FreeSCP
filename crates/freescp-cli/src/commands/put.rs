//! `freescp put` — upload a local file.

use std::path::Path;

use anyhow::{bail, Result};

use freescp_core::Protocol;

use crate::cli::PutArgs;
use crate::commands::{cancel_cb, cancel_flag, connect, CommonArgs, TransferProgress};
use crate::session;

pub async fn run(common: &CommonArgs, args: &PutArgs) -> Result<u8> {
    let target = session::parse_target(&args.target)?;
    let protocol = session::resolved_protocol(&args.conn, Protocol::Sftp);
    session::require_file_protocol(protocol)?;
    session::require_transfers(protocol)?;

    let local_path = Path::new(&args.local);
    if !local_path.is_file() {
        bail!(
            "local file '{}' does not exist or is not a regular file",
            args.local
        );
    }
    let remote = match &args.remote {
        Some(remote) => remote.clone(),
        None => local_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "cannot derive a remote file name from '{}'; pass one explicitly",
                    args.local
                )
            })?
            .to_string(),
    };

    let options = session::prepare(&args.conn, &target, protocol)?;
    let mut client = connect(&options, common.quiet).await?;

    let progress = TransferProgress::new(&remote, common.quiet);
    let flag = cancel_flag();
    let outcome = client
        .put(
            &args.local,
            &remote,
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
                &format!("uploaded {} -> {}", args.local, remote),
            );
            Ok(0)
        }
        Err(err) => {
            progress.abort();
            Err(err.into())
        }
    }
}
