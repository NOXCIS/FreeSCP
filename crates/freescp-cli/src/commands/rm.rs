//! `freescp rm` — remove remote files or empty directories.

use anyhow::{bail, Result};

use freescp_core::{Protocol, SftpClient};

use crate::cli::RmArgs;
use crate::commands::{connect, CommonArgs};
use crate::session;

pub async fn run(common: &CommonArgs, args: &RmArgs) -> Result<u8> {
    let target = session::parse_target(&args.target)?;
    let protocol = session::resolved_protocol(&args.conn, Protocol::Sftp);
    session::require_file_protocol(protocol)?;

    let options = session::prepare(&args.conn, &target, protocol)?;
    let mut client = connect(&options, common.quiet).await?;
    let outcome = remove_paths(client.as_mut(), &args.paths, args.force).await;
    let _ = client.disconnect().await;
    outcome?;

    if !common.quiet {
        for path in &args.paths {
            eprintln!("freescp: removed {path}");
        }
    }
    Ok(0)
}

async fn remove_paths(client: &mut dyn SftpClient, paths: &[String], force: bool) -> Result<()> {
    for path in paths {
        match client.exists(path).await {
            Ok(None) => {
                if !force {
                    bail!("{path}: no such file or directory");
                }
            }
            Ok(Some(true)) => client.remove_dir(path).await?,
            Ok(Some(false)) => client.remove_file(path).await?,
            Err(err) => {
                if !force {
                    return Err(err.into());
                }
            }
        }
    }
    Ok(())
}
