//! `freescp mkdir` — create a remote directory.

use anyhow::Result;

use freescp_core::{Protocol, SftpClient};

use crate::cli::MkdirArgs;
use crate::commands::{connect, parse_mode, CommonArgs};
use crate::session;

pub async fn run(common: &CommonArgs, args: &MkdirArgs) -> Result<u8> {
    let target = session::parse_target(&args.target)?;
    let protocol = session::resolved_protocol(&args.conn, Protocol::Sftp);
    session::require_file_protocol(protocol)?;
    let mode = parse_mode(&args.mode)?;

    let options = session::prepare(&args.conn, &target, protocol)?;
    let mut client = connect(&options, common.quiet).await?;
    let outcome = if args.parents {
        create_parents(client.as_mut(), &args.path, mode).await
    } else {
        client.mkdir(&args.path, mode).await.map_err(Into::into)
    };
    let _ = client.disconnect().await;
    outcome?;

    if !common.quiet {
        eprintln!("freescp: created {}", args.path);
    }
    Ok(0)
}

/// Creates every missing component of `path` (`mkdir -p`).
async fn create_parents(client: &mut dyn SftpClient, path: &str, mode: u32) -> Result<()> {
    let mut prefix = if path.starts_with('/') {
        String::from("/")
    } else {
        String::new()
    };
    for segment in path.split('/').filter(|s| !s.is_empty() && *s != ".") {
        if prefix.is_empty() {
            prefix = segment.to_string();
        } else if prefix == "/" {
            prefix.push_str(segment);
        } else {
            prefix.push('/');
            prefix.push_str(segment);
        }
        if client.exists(&prefix).await.unwrap_or(None) != Some(true) {
            client.mkdir(&prefix, mode).await?;
        }
    }
    Ok(())
}
