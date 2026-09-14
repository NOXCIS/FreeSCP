//! `freescp exists` — test whether a remote path exists.

use anyhow::Result;

use freescp_core::Protocol;

use crate::cli::ExistsArgs;
use crate::commands::{connect, CommonArgs};
use crate::output;
use crate::session;

pub async fn run(common: &CommonArgs, args: &ExistsArgs) -> Result<u8> {
    let target = session::parse_target(&args.target)?;
    let protocol = session::resolved_protocol(&args.conn, Protocol::Sftp);
    session::require_file_protocol(protocol)?;

    let options = session::prepare(&args.conn, &target, protocol)?;
    let mut client = connect(&options, common.quiet).await?;
    let exists = client.exists(&args.path).await;
    let _ = client.disconnect().await;
    let exists = exists?;

    match exists {
        Some(is_dir) => {
            if common.json {
                output::print_json(&serde_json::json!({
                    "path": args.path,
                    "exists": true,
                    "is_dir": is_dir,
                }))?;
            } else {
                println!(
                    "{} exists ({})",
                    args.path,
                    if is_dir { "directory" } else { "file" }
                );
            }
            Ok(0)
        }
        None => {
            if common.json {
                output::print_json(&serde_json::json!({
                    "path": args.path,
                    "exists": false,
                }))?;
            } else {
                println!("{} does not exist", args.path);
            }
            Ok(1)
        }
    }
}
