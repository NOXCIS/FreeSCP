//! `freescp stat` — show metadata for a remote path.

use anyhow::Result;

use freescp_core::Protocol;

use crate::cli::StatArgs;
use crate::commands::{connect, CommonArgs};
use crate::output;
use crate::session;

pub async fn run(common: &CommonArgs, args: &StatArgs) -> Result<u8> {
    let target = session::parse_target(&args.target)?;
    let protocol = session::resolved_protocol(&args.conn, Protocol::Sftp);
    session::require_file_protocol(protocol)?;

    let options = session::prepare(&args.conn, &target, protocol)?;
    let mut client = connect(&options, common.quiet).await?;
    let info = client.stat(&args.path).await;
    let _ = client.disconnect().await;
    let info = info?;

    if common.json {
        output::print_json(&output::file_info_json(&info))?;
        return Ok(0);
    }

    println!("Path:     {}", args.path);
    println!("Name:     {}", info.name);
    println!(
        "Type:     {}",
        if info.is_dir { "directory" } else { "file" }
    );
    println!(
        "Size:     {}",
        if info.has_size {
            output::format_size(info.size)
        } else {
            "unknown".to_string()
        }
    );
    println!(
        "Mode:     {}",
        if info.mode == 0 {
            "unknown".to_string()
        } else {
            format!(
                "{} ({:04o})",
                output::format_mode(info.mode, info.is_dir),
                info.mode & 0o7777
            )
        }
    );
    println!("Owner:    {}:{}", info.uid, info.gid);
    println!("Modified: {}", output::format_time(info.mtime));
    Ok(0)
}
