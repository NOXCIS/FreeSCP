//! Human-readable and JSON rendering of remote file metadata.

use anyhow::Result;
use chrono::{Local, TimeZone};
use freescp_core::FileInfo;
use serde_json::{json, Value};

/// Formats a byte count using binary units (`1.5 KiB`).
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Formats POSIX mode bits as an `ls -l`-style string.
pub fn format_mode(mode: u32, is_dir: bool) -> String {
    let file_type = if is_dir { 'd' } else { '-' };
    if mode == 0 {
        return format!("{file_type}---------");
    }
    let mut out = String::with_capacity(10);
    out.push(file_type);
    for shift in [6u32, 3, 0] {
        for (index, flag) in ['r', 'w', 'x'].iter().enumerate() {
            let bit = shift + 2 - index as u32;
            out.push(if mode & (1 << bit) != 0 { *flag } else { '-' });
        }
    }
    out
}

/// Formats a Unix epoch timestamp in local time (`-` when unknown).
pub fn format_time(mtime: u64) -> String {
    if mtime == 0 {
        return "-".to_string();
    }
    match Local.timestamp_opt(mtime as i64, 0).single() {
        Some(time) => time.format("%Y-%m-%d %H:%M").to_string(),
        None => "-".to_string(),
    }
}

/// JSON representation of one entry.
pub fn file_info_json(info: &FileInfo) -> Value {
    json!({
        "name": info.name,
        "is_dir": info.is_dir,
        "size": if info.has_size { Some(info.size) } else { None },
        "mtime": if info.mtime != 0 { Some(info.mtime) } else { None },
        "mode": if info.mode != 0 { Some(info.mode) } else { None },
        "uid": info.uid,
        "gid": info.gid,
    })
}

/// Prints a pretty JSON value to stdout.
pub fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Prints a directory listing: one `ls -l`-style line per entry, or a JSON
/// array. `.`/`..` entries are hidden.
pub fn print_listing(entries: &[FileInfo], json_output: bool) -> Result<()> {
    let mut entries: Vec<&FileInfo> = entries
        .iter()
        .filter(|entry| entry.name != "." && entry.name != "..")
        .collect();
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    if json_output {
        let array: Vec<Value> = entries.iter().map(|entry| file_info_json(entry)).collect();
        return print_json(&Value::Array(array));
    }

    for entry in entries {
        let size = if entry.has_size {
            format_size(entry.size)
        } else {
            "-".to_string()
        };
        let name = if entry.is_dir {
            format!("{}/", entry.name)
        } else {
            entry.name.clone()
        };
        println!(
            "{} {:>10} {} {}",
            format_mode(entry.mode, entry.is_dir),
            size,
            format_time(entry.mtime),
            name
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_sizes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(999), "999 B");
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn formats_modes() {
        assert_eq!(format_mode(0o755, true), "drwxr-xr-x");
        assert_eq!(format_mode(0o644, false), "-rw-r--r--");
        assert_eq!(format_mode(0o600, false), "-rw-------");
        assert_eq!(format_mode(0, false), "----------");
    }

    #[test]
    fn listing_json_contains_entries() {
        let entries = [
            FileInfo {
                name: "b.txt".into(),
                size: 12,
                has_size: true,
                ..FileInfo::default()
            },
            FileInfo {
                name: "..".into(),
                is_dir: true,
                ..FileInfo::default()
            },
            FileInfo {
                name: "a".into(),
                is_dir: true,
                ..FileInfo::default()
            },
        ];
        let mut visible: Vec<&FileInfo> = entries
            .iter()
            .filter(|entry| entry.name != "." && entry.name != "..")
            .collect();
        visible.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        assert_eq!(
            visible.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            ["a", "b.txt"]
        );
    }
}
