//! Recent-path / recent-server history: pure-Rust port of the history
//! handling in `ui/MainWindow.cpp` (`addRecentLocalPath`,
//! `addRecentRemotePath`, `addRecentServer`, `encodeRecentServerEntry`,
//! `decodeRecentServerEntry` and the History dialog data loading).
//!
//! Qt stores three `QStringList`s under `History/recent*` keys in QSettings;
//! this port stores the same three lists in
//! `<config_dir>/freescp/history.toml`. Server entries keep the C++ on-disk
//! shape: a QUrlQuery-encoded string
//! (`protocol=sftp&host=...&port=22&user=...`), percent-encoded.

use freescp_core::{
    default_port_for_protocol, default_port_for_telnet, protocol_display_name,
    protocol_from_storage_name, protocol_storage_name, webdav_scheme_from_storage_name,
    webdav_scheme_storage_name, Protocol, SessionOptions, WebDavScheme,
};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// Maximum entries per history list, mirroring
/// `kRecentHistoryMaxEntries` in MainWindow.cpp.
pub const MAX_RECENT_ENTRIES: usize = 20;

const HISTORY_FILE: &str = "history.toml";

/// On-disk shape of the history (mirrors the three QSettings string lists).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct HistoryFile {
    recent_local_paths: Vec<String>,
    recent_remote_paths: Vec<String>,
    recent_servers: Vec<String>,
}

fn history_path() -> PathBuf {
    crate::settings::config_dir().join(HISTORY_FILE)
}

fn load_history() -> HistoryFile {
    let path = history_path();
    match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
            tracing::warn!(
                "Could not parse history file {}: {e}; starting empty",
                path.display()
            );
            HistoryFile::default()
        }),
        Err(_) => HistoryFile::default(),
    }
}

fn save_history(history: &HistoryFile) -> Result<(), String> {
    let dir = crate::settings::config_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Could not create config directory {}: {e}", dir.display()))?;
    let text = toml::to_string(history).map_err(|e| format!("Could not serialize history: {e}"))?;
    std::fs::write(history_path(), text).map_err(|e| format!("Could not write history: {e}"))
}

/// Prepends a trimmed, non-empty value, removes duplicates and truncates to
/// [`MAX_RECENT_ENTRIES`] — port of `prependRecentValue` in MainWindow.cpp.
fn prepend_recent_value(list: &mut Vec<String>, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    list.retain(|existing| existing != trimmed);
    list.insert(0, trimmed.to_string());
    list.truncate(MAX_RECENT_ENTRIES);
}

/// Adds a local path to the recent-local list, mirroring
/// `MainWindow::addRecentLocalPath`.
pub fn add_recent_local_path(path: &str) {
    let normalized = normalize_local_history_path(path);
    if normalized.is_empty() {
        return;
    }
    let mut history = load_history();
    prepend_recent_value(&mut history.recent_local_paths, &normalized);
    if let Err(e) = save_history(&history) {
        tracing::warn!("Could not persist local path history: {e}");
    }
}

/// Adds a remote path to the recent-remote list, mirroring
/// `MainWindow::addRecentRemotePath`.
pub fn add_recent_remote_path(path: &str) {
    let normalized = normalize_remote_path_for_match(path);
    if normalized.is_empty() {
        return;
    }
    let mut history = load_history();
    prepend_recent_value(&mut history.recent_remote_paths, &normalized);
    if let Err(e) = save_history(&history) {
        tracing::warn!("Could not persist remote path history: {e}");
    }
}

/// Adds a server (quick-connect preset) to the recent-server list, mirroring
/// `MainWindow::addRecentServer`. Entries are stored as the C++ QUrlQuery
/// encoding (`protocol=...&host=...&port=...&user=...`).
pub fn add_recent_server(opt: &SessionOptions) {
    let encoded = encode_recent_server(opt);
    if encoded.is_empty() {
        return;
    }
    let mut history = load_history();
    prepend_recent_value(&mut history.recent_servers, &encoded);
    if let Err(e) = save_history(&history) {
        tracing::warn!("Could not persist server history: {e}");
    }
}

/// Recent local paths, newest first (normalized; invalid entries dropped).
pub fn recent_local_paths() -> Vec<String> {
    load_history()
        .recent_local_paths
        .into_iter()
        .map(|p| normalize_local_history_path(&p))
        .filter(|p| !p.is_empty())
        .collect()
}

/// Recent remote paths, newest first (normalized; invalid entries dropped).
pub fn recent_remote_paths() -> Vec<String> {
    load_history()
        .recent_remote_paths
        .into_iter()
        .map(|p| normalize_remote_path_for_match(&p))
        .filter(|p| !p.is_empty())
        .collect()
}

/// Recent servers with their display labels, newest first.
pub fn recent_servers_with_labels() -> Vec<(SessionOptions, String)> {
    load_history()
        .recent_servers
        .iter()
        .filter_map(|encoded| decode_recent_server(encoded))
        .collect()
}

/// Removes all history entries (port of the "Clear history" action).
pub fn clear_history() -> Result<(), String> {
    save_history(&HistoryFile::default())
}

// ---------------------------------------------------------------------------
// Path normalization (ports of the MainWindow.cpp helpers)
// ---------------------------------------------------------------------------

/// Port of `normalizedLocalHistoryPath`: trim, convert separators, clean
/// lexically, and make absolute against the current directory.
fn normalize_local_history_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut path = PathBuf::from(trimmed);
    if !path.is_absolute() {
        if let Ok(cwd) = std::env::current_dir() {
            path = cwd.join(path);
        }
    }
    lexical_normalize(&path).to_string_lossy().into_owned()
}

/// Lexical path cleaning without touching the filesystem (port of
/// `QDir::cleanPath` semantics: resolves "." and ".." components).
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => result.push(prefix.as_os_str()),
            Component::RootDir => {
                // `PathBuf::push` would *replace* the prefix on Windows for
                // absolute paths; append the root separator manually instead.
                let mut s = result.into_os_string();
                s.push(std::path::MAIN_SEPARATOR.to_string());
                result = PathBuf::from(s);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(part) => result.push(part),
        }
    }
    result
}

/// Port of `normalizeRemotePathForMatch`: trim, force leading '/', collapse
/// duplicate slashes and drop a trailing slash (unless root).
fn normalize_remote_path_for_match(raw: &str) -> String {
    let mut normalized = raw.trim().to_string();
    if normalized.is_empty() {
        normalized = "/".to_string();
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
    }
    if normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

// ---------------------------------------------------------------------------
// Recent-server encoding (port of encode/decodeRecentServerEntry)
// ---------------------------------------------------------------------------

/// Encodes a session preset as the C++ QUrlQuery string used by
/// `History/recentServers` entries.
fn encode_recent_server(opt: &SessionOptions) -> String {
    let host = opt.host.trim().to_lowercase();
    if host.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<String> = Vec::with_capacity(5);
    pairs.push(format!(
        "protocol={}",
        percent_encode(protocol_storage_name(opt.protocol))
    ));
    pairs.push(format!("host={}", percent_encode(&host)));
    pairs.push(format!("port={}", opt.port));
    pairs.push(format!("user={}", percent_encode(opt.username.trim())));
    if opt.protocol == Protocol::WebDav {
        pairs.push(format!(
            "webdavScheme={}",
            percent_encode(webdav_scheme_storage_name(opt.webdav_scheme))
        ));
    }
    if opt.protocol == Protocol::Smb {
        if let Some(domain) = opt.smb_domain.as_deref().map(str::trim) {
            if !domain.is_empty() {
                pairs.push(format!("smbDomain={}", percent_encode(domain)));
            }
        }
    }
    if opt.protocol == Protocol::Telnet {
        if opt.telnet_tls {
            pairs.push("telnetTls=1".to_string());
        }
        if !opt.telnet_auto_login {
            pairs.push("telnetAutoLogin=0".to_string());
        }
    }
    pairs.join("&")
}

/// Decodes a recent-server entry into [`SessionOptions`] plus the display
/// label (`"SFTP  user@host:port"`), mirroring `decodeRecentServerEntry`.
fn decode_recent_server(encoded: &str) -> Option<(SessionOptions, String)> {
    let mut protocol_storage = String::new();
    let mut host = String::new();
    let mut port_raw: Option<u16> = None;
    let mut user = String::new();
    let mut webdav_scheme_storage = String::new();
    let mut smb_domain = String::new();
    let mut telnet_tls = false;
    let mut telnet_auto_login = true;

    for pair in encoded.split('&') {
        let (raw_key, raw_value) = pair.split_once('=')?;
        let key = percent_decode(raw_key)?;
        let value = percent_decode(raw_value)?;
        match key.as_str() {
            "protocol" => protocol_storage = value,
            "host" => host = value,
            "port" => {
                port_raw = value.trim().parse::<u16>().ok();
            }
            "user" => user = value,
            "webdavScheme" => webdav_scheme_storage = value,
            "smbDomain" => smb_domain = value,
            "telnetTls" => telnet_tls = value.trim() == "1",
            "telnetAutoLogin" => telnet_auto_login = value.trim() != "0",
            _ => {}
        }
    }

    let host = host.trim().to_lowercase();
    if host.is_empty() {
        return None;
    }
    let protocol = protocol_from_storage_name(&protocol_storage);
    let port = match port_raw {
        Some(p) if p > 0 => p,
        _ if protocol == Protocol::Telnet => default_port_for_telnet(telnet_tls),
        _ => default_port_for_protocol(protocol),
    };
    let username = user.trim().to_string();
    let webdav_scheme = if protocol == Protocol::WebDav {
        if !webdav_scheme_storage.is_empty() {
            webdav_scheme_from_storage_name(&webdav_scheme_storage)
        } else if port == 80 {
            WebDavScheme::Http
        } else {
            WebDavScheme::Https
        }
    } else {
        WebDavScheme::Https
    };
    let (webdav_verify_peer, webdav_ca_cert_path) = if webdav_scheme == WebDavScheme::Http {
        (false, None)
    } else {
        (true, None)
    };
    let smb_domain_opt = if protocol == Protocol::Smb && !smb_domain.trim().is_empty() {
        Some(smb_domain.trim().to_string())
    } else {
        None
    };
    let (telnet_tls_opt, telnet_auto_opt) = if protocol == Protocol::Telnet {
        (telnet_tls, telnet_auto_login)
    } else {
        (false, true)
    };
    let opt = SessionOptions {
        protocol,
        host: host.clone(),
        port,
        username,
        webdav_scheme,
        webdav_verify_peer,
        webdav_ca_cert_path,
        smb_domain: smb_domain_opt,
        telnet_tls: telnet_tls_opt,
        telnet_auto_login: telnet_auto_opt,
        ..SessionOptions::default()
    };

    let mut endpoint = host;
    if port != default_port_for_protocol(protocol) {
        endpoint = format!("{endpoint}:{port}");
    }
    if !opt.username.is_empty() {
        endpoint = format!("{}@{endpoint}", opt.username);
    }
    let label = format!(
        "{}  {endpoint}",
        protocol_display_name(protocol).to_uppercase()
    );

    Some((opt, label))
}

// ---------------------------------------------------------------------------
// Percent-encoding helpers (stand-in for QUrlQuery::toString(FullyEncoded))
// ---------------------------------------------------------------------------

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = input.get(i + 1..i + 3)?;
            let byte = u8::from_str_radix(hex, 16).ok()?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_path_normalization_matches_cpp() {
        assert_eq!(normalize_remote_path_for_match(""), "/");
        assert_eq!(normalize_remote_path_for_match("  "), "/");
        assert_eq!(normalize_remote_path_for_match("var/log"), "/var/log");
        assert_eq!(normalize_remote_path_for_match("/var//log/"), "/var/log");
        assert_eq!(normalize_remote_path_for_match("/"), "/");
        assert_eq!(normalize_remote_path_for_match("//"), "/");
    }

    #[test]
    fn local_path_normalization_is_absolute_and_clean() {
        let norm = normalize_local_history_path("/home/user/../user/docs");
        assert_eq!(norm, "/home/user/docs");
        // Relative paths are made absolute.
        let rel = normalize_local_history_path("a/../b");
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(Path::new(&rel), lexical_normalize(&cwd.join("b")));
    }

    #[test]
    fn prepend_caps_and_dedups() {
        let mut list: Vec<String> = vec![];
        for i in 0..25 {
            prepend_recent_value(&mut list, &format!("path{i}"));
        }
        prepend_recent_value(&mut list, "path0");
        assert_eq!(list.len(), MAX_RECENT_ENTRIES);
        assert_eq!(list.first().map(String::as_str), Some("path0"));
        prepend_recent_value(&mut list, "  ");
        assert_eq!(list.len(), MAX_RECENT_ENTRIES);
    }

    #[test]
    fn server_entry_roundtrip() {
        let opt = SessionOptions {
            protocol: Protocol::Sftp,
            host: "Example.COM ".to_string(),
            port: 2222,
            username: "root".to_string(),
            ..SessionOptions::default()
        };
        let encoded = encode_recent_server(&opt);
        let (decoded, label) = decode_recent_server(&encoded).unwrap();
        assert_eq!(decoded.protocol, Protocol::Sftp);
        assert_eq!(decoded.host, "example.com");
        assert_eq!(decoded.port, 2222);
        assert_eq!(decoded.username, "root");
        assert_eq!(label, "SFTP  root@example.com:2222");
    }

    #[test]
    fn server_entry_webdav_adjustments() {
        let opt = SessionOptions {
            protocol: Protocol::WebDav,
            host: "dav.example.com".to_string(),
            port: 80,
            webdav_scheme: WebDavScheme::Http,
            username: String::new(),
            ..SessionOptions::default()
        };
        let (decoded, label) = decode_recent_server(&encode_recent_server(&opt)).unwrap();
        assert_eq!(decoded.webdav_scheme, WebDavScheme::Http);
        assert!(!decoded.webdav_verify_peer);
        assert!(decoded.webdav_ca_cert_path.is_none());
        assert_eq!(label, "WEBDAV  dav.example.com:80");
    }

    #[test]
    fn server_entry_smb_domain_roundtrip() {
        let opt = SessionOptions {
            protocol: Protocol::Smb,
            host: "nas.example.com".to_string(),
            port: 445,
            smb_domain: Some("WORKGROUP & Friends".to_string()),
            username: "alice".to_string(),
            ..SessionOptions::default()
        };
        let encoded = encode_recent_server(&opt);
        let (decoded, label) = decode_recent_server(&encoded).unwrap();
        assert_eq!(decoded.protocol, Protocol::Smb);
        assert_eq!(decoded.smb_domain.as_deref(), Some("WORKGROUP & Friends"));
        assert_eq!(label, "SMB  alice@nas.example.com");
        // No domain: nothing is encoded and the decode leaves it None.
        let bare = SessionOptions {
            protocol: Protocol::Smb,
            host: "nas.example.com".to_string(),
            ..SessionOptions::default()
        };
        let encoded = encode_recent_server(&bare);
        assert!(!encoded.contains("smbDomain"));
        assert_eq!(decode_recent_server(&encoded).unwrap().0.smb_domain, None);
        // Empty/whitespace domain is not encoded either.
        let blank = SessionOptions {
            protocol: Protocol::Smb,
            host: "nas.example.com".to_string(),
            smb_domain: Some("   ".to_string()),
            ..SessionOptions::default()
        };
        assert!(!encode_recent_server(&blank).contains("smbDomain"));
    }

    #[test]
    fn server_entry_telnet_roundtrip() {
        let opt = SessionOptions {
            protocol: Protocol::Telnet,
            host: "bbs.example.com".to_string(),
            port: 992,
            telnet_tls: true,
            telnet_verify_peer: false,
            telnet_auto_login: false,
            username: "alice".to_string(),
            ..SessionOptions::default()
        };
        let encoded = encode_recent_server(&opt);
        assert!(encoded.contains("telnetTls=1"));
        assert!(encoded.contains("telnetAutoLogin=0"));
        let (decoded, label) = decode_recent_server(&encoded).unwrap();
        assert_eq!(decoded.protocol, Protocol::Telnet);
        assert!(decoded.telnet_tls);
        assert!(!decoded.telnet_auto_login);
        assert_eq!(decoded.port, 992);
        assert_eq!(label, "TELNET  alice@bbs.example.com:992");
        // Defaults: plain telnet on 23 with auto-login on, nothing encoded.
        let bare = SessionOptions {
            protocol: Protocol::Telnet,
            host: "bbs.example.com".to_string(),
            port: 23,
            ..SessionOptions::default()
        };
        let encoded = encode_recent_server(&bare);
        assert!(!encoded.contains("telnetTls"));
        assert!(!encoded.contains("telnetAutoLogin"));
        let (decoded, _) = decode_recent_server(&encoded).unwrap();
        assert!(!decoded.telnet_tls);
        assert!(decoded.telnet_auto_login);
        assert_eq!(decoded.port, 23);
        // A TLS entry without an explicit port decodes to 992.
        let (decoded, label) =
            decode_recent_server("protocol=telnet&host=bbs.example.com&port=0&telnetTls=1")
                .unwrap();
        assert_eq!(decoded.port, 992);
        assert_eq!(label, "TELNET  bbs.example.com:992");
    }

    #[test]
    fn invalid_server_entries_are_rejected() {
        assert!(decode_recent_server("").is_none());
        assert!(decode_recent_server("protocol=sftp&port=22").is_none());
        assert!(decode_recent_server("host=%zz").is_none());
    }

    #[test]
    fn percent_roundtrip() {
        for raw in ["a b&c=d", "user@host", "sftp://x", "héllo"] {
            assert_eq!(percent_decode(&percent_encode(raw)).as_deref(), Some(raw));
        }
    }
}
