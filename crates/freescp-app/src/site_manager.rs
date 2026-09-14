//! Saved sites (connection presets) + the Site Manager dialog: pure-Rust
//! port of `ui/SiteManagerDialog.cpp`.
//!
//! ## Storage format (port of the QSettings array `sites`)
//!
//! Qt persists an array `sites` of entries under QSettings("OpenSCP",
//! "OpenSCP"), one key per field (see `SiteFileEntry` below for the exact
//! key names). This port stores the same data as a TOML document:
//!
//! `<config_dir>/freescp/sites.toml`
//!
//! ```toml
//! [[sites]]
//! id = "2c9a4b1e-…"          # stable UUID used for secret keys
//! name = "example"
//! protocol = "sftp"           # storage name
//! scp_transfer_mode = "auto"
//! host = "example.com"
//! port = 22
//! webdav_scheme = "https"
//! user = "root"
//! key_path = ""
//! proxy_type = 0              # 0 none, 1 socks5, 2 http-connect
//! proxy_host = ""
//! proxy_port = 0
//! proxy_user = ""
//! jump_host = ""
//! jump_port = 22
//! jump_user = ""
//! jump_key_path = ""
//! known_hosts = ""
//! kh_policy = 0               # 0 strict, 1 accept-new, 2 off
//! integrity_policy = 1        # 0 off, 1 optional, 2 required
//! ftps_verify_peer = true
//! ftps_ca_cert_path = ""
//! webdav_verify_peer = true
//! webdav_ca_cert_path = ""
//! smb_domain = ""              # workgroup/domain for SMB NTLM auth
//! save_credentials = true
//! ```
//!
//! ## Secrets (port of SecretStore key scheme in SiteManagerDialog.cpp)
//!
//! Passwords/passphrases are never stored in the TOML. They go to the
//! keyring (`src/secrets.rs`) under keys derived from the *stable site UUID*:
//!
//! - `site-id:<id>:password`  ← `SessionOptions::password`
//! - `site-id:<id>:keypass`   ← `SessionOptions::private_key_passphrase`
//! - `site-id:<id>:proxypass` ← `SessionOptions::proxy_password`
//!
//! Legacy entries written before UUIDs existed used the site name
//! (`site:<name>:<item>`); reads fall back to those keys like the C++ code.

use crate::secrets;
use freescp_core::{
    capabilities_for_protocol, default_port_for_protocol, default_port_for_proxy_type,
    default_port_for_telnet, default_port_for_webdav_scheme, protocol_display_name,
    protocol_from_storage_name, protocol_storage_name, proxy_type_from_storage_value,
    scp_transfer_mode_from_storage_name, scp_transfer_mode_storage_name,
    webdav_scheme_from_storage_name, webdav_scheme_storage_name, KnownHostsPolicy, Protocol,
    ProxyType, ScpTransferMode, SessionOptions, TransferIntegrityPolicy, WebDavScheme,
};
use serde::{Deserialize, Serialize};
use slint::{ComponentHandle, Model, SharedString};
use std::path::PathBuf;

/// Sites storage file inside the FreeSCP config directory.
pub const SITES_FILE: &str = "sites.toml";

fn sites_path() -> PathBuf {
    crate::settings::config_dir().join(SITES_FILE)
}

// ---------------------------------------------------------------------------
// Shared application state (re-export)
// ---------------------------------------------------------------------------

/// The shared application state owned by the main-window workstream
/// (`src/state.rs`). Re-exported so the dialog workstreams can refer to the
/// single canonical type.
pub use crate::state::AppState;

// ---------------------------------------------------------------------------
// Public SiteEntry (contract shape) + storage type
// ---------------------------------------------------------------------------

/// A saved site: flat mirror of the contract fields plus the remaining
/// advanced `SessionOptions` fields. Flat (rather than embedding
/// `SessionOptions`) so sibling workstreams can use the exact field names
/// from the contract.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SiteEntry {
    /// Stable UUID used for the keyring secret keys (C++ `id`).
    pub id: String,
    pub name: String,
    /// Whether credentials may be stored (C++ `SiteEntry::saveCredentials`).
    pub save_credentials: bool,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key_path: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub scp_transfer_mode: ScpTransferMode,
    pub known_hosts_path: Option<String>,
    pub known_hosts_policy: KnownHostsPolicy,
    pub transfer_integrity_policy: TransferIntegrityPolicy,
    pub ftps_verify_peer: bool,
    pub ftps_ca_cert_path: Option<String>,
    pub webdav_scheme: WebDavScheme,
    pub webdav_verify_peer: bool,
    pub webdav_ca_cert_path: Option<String>,
    pub smb_domain: Option<String>,
    /// Telnet console settings (TLS + auto-login); see `SessionOptions`.
    pub telnet_tls: bool,
    pub telnet_verify_peer: bool,
    pub telnet_ca_cert_path: Option<String>,
    pub telnet_auto_login: bool,
    pub proxy_type: ProxyType,
    pub proxy_host: String,
    pub proxy_port: u16,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,
    pub jump_host: Option<String>,
    pub jump_port: u16,
    pub jump_username: Option<String>,
    pub jump_private_key_path: Option<String>,
}

impl SiteEntry {
    /// Converts into a [`SessionOptions`] (drops callbacks and the
    /// `known_hosts_hash_names`/`show_fp_hex` UI prefs, which come from
    /// global preferences at connect time).
    pub fn to_session_options(&self) -> SessionOptions {
        SessionOptions {
            protocol: self.protocol,
            scp_transfer_mode: self.scp_transfer_mode,
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            password: self.password.clone(),
            private_key_path: self.private_key_path.clone(),
            private_key_passphrase: self.private_key_passphrase.clone(),
            known_hosts_path: self.known_hosts_path.clone(),
            known_hosts_policy: self.known_hosts_policy,
            transfer_integrity_policy: self.transfer_integrity_policy,
            ftps_verify_peer: self.ftps_verify_peer,
            ftps_ca_cert_path: self.ftps_ca_cert_path.clone(),
            webdav_scheme: self.webdav_scheme,
            webdav_verify_peer: self.webdav_verify_peer,
            webdav_ca_cert_path: self.webdav_ca_cert_path.clone(),
            smb_domain: self.smb_domain.clone(),
            telnet_tls: self.telnet_tls,
            telnet_verify_peer: self.telnet_verify_peer,
            telnet_ca_cert_path: self.telnet_ca_cert_path.clone(),
            telnet_auto_login: self.telnet_auto_login,
            proxy_type: self.proxy_type,
            proxy_host: self.proxy_host.clone(),
            proxy_port: self.proxy_port,
            proxy_username: self.proxy_username.clone(),
            proxy_password: self.proxy_password.clone(),
            jump_host: self.jump_host.clone(),
            jump_port: self.jump_port,
            jump_username: self.jump_username.clone(),
            jump_private_key_path: self.jump_private_key_path.clone(),
            ..SessionOptions::default()
        }
    }

    /// True when any credential is stored in the keyring for this site.
    #[allow(dead_code)] // editor doesn't display per-site credential badges yet
    pub fn has_stored_credentials(&self) -> bool {
        let has = |item: &str| {
            secrets::get_secret(&id_secret_key(&self.id, item))
                .ok()
                .flatten()
                .is_some()
        };
        has("password") || has("keypass") || has("proxypass")
    }
}

/// TOML storage shape. Field names mirror the C++ QSettings keys for the
/// `sites` array. `Option<T>` marks values that were absent from storage and
/// should fall back to global preferences; `0` ports mean "default for the
/// protocol" (see `impl From<SiteFileEntry> for SiteEntry`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct SiteFileEntry {
    id: String,
    name: String,
    protocol: String,
    scp_transfer_mode: String,
    host: String,
    port: u16,
    webdav_scheme: String,
    user: String,
    key_path: String,
    proxy_type: i32,
    proxy_host: String,
    proxy_port: u16,
    proxy_user: String,
    jump_host: String,
    jump_port: u16,
    jump_user: String,
    jump_key_path: String,
    known_hosts: String,
    kh_policy: i32,
    integrity_policy: i32,
    ftps_verify_peer: Option<bool>,
    ftps_ca_cert_path: String,
    webdav_verify_peer: Option<bool>,
    webdav_ca_cert_path: String,
    smb_domain: String,
    telnet_tls: Option<bool>,
    telnet_verify_peer: Option<bool>,
    telnet_ca_cert_path: String,
    telnet_auto_login: Option<bool>,
    save_credentials: Option<bool>,
}

impl From<&SiteEntry> for SiteFileEntry {
    fn from(e: &SiteEntry) -> Self {
        let opt = |o: &Option<String>| o.clone().unwrap_or_default();
        SiteFileEntry {
            id: e.id.clone(),
            name: e.name.clone(),
            protocol: protocol_storage_name(e.protocol).to_string(),
            scp_transfer_mode: scp_transfer_mode_storage_name(e.scp_transfer_mode).to_string(),
            host: e.host.clone(),
            port: e.port,
            webdav_scheme: webdav_scheme_storage_name(e.webdav_scheme).to_string(),
            user: e.username.clone(),
            key_path: opt(&e.private_key_path),
            proxy_type: proxy_type_storage_value(e.proxy_type),
            proxy_host: e.proxy_host.clone(),
            proxy_port: e.proxy_port,
            proxy_user: opt(&e.proxy_username),
            jump_host: opt(&e.jump_host),
            jump_port: e.jump_port,
            jump_user: opt(&e.jump_username),
            jump_key_path: opt(&e.jump_private_key_path),
            known_hosts: opt(&e.known_hosts_path),
            kh_policy: known_hosts_policy_storage_value(e.known_hosts_policy),
            integrity_policy: transfer_integrity_policy_storage_value(e.transfer_integrity_policy),
            ftps_verify_peer: Some(e.ftps_verify_peer),
            ftps_ca_cert_path: opt(&e.ftps_ca_cert_path),
            webdav_verify_peer: Some(e.webdav_verify_peer),
            webdav_ca_cert_path: opt(&e.webdav_ca_cert_path),
            smb_domain: opt(&e.smb_domain),
            telnet_tls: Some(e.telnet_tls),
            telnet_verify_peer: Some(e.telnet_verify_peer),
            telnet_ca_cert_path: opt(&e.telnet_ca_cert_path),
            telnet_auto_login: Some(e.telnet_auto_login),
            save_credentials: Some(e.save_credentials),
        }
    }
}

impl From<SiteFileEntry> for SiteEntry {
    fn from(f: SiteFileEntry) -> Self {
        let protocol = protocol_from_storage_name(&f.protocol);
        let port = if f.port == 0 {
            default_port_for_protocol(protocol)
        } else {
            f.port
        };
        let proxy_type = proxy_type_from_storage_value(f.proxy_type);
        let proxy_port = if f.proxy_port == 0 {
            default_port_for_proxy_type(proxy_type)
        } else {
            f.proxy_port
        };
        let prefs = crate::settings::Preferences::load();
        let opt_or = |o: &Option<String>| {
            if o.as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_some()
            {
                o.clone()
            } else {
                None
            }
        };
        let mut e = SiteEntry {
            id: f.id,
            name: f.name,
            protocol,
            host: f.host,
            port,
            username: f.user,
            private_key_path: opt_or(&Some(f.key_path)),
            scp_transfer_mode: scp_transfer_mode_from_storage_name(&f.scp_transfer_mode),
            known_hosts_path: opt_or(&Some(f.known_hosts)),
            known_hosts_policy: match f.kh_policy {
                1 => KnownHostsPolicy::AcceptNew,
                2 => KnownHostsPolicy::Off,
                _ => KnownHostsPolicy::Strict,
            },
            transfer_integrity_policy: match f.integrity_policy {
                0 => TransferIntegrityPolicy::Off,
                2 => TransferIntegrityPolicy::Required,
                _ => TransferIntegrityPolicy::Optional,
            },
            // C++ falls back to `defaultFtpsVerifyPeer` (a global pref)
            // when the key is missing; mirror that with the preference.
            ftps_verify_peer: f.ftps_verify_peer.unwrap_or(prefs.ftps_verify_peer_default),
            ftps_ca_cert_path: opt_or(&Some(f.ftps_ca_cert_path)),
            webdav_scheme: webdav_scheme_from_storage_name(&f.webdav_scheme),
            webdav_verify_peer: f.webdav_verify_peer.unwrap_or(true),
            webdav_ca_cert_path: opt_or(&Some(f.webdav_ca_cert_path)),
            smb_domain: opt_or(&Some(f.smb_domain)),
            telnet_tls: f.telnet_tls.unwrap_or(false),
            telnet_verify_peer: f.telnet_verify_peer.unwrap_or(true),
            telnet_ca_cert_path: opt_or(&Some(f.telnet_ca_cert_path)),
            telnet_auto_login: f.telnet_auto_login.unwrap_or(true),
            proxy_type,
            proxy_host: f.proxy_host,
            proxy_port,
            proxy_username: opt_or(&Some(f.proxy_user)),
            jump_host: opt_or(&Some(f.jump_host)),
            jump_port: if f.jump_port == 0 { 22 } else { f.jump_port },
            jump_username: opt_or(&Some(f.jump_user)),
            jump_private_key_path: opt_or(&Some(f.jump_key_path)),
            save_credentials: f.save_credentials.unwrap_or(true),
            password: None,
            private_key_passphrase: None,
            proxy_password: None,
        };
        // C++: plain-HTTP WebDAV forces peer verification off.
        if e.protocol == Protocol::WebDav && e.webdav_scheme == WebDavScheme::Http {
            e.webdav_verify_peer = false;
            e.webdav_ca_cert_path = None;
        }
        e
    }
}

/// Manual serde: stores enums as their storage-name strings / discriminant
/// ints via [`SiteFileEntry`] (the `freescp_core` enums intentionally do not
/// derive serde).
impl Serialize for SiteEntry {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SiteFileEntry::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SiteEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        SiteFileEntry::deserialize(deserializer).map(SiteEntry::from)
    }
}

/// C++ enum-order storage values (mirrors `(int)e.opt.proxy_type` etc.).
fn proxy_type_storage_value(p: ProxyType) -> i32 {
    match p {
        ProxyType::None => 0,
        ProxyType::Socks5 => 1,
        ProxyType::HttpConnect => 2,
    }
}

fn known_hosts_policy_storage_value(p: KnownHostsPolicy) -> i32 {
    match p {
        KnownHostsPolicy::Strict => 0,
        KnownHostsPolicy::AcceptNew => 1,
        KnownHostsPolicy::Off => 2,
    }
}

fn transfer_integrity_policy_storage_value(p: TransferIntegrityPolicy) -> i32 {
    match p {
        TransferIntegrityPolicy::Off => 0,
        TransferIntegrityPolicy::Optional => 1,
        TransferIntegrityPolicy::Required => 2,
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct SitesFile {
    sites: Vec<SiteFileEntry>,
}

fn load_sites_file() -> SitesFile {
    let path = sites_path();
    match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
            tracing::warn!(
                "Could not parse sites file {}: {e}; starting empty",
                path.display()
            );
            SitesFile::default()
        }),
        Err(_) => SitesFile::default(),
    }
}

fn save_sites_file(file: &SitesFile) -> Result<(), String> {
    let dir = crate::settings::config_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Could not create config directory {}: {e}", dir.display()))?;
    let text =
        toml::to_string_pretty(file).map_err(|e| format!("Could not serialize sites: {e}"))?;
    std::fs::write(sites_path(), text).map_err(|e| format!("Could not write sites: {e}"))
}

// ---------------------------------------------------------------------------
// Secret key scheme (port of SiteManagerDialog.cpp helpers)
// ---------------------------------------------------------------------------

/// Keyring key for a secret of a site with a stable UUID
/// (`site-id:<id>:<item>`).
fn id_secret_key(site_id: &str, item: &str) -> String {
    format!("site-id:{site_id}:{item}")
}

/// Legacy keyring key used before sites had UUIDs (`site:<name>:<item>`).
fn legacy_name_secret_key(site_name: &str, item: &str) -> String {
    format!("site:{site_name}:{item}")
}

/// C++ secret items: password, private-key passphrase, proxy password.
const SECRET_ITEMS: [&str; 3] = ["password", "keypass", "proxypass"];

fn get_site_secret(e: &SiteEntry, item: &str) -> Option<String> {
    match secrets::get_secret(&id_secret_key(&e.id, item)) {
        Ok(Some(v)) => Some(v),
        _ => secrets::get_secret(&legacy_name_secret_key(&e.name, item))
            .ok()
            .flatten(),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Loads all saved sites, newest-last (same order as the C++ table), with
/// credentials preloaded from the keyring (mirrors C++ `loadSiteEntries`).
pub fn load_sites() -> Vec<SiteEntry> {
    load_sites_file()
        .sites
        .into_iter()
        .map(|f| {
            let mut e = SiteEntry::from(f);
            e.password = get_site_secret(&e, "password");
            e.private_key_passphrase = get_site_secret(&e, "keypass");
            e.proxy_password = get_site_secret(&e, "proxypass");
            e.save_credentials = e.save_credentials
                || e.password.is_some()
                || e.private_key_passphrase.is_some()
                || e.proxy_password.is_some();
            e
        })
        .collect()
}

/// Looks up a site by name (case-insensitive, like the C++ table lookup) and
/// returns it as connectable [`SessionOptions`] with credentials preloaded.
pub fn site_with_secrets(name: &str) -> Option<SessionOptions> {
    load_sites()
        .into_iter()
        .find(|e| e.name.eq_ignore_ascii_case(name))
        .map(|e| e.to_session_options())
}

/// Creates or updates a saved site under `name`, porting C++
/// `SiteManagerDialog::saveSite` semantics:
///
/// - Existing sites are matched by name (case-insensitive) and keep their
///   stable UUID (so stored secrets survive renames of other fields).
/// - Secrets present in `opt` (`password`, `private_key_passphrase`,
///   `proxy_password`) are persisted to the keyring; secrets set to `None`
///   are removed (mirroring the C++ "Save password" checkbox behavior).
/// - A warning is posted to the status bar when credentials would be stored
///   through the insecure fallback backend.
pub fn save_site(state: &AppState, name: &str, opt: &SessionOptions) -> Result<(), String> {
    save_site_inner(state, name, opt, None).map(|_| ())
}

/// Like [`save_site`], but also returns the site's stable id and the list of
/// credential-persist issue lines ("Password: <error>" etc., port of the C++
/// `showPersistIssues` lines). `existing_id` replaces the name-based lookup
/// so that renames during Edit update the right entry (C++ edits by model
/// index).
pub fn save_site_with_issues(
    state: &AppState,
    name: &str,
    opt: &SessionOptions,
    existing_id: Option<&str>,
) -> Result<(String, Vec<String>), String> {
    save_site_inner(state, name, opt, existing_id)
}

fn save_site_inner(
    state: &AppState,
    name: &str,
    opt: &SessionOptions,
    existing_id: Option<&str>,
) -> Result<(String, Vec<String>), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Site name is empty".to_string());
    }

    let mut file = load_sites_file();
    let (id, entry) = match existing_id
        .filter(|id| !id.is_empty())
        .and_then(|wanted_id| {
            file.sites
                .iter_mut()
                .find(|f| f.id == wanted_id)
                .map(|existing| (wanted_id, existing))
        }) {
        Some((wanted_id, existing)) => {
            let e = entry_from_options(wanted_id, name, opt);
            *existing = SiteFileEntry::from(&e);
            (wanted_id.to_string(), e)
        }
        None => upsert_by_name(&mut file, name, opt),
    };

    save_sites_file(&file)?;

    // Persist secrets (same items as the C++ persistSite): password and key
    // passphrase are set when provided; the proxy password is set when
    // provided and removed otherwise.
    let mut issues = Vec::new();
    if let Some(line) = persist_secret(&entry, "password", opt.password.as_deref()) {
        issues.push(line);
    }
    if let Some(line) = persist_secret(&entry, "keypass", opt.private_key_passphrase.as_deref()) {
        issues.push(line);
    }
    // Proxy password: set when supplied, cleared otherwise (C++ persistSite).
    match opt.proxy_password.as_deref().filter(|v| !v.is_empty()) {
        Some(v) => {
            if let Some(line) = persist_secret(&entry, "proxypass", Some(v)) {
                issues.push(line);
            }
        }
        None => remove_secret_item(&entry, "proxypass"),
    }

    // Port of the SecretStore warning: credentials stored through the
    // insecure fallback are visibly flagged on the status line.
    if secrets::insecure_fallback_active() && entry.save_credentials {
        state.set_status("Warning: credentials stored insecurely (secure storage unavailable)");
        tracing::warn!("Saving credentials for site {name} via the insecure fallback");
    }

    Ok((id, issues))
}

/// Name-based upsert (used by [`save_site`] and as the fallback when the
/// edit id no longer exists in storage).
fn upsert_by_name(file: &mut SitesFile, name: &str, opt: &SessionOptions) -> (String, SiteEntry) {
    match file
        .sites
        .iter_mut()
        .find(|f| f.name.eq_ignore_ascii_case(name))
    {
        Some(existing) => {
            let id = if existing.id.is_empty() {
                new_site_id()
            } else {
                existing.id.clone()
            };
            let e = entry_from_options(&id, name, opt);
            *existing = SiteFileEntry::from(&e);
            (id, e)
        }
        None => {
            let id = new_site_id();
            let e = entry_from_options(&id, name, opt);
            file.sites.push(SiteFileEntry::from(&e));
            (id, e)
        }
    }
}

/// Maps one concrete `~/.ssh/config` alias to a saved site. The entry keeps
/// the *alias* as its host (not the resolved `HostName`) so connect-time
/// [`crate::connect`] resolution keeps honoring later config edits; SFTP is
/// the natural protocol for imported SSH hosts.
fn ssh_alias_to_site(
    alias: &str,
    block: &freescp_core::ssh_config::SshHostBlock,
    kh_policy: KnownHostsPolicy,
    integrity_policy: TransferIntegrityPolicy,
) -> SiteEntry {
    let (jump_username, jump_host, jump_port) = block
        .proxy_jump
        .as_deref()
        .map(freescp_core::ssh_config::parse_proxy_jump)
        .map_or((None, None, 22), |(u, h, p)| (u, Some(h), p.unwrap_or(22)));
    SiteEntry {
        id: new_site_id(),
        name: alias.to_string(),
        save_credentials: false,
        protocol: Protocol::Sftp,
        host: alias.to_string(),
        port: block.port.unwrap_or(22),
        username: block.user.clone().unwrap_or_default(),
        password: None,
        private_key_path: block.identity_files.first().cloned(),
        private_key_passphrase: None,
        scp_transfer_mode: ScpTransferMode::Auto,
        known_hosts_path: None,
        known_hosts_policy: kh_policy,
        transfer_integrity_policy: integrity_policy,
        ftps_verify_peer: true,
        ftps_ca_cert_path: None,
        webdav_scheme: WebDavScheme::Https,
        webdav_verify_peer: true,
        webdav_ca_cert_path: None,
        smb_domain: None,
        telnet_tls: false,
        telnet_verify_peer: true,
        telnet_ca_cert_path: None,
        telnet_auto_login: true,
        proxy_type: ProxyType::None,
        proxy_host: String::new(),
        proxy_port: 0,
        proxy_username: None,
        proxy_password: None,
        jump_host,
        jump_port,
        jump_username,
        jump_private_key_path: None,
    }
}

/// Adds imported entries to the sites file, skipping names that already
/// exist (case-insensitive, like the duplicate-name check). Returns
/// `(imported, skipped)`.
fn upsert_imported_sites(file: &mut SitesFile, entries: &[SiteEntry]) -> (usize, usize) {
    let mut imported = 0;
    let mut skipped = 0;
    for entry in entries {
        if file
            .sites
            .iter()
            .any(|f| f.name.eq_ignore_ascii_case(&entry.name))
        {
            skipped += 1;
        } else {
            file.sites.push(SiteFileEntry::from(entry));
            imported += 1;
        }
    }
    (imported, skipped)
}

fn entry_from_options(id: &str, name: &str, opt: &SessionOptions) -> SiteEntry {
    SiteEntry {
        id: id.to_string(),
        name: name.to_string(),
        save_credentials: opt.password.is_some()
            || opt.private_key_passphrase.is_some()
            || opt.proxy_password.is_some(),
        protocol: opt.protocol,
        host: opt.host.trim().to_string(),
        port: opt.port,
        username: opt.username.trim().to_string(),
        password: opt.password.clone(),
        private_key_path: opt.private_key_path.clone(),
        private_key_passphrase: opt.private_key_passphrase.clone(),
        scp_transfer_mode: opt.scp_transfer_mode,
        known_hosts_path: opt.known_hosts_path.clone(),
        known_hosts_policy: opt.known_hosts_policy,
        transfer_integrity_policy: opt.transfer_integrity_policy,
        ftps_verify_peer: opt.ftps_verify_peer,
        ftps_ca_cert_path: opt.ftps_ca_cert_path.clone(),
        webdav_scheme: opt.webdav_scheme,
        webdav_verify_peer: opt.webdav_verify_peer,
        webdav_ca_cert_path: opt.webdav_ca_cert_path.clone(),
        smb_domain: opt.smb_domain.clone(),
        telnet_tls: opt.telnet_tls,
        telnet_verify_peer: opt.telnet_verify_peer,
        telnet_ca_cert_path: opt.telnet_ca_cert_path.clone(),
        telnet_auto_login: opt.telnet_auto_login,
        proxy_type: opt.proxy_type,
        proxy_host: opt.proxy_host.trim().to_string(),
        proxy_port: opt.proxy_port,
        proxy_username: opt.proxy_username.clone(),
        proxy_password: opt.proxy_password.clone(),
        jump_host: opt.jump_host.clone(),
        jump_port: opt.jump_port,
        jump_username: opt.jump_username.clone(),
        jump_private_key_path: opt.jump_private_key_path.clone(),
    }
}

/// Stores one keyring secret; never removes it. Returns a C++-style issue
/// line (`"<Label>: <error>"`) when storing fails (mirroring
/// `showPersistIssues`, which reports set errors only). The C++ `onAdd` /
/// `onEdit` only ever call `setSecret` for password and key passphrase — an
/// emptied field leaves the stored secret in place — so the clear button
/// alone does not wipe credentials.
fn persist_secret(entry: &SiteEntry, item: &str, value: Option<&str>) -> Option<String> {
    let key = id_secret_key(&entry.id, item);
    match value {
        Some(v) if !v.is_empty() => {
            if let Err(e) = secrets::set_secret(&key, v) {
                tracing::warn!("Could not store {item} for site {}: {e}", entry.name);
                return Some(format!("{}: {e}", secret_item_label(item)));
            }
        }
        _ => {}
    }
    None
}

/// Proxy passwords are the one secret the C++ clears: `persistSite` removes
/// the stored proxypass whenever no proxy password is supplied (including
/// when the proxy itself is disabled).
fn remove_secret_item(entry: &SiteEntry, item: &str) {
    if let Err(e) = secrets::remove_secret(&id_secret_key(&entry.id, item)) {
        tracing::warn!("Could not remove {item} for site {}: {e}", entry.name);
    }
}

/// Human label for a secret item (port of the C++ `tr("Password")` etc.
/// labels used in the persist-issue lines).
fn secret_item_label(item: &str) -> &str {
    match item {
        "password" => "Password",
        "keypass" => "Key passphrase",
        "proxypass" => "Proxy password",
        other => other,
    }
}

/// Deletes a saved site by name (case-insensitive), porting
/// `SiteManagerDialog::deleteSite`. Stored secrets are removed only when the
/// `Sites/deleteSecretsOnRemove` preference is enabled, like the C++ code;
/// the same preference also removes the site's known_hosts entry (port of
/// `RemoveKnownHostEntry` in the C++ delete flow).
pub fn delete_site(name: &str) -> Result<(), String> {
    let name = name.trim();
    let mut file = load_sites_file();
    let removed: Vec<SiteEntry> = file
        .sites
        .iter()
        .filter(|f| f.name.eq_ignore_ascii_case(name))
        .cloned()
        .map(SiteEntry::from)
        .collect();
    let original_len = file.sites.len();
    file.sites.retain(|f| !f.name.eq_ignore_ascii_case(name));
    if file.sites.len() == original_len {
        return Err(format!("Site \"{name}\" not found"));
    }
    save_sites_file(&file)?;

    let prefs = crate::settings::Preferences::load();
    for entry in &removed {
        if prefs.delete_secrets_on_remove {
            for item in SECRET_ITEMS {
                if let Err(e) = secrets::remove_secret(&id_secret_key(&entry.id, item)) {
                    tracing::warn!("Could not remove secret for deleted site: {e}");
                }
            }
            // Legacy name-keyed secrets are cleaned up only under the same
            // preference (C++ calls removeLegacyNameSecrets inside the
            // `if (deleteSecrets)` block).
            for item in SECRET_ITEMS {
                let _ = secrets::remove_secret(&legacy_name_secret_key(name, item));
            }
            remove_site_known_hosts(entry);
        }
    }
    Ok(())
}

/// Removes the deleted site's known_hosts entry (port of the
/// `RemoveKnownHostEntry` call in `SiteManagerDialog::onRemove`): uses the
/// site's configured known_hosts path, falling back to `~/.ssh/known_hosts`,
/// and only touches existing files.
fn remove_site_known_hosts(entry: &SiteEntry) {
    let host = entry.host.trim().to_string();
    if host.is_empty() {
        return;
    }
    let configured = entry
        .known_hosts_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let path = match configured {
        Some(p) => Some(std::path::PathBuf::from(p)),
        None => freescp_core::known_hosts::default_known_hosts_path(),
    };
    let Some(path) = path else {
        return;
    };
    if !path.is_file() {
        return;
    }
    if let Err(e) = freescp_core::known_hosts::remove_host(&path, &host, entry.port) {
        tracing::warn!(
            "Could not remove known_hosts entry for {host}:{} from {}: {e}",
            entry.port,
            path.display()
        );
    }
}

/// Generates a random UUID v4 string for new site IDs (the C++ app uses
/// `QUuid::createUuid()`). Implemented locally because `uuid`/`rand` are not
/// declared dependencies of `freescp-app`.
///
/// Reads `/dev/urandom` on Unix; falls back to a time+PID-based
/// pseudo-random identifier elsewhere (site IDs only need uniqueness, not
/// cryptographic strength).
pub fn new_site_id() -> String {
    let mut bytes = [0u8; 16];
    let mut filled = false;
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(&mut bytes).is_ok() {
                filled = true;
            }
        }
    }
    if !filled {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id() as u128;
        let mut x = (nanos ^ (pid << 32)) as u64;
        for b in bytes.iter_mut() {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (x >> 33) as u8;
        }
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

// ---------------------------------------------------------------------------
// Site Manager dialog wiring
// ---------------------------------------------------------------------------

/// Opens the Site Manager dialog, listing all saved sites and wiring the
/// CRUD + connect callbacks. Port of `SiteManagerDialog::showEvent` /
/// `onAdd/onEdit/onDelete/onConnect`.
pub fn open(win: &crate::ui::main_window::MainWindow, state: &AppState) {
    let win_weak = win.as_weak();

    let dialog = crate::ui::site_manager::SiteManagerDialog::new()
        .expect("Failed to create SiteManagerDialog");
    let weak = dialog.as_weak();

    // Center the dialog over the main window (port of parenting/modal
    // placement in the C++).
    if let Some(win) = win_weak.upgrade() {
        crate::remote::center_window_over(&win, dialog.window());
    }

    // Default table sort: name ascending (Qt sortByColumn(0, Asc)). The
    // dialog's sort-column/sort-ascending properties are the session sort
    // state; handlers read them back before re-sorting.
    dialog.set_sort_column(0);
    dialog.set_sort_ascending(true);
    refresh_rows(&dialog, 0, true);

    dialog.on_new_requested({
        let weak = weak.clone();
        move || {
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    let prefs = crate::settings::Preferences::load();
                    dialog.set_editor_name("".into());
                    dialog.set_editor_protocol(
                        protocol_storage_name(prefs.default_protocol_enum()).into(),
                    );
                    dialog.set_editor_host("".into());
                    dialog.set_editor_port(
                        default_port_for_protocol(prefs.default_protocol_enum()) as i32,
                    );
                    dialog.set_editor_username("".into());
                    dialog.set_editor_password("".into());
                    dialog.set_editor_key_path("".into());
                    dialog.set_editor_key_passphrase("".into());
                    dialog.set_editor_save_credentials(true);
                    dialog.set_editor_scp_mode(SharedString::from(scp_transfer_mode_storage_name(
                        prefs.default_scp_mode_enum(),
                    )));
                    dialog.set_editor_known_hosts_policy(prefs.default_known_hosts_policy as i32);
                    dialog.set_editor_integrity_policy(
                        prefs.default_transfer_integrity_policy as i32,
                    );
                    dialog.set_editor_ftps_verify_peer(prefs.ftps_verify_peer_default);
                    dialog.set_editor_ftps_ca_cert(prefs.ftps_ca_cert_path_default.clone().into());
                    dialog.set_editor_webdav_scheme("https".into());
                    dialog.set_editor_webdav_verify_peer(true);
                    dialog.set_editor_webdav_ca_cert("".into());
                    dialog.set_editor_smb_domain("".into());
                    dialog.set_editor_telnet_tls(false);
                    dialog.set_editor_telnet_verify_peer(true);
                    dialog.set_editor_telnet_ca_cert("".into());
                    dialog.set_editor_telnet_auto_login(true);
                    dialog.set_editor_proxy_type(0);
                    dialog.set_editor_proxy_host("".into());
                    // Qt proxyPort_ defaults to the SOCKS5 port (1080).
                    dialog.set_editor_proxy_port(
                        default_port_for_proxy_type(ProxyType::Socks5) as i32
                    );
                    dialog.set_editor_proxy_username("".into());
                    dialog.set_editor_proxy_password("".into());
                    dialog.set_editor_jump_host("".into());
                    dialog.set_editor_jump_port(22);
                    dialog.set_editor_jump_enabled(false);
                    dialog.set_editor_jump_username("".into());
                    dialog.set_editor_jump_key_path("".into());
                    dialog.set_editor_known_hosts_path("".into());
                    dialog.set_editor_mode_is_add(true);
                    dialog.set_editing_site_id("".into());
                    dialog.set_editor_visible(true);
                },
            );
        }
    });

    dialog.on_edit_requested({
        let weak = weak.clone();
        move |name: SharedString| {
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    let site = load_sites()
                        .into_iter()
                        .find(|e| e.name.eq_ignore_ascii_case(name.as_ref()))
                        .unwrap_or_default();
                    populate_editor(&dialog, &site);
                    dialog.set_editor_visible(true);
                },
            );
        }
    });

    dialog.on_delete_requested({
        let weak = weak.clone();
        move |name: SharedString| {
            let name = name.to_string();
            if let Err(e) = delete_site(&name) {
                tracing::warn!("Could not delete site {name}: {e}");
            }
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    let col = dialog.get_sort_column().max(0) as usize;
                    let asc = dialog.get_sort_ascending();
                    refresh_rows(&dialog, col, asc);
                    dialog.set_editor_visible(false);
                },
            );
        }
    });

    // Import concrete Host aliases from ~/.ssh/config as saved sites
    // (Rust-only feature; the C++ Site Manager had no import). Existing
    // sites win over same-named aliases, so re-importing is idempotent.
    dialog.on_import_ssh_config_requested({
        let weak = weak.clone();
        move || {
            let Some(config) = freescp_core::ssh_config::SshConfig::load_user_config() else {
                crate::connect::show_alert(
                    "Import SSH config",
                    &crate::connect::tr("~/.ssh/config was not found.", &[]),
                );
                return;
            };
            let prefs = crate::settings::Preferences::load();
            let entries: Vec<SiteEntry> = config
                .concrete_aliases()
                .iter()
                .map(|(alias, block)| {
                    ssh_alias_to_site(
                        alias,
                        block,
                        prefs.default_known_hosts_policy_enum(),
                        prefs.default_transfer_integrity_policy_enum(),
                    )
                })
                .collect();
            let mut file = load_sites_file();
            let (imported, skipped) = upsert_imported_sites(&mut file, &entries);
            if imported > 0 {
                if let Err(e) = save_sites_file(&file) {
                    crate::connect::show_alert(
                        "Error",
                        &format!("Could not import sites from ~/.ssh/config.\n{e}"),
                    );
                    tracing::warn!("Could not save imported ssh-config sites: {e}");
                    return;
                }
            }
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    let col = dialog.get_sort_column().max(0) as usize;
                    let asc = dialog.get_sort_ascending();
                    refresh_rows(&dialog, col, asc);
                },
            );
            let message = match (imported, skipped) {
                (0, 0) => crate::connect::tr(
                    "No importable Host entries were found in ~/.ssh/config.",
                    &[],
                ),
                (n, 0) => crate::connect::tr(
                    "Imported %1 site(s) from the SSH configuration.",
                    &[n.to_string()],
                ),
                (n, m) => crate::connect::tr(
                    "Imported %1 site(s) from the SSH configuration; %2 already existed.",
                    &[n.to_string(), m.to_string()],
                ),
            };
            crate::connect::show_alert("Import SSH config", &message);
        }
    });

    dialog.on_connect_requested({
        let state = state.clone();
        let weak = weak.clone();
        move |name: SharedString| {
            start_site_connect(&state, &name);
            // C++ onConnect() calls accept(): the manager closes on both the
            // toolbar (modal) and startup/disconnect (modeless) paths.
            if let Some(dialog) = weak.upgrade() {
                let _ = dialog.hide(); // hiding after connect is cosmetic
            }
        }
    });

    dialog.on_connect_site_requested({
        let state = state.clone();
        let weak = weak.clone();
        move |name: SharedString| {
            start_site_connect(&state, &name);
            // Double-click connects and closes the dialog (C++ behavior).
            if let Some(dialog) = weak.upgrade() {
                let _ = dialog.hide(); // hiding after connect is cosmetic
            }
        }
    });

    dialog.on_site_clicked({
        let weak = weak.clone();
        let dialog_id = NEXT_DIALOG_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        move |idx: i32| {
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    handle_row_click(&dialog, idx, dialog_id);
                },
            );
        }
    });

    dialog.on_save_requested({
        let weak = weak.clone();
        let state = state.clone();
        move || {
            let state = state.clone();
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    let mut name = dialog.get_editor_name().trim().to_string();
                    let is_add = dialog.get_editor_mode_is_add();
                    let editing_id = dialog.get_editing_site_id().to_string();
                    // C++ onAdd: an empty name falls back to `user@host`.
                    if name.is_empty() && is_add {
                        name = auto_site_name(
                            &dialog.get_editor_username(),
                            &dialog.get_editor_host(),
                        )
                        .unwrap_or_default();
                    }
                    if name.is_empty() {
                        crate::connect::show_alert(
                            "Name required",
                            "Enter a site name to save this connection.",
                        );
                        return;
                    }
                    // C++ hasDuplicateSiteName: case-insensitive, ignoring
                    // the entry being edited.
                    let existing_id = (!editing_id.is_empty()).then_some(editing_id.as_str());
                    if has_duplicate_site_name(&load_sites(), &name, existing_id) {
                        crate::connect::show_alert(
                            "Duplicate name",
                            &crate::connect::tr(
                                "A site named \"%1\" already exists. Use a different name.",
                                std::slice::from_ref(&name),
                            ),
                        );
                        return;
                    }
                    let old_name = existing_id
                        .and_then(|id| load_sites().into_iter().find(|e| e.id == id))
                        .map(|e| e.name);
                    let opt = editor_options(&dialog);
                    match save_site_with_issues(&state, &name, &opt, existing_id) {
                        Ok((id, issues)) => {
                            // C++ showPersistIssues: report keyring failures.
                            if !issues.is_empty() {
                                crate::connect::show_alert(
                                    "Credentials not saved",
                                    &crate::connect::tr(
                                        "Could not save one or more credentials in the secure backend:\n%1",
                                        std::slice::from_ref(&issues.join("\n")),
                                    ),
                                );
                            }
                            // C++ onEdit: renames drop the legacy name-keyed
                            // secrets of the old name.
                            if let Some(old) = old_name {
                                if old != name {
                                    for item in SECRET_ITEMS {
                                        let _ =
                                            secrets::remove_secret(&legacy_name_secret_key(&old, item));
                                    }
                                }
                            }
                            let (col, asc) = (
                                dialog.get_sort_column().max(0) as usize,
                                dialog.get_sort_ascending(),
                            );
                            refresh_rows(&dialog, col, asc);
                            // Reselect the edited site even if sorting moved it.
                            if existing_id.is_some() {
                                select_row_by_id(&dialog, &id);
                            }
                            dialog.set_editor_visible(false);
                        }
                        Err(e) => {
                            crate::connect::show_alert(
                                "Error",
                                &crate::connect::tr(
                                    "Could not save site \"%1\".\n%2",
                                    &[name.clone(), e.to_string()],
                                ),
                            );
                            tracing::warn!("Could not save site {name}: {e}");
                        }
                    }
                },
            );
        }
    });

    dialog.on_sort_requested({
        let weak = weak.clone();
        move |col: i32| {
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    let col = col.clamp(0, 3);
                    let prev_col = dialog.get_sort_column();
                    let prev_asc = dialog.get_sort_ascending();
                    let asc = if prev_col == col { !prev_asc } else { true };
                    dialog.set_sort_column(col);
                    dialog.set_sort_ascending(asc);
                    refresh_rows(&dialog, col as usize, asc);
                },
            );
        }
    });

    dialog.on_browse_path_requested({
        let weak = weak.clone();
        move |field: slint::SharedString| {
            // Native file chooser (Slint has no built-in file dialog), shared
            // with the connection dialog: per-field title + starting directory
            // (`~/.ssh` for keys and known_hosts, home for CA bundles).
            let Some(path) = crate::connect::pick_connection_file(field.as_str()) else {
                return;
            };
            let Some(dialog) = weak.upgrade() else {
                return;
            };
            let path_s: slint::SharedString = path.to_string_lossy().into_owned().into();
            match field.as_str() {
                "private-key" => dialog.set_editor_key_path(path_s),
                "known-hosts" => dialog.set_editor_known_hosts_path(path_s),
                "ftps-ca" => dialog.set_editor_ftps_ca_cert(path_s),
                "webdav-ca" => dialog.set_editor_webdav_ca_cert(path_s),
                "telnet-ca" => dialog.set_editor_telnet_ca_cert(path_s),
                "jump-key" => dialog.set_editor_jump_key_path(path_s),
                other => tracing::warn!(field = %other, "unknown site-manager browse field"),
            }
        }
    });

    dialog.on_protocol_changed({
        let weak = weak.clone();
        move || {
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    // C++ updateProtocolUi: port resets to the protocol
                    // default (WebDAV honors the selected scheme).
                    let protocol = protocol_from_storage_name(&dialog.get_editor_protocol());
                    // C++ updateJumpFields unchecks the jump host when the
                    // protocol does not support it (SSH-only).
                    if !capabilities_for_protocol(protocol).supports_jump_host
                        && dialog.get_editor_jump_enabled()
                    {
                        dialog.set_editor_jump_enabled(false);
                    }
                    let default_port = if protocol == Protocol::WebDav {
                        let scheme = if dialog.get_editor_webdav_scheme() == "http" {
                            WebDavScheme::Http
                        } else {
                            WebDavScheme::Https
                        };
                        default_port_for_webdav_scheme(scheme)
                    } else if protocol == Protocol::Telnet {
                        default_port_for_telnet(dialog.get_editor_telnet_tls())
                    } else {
                        default_port_for_protocol(protocol)
                    };
                    dialog.set_editor_port(default_port as i32);
                },
            );
        }
    });

    // Proxy selection: jump-host exclusion + proxy port defaults (port of the
    // C++ proxyType_ currentIndexChanged handler + updateProxyFields).
    dialog.on_proxy_type_changed({
        let weak = weak.clone();
        let last_proxy_type = std::sync::Arc::new(std::sync::atomic::AtomicI32::new(0));
        move || {
            let last_proxy_type = last_proxy_type.clone();
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    let proxy = proxy_type_from_storage_value(dialog.get_editor_proxy_type());
                    // C++: selecting a non-direct proxy disables the jump host.
                    if proxy != ProxyType::None && dialog.get_editor_jump_enabled() {
                        dialog.set_editor_jump_enabled(false);
                    }
                    let previous = proxy_type_from_storage_value(
                        last_proxy_type.load(std::sync::atomic::Ordering::Relaxed),
                    );
                    let previous_default = default_port_for_proxy_type(previous) as i32;
                    let next_default = default_port_for_proxy_type(proxy) as i32;
                    let current_port = dialog.get_editor_proxy_port();
                    let first_selection = previous == ProxyType::None;
                    let uses_previous_default =
                        previous_default != 0 && current_port == previous_default;
                    if proxy != ProxyType::None
                        && next_default != 0
                        && (first_selection || uses_previous_default)
                        && current_port != next_default
                    {
                        dialog.set_editor_proxy_port(next_default);
                    }
                    last_proxy_type.store(
                        dialog.get_editor_proxy_type(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                },
            );
        }
    });

    // C++ jumpEnabled_ toggled: enabling the jump host resets the proxy to
    // "Direct (no proxy)".
    dialog.on_jump_enabled_changed({
        let weak = weak.clone();
        move || {
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    if dialog.get_editor_jump_enabled() && dialog.get_editor_proxy_type() != 0 {
                        dialog.set_editor_proxy_type(0);
                    }
                },
            );
        }
    });

    // WebDAV scheme switch: the port follows the scheme default (443<->80)
    // while it still holds the previous scheme's default (port of the C++
    // webDavScheme_ currentIndexChanged handler).
    dialog.on_webdav_scheme_changed({
        let weak = weak.clone();
        let last_webdav_https = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        move || {
            let last_webdav_https = last_webdav_https.clone();
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    let next_https = dialog.get_editor_webdav_scheme() != "http";
                    let scheme = |https: bool| {
                        if https {
                            WebDavScheme::Https
                        } else {
                            WebDavScheme::Http
                        }
                    };
                    let previous_default = default_port_for_webdav_scheme(scheme(
                        last_webdav_https.load(std::sync::atomic::Ordering::Relaxed),
                    )) as i32;
                    let next_default = default_port_for_webdav_scheme(scheme(next_https)) as i32;
                    if protocol_from_storage_name(&dialog.get_editor_protocol()) == Protocol::WebDav
                        && dialog.get_editor_port() == previous_default
                        && previous_default != next_default
                    {
                        dialog.set_editor_port(next_default);
                    }
                    last_webdav_https.store(next_https, std::sync::atomic::Ordering::Relaxed);
                },
            );
        }
    });

    // Telnet TLS toggle: the port follows 23 <-> 992 while it still holds the
    // previous default (same rule as the WebDAV scheme switch).
    dialog.on_telnet_tls_changed({
        let weak = weak.clone();
        let last_telnet_tls = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        move || {
            let last_telnet_tls = last_telnet_tls.clone();
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    let next_tls = dialog.get_editor_telnet_tls();
                    let previous_default = default_port_for_telnet(
                        last_telnet_tls.load(std::sync::atomic::Ordering::Relaxed),
                    ) as i32;
                    let next_default = default_port_for_telnet(next_tls) as i32;
                    if protocol_from_storage_name(&dialog.get_editor_protocol()) == Protocol::Telnet
                        && dialog.get_editor_port() == previous_default
                        && previous_default != next_default
                    {
                        dialog.set_editor_port(next_default);
                    }
                    last_telnet_tls.store(next_tls, std::sync::atomic::Ordering::Relaxed);
                },
            );
        }
    });

    dialog.on_editor_cancel_requested({
        let weak = weak.clone();
        move || {
            let _ = weak.upgrade_in_event_loop(
                move |dialog: crate::ui::site_manager::SiteManagerDialog| {
                    dialog.set_editor_visible(false);
                },
            );
        }
    });

    dialog.on_close_requested({
        let weak = weak.clone();
        move || {
            let _ =
                weak.upgrade_in_event_loop(|dialog: crate::ui::site_manager::SiteManagerDialog| {
                    let _ = dialog.hide();
                });
        }
    });

    if let Err(e) = dialog.show() {
        tracing::warn!("Could not show Site Manager: {e}");
    }
}

/// Loads a saved site (credentials included), applies the global security
/// prefs, and starts the connect pipeline (port of
/// `SiteManagerDialog::onConnect` + `startSftpConnect`).
fn start_site_connect(state: &AppState, name: &str) {
    let Some(mut opt) = site_with_secrets(name) else {
        state.set_status(&format!("Site \"{name}\" not found"));
        return;
    };
    let prefs = crate::settings::Preferences::load();
    opt.known_hosts_hash_names = prefs.known_hosts_hashed;
    opt.show_fp_hex = prefs.fp_hex;
    if !crate::connect::confirm_insecure_host_policy(state, &opt) {
        state.set_status("Connection canceled: no-verification policy not confirmed");
        return;
    }
    let opt = crate::connect::attach_session_callbacks(opt, state);
    // `None`: the session installs into the active tab when it is idle, else
    // a fresh tab opens for it.
    crate::connect::start_connect(state, None, opt);
}

/// Monotonic per-dialog instance id used by the double-click detector so a
/// dialog reopened in place starts with a clean click history.
static NEXT_DIALOG_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

// Last click seen by [`handle_row_click`] on this thread:
// `(dialog id, row, click time)`.
thread_local! {
    static LAST_ROW_CLICK: std::cell::RefCell<Option<(u32, i32, std::time::Instant)>> =
        const { std::cell::RefCell::new(None) };
}

/// Single/double click detection for the site list, replacing the
/// timer-based detection that triggered a Slint 1.17 codegen bug when the
/// `Timer` was referenced from inside a `for` delegate. A second click on
/// the same row of the same dialog within 400 ms re-emits
/// `connect-site-requested`. `dialog_id` is assigned once per dialog
/// instance in [`open`] so a reopened dialog starts with a clean history.
fn handle_row_click(dialog: &crate::ui::site_manager::SiteManagerDialog, idx: i32, dialog_id: u32) {
    let now = std::time::Instant::now();
    let is_double = LAST_ROW_CLICK.with(|last| {
        let mut last = last.borrow_mut();
        let was = match *last {
            Some((id, row, then)) => {
                id == dialog_id
                    && row == idx
                    && now.duration_since(then) <= std::time::Duration::from_millis(400)
            }
            None => false,
        };
        *last = Some((dialog_id, idx, now));
        was
    });
    if is_double {
        let rows = dialog.get_rows();
        if let Some(row) = rows.row_data(idx as usize) {
            dialog.invoke_connect_site_requested(row.name.clone());
        }
    }
}

/// Rebuilds the dialog's `rows` model from [`load_sites`], sorted by the
/// given column (`0` name, `1` protocol, `2` host, `3` user). The current
/// selection is preserved by id — the C++ table stores the original model
/// index in each item for the same purpose.
fn refresh_rows(dialog: &crate::ui::site_manager::SiteManagerDialog, sort_col: usize, asc: bool) {
    refresh_rows_from_sites(dialog, load_sites(), sort_col, asc);
}

/// Pure model rebuild so tests can drive it without touching the on-disk
/// sites.toml: sorts [`SiteEntry`]s into the dialog's row model and restores
/// the selection for the previously selected site id.
fn refresh_rows_from_sites(
    dialog: &crate::ui::site_manager::SiteManagerDialog,
    sites: Vec<SiteEntry>,
    sort_col: usize,
    asc: bool,
) {
    let selected_id = selected_row_id(dialog);
    let mut rows: Vec<crate::ui::site_manager::SiteRow> = sites
        .into_iter()
        .map(|e| crate::ui::site_manager::SiteRow {
            id: e.id.clone().into(),
            name: e.name.clone().into(),
            protocol: protocol_display_name(e.protocol).into(),
            host: e.host.clone().into(),
            username: e.username.clone().into(),
        })
        .collect();
    sort_site_rows(&mut rows, sort_col, asc);
    let new_selection = selected_id
        .as_deref()
        .and_then(|id| rows.iter().position(|r| r.id == id))
        .map(|idx| idx as i32)
        .unwrap_or(-1);
    dialog.set_rows((&rows[..]).into());
    dialog.set_current_row(new_selection);
    if new_selection >= 0 {
        scroll_row_into_view(dialog, new_selection);
    }
}

/// Returns the id of the currently selected row, if any.
fn selected_row_id(dialog: &crate::ui::site_manager::SiteManagerDialog) -> Option<String> {
    let idx = dialog.get_current_row();
    if idx < 0 {
        return None;
    }
    let rows = dialog.get_rows();
    rows.row_data(idx as usize).map(|row| row.id.to_string())
}

/// Selects the row with the given site id (used to reselect the edited site
/// after a save, like the C++ reselect loop) and scrolls it into view.
fn select_row_by_id(dialog: &crate::ui::site_manager::SiteManagerDialog, id: &str) {
    let rows = dialog.get_rows();
    let idx = rows
        .iter()
        .position(|row| row.id == id)
        .map(|idx| idx as i32);
    let Some(idx) = idx else {
        return;
    };
    dialog.set_current_row(idx);
    scroll_row_into_view(dialog, idx);
}

/// Keeps a table row visible (30px row height, mirrors the Slint-side
/// `move-selection` scroll math).
fn scroll_row_into_view(dialog: &crate::ui::site_manager::SiteManagerDialog, idx: i32) {
    dialog.invoke_ensure_row_visible(idx);
}

/// Case-insensitive sort over the four table columns (port of the Qt table
/// sorting enabled via `setSortingEnabled(true)`).
fn sort_site_rows(rows: &mut [crate::ui::site_manager::SiteRow], col: usize, asc: bool) {
    let key = |row: &crate::ui::site_manager::SiteRow| -> String {
        match col {
            1 => row.protocol.to_string(),
            2 => row.host.to_string(),
            3 => row.username.to_string(),
            _ => row.name.to_string(),
        }
        .to_lowercase()
    };
    rows.sort_by(|a, b| {
        let ord = key(a).cmp(&key(b));
        if asc {
            ord
        } else {
            ord.reverse()
        }
    });
}

/// Fills the inline editor from a [`SiteEntry`] (port of the C++ edit flow).
fn populate_editor(dialog: &crate::ui::site_manager::SiteManagerDialog, site: &SiteEntry) {
    dialog.set_editor_name(site.name.clone().into());
    dialog.set_editor_protocol(protocol_storage_name(site.protocol).into());
    dialog.set_editor_host(site.host.clone().into());
    dialog.set_editor_port(site.port as i32);
    dialog.set_editor_username(site.username.clone().into());
    dialog.set_editor_password(site.password.clone().unwrap_or_default().into());
    dialog.set_editor_key_path(site.private_key_path.clone().unwrap_or_default().into());
    dialog.set_editor_key_passphrase(
        site.private_key_passphrase
            .clone()
            .unwrap_or_default()
            .into(),
    );
    dialog.set_editor_save_credentials(site.save_credentials);
    dialog.set_editor_scp_mode(scp_transfer_mode_storage_name(site.scp_transfer_mode).into());
    dialog.set_editor_known_hosts_policy(match site.known_hosts_policy {
        KnownHostsPolicy::Strict => 0,
        KnownHostsPolicy::AcceptNew => 1,
        KnownHostsPolicy::Off => 2,
    });
    dialog.set_editor_integrity_policy(match site.transfer_integrity_policy {
        TransferIntegrityPolicy::Off => 0,
        TransferIntegrityPolicy::Optional => 1,
        TransferIntegrityPolicy::Required => 2,
    });
    dialog.set_editor_ftps_verify_peer(site.ftps_verify_peer);
    dialog.set_editor_ftps_ca_cert(site.ftps_ca_cert_path.clone().unwrap_or_default().into());
    dialog.set_editor_webdav_scheme(webdav_scheme_storage_name(site.webdav_scheme).into());
    dialog.set_editor_webdav_verify_peer(site.webdav_verify_peer);
    dialog.set_editor_webdav_ca_cert(site.webdav_ca_cert_path.clone().unwrap_or_default().into());
    dialog.set_editor_smb_domain(site.smb_domain.clone().unwrap_or_default().into());
    dialog.set_editor_telnet_tls(site.telnet_tls);
    dialog.set_editor_telnet_verify_peer(site.telnet_verify_peer);
    dialog.set_editor_telnet_ca_cert(site.telnet_ca_cert_path.clone().unwrap_or_default().into());
    dialog.set_editor_telnet_auto_login(site.telnet_auto_login);
    // C++ setOptions: the jump host wins over the proxy. When a jump host is
    // configured the proxy selector shows "Direct" and the proxy fields stay
    // empty (the C++ dialog is freshly constructed per edit; this inline
    // editor persists, so clear stale values explicitly).
    let has_jump = site.jump_host.is_some();
    let effective_proxy_type = if has_jump {
        ProxyType::None
    } else {
        site.proxy_type
    };
    dialog.set_editor_proxy_type(match effective_proxy_type {
        ProxyType::None => 0,
        ProxyType::Socks5 => 1,
        ProxyType::HttpConnect => 2,
    });
    if effective_proxy_type == ProxyType::None {
        dialog.set_editor_proxy_host("".into());
        dialog.set_editor_proxy_port(default_port_for_proxy_type(ProxyType::Socks5) as i32);
        dialog.set_editor_proxy_username("".into());
        dialog.set_editor_proxy_password("".into());
    } else {
        dialog.set_editor_proxy_host(site.proxy_host.clone().into());
        dialog.set_editor_proxy_port(site.proxy_port as i32);
        dialog.set_editor_proxy_username(site.proxy_username.clone().unwrap_or_default().into());
        dialog.set_editor_proxy_password(site.proxy_password.clone().unwrap_or_default().into());
    }
    dialog.set_editor_jump_host(site.jump_host.clone().unwrap_or_default().into());
    dialog.set_editor_jump_port(site.jump_port as i32);
    dialog.set_editor_jump_enabled(site.jump_host.is_some());
    dialog.set_editor_jump_username(site.jump_username.clone().unwrap_or_default().into());
    dialog.set_editor_jump_key_path(
        site.jump_private_key_path
            .clone()
            .unwrap_or_default()
            .into(),
    );
    dialog.set_editor_known_hosts_path(site.known_hosts_path.clone().unwrap_or_default().into());
    dialog.set_editor_mode_is_add(false);
    dialog.set_editing_site_id(site.id.clone().into());
}

/// Builds [`SessionOptions`] from the editor fields, porting
/// `ConnectionDialog::options()` including the transport rules (jump host
/// wins over proxy, never combined) and the protocol-specific resets (SCP
/// mode forced to Auto outside SCP, FTPS/WebDAV TLS fields cleared for other
/// protocols).
fn editor_options(dialog: &crate::ui::site_manager::SiteManagerDialog) -> SessionOptions {
    let protocol = protocol_from_storage_name(&dialog.get_editor_protocol());
    let caps = capabilities_for_protocol(protocol);
    let port_raw = dialog.get_editor_port().max(0) as u16;
    let port = if port_raw == 0 {
        default_port_for_protocol(protocol)
    } else {
        port_raw
    };
    // Credentials are collected whenever provided; the "Save
    // passwords/passphrases" checkbox does not gate them (C++
    // ConnectionDialog::options only checks for empty text; the checkbox only
    // feeds the ad-hoc quick-connect save prompt). Text is used raw, like
    // QLineEdit::text() — passwords with leading/trailing spaces survive.
    let password = dialog.get_editor_password().to_string();
    let key_passphrase = dialog.get_editor_key_passphrase().to_string();
    let proxy_password = dialog.get_editor_proxy_password().to_string();
    let _save_credentials = dialog.get_editor_save_credentials();

    // Transport: a jump host wins over the proxy (C++ useJump/useProxy).
    let jump_host = non_empty(dialog.get_editor_jump_host());
    let use_jump =
        caps.supports_jump_host && dialog.get_editor_jump_enabled() && jump_host.is_some();
    let requested_proxy_type = proxy_type_from_storage_value(dialog.get_editor_proxy_type());
    let use_proxy = caps.supports_proxy && requested_proxy_type != ProxyType::None && !use_jump;
    let proxy_type = if use_proxy {
        requested_proxy_type
    } else {
        ProxyType::None
    };
    let proxy_port_raw = dialog.get_editor_proxy_port().max(0) as u16;
    let proxy_port = if proxy_port_raw == 0 {
        default_port_for_proxy_type(requested_proxy_type)
    } else {
        proxy_port_raw
    };

    // WebDAV scheme/TLS only apply to WebDAV; plain HTTP forces no
    // verification (C++ resets webdav_* for other protocols).
    let webdav_scheme = if protocol == Protocol::WebDav {
        webdav_scheme_from_storage_name(&dialog.get_editor_webdav_scheme())
    } else {
        WebDavScheme::Https
    };
    let webdav_verify_peer = if protocol == Protocol::WebDav {
        if webdav_scheme == WebDavScheme::Http {
            false
        } else {
            dialog.get_editor_webdav_verify_peer()
        }
    } else {
        true
    };
    let webdav_ca = if protocol == Protocol::WebDav && webdav_scheme == WebDavScheme::Https {
        non_empty(dialog.get_editor_webdav_ca_cert())
    } else {
        None
    };
    // SMB workgroup/domain for NTLM authentication.
    let smb_domain = if protocol == Protocol::Smb {
        non_empty(dialog.get_editor_smb_domain())
    } else {
        None
    };
    // Telnet console settings (TLS + auto-login); plain telnet ignores the
    // TLS fields.
    let telnet_tls = protocol == Protocol::Telnet && dialog.get_editor_telnet_tls();
    let telnet_verify_peer = if telnet_tls {
        dialog.get_editor_telnet_verify_peer()
    } else {
        true
    };
    let telnet_ca = if telnet_tls {
        non_empty(dialog.get_editor_telnet_ca_cert())
    } else {
        None
    };
    let telnet_auto_login = protocol != Protocol::Telnet || dialog.get_editor_telnet_auto_login();

    let prefs = crate::settings::Preferences::load();

    SessionOptions {
        protocol,
        host: dialog.get_editor_host().trim().to_string(),
        port,
        username: dialog.get_editor_username().trim().to_string(),
        password: if password.is_empty() {
            None
        } else {
            Some(password)
        },
        private_key_path: non_empty(dialog.get_editor_key_path()),
        private_key_passphrase: if key_passphrase.is_empty() {
            None
        } else {
            Some(key_passphrase)
        },
        scp_transfer_mode: if protocol == Protocol::Scp {
            scp_transfer_mode_from_storage_name(&dialog.get_editor_scp_mode())
        } else {
            ScpTransferMode::Auto
        },
        known_hosts_policy: match dialog.get_editor_known_hosts_policy() {
            1 => KnownHostsPolicy::AcceptNew,
            2 => KnownHostsPolicy::Off,
            _ => KnownHostsPolicy::Strict,
        },
        transfer_integrity_policy: match dialog.get_editor_integrity_policy() {
            0 => TransferIntegrityPolicy::Off,
            2 => TransferIntegrityPolicy::Required,
            _ => TransferIntegrityPolicy::Optional,
        },
        ftps_verify_peer: if protocol == Protocol::Ftps {
            dialog.get_editor_ftps_verify_peer()
        } else {
            true
        },
        ftps_ca_cert_path: if protocol == Protocol::Ftps {
            non_empty(dialog.get_editor_ftps_ca_cert())
        } else {
            None
        },
        webdav_scheme,
        webdav_verify_peer,
        webdav_ca_cert_path: webdav_ca,
        smb_domain,
        telnet_tls,
        telnet_verify_peer,
        telnet_ca_cert_path: telnet_ca,
        telnet_auto_login,
        proxy_type,
        proxy_host: if use_proxy {
            dialog.get_editor_proxy_host().trim().to_string()
        } else {
            String::new()
        },
        proxy_port: if use_proxy { proxy_port } else { 0 },
        proxy_username: if use_proxy {
            non_empty(dialog.get_editor_proxy_username())
        } else {
            None
        },
        proxy_password: if use_proxy && !proxy_password.is_empty() {
            Some(proxy_password)
        } else {
            None
        },
        jump_host: if use_jump { jump_host } else { None },
        jump_port: {
            let raw = dialog.get_editor_jump_port();
            if raw <= 0 {
                22
            } else {
                raw as u16
            }
        },
        jump_username: if use_jump {
            non_empty(dialog.get_editor_jump_username())
        } else {
            None
        },
        jump_private_key_path: if use_jump {
            non_empty(dialog.get_editor_jump_key_path())
        } else {
            None
        },
        known_hosts_path: non_empty(dialog.get_editor_known_hosts_path()),
        // Fields the site dialog does not edit: inherit global preferences.
        known_hosts_hash_names: prefs.known_hosts_hashed,
        show_fp_hex: prefs.fp_hex,
        ..SessionOptions::default()
    }
}

/// Converts a possibly-empty editor string into an `Option<String>`.
fn non_empty(value: slint::SharedString) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Auto-name fallback used on Add when the name field is empty (C++
/// `onAdd`: `QString("%1@%2").arg(user, host)`).
fn auto_site_name(user: &str, host: &str) -> Option<String> {
    let user = user.trim();
    let host = host.trim();
    if user.is_empty() && host.is_empty() {
        None
    } else {
        Some(format!("{user}@{host}"))
    }
}

/// C++ `hasDuplicateSiteName`: case-insensitive comparison, optionally
/// ignoring the site being edited (matched by stable id).
fn has_duplicate_site_name(sites: &[SiteEntry], candidate: &str, ignore_id: Option<&str>) -> bool {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return false;
    }
    sites.iter().any(|e| {
        ignore_id.map(|id| e.id != id).unwrap_or(true) && e.name.eq_ignore_ascii_case(candidate)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_format_is_v4() {
        let id = new_site_id();
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        assert!(parts[2].starts_with('4'));
        assert_eq!(id.chars().count(), 36);
        // Uniqueness sanity check.
        let ids: std::collections::HashSet<String> = (0..64).map(|_| new_site_id()).collect();
        assert_eq!(ids.len(), 64);
    }

    #[test]
    fn site_entry_toml_roundtrip() {
        let mut e = SiteEntry {
            id: new_site_id(),
            name: "example".to_string(),
            protocol: Protocol::Ftps,
            host: "example.com".to_string(),
            port: 990,
            username: "root".to_string(),
            ..SiteEntry::default()
        };
        e.save_credentials = true;
        e.known_hosts_policy = KnownHostsPolicy::AcceptNew;
        e.transfer_integrity_policy = TransferIntegrityPolicy::Required;
        e.proxy_type = ProxyType::Socks5;
        e.proxy_port = 1080;
        e.jump_host = Some("bastion".to_string());
        e.smb_domain = Some("WORKGROUP".to_string());
        let text = toml::to_string(&e).unwrap();
        let parsed: SiteEntry = toml::from_str(&text).unwrap();
        assert_eq!(e.id, parsed.id);
        assert_eq!(e.name, parsed.name);
        assert_eq!(e.protocol, parsed.protocol);
        assert_eq!(e.host, parsed.host);
        assert_eq!(e.port, parsed.port);
        assert_eq!(e.username, parsed.username);
        assert_eq!(e.known_hosts_policy, parsed.known_hosts_policy);
        assert_eq!(
            e.transfer_integrity_policy,
            parsed.transfer_integrity_policy
        );
        assert_eq!(e.proxy_type, parsed.proxy_type);
        assert_eq!(e.proxy_port, parsed.proxy_port);
        assert_eq!(e.jump_host, parsed.jump_host);
        assert_eq!(e.smb_domain, parsed.smb_domain);
    }

    #[test]
    fn smb_site_gets_default_port_and_keeps_domain() {
        let file = SiteFileEntry {
            name: "nas".to_string(),
            protocol: "smb".to_string(),
            port: 0,
            smb_domain: "WORKGROUP".to_string(),
            ..SiteFileEntry::default()
        };
        let e = SiteEntry::from(file);
        assert_eq!(e.protocol, Protocol::Smb);
        assert_eq!(e.port, 445);
        assert_eq!(e.smb_domain.as_deref(), Some("WORKGROUP"));
        // An empty stored domain resolves to None.
        let none_file = SiteFileEntry {
            name: "nas2".to_string(),
            protocol: "smb".to_string(),
            ..SiteFileEntry::default()
        };
        assert_eq!(SiteEntry::from(none_file).smb_domain, None);
    }

    #[test]
    fn missing_port_defaults_to_protocol_default() {
        let file = SiteFileEntry {
            name: "dav".to_string(),
            protocol: "webdav".to_string(),
            port: 0,
            ..SiteFileEntry::default()
        };
        let e = SiteEntry::from(file);
        assert_eq!(e.protocol, Protocol::WebDav);
        assert_eq!(e.port, 443);
        assert_eq!(e.jump_port, 22);
        assert_eq!(e.webdav_scheme, WebDavScheme::Https);
    }

    #[test]
    fn legacy_http_webdav_disables_peer_verification() {
        let file = SiteFileEntry {
            name: "dav".to_string(),
            protocol: "webdav".to_string(),
            webdav_scheme: "http".to_string(),
            port: 80,
            ..SiteFileEntry::default()
        };
        let e = SiteEntry::from(file);
        assert!(!e.webdav_verify_peer);
        assert!(e.webdav_ca_cert_path.is_none());
    }

    #[test]
    fn secret_key_scheme_matches_cpp() {
        assert_eq!(id_secret_key("abc", "password"), "site-id:abc:password");
        assert_eq!(
            legacy_name_secret_key("mysite", "keypass"),
            "site:mysite:keypass"
        );
    }

    // -----------------------------------------------------------------------
    // Site Manager parity tests (validation, sorting, kh cleanup, editor).
    // -----------------------------------------------------------------------

    /// Slint 1.17 keeps the platform backend thread-local, so the testing
    /// backend must be installed once per test thread (not just once per
    /// process).
    fn test_backend() {
        thread_local! {
            static INIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        }
        if !INIT.with(|c| c.replace(true)) {
            i_slint_backend_testing::init_no_event_loop();
        }
    }

    fn test_site(id: &str, name: &str) -> SiteEntry {
        SiteEntry {
            id: id.to_string(),
            name: name.to_string(),
            host: format!("{name}.example.com"),
            ..SiteEntry::default()
        }
    }

    fn test_row(
        id: &str,
        name: &str,
        protocol: &str,
        host: &str,
        username: &str,
    ) -> crate::ui::site_manager::SiteRow {
        crate::ui::site_manager::SiteRow {
            id: id.into(),
            name: name.into(),
            protocol: protocol.into(),
            host: host.into(),
            username: username.into(),
        }
    }

    #[test]
    fn auto_name_falls_back_to_user_at_host() {
        assert_eq!(
            auto_site_name("root", "example.com").as_deref(),
            Some("root@example.com")
        );
        assert_eq!(
            auto_site_name("", "example.com").as_deref(),
            Some("@example.com")
        );
        assert_eq!(auto_site_name("root", "").as_deref(), Some("root@"));
        assert_eq!(auto_site_name("", ""), None);
        assert_eq!(auto_site_name("   ", "  "), None);
    }

    #[test]
    fn duplicate_name_check_is_case_insensitive_and_ignores_own_id() {
        let sites = vec![test_site("id-1", "Example"), test_site("id-2", "other")];
        assert!(has_duplicate_site_name(&sites, "example", None));
        assert!(has_duplicate_site_name(&sites, "EXAMPLE", None));
        assert!(!has_duplicate_site_name(&sites, "other2", None));
        assert!(!has_duplicate_site_name(&sites, "", None));
        assert!(!has_duplicate_site_name(&sites, "  ", None));
        // Renaming a site to its own (differently-cased) name is allowed.
        assert!(!has_duplicate_site_name(&sites, "example", Some("id-1")));
        assert!(has_duplicate_site_name(&sites, "example", Some("id-2")));
    }

    #[test]
    fn site_rows_sort_case_insensitively() {
        let mut rows = vec![
            test_row("id-z", "zeta", "SFTP", "z.example.com", "root"),
            test_row("id-a", "Alpha", "SCP", "a.example.com", "User"),
            test_row("id-b", "beta", "FTP", "b.example.com", "user"),
        ];
        sort_site_rows(&mut rows, 0, true);
        let names: Vec<String> = rows.iter().map(|r| r.name.to_string()).collect();
        assert_eq!(names, ["Alpha", "beta", "zeta"]);
        sort_site_rows(&mut rows, 0, false);
        let names: Vec<String> = rows.iter().map(|r| r.name.to_string()).collect();
        assert_eq!(names, ["zeta", "beta", "Alpha"]);
        // "User"/"user" compare equal: stable order is preserved.
        sort_site_rows(&mut rows, 3, true);
        let users: Vec<String> = rows.iter().map(|r| r.username.to_string()).collect();
        assert_eq!(users, ["root", "user", "User"]);
        sort_site_rows(&mut rows, 2, true);
        let hosts: Vec<String> = rows.iter().map(|r| r.host.to_string()).collect();
        assert_eq!(hosts, ["a.example.com", "b.example.com", "z.example.com"]);
    }

    #[test]
    fn editor_roundtrip_preserves_advanced_fields() {
        test_backend();
        let dialog = crate::ui::site_manager::SiteManagerDialog::new()
            .expect("Failed to create SiteManagerDialog");
        let site = SiteEntry {
            id: "roundtrip-id".to_string(),
            name: "roundtrip".to_string(),
            protocol: Protocol::Sftp,
            host: "example.com".to_string(),
            port: 22,
            username: "root".to_string(),
            known_hosts_path: Some("/custom/known_hosts".to_string()),
            jump_host: Some("bastion".to_string()),
            jump_port: 2200,
            jump_username: Some("jumpuser".to_string()),
            jump_private_key_path: Some("/keys/bastion.pem".to_string()),
            ..SiteEntry::default()
        };
        populate_editor(&dialog, &site);
        assert_eq!(dialog.get_editor_known_hosts_path(), "/custom/known_hosts");
        assert!(dialog.get_editor_jump_enabled());
        assert_eq!(dialog.get_editor_jump_username(), "jumpuser");
        assert_eq!(dialog.get_editor_jump_key_path(), "/keys/bastion.pem");
        assert_eq!(dialog.get_editor_jump_port(), 2200);
        assert!(!dialog.get_editor_mode_is_add());
        assert_eq!(dialog.get_editing_site_id(), "roundtrip-id");
        // Round-trip through editor_options() must keep the advanced fields.
        let opt = editor_options(&dialog);
        assert_eq!(opt.known_hosts_path.as_deref(), Some("/custom/known_hosts"));
        assert_eq!(opt.jump_username.as_deref(), Some("jumpuser"));
        assert_eq!(
            opt.jump_private_key_path.as_deref(),
            Some("/keys/bastion.pem")
        );
        assert_eq!(opt.jump_port, 2200);
        assert_eq!(opt.jump_host.as_deref(), Some("bastion"));
    }

    #[test]
    fn editor_add_mode_resets_to_defaults() {
        test_backend();
        let dialog = crate::ui::site_manager::SiteManagerDialog::new()
            .expect("Failed to create SiteManagerDialog");
        dialog.set_editor_mode_is_add(true);
        dialog.set_editing_site_id("".into());
        dialog.set_editor_jump_enabled(false);
        dialog.set_editor_jump_username("".into());
        dialog.set_editor_jump_key_path("".into());
        dialog.set_editor_known_hosts_path("".into());
        assert!(dialog.get_editor_mode_is_add());
        assert_eq!(dialog.get_editing_site_id(), "");
        let opt = editor_options(&dialog);
        assert_eq!(opt.jump_username, None);
        assert_eq!(opt.jump_private_key_path, None);
        assert_eq!(opt.known_hosts_path, None);
    }

    #[test]
    fn editor_options_jump_wins_over_proxy_and_resets_protocol_fields() {
        test_backend();
        let dialog = crate::ui::site_manager::SiteManagerDialog::new()
            .expect("Failed to create SiteManagerDialog");
        // SFTP with a SOCKS5 proxy AND an enabled jump host: the jump host
        // wins and the proxy is dropped (C++ useJump/useProxy).
        dialog.set_editor_protocol("sftp".into());
        dialog.set_editor_proxy_type(1);
        dialog.set_editor_proxy_host("proxy.example.com".into());
        dialog.set_editor_proxy_port(1080);
        dialog.set_editor_jump_enabled(true);
        dialog.set_editor_jump_host("bastion".into());
        dialog.set_editor_jump_username("jumpuser".into());
        // Values that must be ignored because the protocol is SFTP:
        dialog.set_editor_scp_mode("scp-only".into());
        dialog.set_editor_ftps_verify_peer(false);
        dialog.set_editor_ftps_ca_cert("/ca.pem".into());
        dialog.set_editor_webdav_scheme("http".into());
        dialog.set_editor_smb_domain("WORKGROUP".into());
        let opt = editor_options(&dialog);
        assert_eq!(opt.proxy_type, ProxyType::None);
        assert!(opt.proxy_host.is_empty());
        assert_eq!(opt.proxy_port, 0);
        assert_eq!(opt.proxy_username, None);
        assert_eq!(opt.proxy_password, None);
        assert_eq!(opt.jump_host.as_deref(), Some("bastion"));
        assert_eq!(opt.jump_username.as_deref(), Some("jumpuser"));
        assert_eq!(opt.scp_transfer_mode, ScpTransferMode::Auto);
        assert!(opt.ftps_verify_peer);
        assert_eq!(opt.ftps_ca_cert_path, None);
        assert_eq!(opt.webdav_scheme, WebDavScheme::Https);
        assert!(opt.webdav_verify_peer);
        assert_eq!(opt.webdav_ca_cert_path, None);
        assert_eq!(opt.smb_domain, None);

        // Disabling the jump host restores the configured proxy.
        dialog.set_editor_jump_enabled(false);
        let opt = editor_options(&dialog);
        assert_eq!(opt.proxy_type, ProxyType::Socks5);
        assert_eq!(opt.proxy_host, "proxy.example.com");
        assert_eq!(opt.proxy_port, 1080);
        assert_eq!(opt.jump_host, None);
        assert_eq!(opt.jump_username, None);

        // Jump checked but host empty: no jump, the proxy still applies
        // (C++ treats an empty jump host as "no jump").
        dialog.set_editor_jump_enabled(true);
        dialog.set_editor_jump_host("".into());
        let opt = editor_options(&dialog);
        assert_eq!(opt.jump_host, None);
        assert_eq!(opt.proxy_type, ProxyType::Socks5);
    }

    #[test]
    fn editor_options_smb_domain_and_default_port() {
        test_backend();
        let dialog = crate::ui::site_manager::SiteManagerDialog::new()
            .expect("Failed to create SiteManagerDialog");
        dialog.set_editor_protocol("smb".into());
        dialog.set_editor_host("nas.example.com".into());
        dialog.set_editor_port(0);
        dialog.set_editor_smb_domain("  WORKGROUP  ".into());
        let opt = editor_options(&dialog);
        assert_eq!(opt.protocol, Protocol::Smb);
        assert_eq!(opt.port, 445);
        assert_eq!(opt.smb_domain.as_deref(), Some("WORKGROUP"));
        // Empty/whitespace domain maps to None.
        dialog.set_editor_smb_domain("   ".into());
        assert_eq!(editor_options(&dialog).smb_domain, None);
    }

    #[test]
    fn populate_editor_jump_wins_over_proxy_display() {
        test_backend();
        let dialog = crate::ui::site_manager::SiteManagerDialog::new()
            .expect("Failed to create SiteManagerDialog");
        let site = SiteEntry {
            id: "jump-id".to_string(),
            name: "jump".to_string(),
            protocol: Protocol::Sftp,
            proxy_type: ProxyType::Socks5,
            proxy_host: "proxy.example.com".to_string(),
            proxy_port: 1080,
            jump_host: Some("bastion".to_string()),
            ..SiteEntry::default()
        };
        populate_editor(&dialog, &site);
        // The editor shows "Direct (no proxy)" and empty proxy fields, like
        // C++ setOptions' effectiveProxyType.
        assert_eq!(dialog.get_editor_proxy_type(), 0);
        assert_eq!(dialog.get_editor_proxy_host(), "");
        assert!(dialog.get_editor_jump_enabled());
        assert_eq!(dialog.get_editor_jump_host(), "bastion");
    }

    #[test]
    fn refresh_rows_sorts_by_name_and_preserves_selection_by_id() {
        test_backend();
        let dialog = crate::ui::site_manager::SiteManagerDialog::new()
            .expect("Failed to create SiteManagerDialog");
        let sites = vec![
            test_site("id-z", "zeta"),
            test_site("id-a", "Alpha"),
            test_site("id-b", "beta"),
        ];
        refresh_rows_from_sites(&dialog, sites.clone(), 0, true);
        let names: Vec<String> = dialog
            .get_rows()
            .iter()
            .map(|r| r.name.to_string())
            .collect();
        assert_eq!(names, ["Alpha", "beta", "zeta"]);
        // Select "zeta", then re-sort descending: the selection must follow
        // the site id, not the old row index.
        dialog.set_current_row(2);
        refresh_rows_from_sites(&dialog, sites, 0, false);
        let names: Vec<String> = dialog
            .get_rows()
            .iter()
            .map(|r| r.name.to_string())
            .collect();
        assert_eq!(names, ["zeta", "beta", "Alpha"]);
        assert_eq!(dialog.get_current_row(), 0);
        // A site that disappears from the model clears the selection.
        refresh_rows_from_sites(&dialog, vec![test_site("id-a", "Alpha")], 0, true);
        assert_eq!(dialog.get_current_row(), -1);
    }

    #[test]
    fn select_row_by_id_reselects_the_edited_site() {
        test_backend();
        let dialog = crate::ui::site_manager::SiteManagerDialog::new()
            .expect("Failed to create SiteManagerDialog");
        let sites = vec![
            test_site("id-z", "zeta"),
            test_site("id-a", "Alpha"),
            test_site("id-b", "beta"),
        ];
        refresh_rows_from_sites(&dialog, sites, 0, true);
        // beta is index 1 after sorting.
        select_row_by_id(&dialog, "id-b");
        assert_eq!(dialog.get_current_row(), 1);
        select_row_by_id(&dialog, "missing-id");
        assert_eq!(dialog.get_current_row(), 1);
    }

    #[test]
    fn remove_site_known_hosts_drops_only_matching_entries() {
        let dir = std::env::temp_dir().join(format!("freescp-kh-test-{}", new_site_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kh = dir.join("known_hosts");
        let key = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC";
        std::fs::write(
            &kh,
            format!(
                "example.com ssh-ed25519 {key}\n[example.com]:2222 ssh-ed25519 {key}\nother.example.com ssh-ed25519 {key}\n"
            ),
        )
        .unwrap();
        let entry = SiteEntry {
            host: "example.com".to_string(),
            port: 2222,
            known_hosts_path: Some(kh.to_string_lossy().into_owned()),
            ..SiteEntry::default()
        };
        remove_site_known_hosts(&entry);
        let remaining = std::fs::read_to_string(&kh).unwrap();
        assert!(!remaining.contains("[example.com]:2222"));
        assert!(remaining.contains("example.com ssh-ed25519"));
        assert!(remaining.contains("other.example.com"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_site_known_hosts_tolerates_missing_file() {
        let dir = std::env::temp_dir().join(format!("freescp-kh-test-{}", new_site_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let entry = SiteEntry {
            host: "example.com".to_string(),
            port: 22,
            known_hosts_path: Some(dir.join("does-not-exist").to_string_lossy().into_owned()),
            ..SiteEntry::default()
        };
        remove_site_known_hosts(&entry); // must not panic
        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // ~/.ssh/config import tests
    // -----------------------------------------------------------------------

    use freescp_core::ssh_config::SshHostBlock;

    #[test]
    fn ssh_alias_to_site_maps_block_fields() {
        let block = SshHostBlock {
            patterns: vec!["db".to_string()],
            host_name: Some("db.internal.example.com".to_string()),
            port: Some(2202),
            user: Some("deploy".to_string()),
            identity_files: vec!["/home/test/.ssh/id_db".to_string()],
            proxy_jump: Some("bastion:2222".to_string()),
        };
        let e = ssh_alias_to_site(
            "db",
            &block,
            KnownHostsPolicy::AcceptNew,
            TransferIntegrityPolicy::Required,
        );
        assert_eq!(e.name, "db");
        assert_eq!(e.protocol, Protocol::Sftp);
        // The alias is kept as the host so later config edits stay in effect
        // through connect-time resolution.
        assert_eq!(e.host, "db");
        assert_eq!(e.port, 2202);
        assert_eq!(e.username, "deploy");
        assert_eq!(e.private_key_path.as_deref(), Some("/home/test/.ssh/id_db"));
        assert_eq!(e.jump_host.as_deref(), Some("bastion"));
        assert_eq!(e.jump_port, 2222);
        assert!(!e.save_credentials);
        assert_eq!(e.known_hosts_policy, KnownHostsPolicy::AcceptNew);
        assert_eq!(
            e.transfer_integrity_policy,
            TransferIntegrityPolicy::Required
        );

        let bare = ssh_alias_to_site(
            "bare",
            &SshHostBlock::default(),
            KnownHostsPolicy::Strict,
            TransferIntegrityPolicy::Optional,
        );
        assert_eq!(bare.port, 22);
        assert_eq!(bare.username, "");
        assert_eq!(bare.private_key_path, None);
        assert_eq!(bare.jump_host, None);
        assert_eq!(bare.jump_port, 22);
    }

    #[test]
    fn import_upserts_and_skips_duplicates() {
        let mut file = SitesFile::default();
        file.sites.push(SiteFileEntry {
            name: "Web".to_string(),
            protocol: "sftp".to_string(),
            ..SiteFileEntry::default()
        });
        let entries = vec![
            ssh_alias_to_site(
                "web",
                &SshHostBlock::default(),
                KnownHostsPolicy::Strict,
                TransferIntegrityPolicy::Optional,
            ),
            ssh_alias_to_site(
                "db",
                &SshHostBlock {
                    user: Some("deploy".to_string()),
                    port: Some(2202),
                    ..SshHostBlock::default()
                },
                KnownHostsPolicy::Strict,
                TransferIntegrityPolicy::Optional,
            ),
        ];
        let (imported, skipped) = upsert_imported_sites(&mut file, &entries);
        assert_eq!((imported, skipped), (1, 1));
        assert_eq!(file.sites.len(), 2);
        // The new entry round-trips through the storage shape.
        let parsed = SiteEntry::from(file.sites[1].clone());
        assert_eq!(parsed.name, "db");
        assert_eq!(parsed.username, "deploy");
        assert_eq!(parsed.port, 2202);
        // Re-importing is a full skip.
        let (imported, skipped) = upsert_imported_sites(&mut file, &entries);
        assert_eq!((imported, skipped), (0, 2));
        assert_eq!(file.sites.len(), 2);
    }
}
