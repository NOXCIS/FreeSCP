//! Application preferences: pure-Rust port of the QSettings-backed settings
//! handled by `ui/SettingsDialog.cpp`.
//!
//! The Qt app persists everything under `QSettings("OpenSCP", "OpenSCP")`
//! (INI/plist). This port stores a single TOML document at
//! `<config_dir>/freescp/preferences.toml`; every QSettings key that
//! `SettingsDialog.cpp` reads or writes is mirrored as a field below (see the
//! `QSettings` key name in each doc comment).
//!
//! On the very first run (no `preferences.toml` yet) the legacy Qt store is
//! imported when one exists: `$XDG_CONFIG_HOME/OpenSCP/OpenSCP.conf` on
//! Linux and `~/Library/Preferences/com.openscp.OpenSCP.plist` on macOS (see
//! [`import_legacy_preferences`]). The import is idempotent and never
//! overwrites an existing `preferences.toml`.

use serde::{Deserialize, Serialize};
use slint::ComponentHandle;
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::state::AppState;

/// Subdirectory (under the platform config directory) holding all FreeSCP
/// persistence files: preferences, sites, history, and the insecure secret
/// fallback. Mirrors `QSettings("OpenSCP", ...)` organization.
const CONFIG_SUBDIR: &str = "freescp";

/// Preferences file name inside [`config_dir`].
pub const PREFERENCES_FILE: &str = "preferences.toml";

/// Absolute path of the FreeSCP config directory
/// (`dirs::config_dir()/freescp`, e.g. `~/.config/freescp` on Linux and
/// `~/Library/Application Support/freescp` on macOS).
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| {
            dirs::home_dir()
                .map(|h| h.join(".config"))
                .unwrap_or_default()
        })
        .join(CONFIG_SUBDIR)
}

/// First-run import of the OpenSCP-era config directories.
///
/// The OpenSCP Rust rewrite kept preferences, sites and the insecure fallback
/// secrets in `config_dir()/openscp`, and the window state next to the legacy
/// Qt store in `config_dir()/OpenSCP`. FreeSCP keeps its files under
/// `config_dir()/freescp` and the window state under `config_dir()/FreeSCP`.
/// When the FreeSCP directories do not exist yet and the OpenSCP ones do,
/// their contents are copied over, so existing users keep their preferences,
/// sites and window layout. Keychain secrets migrate lazily on first read
/// (see `secrets::migrate_legacy_secret`); the legacy directories are left
/// untouched so reverting to OpenSCP stays possible.
///
/// Must run before the first `Preferences::load()`; idempotent, because the
/// copy is skipped once `config_dir()` exists.
pub fn import_legacy_config_dir() {
    let new_dir = config_dir();
    if new_dir.is_dir() {
        return;
    }
    let Some(base) = new_dir.parent() else {
        return;
    };
    import_legacy_config_dir_from(base, &new_dir);
}

fn import_legacy_config_dir_from(base: &std::path::Path, new_dir: &std::path::Path) {
    // Idempotency guard: once the FreeSCP store exists, never touch it again.
    if new_dir.is_dir() {
        return;
    }
    let legacy_dir = base.join("openscp");
    if legacy_dir.is_dir() {
        match copy_dir_contents(&legacy_dir, new_dir) {
            Ok(count) if count > 0 => tracing::info!(
                "Imported {count} OpenSCP config file(s) into {}",
                new_dir.display()
            ),
            Ok(_) => {}
            Err(err) => tracing::warn!("Could not import the OpenSCP config directory: {err}"),
        }
    }

    let legacy_window_state = base.join("OpenSCP").join("window-state.toml");
    let window_state_dir = base.join("FreeSCP");
    let new_window_state = window_state_dir.join("window-state.toml");
    if legacy_window_state.is_file() && !new_window_state.exists() {
        if let Err(err) = std::fs::create_dir_all(&window_state_dir) {
            tracing::warn!("Could not create {}: {err}", window_state_dir.display());
            return;
        }
        match std::fs::copy(&legacy_window_state, &new_window_state) {
            Ok(_) => {
                tracing::info!(
                    "Imported OpenSCP window state into {}",
                    new_window_state.display()
                )
            }
            Err(err) => tracing::warn!("Could not import the OpenSCP window state: {err}"),
        }
    }
}

/// Recursively copies `src` into `dst` (created on demand), returning the
/// number of files copied. Symlinks are skipped.
fn copy_dir_contents(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<usize> {
    std::fs::create_dir_all(dst)?;
    let mut copied = 0usize;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dest = dst.join(entry.file_name());
        if file_type.is_dir() {
            copied += copy_dir_contents(&entry.path(), &dest)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &dest)?;
            copied += 1;
        }
    }
    Ok(copied)
}

/// Default local download directory, mirroring
/// `SettingsDialog.cpp::defaultDownloadDirPath()`
/// (`QStandardPaths::DownloadLocation`, falling back to `~/Downloads`).
pub fn default_download_dir() -> PathBuf {
    dirs::download_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join("Downloads")))
        .unwrap_or_default()
}

/// Default staging root, mirroring `SettingsDialog.cpp`:
/// `~/Downloads/FreeSCP-Dragged`.
pub fn default_staging_root() -> PathBuf {
    default_download_dir().join("FreeSCP-Dragged")
}

/// All user preferences. Field names map 1:1 to the QSettings keys in
/// `ui/SettingsDialog.cpp` (key name documented per field). Missing keys in
/// the TOML file fall back to [`Default`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Preferences {
    /// `UI/language` — "en", "es", "fr", "pt".
    pub language: String,
    /// `UI/showHidden`.
    pub show_hidden: bool,
    /// `UI/singleClick`.
    pub single_click: bool,
    /// `UI/openBehaviorMode` — "ask" | "reveal" | "open".
    /// ("ask" is derived from the legacy `UI/openRevealInFolder` when absent,
    /// see the C++ load path.)
    pub open_behavior: String,
    /// `Shortcuts/openTransfers` (Qt portable text, e.g. "F12").
    pub open_transfers_shortcut: String,
    /// `Shortcuts/openHistory` (Qt portable text, e.g. "Ctrl+Shift+H").
    pub open_history_shortcut: String,
    /// `UI/showQueueOnEnqueue`.
    pub show_queue_on_enqueue: bool,
    /// `UI/defaultDownloadDir`.
    pub default_download_dir: String,
    /// `UI/showConnOnStart` — open the Site Manager on startup.
    pub open_site_manager_on_startup: bool,
    /// `UI/openSiteManagerOnDisconnect`.
    pub open_site_manager_on_disconnect: bool,
    /// `Sites/deleteSecretsOnRemove` — when deleting a site, also remove its
    /// stored credentials.
    pub delete_secrets_on_remove: bool,
    /// `Protocol/defaultProtocol` — protocol storage name ("sftp", ...).
    pub default_protocol: String,
    /// `Protocol/scpTransferModeDefault` — "auto" | "scp-only".
    pub default_scp_mode: String,
    /// `Security/defaultKnownHostsPolicy` — 0 Strict, 1 AcceptNew, 2 Off
    /// (matches the C++ enum discriminants).
    pub default_known_hosts_policy: i64,
    /// `Security/defaultTransferIntegrityPolicy` — 0 Off, 1 Optional,
    /// 2 Required (matches the C++ enum discriminants).
    pub default_transfer_integrity_policy: i64,
    /// `Security/ftpsVerifyPeerDefault`.
    pub ftps_verify_peer_default: bool,
    /// `Security/ftpsCaCertPathDefault` (empty = system CA bundle).
    pub ftps_ca_cert_path_default: String,
    /// `Security/knownHostsHashed` — hash hostnames in known_hosts.
    pub known_hosts_hashed: bool,
    /// `Security/fpHex` — show fingerprints in HEX colon format (visual only).
    pub fp_hex: bool,
    /// `Terminal/forceInteractiveLogin` — disable key/agent auth for
    /// "Open in terminal".
    pub terminal_force_interactive_login: bool,
    /// `Terminal/enableSftpCliFallback`.
    pub terminal_enable_sftp_cli_fallback: bool,
    /// `Security/noHostVerificationTtlMin` — minutes (1..=120).
    pub no_host_verification_ttl_min: i64,
    /// `Security/enableInsecureSecretFallback` — allow the insecure
    /// credential fallback (non-macOS without a secure backend).
    pub enable_insecure_secret_fallback: bool,
    /// `Security/macKeychainRestrictive` — stricter Keychain accessibility
    /// (macOS only).
    pub mac_keychain_restrictive: bool,
    /// `Transfer/maxConcurrent` — parallel transfer count (1..=8).
    pub max_concurrent: i64,
    /// `Transfer/globalSpeedKBps` — default global speed limit (0 = none).
    pub global_speed_kbps: i64,
    /// `Transfer/defaultQueueAutoClearMode` — 0 Off, 1 Completed,
    /// 2 Failed/Canceled, 3 All finished.
    pub default_queue_auto_clear_mode: i64,
    /// `Transfer/defaultQueueAutoClearMinutes` (1..=1440).
    pub default_queue_auto_clear_minutes: i64,
    /// `Network/sessionHealthIntervalSec` (60..=86400).
    pub session_health_interval_sec: i64,
    /// `Network/remoteWriteabilityTtlMs` (1000..=120000).
    pub remote_writeability_ttl_ms: i64,
    /// `Advanced/stagingRoot`.
    pub staging_root: String,
    /// `Advanced/autoCleanStaging`.
    pub auto_clean_staging: bool,
    /// `Advanced/stagingRetentionDays` (1..=365).
    pub staging_retention_days: i64,
    /// `Advanced/stagingPrepTimeoutMs` (250..=60000).
    pub staging_prep_timeout_ms: i64,
    /// `Advanced/stagingConfirmItems` (50..=100000).
    pub staging_confirm_items: i64,
    /// `Advanced/stagingConfirmMiB` (128..=65536).
    pub staging_confirm_mib: i64,
    /// `Advanced/maxFolderDepth` (4..=256).
    pub max_folder_depth: i64,
}

impl Default for Preferences {
    fn default() -> Self {
        Preferences {
            language: "en".into(),
            show_hidden: false,
            single_click: false,
            open_behavior: "ask".into(),
            open_transfers_shortcut: "F12".into(),
            open_history_shortcut: "Ctrl+Shift+H".into(),
            show_queue_on_enqueue: true,
            default_download_dir: default_download_dir().to_string_lossy().into_owned(),
            open_site_manager_on_startup: true,
            open_site_manager_on_disconnect: true,
            delete_secrets_on_remove: false,
            default_protocol: freescp_core::protocol_storage_name(freescp_core::Protocol::Sftp)
                .to_string(),
            default_scp_mode: freescp_core::scp_transfer_mode_storage_name(
                freescp_core::ScpTransferMode::Auto,
            )
            .to_string(),
            default_known_hosts_policy: 0,        // Strict
            default_transfer_integrity_policy: 1, // Optional
            ftps_verify_peer_default: true,
            ftps_ca_cert_path_default: String::new(),
            known_hosts_hashed: true,
            fp_hex: false,
            terminal_force_interactive_login: false,
            terminal_enable_sftp_cli_fallback: true,
            no_host_verification_ttl_min: 15,
            enable_insecure_secret_fallback: false,
            mac_keychain_restrictive: false,
            max_concurrent: 2,
            global_speed_kbps: 0,
            default_queue_auto_clear_mode: 0, // Off
            default_queue_auto_clear_minutes: 15,
            session_health_interval_sec: 600,
            remote_writeability_ttl_ms: 15_000,
            staging_root: default_staging_root().to_string_lossy().into_owned(),
            auto_clean_staging: true,
            staging_retention_days: 7,
            staging_prep_timeout_ms: 2000,
            staging_confirm_items: 500,
            staging_confirm_mib: 1024,
            max_folder_depth: 32,
        }
    }
}

impl Preferences {
    /// Loads preferences from `config_dir()/freescp/preferences.toml`.
    /// Missing files or unparseable content fall back to [`Default`] (the
    /// C++ app likewise starts with defaults when QSettings has no values).
    pub fn load() -> Self {
        let path = config_dir().join(PREFERENCES_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => match toml::from_str::<Preferences>(&text) {
                Ok(prefs) => prefs,
                Err(e) => {
                    tracing::warn!(
                        "Could not parse preferences file {}: {e}; using defaults",
                        path.display()
                    );
                    Preferences::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // First run: import the legacy Qt QSettings store when one
                // exists. The cheap "does a legacy file exist?" check happens
                // inside `import_legacy_preferences`. Writing the imported
                // preferences makes the migration idempotent (the next load
                // finds `preferences.toml` and never re-imports).
                if let Some(imported) = import_legacy_preferences() {
                    tracing::info!("Imported legacy OpenSCP settings into {}", path.display());
                    if let Err(e) = imported.save() {
                        tracing::warn!("Could not persist imported preferences: {e}");
                    }
                    return imported;
                }
                Preferences::default()
            }
            Err(e) => {
                tracing::warn!(
                    "Could not read preferences file {}: {e}; using defaults",
                    path.display()
                );
                Preferences::default()
            }
        }
    }

    /// Persists preferences to `config_dir()/freescp/preferences.toml`,
    /// creating the directory when needed.
    pub fn save(&self) -> Result<(), String> {
        let dir = config_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Could not create config directory {}: {e}", dir.display()))?;
        let text = toml::to_string_pretty(self)
            .map_err(|e| format!("Could not serialize preferences: {e}"))?;
        std::fs::write(dir.join(PREFERENCES_FILE), text)
            .map_err(|e| format!("Could not write preferences: {e}"))
    }

    /// `default_protocol` parsed as a core [`freescp_core::Protocol`].
    pub fn default_protocol_enum(&self) -> freescp_core::Protocol {
        freescp_core::protocol_from_storage_name(&self.default_protocol)
    }

    /// `default_scp_mode` parsed as a core [`freescp_core::ScpTransferMode`].
    pub fn default_scp_mode_enum(&self) -> freescp_core::ScpTransferMode {
        freescp_core::scp_transfer_mode_from_storage_name(&self.default_scp_mode)
    }

    /// `default_known_hosts_policy` as a core enum (0 Strict, 1 AcceptNew,
    /// 2 Off; anything else falls back to Strict like the C++ load path).
    pub fn default_known_hosts_policy_enum(&self) -> freescp_core::KnownHostsPolicy {
        match self.default_known_hosts_policy {
            1 => freescp_core::KnownHostsPolicy::AcceptNew,
            2 => freescp_core::KnownHostsPolicy::Off,
            _ => freescp_core::KnownHostsPolicy::Strict,
        }
    }

    /// `default_transfer_integrity_policy` as a core enum (0 Off, 1 Optional,
    /// 2 Required; anything else falls back to Optional).
    pub fn default_transfer_integrity_policy_enum(&self) -> freescp_core::TransferIntegrityPolicy {
        match self.default_transfer_integrity_policy {
            0 => freescp_core::TransferIntegrityPolicy::Off,
            2 => freescp_core::TransferIntegrityPolicy::Required,
            _ => freescp_core::TransferIntegrityPolicy::Optional,
        }
    }
}

// ---------------------------------------------------------------------------
// Keyboard shortcuts
// ---------------------------------------------------------------------------

/// Supported chords for the transfer-queue shortcut (Qt portable text).
///
/// Slint has no dynamic `KeyBinding`: `ui/settings.slint` cannot build bindings
/// from a runtime list, so its `ShortcutRecorder` hard-codes the accepted
/// chords. This list and the recorder must stay in sync; the
/// `slint_shortcut_recorder_lists_every_candidate` unit test fails when they
/// drift. `main.rs` also mirrors these constants for its live `KeyBinding`s.
pub const QUEUE_SHORTCUT_CANDIDATES: [&str; 4] = ["F12", "Ctrl+Shift+T", "Ctrl+Alt+T", "Ctrl+J"];

/// Supported chords for the connection-history shortcut (Qt portable text).
pub const HISTORY_SHORTCUT_CANDIDATES: [&str; 3] = ["Ctrl+Shift+H", "Ctrl+H", "Ctrl+Alt+H"];

/// [`QUEUE_SHORTCUT_CANDIDATES`] as a slice.
#[allow(dead_code)]
pub fn queue_shortcut_candidates() -> &'static [&'static str] {
    &QUEUE_SHORTCUT_CANDIDATES
}

/// [`HISTORY_SHORTCUT_CANDIDATES`] as a slice.
#[allow(dead_code)]
pub fn history_shortcut_candidates() -> &'static [&'static str] {
    &HISTORY_SHORTCUT_CANDIDATES
}

/// Comma-joined candidate list, used by the Apply-time alert that names the
/// chords the shortcut fields accept.
pub fn queue_shortcut_hint() -> String {
    QUEUE_SHORTCUT_CANDIDATES.join(", ")
}

/// Comma-joined candidate list, used by the Apply-time alert that names the
/// chords the shortcut fields accept.
pub fn history_shortcut_hint() -> String {
    HISTORY_SHORTCUT_CANDIDATES.join(", ")
}

/// Canonicalizes a Qt-portable shortcut string without validating it:
/// modifier aliases ("Cmd", "Meta", "Option", ...) are mapped onto
/// "Ctrl"/"Alt"/"Shift", modifiers are reordered canonically, and the key
/// name is upper-cased.
fn canonical_shortcut(value: &str) -> String {
    const MODIFIER_ORDER: [&str; 3] = ["Ctrl", "Alt", "Shift"];
    let mut tokens: Vec<String> = value
        .split('+')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(|part| match part.to_lowercase().as_str() {
            "cmd" | "command" | "meta" | "ctrl" | "control" => "Ctrl".to_string(),
            "alt" | "option" => "Alt".to_string(),
            "shift" => "Shift".to_string(),
            other => other.to_uppercase(),
        })
        .collect();
    tokens.sort_by_key(|token| {
        MODIFIER_ORDER
            .iter()
            .position(|m| *m == token)
            .unwrap_or(MODIFIER_ORDER.len())
    });
    tokens.join("+")
}

/// Whether `value` names one of `candidates` after [`canonical_shortcut`]
/// ("cmd+s" spellings and any modifier order are accepted).
fn shortcut_supported(value: &str, candidates: &[&str]) -> bool {
    candidates.contains(&canonical_shortcut(value).as_str())
}

/// Normalizes a stored shortcut string (Qt portable text) into one of the
/// Slint candidate identifiers. Invalid or unsupported values fall back to
/// `default`. "Cmd" is normalized to "Ctrl" (Qt portable text uses "Ctrl"
/// on all platforms, including macOS) and modifier order is canonicalized.
pub fn normalized_shortcut(value: &str, candidates: &[&str], default: &str) -> String {
    let normalized = canonical_shortcut(value);
    if candidates.contains(&normalized.as_str()) {
        normalized
    } else {
        default.to_string()
    }
}

/// Outcome of validating the two shortcut-recorder fields on Apply.
#[derive(Debug, PartialEq, Eq)]
struct ValidatedShortcuts {
    /// Canonical Transfers shortcut, always one of
    /// [`QUEUE_SHORTCUT_CANDIDATES`].
    queue: String,
    /// Canonical History shortcut, always one of
    /// [`HISTORY_SHORTCUT_CANDIDATES`].
    history: String,
    /// Warning text when the typed Transfers chord was not supported.
    queue_warning: Option<String>,
    /// Warning text when the typed History chord was not supported.
    history_warning: Option<String>,
}

/// The `ShortcutRecorder` fields in `ui/settings.slint` only store candidate
/// chords (the Qt dialog used `QKeySequenceEdit` the same way), but a value
/// loaded from disk or pushed by `main.rs` may still be unsupported: it falls
/// back to the default and the returned warning names the supported chords so
/// the Apply path can alert and rewrite the field with the persisted value.
fn validate_shortcuts(queue_text: &str, history_text: &str) -> ValidatedShortcuts {
    let queue_typed = queue_text.trim();
    let history_typed = history_text.trim();
    let queue = normalized_shortcut(queue_typed, &QUEUE_SHORTCUT_CANDIDATES, "F12");
    let history = normalized_shortcut(history_typed, &HISTORY_SHORTCUT_CANDIDATES, "Ctrl+Shift+H");
    let queue_warning = (!shortcut_supported(queue_typed, &QUEUE_SHORTCUT_CANDIDATES)).then(|| {
        format!(
            "\"{queue_typed}\" is not a supported Transfers shortcut.\n\
             Supported shortcuts: {}.\nUsing {queue}.",
            queue_shortcut_hint()
        )
    });
    let history_warning =
        (!shortcut_supported(history_typed, &HISTORY_SHORTCUT_CANDIDATES)).then(|| {
            format!(
                "\"{history_typed}\" is not a supported History shortcut.\n\
                 Supported shortcuts: {}.\nUsing {history}.",
                history_shortcut_hint()
            )
        });
    ValidatedShortcuts {
        queue,
        history,
        queue_warning,
        history_warning,
    }
}

// ---------------------------------------------------------------------------
// Insecure credential fallback availability
// ---------------------------------------------------------------------------

/// Whether the "Allow insecure credentials fallback" checkbox should be
/// shown. Port of the compile-time gate in `ui/SettingsDialog.cpp`:
///
/// ```text
/// #if !defined(__APPLE__) && !defined(Q_OS_MAC) && !defined(Q_OS_MACOS) &&
///     !defined(HAVE_LIBSECRET) && !defined(FREESCP_BUILD_SECURE_ONLY)
/// ```
///
/// The C++ build hides the checkbox whenever a secure backend is compiled in
/// (libsecret on Linux) or the build is secure-only. The Rust port always
/// compiles the keyring backends (`apple-native` on macOS, `sync-secret-service`
/// on Linux), i.e. the secure backend is always available in this build — the
/// `HAVE_LIBSECRET` equivalent — so this returns `false` everywhere.
///
/// The runtime escape hatch is unaffected: setting
/// `FREESCP_ENABLE_INSECURE_FALLBACK=1` still enables the fallback (see
/// `secrets.rs`), it just is not advertised in the UI.
///
/// Wired into `SettingsDialog.insecure-fallback-available` by
/// [`load_dialog_from_prefs`].
pub fn insecure_fallback_available() -> bool {
    // Not Apple (macOS uses the Keychain) and no secure backend compiled in.
    #[cfg(target_os = "macos")]
    {
        false
    }
    #[cfg(not(target_os = "macos"))]
    {
        // `keyring/sync-secret-service` is always compiled in (workspace
        // dependency), which is the faithful equivalent of HAVE_LIBSECRET.
        false
    }
}

// ---------------------------------------------------------------------------
// Legacy QSettings import (first run only)
// ---------------------------------------------------------------------------

/// Legacy Qt INI settings file (Linux):
/// `$XDG_CONFIG_HOME/OpenSCP/OpenSCP.conf`, defaulting to
/// `~/.config/OpenSCP/OpenSCP.conf`. Mirrors the QSettings file layout for
/// `QSettings("OpenSCP", "OpenSCP")`.
///
/// Only reached from the non-macOS import branch, but kept compiled
/// everywhere so its unit tests run on the macOS dev machine too.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn legacy_ini_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))?;
    Some(base.join("OpenSCP").join("OpenSCP.conf"))
}

/// Legacy Qt plist settings file (macOS):
/// `~/Library/Preferences/com.openscp.OpenSCP.plist`.
#[cfg(target_os = "macos")]
pub fn legacy_plist_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join("Library/Preferences/com.openscp.OpenSCP.plist"))
}

/// Parses Qt INI text (as written by `QSettings::IniFormat`) into a map of
/// `Section/key` → value. Keys inside a section may contain `/` (nested
/// groups, e.g. `[UI]` + `mainWindow/geometry`), arrays use the
/// `[sites] size=N` + `[sites/1] ...` form and are kept as ordinary keys;
/// only the scalar keys listed in [`preferences_from_legacy`] are consumed.
///
/// Only reached from the non-macOS import branch, but kept compiled
/// everywhere so its unit tests run on the macOS dev machine too.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn parse_qt_ini(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut section = String::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = unescape_qt_ini(inner.trim());
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let full_key = if section.is_empty() {
            unescape_qt_ini(key)
        } else {
            format!("{section}/{}", unescape_qt_ini(key))
        };
        map.insert(full_key, unescape_qt_ini(value.trim()));
    }
    map
}

/// Qt INI escape handling (`\\`, `\n`, `\t`, `\r`); unknown escapes keep the
/// escaped character, like Qt does.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn unescape_qt_ini(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// Parses the JSON emitted by `plutil -convert json` (or `defaults export`
/// piped through `plutil`) for the legacy macOS plist. `QSettings` on macOS
/// stores group hierarchies as dot-joined flat keys (`UI.language`), which
/// are normalized back to the `/` separator used everywhere else in this
/// module. Bools/ints are stringified, string arrays are comma-joined (the
/// same representation QSettings uses for `QStringList`).
pub fn parse_legacy_plist_json(text: &str) -> Option<BTreeMap<String, String>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    let mut map = BTreeMap::new();
    for (key, value) in object {
        let key = key.replace('.', "/");
        match value {
            serde_json::Value::String(s) => {
                map.insert(key, s.clone());
            }
            serde_json::Value::Bool(b) => {
                map.insert(key, b.to_string());
            }
            serde_json::Value::Number(n) => {
                map.insert(key, n.to_string());
            }
            serde_json::Value::Array(items) => {
                let joined = items
                    .iter()
                    .filter_map(|item| item.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                if !joined.is_empty() {
                    map.insert(key, joined);
                }
            }
            _ => {}
        }
    }
    Some(map)
}

/// Reads the legacy QSettings store, if one exists. The non-macOS branch is
/// a cheap `stat` plus a text read; the macOS branch shells out to
/// `defaults export`/`plutil` (no plist crate is available).
pub fn legacy_settings_map() -> Option<BTreeMap<String, String>> {
    #[cfg(target_os = "macos")]
    {
        legacy_settings_map_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        legacy_settings_map_ini()
    }
}

#[cfg(not(target_os = "macos"))]
fn legacy_settings_map_ini() -> Option<BTreeMap<String, String>> {
    let path = legacy_ini_path()?;
    if !path.is_file() {
        return None; // cheap stat on the no-legacy-file path
    }
    let text = std::fs::read_to_string(&path).ok()?;
    let map = parse_qt_ini(&text);
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

#[cfg(target_os = "macos")]
fn legacy_settings_map_macos() -> Option<BTreeMap<String, String>> {
    let path = legacy_plist_path()?;
    if !path.is_file() {
        return None; // cheap stat on the no-legacy-file path
    }
    // `defaults export` reads through cfprefsd, so it also sees values that
    // were written by the Qt app but not yet flushed to the plist file;
    // plutil converts the XML plist to JSON for serde_json.
    if let Ok(output) = std::process::Command::new("sh")
        .arg("-c")
        .arg(
            "defaults export com.openscp.OpenSCP - 2>/dev/null \
             | plutil -convert json -o - - 2>/dev/null",
        )
        .output()
    {
        if output.status.success() {
            if let Some(map) = parse_legacy_plist_json(&String::from_utf8_lossy(&output.stdout)) {
                if !map.is_empty() {
                    return Some(map);
                }
            }
        }
    }
    // Fallback: convert the plist file directly.
    let output = std::process::Command::new("/usr/bin/plutil")
        .arg("-convert")
        .arg("json")
        .arg("-o")
        .arg("-")
        .arg(&path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let map = parse_legacy_plist_json(&String::from_utf8_lossy(&output.stdout))?;
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

/// Imports the legacy Qt QSettings store into a [`Preferences`] value.
/// Returns `None` when no legacy source exists or it contains none of the
/// keys we import (so a legacy file holding only geometry/history/sites does
/// not create a `preferences.toml`).
///
/// Only the keys documented in the port plan are imported; window geometry,
/// history, sites and Qt transfer-queue keys have their own stores.
pub fn import_legacy_preferences() -> Option<Preferences> {
    let map = legacy_settings_map()?;
    preferences_from_legacy(&map)
}

/// Maps a legacy QSettings key/value map (keys in `Section/key` form) onto
/// [`Preferences`], applying the two C++ derivation rules:
///
/// 1. `UI/openBehaviorMode` absent → derive from `UI/openRevealInFolder`
///    (true → "reveal", false → "ask"), `SettingsDialog.cpp:698-712`.
/// 2. `UI/openSiteManagerOnDisconnect` absent → one-shot copy of
///    `UI/showConnOnStart`, `MainWindow.cpp:1227-1246`.
///
/// Values are validated/clamped to the same ranges as the C++ load path
/// (out-of-range values keep the Rust default, unknown strings fall back
/// like the C++ `findData` fallbacks).
pub fn preferences_from_legacy(map: &BTreeMap<String, String>) -> Option<Preferences> {
    let mut prefs = Preferences::default();
    let mut applied = false;

    macro_rules! legacy_set {
        ($field:ident, $key:literal, $conv:expr) => {
            if let Some(value) = map.get($key).and_then($conv) {
                prefs.$field = value;
                applied = true;
            }
        };
    }

    legacy_set!(language, "UI/language", legacy_string);
    legacy_set!(show_hidden, "UI/showHidden", legacy_bool);
    legacy_set!(single_click, "UI/singleClick", legacy_bool);
    legacy_set!(show_queue_on_enqueue, "UI/showQueueOnEnqueue", legacy_bool);
    legacy_set!(default_download_dir, "UI/defaultDownloadDir", |v| {
        legacy_string(v)
    });
    legacy_set!(
        open_site_manager_on_startup,
        "UI/showConnOnStart",
        legacy_bool
    );
    legacy_set!(
        delete_secrets_on_remove,
        "Sites/deleteSecretsOnRemove",
        legacy_bool
    );
    legacy_set!(default_protocol, "Protocol/defaultProtocol", |v| {
        legacy_string(v).map(|s| {
            freescp_core::protocol_storage_name(freescp_core::protocol_from_storage_name(
                s.trim().to_lowercase().as_str(),
            ))
            .to_string()
        })
    });
    legacy_set!(default_scp_mode, "Protocol/scpTransferModeDefault", |v| {
        legacy_string(v).map(|s| {
            freescp_core::scp_transfer_mode_storage_name(
                freescp_core::scp_transfer_mode_from_storage_name(s.trim().to_lowercase().as_str()),
            )
            .to_string()
        })
    });
    legacy_set!(
        default_known_hosts_policy,
        "Security/defaultKnownHostsPolicy",
        |v| { legacy_int(v).map(|n| n.clamp(0, 2)) }
    );
    legacy_set!(
        default_transfer_integrity_policy,
        "Security/defaultTransferIntegrityPolicy",
        |v| legacy_int(v).map(|n| n.clamp(0, 2))
    );
    legacy_set!(
        ftps_verify_peer_default,
        "Security/ftpsVerifyPeerDefault",
        legacy_bool
    );
    legacy_set!(
        ftps_ca_cert_path_default,
        "Security/ftpsCaCertPathDefault",
        |v| { legacy_string(v) }
    );
    legacy_set!(known_hosts_hashed, "Security/knownHostsHashed", legacy_bool);
    legacy_set!(fp_hex, "Security/fpHex", legacy_bool);
    legacy_set!(
        terminal_force_interactive_login,
        "Terminal/forceInteractiveLogin",
        legacy_bool
    );
    legacy_set!(
        terminal_enable_sftp_cli_fallback,
        "Terminal/enableSftpCliFallback",
        legacy_bool
    );
    legacy_set!(
        no_host_verification_ttl_min,
        "Security/noHostVerificationTtlMin",
        |v| legacy_int(v).map(|n| n.clamp(1, 120))
    );
    legacy_set!(
        enable_insecure_secret_fallback,
        "Security/enableInsecureSecretFallback",
        legacy_bool
    );
    legacy_set!(
        mac_keychain_restrictive,
        "Security/macKeychainRestrictive",
        legacy_bool
    );
    legacy_set!(max_concurrent, "Transfer/maxConcurrent", |v| legacy_int(v)
        .map(|n| n.clamp(1, 8)));
    legacy_set!(global_speed_kbps, "Transfer/globalSpeedKBps", |v| {
        legacy_int(v).map(|n| n.clamp(0, 1_000_000))
    });
    legacy_set!(
        default_queue_auto_clear_mode,
        "Transfer/defaultQueueAutoClearMode",
        |v| legacy_int(v).map(|n| n.clamp(0, 3))
    );
    legacy_set!(
        default_queue_auto_clear_minutes,
        "Transfer/defaultQueueAutoClearMinutes",
        |v| legacy_int(v).map(|n| n.clamp(1, 1440))
    );
    legacy_set!(
        session_health_interval_sec,
        "Network/sessionHealthIntervalSec",
        |v| legacy_int(v).map(|n| n.clamp(60, 86400))
    );
    legacy_set!(
        remote_writeability_ttl_ms,
        "Network/remoteWriteabilityTtlMs",
        |v| legacy_int(v).map(|n| n.clamp(1000, 120_000))
    );
    legacy_set!(staging_root, "Advanced/stagingRoot", legacy_string);
    legacy_set!(auto_clean_staging, "Advanced/autoCleanStaging", legacy_bool);
    legacy_set!(
        staging_retention_days,
        "Advanced/stagingRetentionDays",
        |v| { legacy_int(v).map(|n| n.clamp(1, 365)) }
    );
    legacy_set!(
        staging_prep_timeout_ms,
        "Advanced/stagingPrepTimeoutMs",
        |v| legacy_int(v).map(|n| n.clamp(250, 60_000))
    );
    legacy_set!(staging_confirm_items, "Advanced/stagingConfirmItems", |v| {
        legacy_int(v).map(|n| n.clamp(50, 100_000))
    });
    legacy_set!(staging_confirm_mib, "Advanced/stagingConfirmMiB", |v| {
        legacy_int(v).map(|n| n.clamp(128, 65_536))
    });
    legacy_set!(max_folder_depth, "Advanced/maxFolderDepth", |v| {
        legacy_int(v).map(|n| n.clamp(4, 256))
    });
    legacy_set!(open_transfers_shortcut, "Shortcuts/openTransfers", |v| {
        legacy_string(v).map(|s| normalized_shortcut(&s, &QUEUE_SHORTCUT_CANDIDATES, "F12"))
    });
    legacy_set!(open_history_shortcut, "Shortcuts/openHistory", |v| {
        legacy_string(v)
            .map(|s| normalized_shortcut(&s, &HISTORY_SHORTCUT_CANDIDATES, "Ctrl+Shift+H"))
    });

    // Rule 1: derive UI/openBehaviorMode from UI/openRevealInFolder when the
    // mode key is absent (SettingsDialog.cpp:698-712).
    let raw_mode = map
        .get("UI/openBehaviorMode")
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty());
    match raw_mode.as_deref() {
        Some(mode @ ("ask" | "reveal" | "open")) => {
            prefs.open_behavior = mode.to_string();
            applied = true;
        }
        Some(_) => {
            prefs.open_behavior = "ask".into(); // C++ findData fallback
            applied = true;
        }
        None => {
            if let Some(reveal) = map.get("UI/openRevealInFolder").and_then(legacy_bool) {
                prefs.open_behavior = if reveal { "reveal" } else { "ask" }.into();
                applied = true;
            }
        }
    }

    // Rule 2: one-shot copy UI/showConnOnStart → UI/openSiteManagerOnDisconnect
    // when the latter is absent (MainWindow.cpp:1227-1246).
    if let Some(value) = map
        .get("UI/openSiteManagerOnDisconnect")
        .and_then(legacy_bool)
    {
        prefs.open_site_manager_on_disconnect = value;
        applied = true;
    } else if let Some(value) = map.get("UI/showConnOnStart").and_then(legacy_bool) {
        prefs.open_site_manager_on_disconnect = value;
        applied = true;
    }

    if applied {
        Some(prefs)
    } else {
        None
    }
}

/// Qt booleans are stored as "true"/"false"; accept the common legacy
/// spellings as well.
fn legacy_bool(raw: impl AsRef<str>) -> Option<bool> {
    match raw.as_ref().trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn legacy_int(raw: impl AsRef<str>) -> Option<i64> {
    raw.as_ref().trim().parse().ok()
}

/// Non-empty trimmed string; empty legacy values keep the Rust default
/// (C++ treats an empty string as "unset" for the fields we import).
fn legacy_string(raw: impl AsRef<str>) -> Option<String> {
    let trimmed = raw.as_ref().trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

// ---------------------------------------------------------------------------
// About dialog: "Used libraries" text
// ---------------------------------------------------------------------------

/// Embedded fallback for the About "Used libraries" text. Kept identical to
/// the default of `libraries-text` in `ui/about.slint` (the final fallback
/// when even this Rust-side lookup finds nothing).
///
/// The About-dialog group below is called from `main.rs` (see WIRING NEEDED);
/// the allows keep `clippy -D warnings` green until that wiring lands.
#[allow(dead_code)]
pub const DEFAULT_LIBRARIES_TEXT: &str = "\
Third-party libraries used by FreeSCP (Rust rewrite)
(Operating system frameworks such as Security and AppKit on macOS, and the
system Secret Service on Linux, are excluded.)

GUI
- Slint
  Description: declarative GUI toolkit (windowing, widgets, gettext support).
  License: GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0
  Site: https://slint.dev/
  Copyright: SixtyFPS GmbH

Protocol backends
- russh
  Description: asynchronous SSH client used by the SFTP/SCP transports.
  License: Apache-2.0
  Site: https://github.com/warp-tech/russh
  Copyright: Eugene Retunsky and contributors
- russh-sftp
  Description: SFTP protocol implementation on top of russh.
  License: Apache-2.0
  Site: https://github.com/AspectUnk/russh-sftp
  Copyright: The russh-sftp developers
- suppaftp
  Description: FTP/FTPS client library.
  License: MIT OR Apache-2.0
  Site: https://github.com/veeso/suppaftp
  Copyright: Christian Visintin and contributors
- reqwest
  Description: HTTP client used by the WebDAV backend.
  License: MIT OR Apache-2.0
  Site: https://github.com/seanmonstar/reqwest
  Copyright: Sean McArthur and contributors
- quick-xml
  Description: XML parser used for WebDAV PROPFIND responses.
  License: MIT
  Site: https://github.com/tafia/quick-xml
  Copyright: The quick-xml developers
- tokio-socks
  Description: SOCKS5 proxy support for the protocol backends.
  License: MIT
  Site: https://github.com/sticnarf/tokio-socks
  Copyright: The tokio-socks developers

Runtime and plumbing
- tokio / futures-util / async-trait
  Description: asynchronous runtime, stream utilities, async trait support.
  License: MIT (tokio); MIT OR Apache-2.0 (futures-util, async-trait)
  Site: https://tokio.rs/ | https://github.com/rust-lang/futures-rs | https://github.com/dtolnay/async-trait
  Copyright: Tokio Contributors, David Tolnay and the futures-rs developers
- thiserror / anyhow
  Description: error type derivation and error context handling.
  License: MIT OR Apache-2.0
  Site: https://github.com/dtolnay/thiserror | https://github.com/dtolnay/anyhow
  Copyright: David Tolnay and contributors
- tracing / tracing-subscriber
  Description: structured logging and log filtering.
  License: MIT
  Site: https://github.com/tokio-rs/tracing
  Copyright: Tokio Contributors
- rand / sha2 / sha1 / hex / base64
  Description: random numbers, hashing and encoding helpers.
  License: MIT OR Apache-2.0
  Site: https://github.com/rust-random/rand | https://github.com/RustCrypto/hashes | https://github.com/KokaKiwi/rust-hex | https://github.com/marshallpierce/rust-base64
  Copyright: The Rand Project Developers, the RustCrypto Developers, KokaKiwi, Marshall Pierce and contributors

Configuration and filesystem
- serde / serde_json / toml
  Description: serialization and configuration parsing (preferences.toml,
  sites.toml, known_hosts).
  License: MIT OR Apache-2.0
  Site: https://serde.rs/ | https://github.com/toml-rs/toml
  Copyright: Erick Tryzelaar, David Tolnay and contributors
- dirs
  Description: platform config/data directory lookup.
  License: MIT OR Apache-2.0
  Site: https://github.com/soc/dirs-rs
  Copyright: The dirs developers
- walkdir / filetime
  Description: recursive directory walking and local file timestamps.
  License: Unlicense OR MIT (walkdir); MIT OR Apache-2.0 (filetime)
  Site: https://github.com/BurntSushi/walkdir | https://github.com/alexcrichton/filetime
  Copyright: Andrew Gallant, Alex Crichton and contributors
- chrono
  Description: date/time handling for timestamps and the transfer queue.
  License: MIT OR Apache-2.0
  Site: https://github.com/chronotope/chrono
  Copyright: The chrono developers
- regex
  Description: regular expressions for filtering and search.
  License: MIT OR Apache-2.0
  Site: https://github.com/rust-lang/regex
  Copyright: The Rust Project Developers

Desktop integration
- rfd
  Description: native file and folder dialogs.
  License: MIT
  Site: https://github.com/PolyMeilex/rfd
  Copyright: The rfd developers
- arboard
  Description: clipboard access (copied paths, diagnostics text).
  License: MIT OR Apache-2.0
  Site: https://github.com/1Password/arboard
  Copyright: The arboard developers
- mime_guess
  Description: file-extension to MIME type mapping.
  License: MIT
  Site: https://github.com/abonander/mime_guess
  Copyright: The mime_guess developers
- sys-locale
  Description: system language detection for the UI language default.
  License: MIT OR Apache-2.0
  Site: https://github.com/1Password/sys-locale
  Copyright: The sys-locale developers
- notify
  Description: filesystem change notifications for local pane refresh.
  License: CC0-1.0
  Site: https://github.com/notify-rs/notify
  Copyright: The notify developers
- keyring
  Description: Secret Service (Linux) credential storage.
  License: MIT OR Apache-2.0
  Site: https://github.com/hwchen/keyring-rs
  Copyright: The keyring developers
- security-framework (macOS only)
  Description: macOS Keychain access.
  License: MIT OR Apache-2.0
  Site: https://github.com/kornelski/rust-security-framework
  Copyright: The rust-security-framework developers

Notes:
- Specific versions may vary depending on platform/distribution.
- Thanks to the authors and communities of each project for their work.
- Full license texts are distributed with the sources of each crate
  (crates.io) and in the projects' repositories.
- The legacy Qt/C++ build of OpenSCP used Qt, libssh2, libcurl, tinyxml2,
  OpenSSL and zlib; their credits and license texts remain in
  docs/credits/CREDITS.md and docs/credits/LICENSES/.

Icons: Tango Icon Theme (Public Domain)";

/// Language suffix used by the C++ About dialog: `UI/language` starts with
/// "es"/"fr"/"pt" (case-insensitive) selects that catalog, anything else
/// falls back to EN (`AboutDialog.cpp:164-174`).
#[allow(dead_code)]
pub fn libraries_language_suffix(language: &str) -> &'static str {
    let lang = language.trim().to_ascii_lowercase();
    if lang.starts_with("es") {
        "ES"
    } else if lang.starts_with("fr") {
        "FR"
    } else if lang.starts_with("pt") {
        "PT"
    } else {
        "EN"
    }
}

/// Loads the About dialog's "Used libraries" text, port of
/// `AboutDialog.cpp:164-196`: try `docs/ABOUT_LIBRARIES_<LANG>.txt` and the
/// C++ fallback candidates next to the executable / CWD, then fall back to
/// [`DEFAULT_LIBRARIES_TEXT`].
#[allow(dead_code)]
pub fn libraries_text(language: &str) -> String {
    let suffix = libraries_language_suffix(language);
    let candidates = [
        format!("ABOUT_LIBRARIES_{suffix}.txt"),
        format!("ABOUT_LIBRARIES_{suffix}"),
        "ABOUT_LIBRARIES.txt".to_string(),
        "ABOUT_LIBRARIES".to_string(),
    ];
    libraries_text_from_bases(&candidates, &docs_search_bases())
        .unwrap_or_else(|| DEFAULT_LIBRARIES_TEXT.to_string())
}

/// Same search bases as `aboutSearchBases()` in `AboutDialog.cpp`: current
/// directory, executable directory, its parent and `../Resources` (macOS
/// bundle). The Cargo manifest directory is appended for dev builds.
#[allow(dead_code)]
fn docs_search_bases() -> Vec<PathBuf> {
    let mut bases: Vec<PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        bases.push(cwd);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            bases.push(dir.to_path_buf());
            if let Some(parent) = dir.parent() {
                bases.push(parent.to_path_buf());
            }
            bases.push(dir.join("../Resources"));
        }
    }
    if let Some(manifest) = option_env!("CARGO_MANIFEST_DIR") {
        let manifest = PathBuf::from(manifest);
        if manifest.is_dir() {
            bases.push(manifest);
        }
    }
    bases
}

/// Port of `findDocsFile`/`findFromCandidates` (`AboutDialog.cpp:37-72`):
/// look for `docs/<candidate>` in each base, then up to five levels above it.
#[allow(dead_code)]
fn libraries_text_from_bases(candidates: &[String], bases: &[PathBuf]) -> Option<String> {
    for base in bases {
        let mut dir = base.clone();
        for _ in 0..5 {
            for name in candidates {
                let candidate = dir.join("docs").join(name);
                if !candidate.is_file() {
                    continue;
                }
                match std::fs::read_to_string(&candidate) {
                    Ok(text) if !text.trim().is_empty() => return Some(text),
                    _ => continue,
                }
            }
            if !dir.pop() {
                break;
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Settings dialog wiring
// ---------------------------------------------------------------------------

// Strong references to every open settings dialog. Slint component handles
// are not `Clone`, so the registry keeps the modeless windows alive (like
// `main.rs` keeps the AboutDialog); the list is thread-local because the
// dialogs are `!Send` and only ever created on the event-loop thread.
thread_local! {
    static OPEN_SETTINGS_DIALOGS: std::cell::RefCell<Vec<crate::ui::settings::SettingsDialog>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Populates a `SettingsDialog` from [`Preferences`].
///
/// Programmatic population must not enable the Apply button: the dirty flag
/// is recomputed against the dialog's loaded baseline (see
/// [`bind_dirty_tracking`]); clearing it up front is belt-and-braces for the
/// deferred Slint `changed` callbacks.
fn load_dialog_from_prefs(dialog: &crate::ui::settings::SettingsDialog, prefs: &Preferences) {
    dialog.set_insecure_fallback_available(insecure_fallback_available());
    dialog.set_transfers_shortcut_hint(queue_shortcut_hint().into());
    dialog.set_history_shortcut_hint(history_shortcut_hint().into());
    dialog.set_language(prefs.language.clone().into());
    dialog.set_show_hidden(prefs.show_hidden);
    dialog.set_single_click(prefs.single_click);
    dialog.set_open_behavior(prefs.open_behavior.clone().into());
    dialog.set_open_transfers_shortcut(prefs.open_transfers_shortcut.clone().into());
    dialog.set_open_history_shortcut(prefs.open_history_shortcut.clone().into());
    dialog.set_show_queue_on_enqueue(prefs.show_queue_on_enqueue);
    dialog.set_open_site_manager_on_startup(prefs.open_site_manager_on_startup);
    dialog.set_open_site_manager_on_disconnect(prefs.open_site_manager_on_disconnect);
    dialog.set_delete_secrets_on_remove(prefs.delete_secrets_on_remove);
    dialog.set_default_protocol(prefs.default_protocol.clone().into());
    dialog.set_default_scp_mode(prefs.default_scp_mode.clone().into());
    dialog.set_default_known_hosts_policy(clamp_i32(prefs.default_known_hosts_policy));
    dialog.set_default_integrity_policy(clamp_i32(prefs.default_transfer_integrity_policy));
    dialog.set_ftps_verify_peer_default(prefs.ftps_verify_peer_default);
    dialog.set_ftps_ca_cert_path_default(prefs.ftps_ca_cert_path_default.clone().into());
    dialog.set_known_hosts_hashed(prefs.known_hosts_hashed);
    dialog.set_fp_hex(prefs.fp_hex);
    dialog.set_terminal_force_interactive_login(prefs.terminal_force_interactive_login);
    dialog.set_terminal_enable_sftp_cli_fallback(prefs.terminal_enable_sftp_cli_fallback);
    dialog.set_no_host_verification_ttl_min(clamp_i32(prefs.no_host_verification_ttl_min));
    dialog.set_enable_insecure_secret_fallback(prefs.enable_insecure_secret_fallback);
    dialog.set_mac_keychain_restrictive(prefs.mac_keychain_restrictive);
    dialog.set_max_concurrent(clamp_i32(prefs.max_concurrent));
    dialog.set_global_speed_kbps(clamp_i32(prefs.global_speed_kbps));
    dialog.set_default_queue_auto_clear_mode(clamp_i32(prefs.default_queue_auto_clear_mode));
    dialog.set_default_queue_auto_clear_minutes(clamp_i32(prefs.default_queue_auto_clear_minutes));
    dialog.set_session_health_interval_sec(clamp_i32(prefs.session_health_interval_sec));
    dialog.set_remote_writeability_ttl_ms(clamp_i32(prefs.remote_writeability_ttl_ms));
    dialog.set_default_download_dir(prefs.default_download_dir.clone().into());
    dialog.set_staging_root(prefs.staging_root.clone().into());
    dialog.set_auto_clean_staging(prefs.auto_clean_staging);
    dialog.set_staging_retention_days(clamp_i32(prefs.staging_retention_days));
    dialog.set_staging_prep_timeout_ms(clamp_i32(prefs.staging_prep_timeout_ms));
    dialog.set_staging_confirm_items(clamp_i32(prefs.staging_confirm_items));
    dialog.set_staging_confirm_mib(clamp_i32(prefs.staging_confirm_mib));
    dialog.set_max_folder_depth(clamp_i32(prefs.max_folder_depth));
    dialog.set_dirty(false);
}

/// Collects [`Preferences`] from the dialog's properties.
fn collect_dialog_prefs(dialog: &crate::ui::settings::SettingsDialog) -> Preferences {
    Preferences {
        language: dialog.get_language().to_string(),
        show_hidden: dialog.get_show_hidden(),
        single_click: dialog.get_single_click(),
        open_behavior: dialog.get_open_behavior().to_string(),
        open_transfers_shortcut: dialog.get_open_transfers_shortcut().to_string(),
        open_history_shortcut: dialog.get_open_history_shortcut().to_string(),
        show_queue_on_enqueue: dialog.get_show_queue_on_enqueue(),
        open_site_manager_on_startup: dialog.get_open_site_manager_on_startup(),
        open_site_manager_on_disconnect: dialog.get_open_site_manager_on_disconnect(),
        delete_secrets_on_remove: dialog.get_delete_secrets_on_remove(),
        default_protocol: dialog.get_default_protocol().to_string(),
        default_scp_mode: dialog.get_default_scp_mode().to_string(),
        default_known_hosts_policy: dialog.get_default_known_hosts_policy() as i64,
        default_transfer_integrity_policy: dialog.get_default_integrity_policy() as i64,
        ftps_verify_peer_default: dialog.get_ftps_verify_peer_default(),
        ftps_ca_cert_path_default: dialog.get_ftps_ca_cert_path_default().to_string(),
        known_hosts_hashed: dialog.get_known_hosts_hashed(),
        fp_hex: dialog.get_fp_hex(),
        terminal_force_interactive_login: dialog.get_terminal_force_interactive_login(),
        terminal_enable_sftp_cli_fallback: dialog.get_terminal_enable_sftp_cli_fallback(),
        no_host_verification_ttl_min: dialog.get_no_host_verification_ttl_min() as i64,
        enable_insecure_secret_fallback: dialog.get_enable_insecure_secret_fallback(),
        mac_keychain_restrictive: dialog.get_mac_keychain_restrictive(),
        max_concurrent: dialog.get_max_concurrent() as i64,
        global_speed_kbps: dialog.get_global_speed_kbps() as i64,
        default_queue_auto_clear_mode: dialog.get_default_queue_auto_clear_mode() as i64,
        default_queue_auto_clear_minutes: dialog.get_default_queue_auto_clear_minutes() as i64,
        session_health_interval_sec: dialog.get_session_health_interval_sec() as i64,
        remote_writeability_ttl_ms: dialog.get_remote_writeability_ttl_ms() as i64,
        default_download_dir: {
            // C++ trims the field, falls back to the default folder when it
            // is empty, and cleans the path (`onApply`).
            let text = dialog.get_default_download_dir().trim().to_string();
            if text.is_empty() {
                default_download_dir().to_string_lossy().into_owned()
            } else {
                text
            }
        },
        staging_root: dialog.get_staging_root().to_string(),
        auto_clean_staging: dialog.get_auto_clean_staging(),
        staging_retention_days: dialog.get_staging_retention_days() as i64,
        staging_prep_timeout_ms: dialog.get_staging_prep_timeout_ms() as i64,
        staging_confirm_items: dialog.get_staging_confirm_items() as i64,
        staging_confirm_mib: dialog.get_staging_confirm_mib() as i64,
        max_folder_depth: dialog.get_max_folder_depth() as i64,
    }
}

fn clamp_i32(value: i64) -> i32 {
    value.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// Whether the dialog's current values still match `baseline` (a preference
/// snapshot), port of the `modified` comparison in
/// `SettingsDialog::updateApplyFromControls`.
fn dialog_matches_prefs(
    dialog: &crate::ui::settings::SettingsDialog,
    baseline: &Preferences,
) -> bool {
    &collect_dialog_prefs(dialog) == baseline
}

/// Wires the dialog's `field-edited` callback to the Apply dirty flag, port
/// of `SettingsDialog::bindDirtyFlag` + `updateApplyFromControls`: Slint's
/// `changed` callbacks are deferred to the next event-loop pass, so the
/// comparison happens here against the loaded baseline instead of using a
/// write-only boolean in Slint. A programmatic load therefore never enables
/// Apply, while reverting an edit (e.g. declining the insecure-fallback
/// warning) disables it again.
fn bind_dirty_tracking(
    dialog: &crate::ui::settings::SettingsDialog,
    baseline: std::rc::Rc<std::cell::RefCell<Preferences>>,
) {
    let weak = dialog.as_weak();
    dialog.on_field_edited(move || {
        if let Some(dialog) = weak.upgrade() {
            let dirty = !dialog_matches_prefs(&dialog, &baseline.borrow());
            dialog.set_dirty(dirty);
        }
    });
}

/// Opens the modeless Settings dialog.
///
/// `state` is the main window's shared `Rc<RefCell<AppState>>`: the dialog
/// merges the persisted [`Preferences`] store with the live
/// [`crate::state::AppPreferences`] subset, and applying the dialog
/// persists the full merged set to `preferences.toml` and applies it to the
/// running application via [`crate::state::AppState::apply_preferences`].
pub fn open(
    win: &crate::ui::main_window::MainWindow,
    state: &std::rc::Rc<std::cell::RefCell<AppState>>,
) {
    let win_weak = win.as_weak();

    let dialog = match crate::ui::settings::SettingsDialog::new() {
        Ok(dialog) => dialog,
        Err(e) => {
            tracing::warn!("Could not create Settings dialog: {e}");
            return;
        }
    };

    // Center the dialog over the main window (port of parenting/modal
    // placement in the C++).
    if let Some(win) = win_weak.upgrade() {
        crate::remote::center_window_over(&win, dialog.window());
    }

    // Merge: persisted preferences overridden by the live AppPreferences
    // (the UI-behavior subset owned by the main-window workstream).
    let live = state.borrow().prefs.clone();
    let mut merged = Preferences::load();
    merged.show_hidden = live.show_hidden;
    merged.single_click = live.single_click;
    merged.open_behavior = live.open_behavior.clone();
    merged.show_queue_on_enqueue = live.show_queue_on_enqueue;
    merged.no_host_verification_ttl_min = live.no_host_verification_ttl_min;
    merged.open_site_manager_on_disconnect = live.open_site_manager_on_disconnect;
    merged.open_site_manager_on_startup = live.open_site_manager_on_startup;

    load_dialog_from_prefs(&dialog, &merged);
    dialog.set_is_macos(cfg!(target_os = "macos"));
    // Dirty-flag baseline: the dialog's normalized view of the merged
    // preferences it was just populated with (see `bind_dirty_tracking`).
    let baseline = std::rc::Rc::new(std::cell::RefCell::new(collect_dialog_prefs(&dialog)));
    bind_dirty_tracking(&dialog, std::rc::Rc::clone(&baseline));

    let weak = dialog.as_weak();
    let apply_state = std::rc::Rc::clone(state);
    let apply_win = win_weak.clone();
    let apply_baseline = std::rc::Rc::clone(&baseline);
    dialog.on_apply_requested(move || {
        let Some(dialog) = weak.upgrade() else { return };
        let prev = Preferences::load();
        let prev_language = prev.language.clone();
        let prev_show_hidden = prev.show_hidden;
        let mut prefs = collect_dialog_prefs(&dialog);
        // The shortcut recorders only ever store a candidate chord, but a
        // value loaded from disk (or pushed by main.rs) may still be
        // unsupported: those fall back to the default, are reported through
        // the same alert mechanism as the other Apply notices, and the field
        // is rewritten with the accepted chord.
        let validated =
            validate_shortcuts(&prefs.open_transfers_shortcut, &prefs.open_history_shortcut);
        for warning in [
            validated.queue_warning.as_deref(),
            validated.history_warning.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let _ = rfd::MessageDialog::new()
                .set_title("Shortcut not supported")
                .set_description(warning)
                .set_buttons(rfd::MessageButtons::Ok)
                .set_level(rfd::MessageLevel::Warning)
                .show();
        }
        prefs.open_transfers_shortcut = validated.queue.clone();
        prefs.open_history_shortcut = validated.history.clone();
        dialog.set_open_transfers_shortcut(validated.queue.clone().into());
        dialog.set_open_history_shortcut(validated.history.clone().into());
        match prefs.save() {
            Ok(()) => tracing::info!("preferences saved"),
            Err(e) => tracing::warn!("Could not save preferences: {e}"),
        }
        match apply_state.try_borrow_mut() {
            Ok(mut state) => state.apply_preferences(&prefs),
            Err(_) => {
                tracing::warn!("state busy; preferences apply on next interaction");
            }
        }
        // The C++ `applyPreferences` also re-arms the main-window shortcuts
        // and retargets the live session-health timer.
        if let Some(win) = apply_win.upgrade() {
            crate::apply_shortcut_prefs(&win, &prefs);
            // C++ applyLocalFilters re-reads the open folder immediately, so
            // toggling "Show hidden files" updates both panes in place.
            if prefs.show_hidden != prev_show_hidden {
                let path = win.get_left_path().to_string();
                crate::reload_local(&win, &apply_state, &path);
            }
        }
        crate::retarget_session_health_timer(prefs.session_health_interval_sec);
        // Port of SettingsDialog::onApply: only notify if language changed.
        if prefs.language != prev_language {
            let _ = rfd::MessageDialog::new()
                .set_title("Language")
                .set_description("Language changes take effect after restart.")
                .set_buttons(rfd::MessageButtons::Ok)
                .set_level(rfd::MessageLevel::Info)
                .show();
        }
        // The applied preferences are the new baseline, so the (deferred)
        // `field-edited` callbacks from the shortcut write-back recompute a
        // clean dialog; Apply is disabled again like the C++ onApply.
        *apply_baseline.borrow_mut() = prefs.clone();
        dialog.set_dirty(false);
        // Apply keeps the dialog open, like the C++ modal dialog; use Close
        // to dismiss it.
    });
    let weak = dialog.as_weak();
    dialog.on_close_requested(move || {
        if let Some(dialog) = weak.upgrade() {
            let _ = dialog.hide();
        }
    });
    let reset_state = std::rc::Rc::clone(state);
    let reset_win = win_weak.clone();
    dialog.on_reset_layout_requested(move || {
        let confirmed = rfd::MessageDialog::new()
            .set_title("Restore layout")
            .set_description("Restore the main window layout and column sizes to their defaults?")
            .set_buttons(rfd::MessageButtons::YesNo)
            .show()
            == rfd::MessageDialogResult::Yes;
        if !confirmed {
            return;
        }
        // Port of the QSettings geometry-key removal in SettingsDialog.cpp:
        // drop the persisted geometry so defaults apply, and resize the live
        // window (defaults from main-window.slint: 1200x700, split 560px).
        let mut st = reset_state.borrow_mut();
        st.window_state = crate::state::WindowState::default();
        if let Err(err) = st.window_state.save_to(&st.settings_dir) {
            tracing::warn!("could not reset window state: {err}");
        }
        if let Some(win) = reset_win.upgrade() {
            win.window()
                .set_size(slint::LogicalSize::new(1200.0, 700.0));
            win.set_left_pane_width(560.0);
            win.set_left_size_width(90.0);
            win.set_left_type_width(120.0);
            win.set_left_mtime_width(150.0);
            win.set_right_size_width(90.0);
            win.set_right_mtime_width(150.0);
            win.set_right_perm_width(120.0);
        }
        let _ = rfd::MessageDialog::new()
            .set_title("Restore layout")
            .set_description("Default layout restored.")
            .set_buttons(rfd::MessageButtons::Ok)
            .set_level(rfd::MessageLevel::Info)
            .show();
    });
    let weak = dialog.as_weak();
    dialog.on_browse_download_dir_requested(move || {
        if let (Some(dialog), Some(dir)) = (weak.upgrade(), rfd::FileDialog::new().pick_folder()) {
            dialog.set_default_download_dir(dir.to_string_lossy().to_string().into());
        }
    });
    let weak = dialog.as_weak();
    dialog.on_browse_staging_dir_requested(move || {
        if let (Some(dialog), Some(dir)) = (weak.upgrade(), rfd::FileDialog::new().pick_folder()) {
            dialog.set_staging_root(dir.to_string_lossy().to_string().into());
        }
    });
    let weak = dialog.as_weak();
    dialog.on_browse_ftps_ca_requested(move || {
        if let (Some(dialog), Some(file)) = (weak.upgrade(), rfd::FileDialog::new().pick_file()) {
            dialog.set_ftps_ca_cert_path_default(file.to_string_lossy().to_string().into());
        }
    });
    let weak = dialog.as_weak();
    dialog.on_insecure_fallback_toggled(move || {
        let Some(dialog) = weak.upgrade() else { return };
        if !dialog.get_enable_insecure_secret_fallback() {
            return; // only enabling needs the warning
        }
        // Port of the QCheckBox::toggled handler in SettingsDialog.cpp.
        let accepted = rfd::MessageDialog::new()
            .set_title("Enable insecure fallback")
            .set_description(
                "This stores credentials unencrypted on disk.\n\
                 On Linux, it is recommended to install and use \
                 libsecret/Secret Service for better security.\n\n\
                 Do you still want to enable insecure fallback?",
            )
            .set_buttons(rfd::MessageButtons::YesNo)
            .set_level(rfd::MessageLevel::Warning)
            .show()
            == rfd::MessageDialogResult::Yes;
        if !accepted {
            dialog.set_enable_insecure_secret_fallback(false);
        }
    });

    if let Err(e) = dialog.show() {
        tracing::warn!("Could not show Settings dialog: {e}");
    }
    OPEN_SETTINGS_DIALOGS.with(|cell| cell.borrow_mut().push(dialog));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_config_dir_import_copies_files_once() {
        let base = std::env::temp_dir().join(format!(
            "freescp-legacy-import-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let new_dir = base.join("freescp");
        std::fs::create_dir_all(base.join("openscp").join("nested")).unwrap();
        std::fs::write(base.join("openscp/preferences.toml"), "language = \"fr\"\n").unwrap();
        std::fs::write(base.join("openscp/nested/sites.toml"), "sites = []\n").unwrap();
        std::fs::create_dir_all(base.join("OpenSCP")).unwrap();
        std::fs::write(base.join("OpenSCP/window-state.toml"), "x = 1\n").unwrap();

        import_legacy_config_dir_from(&base, &new_dir);
        assert_eq!(
            std::fs::read_to_string(new_dir.join("preferences.toml")).unwrap(),
            "language = \"fr\"\n"
        );
        assert!(new_dir.join("nested/sites.toml").is_file());
        assert_eq!(
            std::fs::read_to_string(base.join("FreeSCP/window-state.toml")).unwrap(),
            "x = 1\n"
        );

        // The import is a no-op once the target directory exists.
        std::fs::write(new_dir.join("preferences.toml"), "language = \"es\"\n").unwrap();
        import_legacy_config_dir_from(&base, &new_dir);
        assert_eq!(
            std::fs::read_to_string(new_dir.join("preferences.toml")).unwrap(),
            "language = \"es\"\n"
        );

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn defaults_match_cpp() {
        let p = Preferences::default();
        assert_eq!(p.language, "en");
        assert!(!p.show_hidden);
        assert!(!p.single_click);
        assert_eq!(p.open_behavior, "ask");
        assert!(p.show_queue_on_enqueue);
        assert!(p.open_site_manager_on_startup);
        assert!(p.open_site_manager_on_disconnect);
        assert_eq!(p.default_protocol, "sftp");
        assert_eq!(p.default_scp_mode, "auto");
        assert_eq!(p.default_known_hosts_policy, 0);
        assert_eq!(p.default_transfer_integrity_policy, 1);
        assert!(p.ftps_verify_peer_default);
        assert!(p.known_hosts_hashed);
        assert_eq!(p.no_host_verification_ttl_min, 15);
        assert_eq!(p.max_concurrent, 2);
        assert_eq!(p.default_queue_auto_clear_minutes, 15);
        assert_eq!(p.session_health_interval_sec, 600);
        assert_eq!(p.remote_writeability_ttl_ms, 15000);
        assert!(p.auto_clean_staging);
        assert_eq!(p.max_folder_depth, 32);
    }

    #[test]
    fn enum_helpers() {
        let p = Preferences {
            default_protocol: "ftps".into(),
            default_scp_mode: "scp-only".into(),
            default_known_hosts_policy: 2,
            default_transfer_integrity_policy: 2,
            ..Preferences::default()
        };
        assert_eq!(p.default_protocol_enum(), freescp_core::Protocol::Ftps);
        assert_eq!(
            p.default_scp_mode_enum(),
            freescp_core::ScpTransferMode::ScpOnly
        );
        assert_eq!(
            p.default_known_hosts_policy_enum(),
            freescp_core::KnownHostsPolicy::Off
        );
        assert_eq!(
            p.default_transfer_integrity_policy_enum(),
            freescp_core::TransferIntegrityPolicy::Required
        );
    }

    #[test]
    fn toml_roundtrip_preserves_values() {
        let p = Preferences {
            show_hidden: true,
            language: "es".into(),
            no_host_verification_ttl_min: 60,
            ..Preferences::default()
        };
        let text = toml::to_string(&p).unwrap();
        let parsed: Preferences = toml::from_str(&text).unwrap();
        assert_eq!(p, parsed);
    }

    #[test]
    fn missing_keys_fall_back_to_defaults() {
        let parsed: Preferences = toml::from_str("show_hidden = true\n").unwrap();
        assert!(parsed.show_hidden);
        assert_eq!(parsed.language, Preferences::default().language);
        assert_eq!(
            parsed.no_host_verification_ttl_min,
            Preferences::default().no_host_verification_ttl_min
        );
    }

    // -----------------------------------------------------------------------
    // Legacy QSettings import: INI parsing (Linux), plist/JSON mapping
    // (macOS), key mapping + the two C++ derivation rules, and shortcut
    // normalization. Pure functions, so they run on every platform.
    // -----------------------------------------------------------------------

    #[test]
    fn qt_ini_parsing_handles_sections_nested_keys_arrays_and_escapes() {
        let text = "\
; comment line
# also a comment
[UI]
language=es
showHidden=true
mainWindow/geometry=@ByteArray(1,2,3)

[Shortcuts]
openTransfers=Ctrl+Shift+T

[sites]
size=2
[sites/1]
host=example.com
user=alice
path=/srv/a\\nb
";
        let map = parse_qt_ini(text);
        assert_eq!(map.get("UI/language").map(String::as_str), Some("es"));
        assert_eq!(map.get("UI/showHidden").map(String::as_str), Some("true"));
        // Keys may contain `/` inside a section (nested groups).
        assert_eq!(
            map.get("UI/mainWindow/geometry").map(String::as_str),
            Some("@ByteArray(1,2,3)")
        );
        assert_eq!(
            map.get("Shortcuts/openTransfers").map(String::as_str),
            Some("Ctrl+Shift+T")
        );
        // Arrays are ordinary keys; only the listed scalars are consumed.
        assert_eq!(map.get("sites/size").map(String::as_str), Some("2"));
        assert_eq!(
            map.get("sites/1/host").map(String::as_str),
            Some("example.com")
        );
        // Qt INI escapes: `\n` in the file decodes to a newline.
        assert_eq!(
            map.get("sites/1/path").map(String::as_str),
            Some("/srv/a\nb")
        );
        assert!(parse_qt_ini("").is_empty());
        assert!(parse_qt_ini("not-a-key-value-pair\n[broken\n").is_empty());
    }

    #[test]
    fn legacy_plist_json_maps_dot_joined_keys_and_scalar_types() {
        let json = r#"{
            "UI.language": "fr",
            "UI.showHidden": true,
            "Transfer.maxConcurrent": 4,
            "History.recentLocalPaths": ["/a", "/b"],
            "UI.nested": {"ignored": 1},
            "Sites.byId": [{"id": "x"}]
        }"#;
        let map = parse_legacy_plist_json(json).expect("valid plist JSON");
        assert_eq!(map.get("UI/language").map(String::as_str), Some("fr"));
        assert_eq!(map.get("UI/showHidden").map(String::as_str), Some("true"));
        assert_eq!(
            map.get("Transfer/maxConcurrent").map(String::as_str),
            Some("4")
        );
        // String arrays are comma-joined like QSettings QStringList.
        assert_eq!(
            map.get("History/recentLocalPaths").map(String::as_str),
            Some("/a, /b")
        );
        // Non-scalar and non-string array entries are ignored.
        assert!(!map.contains_key("UI/nested"));
        assert!(!map.contains_key("Sites/byId"));
        assert!(parse_legacy_plist_json("not json").is_none());
        assert!(parse_legacy_plist_json("[]").is_none());
    }

    #[test]
    fn legacy_values_map_onto_preferences_with_cpp_derivations() {
        let mut map = BTreeMap::new();
        map.insert("UI/language".to_string(), "pt".to_string());
        map.insert("UI/showHidden".to_string(), "true".to_string());
        map.insert("UI/showConnOnStart".to_string(), "false".to_string());
        map.insert("UI/openRevealInFolder".to_string(), "true".to_string());
        map.insert("Transfer/maxConcurrent".to_string(), "99".to_string());
        map.insert(
            "Security/noHostVerificationTtlMin".to_string(),
            "0".to_string(),
        );
        map.insert("Shortcuts/openTransfers".to_string(), "cmd+j".to_string());
        map.insert(
            "UI/mainWindow/geometry".to_string(),
            "@ByteArray(1)".to_string(),
        );
        let prefs = preferences_from_legacy(&map).expect("importable keys");
        assert_eq!(prefs.language, "pt");
        assert!(prefs.show_hidden);
        // Rule 2: openSiteManagerOnDisconnect copies showConnOnStart.
        assert!(!prefs.open_site_manager_on_disconnect);
        // Rule 1: openBehaviorMode absent → derived from openRevealInFolder.
        assert_eq!(prefs.open_behavior, "reveal");
        // Out-of-range ints keep the Rust default via the C++ clamp.
        assert_eq!(prefs.max_concurrent, 8);
        assert_eq!(prefs.no_host_verification_ttl_min, 1);
        // Qt portable aliases are normalized to the stored spelling.
        assert_eq!(prefs.open_transfers_shortcut, "Ctrl+J");

        // An explicit openBehaviorMode wins over the derived value, and an
        // explicit openSiteManagerOnDisconnect wins over showConnOnStart.
        let mut explicit = BTreeMap::new();
        explicit.insert("UI/openBehaviorMode".to_string(), "open".to_string());
        explicit.insert("UI/openRevealInFolder".to_string(), "true".to_string());
        explicit.insert("UI/showConnOnStart".to_string(), "false".to_string());
        explicit.insert(
            "UI/openSiteManagerOnDisconnect".to_string(),
            "true".to_string(),
        );
        let prefs = preferences_from_legacy(&explicit).expect("importable keys");
        assert_eq!(prefs.open_behavior, "open");
        assert!(prefs.open_site_manager_on_disconnect);

        // Unknown mode strings fall back like the C++ findData lookup.
        let mut unknown = BTreeMap::new();
        unknown.insert("UI/openBehaviorMode".to_string(), "bogus".to_string());
        assert_eq!(
            preferences_from_legacy(&unknown).unwrap().open_behavior,
            "ask"
        );

        // A store with only geometry/history/sites must not create a file.
        let mut ignored = BTreeMap::new();
        ignored.insert(
            "UI/mainWindow/geometry".to_string(),
            "@ByteArray(1)".to_string(),
        );
        ignored.insert("History/recentLocalPaths".to_string(), "/a".to_string());
        assert!(preferences_from_legacy(&ignored).is_none());
        assert!(preferences_from_legacy(&BTreeMap::new()).is_none());
    }

    /// The candidate lists exposed for main.rs must be the same sets that
    /// `normalized_shortcut` accepts, and the hint text must list them.
    #[test]
    fn candidate_lists_and_normalization_agree() {
        assert_eq!(queue_shortcut_candidates(), QUEUE_SHORTCUT_CANDIDATES);
        assert_eq!(history_shortcut_candidates(), HISTORY_SHORTCUT_CANDIDATES);
        for candidate in QUEUE_SHORTCUT_CANDIDATES {
            assert_eq!(
                normalized_shortcut(candidate, &QUEUE_SHORTCUT_CANDIDATES, "F12"),
                candidate,
                "{candidate} must normalize to itself"
            );
            assert!(queue_shortcut_hint().contains(candidate));
        }
        for candidate in HISTORY_SHORTCUT_CANDIDATES {
            assert_eq!(
                normalized_shortcut(candidate, &HISTORY_SHORTCUT_CANDIDATES, "Ctrl+Shift+H"),
                candidate,
                "{candidate} must normalize to itself"
            );
            assert!(history_shortcut_hint().contains(candidate));
        }
        // Unknown/unset values fall back to the default.
        assert_eq!(
            normalized_shortcut("", &QUEUE_SHORTCUT_CANDIDATES, "F12"),
            "F12"
        );
        assert_eq!(
            normalized_shortcut("Ctrl+Q", &QUEUE_SHORTCUT_CANDIDATES, "F12"),
            "F12"
        );
        // A hand-edited preferences.toml must still be recoverable: the macOS
        // "Cmd" spelling and any modifier order normalize to a candidate, an
        // unknown chord falls back to the default.
        let prefs: Preferences =
            toml::from_str("open_transfers_shortcut = \"cmd+shift+t\"").unwrap();
        assert_eq!(prefs.open_transfers_shortcut, "cmd+shift+t");
        assert_eq!(validate_shortcuts("cmd+shift+t", "").queue, "Ctrl+Shift+T");
        assert_eq!(validate_shortcuts("ctrl+q", "").queue, "F12");
    }

    // -----------------------------------------------------------------------
    // About dialog "Used libraries": language suffixes, the docs/ search
    // (port of findDocsFile) and the embedded fallback.
    // -----------------------------------------------------------------------

    #[test]
    fn libraries_language_suffix_matches_the_cpp_mapping() {
        assert_eq!(libraries_language_suffix("en"), "EN");
        assert_eq!(libraries_language_suffix("EN_us"), "EN");
        assert_eq!(libraries_language_suffix("es"), "ES");
        assert_eq!(libraries_language_suffix("es_MX"), "ES");
        assert_eq!(libraries_language_suffix("fr"), "FR");
        assert_eq!(libraries_language_suffix("pt_BR"), "PT");
        // Anything else falls back to the English catalog.
        assert_eq!(libraries_language_suffix("de"), "EN");
        assert_eq!(libraries_language_suffix(""), "EN");
    }

    #[test]
    fn libraries_text_search_prefers_existing_files_and_ignores_empty_ones() {
        let root =
            std::env::temp_dir().join(format!("freescp-about-libraries-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let docs = root.join("docs");
        std::fs::create_dir_all(&docs).expect("create fixture docs dir");
        std::fs::write(docs.join("ABOUT_LIBRARIES_ES.txt"), "créditos es").unwrap();
        std::fs::write(docs.join("EMPTY.txt"), "   \n").unwrap();

        let bases = vec![root.clone()];
        assert_eq!(
            libraries_text_from_bases(&["ABOUT_LIBRARIES_ES.txt".to_string()], &bases).as_deref(),
            Some("créditos es")
        );
        // Missing and empty candidates yield None, so `libraries_text` uses
        // the embedded default.
        assert!(
            libraries_text_from_bases(&["ABOUT_LIBRARIES_XX.txt".to_string()], &bases).is_none()
        );
        assert!(libraries_text_from_bases(&["EMPTY.txt".to_string()], &bases).is_none());
        assert!(libraries_text_from_bases(&[], &bases).is_none());
        assert!(libraries_text_from_bases(&["x.txt".to_string()], &[]).is_none());

        // findDocsFile walks up to five levels above each base.
        let deep = root.join("a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        assert_eq!(
            libraries_text_from_bases(&["ABOUT_LIBRARIES_ES.txt".to_string()], &[deep]).as_deref(),
            Some("créditos es")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// End-to-end lookup: with the repo checked out, the manifest directory
    /// base reaches `docs/`, so the localized file is preferred over the
    /// embedded fallback (which stays the last resort).
    #[test]
    fn libraries_text_reads_the_docs_files_next_to_the_manifests() {
        assert!(libraries_text("es").starts_with("Librerías de terceros"));
        assert!(libraries_text("fr").starts_with("Bibliothèques tierces"));
        assert!(libraries_text("pt").starts_with("Bibliotecas de terceiros"));
        assert!(libraries_text("en").starts_with("Third-party libraries used by FreeSCP"));
        // Unknown languages reuse the English catalog.
        assert!(libraries_text("de").starts_with("Third-party libraries used by FreeSCP"));
        assert!(DEFAULT_LIBRARIES_TEXT.starts_with("Third-party libraries used by FreeSCP"));
    }

    // -----------------------------------------------------------------------
    // About dialog contract (ui/about.slint): the credits shown by the dialog
    // must stay in sync with the Rust fallback constant that `libraries_text`
    // returns, and the named Close button must raise `close-requested` (the
    // callback `wire_about_dialog` in main.rs connects).
    // -----------------------------------------------------------------------

    /// Slint 1.17 keeps the platform backend thread-local, so the testing
    /// backend must be installed once per test thread (same helper as the
    /// Site Manager tests).
    fn test_backend() {
        thread_local! {
            static INIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        }
        if !INIT.with(|c| c.replace(true)) {
            i_slint_backend_testing::init_no_event_loop();
        }
    }

    #[test]
    fn about_dialog_defaults_describe_the_rust_dependency_set() {
        test_backend();
        let dialog = crate::ui::about::AboutDialog::new().expect("create AboutDialog");
        assert_eq!(dialog.get_libraries_text().as_str(), DEFAULT_LIBRARIES_TEXT);
        assert!(dialog.get_version_text().contains("Rust rewrite"));
    }

    /// Clicks `close-button := Button` in ui/about.slint through the Slint
    /// testing backend. The element query API needs compiler debug info, which
    /// build.rs only emits when `SLINT_EMIT_DEBUG_INFO=1` is set at build time,
    /// so the test reports a skip instead of failing without it.
    #[test]
    fn about_close_button_triggers_close_requested() {
        if std::env::var_os("SLINT_EMIT_DEBUG_INFO").is_none() {
            eprintln!("skipping: build with SLINT_EMIT_DEBUG_INFO=1 to query elements");
            return;
        }
        test_backend();
        let dialog = crate::ui::about::AboutDialog::new().expect("create AboutDialog");
        let clicked = std::rc::Rc::new(std::cell::Cell::new(false));
        {
            let clicked = clicked.clone();
            dialog.on_close_requested(move || clicked.set(true));
        }
        let button = i_slint_backend_testing::ElementHandle::find_by_element_id(
            &dialog,
            "AboutDialog::close-button",
        )
        .next()
        .expect("named Close button");
        button.invoke_accessible_default_action();
        assert!(clicked.get(), "Close button must trigger close-requested");
    }

    // -----------------------------------------------------------------------
    // Settings dialog: shortcut validation (Apply path) and the platform gate
    // for the insecure-fallback checkbox.
    // -----------------------------------------------------------------------

    #[test]
    fn supported_shortcuts_pass_through_either_spelling() {
        let canonical = validate_shortcuts("F12", "Ctrl+Shift+H");
        assert_eq!(canonical.queue, "F12");
        assert_eq!(canonical.history, "Ctrl+Shift+H");
        assert_eq!(canonical.queue_warning, None);
        assert_eq!(canonical.history_warning, None);
        // Qt portable aliases and any modifier order are accepted (macOS
        // "Cmd" maps to "Ctrl", like the C++ portable text).
        assert_eq!(validate_shortcuts("f12", "shift+ctrl+h"), canonical);
        assert_eq!(validate_shortcuts(" Ctrl+J ", "cmd+h").queue, "Ctrl+J");
        assert_eq!(validate_shortcuts(" Ctrl+J ", "cmd+h").history, "Ctrl+H");
        assert_eq!(validate_shortcuts(" Ctrl+J ", "cmd+h").queue_warning, None);
        assert_eq!(
            validate_shortcuts(" Ctrl+J ", "cmd+h").history_warning,
            None
        );
    }

    #[test]
    fn unsupported_shortcuts_fall_back_and_report_candidates() {
        let rejected = validate_shortcuts("Ctrl+Q", "");
        assert_eq!(rejected.queue, "F12");
        assert_eq!(rejected.history, "Ctrl+Shift+H");
        let queue_warning = rejected.queue_warning.as_deref().expect("queue warning");
        assert!(queue_warning.contains("Ctrl+Q"), "{queue_warning}");
        assert!(
            queue_warning.contains(&queue_shortcut_hint()),
            "{queue_warning}"
        );
        assert!(queue_warning.contains("F12"), "{queue_warning}");
        let history_warning = rejected
            .history_warning
            .as_deref()
            .expect("history warning");
        assert!(
            history_warning.contains(&history_shortcut_hint()),
            "{history_warning}"
        );
        // A supported chord in one field never warns about the other field.
        let mixed = validate_shortcuts("F12", "nonsense");
        assert_eq!(mixed.queue_warning, None);
        assert!(mixed.history_warning.is_some());
    }

    #[test]
    fn insecure_fallback_gate_hides_the_checkbox_losslessly() {
        test_backend();
        assert!(
            !insecure_fallback_available(),
            "the secure keyring backend is always compiled in"
        );
        let dialog = crate::ui::settings::SettingsDialog::new().expect("create SettingsDialog");
        let prefs = Preferences {
            enable_insecure_secret_fallback: true,
            ..Preferences::default()
        };
        load_dialog_from_prefs(&dialog, &prefs);
        assert!(!dialog.get_insecure_fallback_available());
        assert!(
            dialog.get_enable_insecure_secret_fallback(),
            "hidden checkbox must keep the loaded value"
        );
        // Round-trip lossless: the hidden field is still collected and saved.
        assert_eq!(collect_dialog_prefs(&dialog), prefs);
    }

    #[test]
    fn dirty_flag_tracks_edits_against_the_loaded_prefs() {
        test_backend();
        let dialog = crate::ui::settings::SettingsDialog::new().expect("create SettingsDialog");
        let prefs = Preferences::default();
        load_dialog_from_prefs(&dialog, &prefs);
        let baseline = std::rc::Rc::new(std::cell::RefCell::new(collect_dialog_prefs(&dialog)));
        bind_dirty_tracking(&dialog, std::rc::Rc::clone(&baseline));

        // Slint defers `changed` callbacks to the next event-loop pass; flush
        // them the way the backend does at the start of an iteration.
        slint::platform::update_timers_and_animations();
        assert!(
            !dialog.get_dirty(),
            "a programmatic load leaves Apply disabled"
        );

        dialog.set_show_hidden(!prefs.show_hidden);
        slint::platform::update_timers_and_animations();
        assert!(dialog.get_dirty(), "an edit enables Apply");

        dialog.set_open_transfers_shortcut("Ctrl+Q".into());
        slint::platform::update_timers_and_animations();
        assert!(dialog.get_dirty());

        dialog.set_show_hidden(prefs.show_hidden);
        slint::platform::update_timers_and_animations();
        assert!(dialog.get_dirty(), "the shortcut field is still edited");

        dialog.set_open_transfers_shortcut(prefs.open_transfers_shortcut.clone().into());
        slint::platform::update_timers_and_animations();
        assert!(
            !dialog.get_dirty(),
            "reverting every edit disables Apply again"
        );
    }

    #[test]
    fn shortcut_candidates_are_present_in_the_slint_recorder() {
        // Slint cannot build `KeyBinding`s dynamically, so `ShortcutRecorder`
        // hard-codes the accepted chords in `chord-supported`; this keeps the
        // two spellings from drifting.
        let slint =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/settings.slint"))
                .expect("read ui/settings.slint");
        for chord in QUEUE_SHORTCUT_CANDIDATES
            .iter()
            .chain(HISTORY_SHORTCUT_CANDIDATES.iter())
        {
            assert!(
                slint.contains(chord),
                "{chord} missing from ui/settings.slint"
            );
        }
    }

    fn press(window: &slint::Window, text: slint::SharedString) {
        window.dispatch_event(slint::platform::WindowEvent::KeyPressed { text });
    }

    fn release(window: &slint::Window, text: slint::SharedString) {
        window.dispatch_event(slint::platform::WindowEvent::KeyReleased { text });
    }

    /// Sends a modifier chord the way a backend does: the modifier keys are
    /// pressed first (`WindowEvent` carries no modifier field; Slint tracks
    /// their state from the key codes itself), then the character, then the
    /// releases.
    fn type_chord(
        window: &slint::Window,
        ctrl: bool,
        meta: bool,
        alt: bool,
        shift: bool,
        key: &str,
    ) {
        let mut held = Vec::new();
        for (is_down, code) in [
            (ctrl, slint::platform::Key::Control),
            (meta, slint::platform::Key::Meta),
            (alt, slint::platform::Key::Alt),
            (shift, slint::platform::Key::Shift),
        ] {
            if is_down {
                press(window, code.into());
                held.push(code);
            }
        }
        press(window, key.into());
        release(window, key.into());
        for code in held.into_iter().rev() {
            release(window, code.into());
        }
    }

    /// Port of the QKeySequenceEdit behaviour: a supported chord replaces the
    /// value, an unsupported one is rejected and keeps the previous value.
    /// Focus is moved with Tab (the recorder rejects Tab so focus traversal
    /// keeps working), which exercises that path too.
    #[test]
    fn shortcut_recorder_captures_chords_and_rejects_unsupported_ones() {
        test_backend();
        let dialog = crate::ui::settings::SettingsDialog::new().expect("create SettingsDialog");
        let prefs = Preferences::default();
        load_dialog_from_prefs(&dialog, &prefs);
        assert_eq!(dialog.get_open_transfers_shortcut().as_str(), "F12");

        let mut captured = false;
        for _ in 0..40 {
            press(dialog.window(), slint::platform::Key::Tab.into());
            type_chord(dialog.window(), true, false, true, false, "T");
            if dialog.get_open_transfers_shortcut().as_str() == "Ctrl+Alt+T" {
                captured = true;
                break;
            }
        }
        assert!(
            captured,
            "the transfer-queue recorder must accept Ctrl+Alt+T once focused"
        );

        // Still focused: an unsupported chord must not change the value.
        type_chord(dialog.window(), true, false, false, false, "Q");
        assert_eq!(
            dialog.get_open_transfers_shortcut().as_str(),
            "Ctrl+Alt+T",
            "an unsupported chord keeps the previous shortcut"
        );

        // The history recorder uses its own candidate set; reach it with Tab
        // and check a history-only chord is accepted there.
        let mut captured = false;
        for _ in 0..40 {
            press(dialog.window(), slint::platform::Key::Tab.into());
            type_chord(dialog.window(), true, false, false, true, "H");
            if dialog.get_open_history_shortcut().as_str() == "Ctrl+Shift+H" {
                captured = true;
                break;
            }
        }
        assert!(
            captured,
            "the history recorder must accept Ctrl+Shift+H once focused"
        );

        // Qt portable text renders Command as "Ctrl", so the macOS Meta key
        // must record as Ctrl: Cmd+H becomes the "Ctrl+H" candidate.
        type_chord(dialog.window(), false, true, false, false, "H");
        assert_eq!(
            dialog.get_open_history_shortcut().as_str(),
            "Ctrl+H",
            "Command/Meta must fold into the Qt portable \"Ctrl\" token"
        );
    }
}
