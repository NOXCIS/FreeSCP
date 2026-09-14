//! Remote panel model and remote operations — Rust/Slint port of the Qt
//! remote panel work:
//!
//! - `ui/RemoteModel.cpp` + `ui/RemoteModel.hpp`: listing, sorting (dirs
//!   first, case-insensitive names), column data, display formatting, path
//!   helpers.
//! - `ui/MainWindowRemoteOps.cpp`: refresh/navigation helpers, new
//!   file/dir, rename, delete, permissions, search, writeability probe,
//!   context-menu gating.
//! - `ui/MainWindowConnection.cpp`: `isLikelyRemoteTransportError` and the
//!   probe half of `runRemoteSessionHealthCheck`.
//! - `ui/PermissionsDialog.cpp`: dialog logic (the Slint UI itself lives in
//!   `crates/freescp-app/ui/permissions.slint`).
//! - `ui/TimeUtils.hpp`: `localShortTime` → [`format_mtime`].
//!
//! Ownership: this module is written by the remote-panel workstream. The
//! sibling main-window workstream owns `src/main.rs`, which expands
//! `slint::include_modules!()` inside `mod ui`; we therefore reference the
//! generated Slint components as `crate::ui::main_window::MainWindow` and
//! `crate::ui::permissions::PermissionsDialog` (NOT a local
//! `include_modules!()`), so the types are byte-identical to the ones the
//! sibling holds.
//!
//! ## Error message convention
//!
//! Every function returns user-facing `String` errors. Transport-level
//! messages are first mapped through [`short_remote_error`] (a port of the
//! C++ `shortRemoteError` heuristic) and then wrapped in the same sentence
//! the C++ `UiAlerts` calls used, e.g.
//! `"Could not create the remote folder.\nPermission denied."`. Callers can
//! show the returned string verbatim in a message box titled `"Remote"`.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::TimeZone;
use freescp_core::{ClientError, FileInfo, SftpClient};
use slint::ComponentHandle;

use crate::local_fs::SearchOutcome;

// ---------------------------------------------------------------------------
// Listing and refresh
// ---------------------------------------------------------------------------

/// List a remote directory and return it sorted the way `RemoteModel`
/// displayed it by default (directories first, name case-insensitive).
///
/// Port of `RemoteModel::setRootPath` (synchronous path) + default sorting.
/// `path` is normalized exactly like the C++ `normalizeRemotePath` (trimmed,
/// forced to start with `/`, `//` collapsed, trailing `/` stripped except
/// for root).
///
/// Only `.` and `..` entries are filtered out. Unlike the C++ model
/// (which hid dotfiles by default), hidden files are *included*: the exact
/// contract has no show-hidden parameter, so callers control visibility via
/// [`is_hidden_name`] + [`filter_entries`].
///
/// On error the returned message is the short, user-facing form only (the
/// caller decides the context prefix, e.g. "Could not open the remote
/// folder." vs "Could not refresh the remote folder." — mirroring the two
/// C++ call sites).
pub async fn refresh_remote(
    client: &mut dyn SftpClient,
    path: &str,
) -> Result<Vec<FileInfo>, String> {
    let normalized = normalize_remote_path(path);
    let mut entries = client
        .list(&normalized)
        .await
        .map_err(|e| client_error_message(&e))?;
    entries.retain(|f| f.name != "." && f.name != "..");
    sort_entries(&mut entries);
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Search (Search items dialog)
// ---------------------------------------------------------------------------

/// Recursive remote search (port of the recursive branch of
/// `searchItemsInCurrentFolder`): breadth-first walk over directories
/// starting at `base`, matching entry names against the pattern. Returns
/// paths relative to `base` with `/` separators. Symlinked directories are
/// not descended into, the walk honors the cancel flag, and results are
/// capped at [`crate::local_fs::MAX_SEARCH_MATCHES`]. The returned
/// [`SearchOutcome`] also carries the C++ `canceled` / `scanErrors` flags
/// for the result summary.
pub async fn search_remote_recursive(
    client: &mut dyn SftpClient,
    base: &str,
    pattern: &str,
    recursive: bool,
    max_depth: usize,
    include_hidden: bool,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<SearchOutcome, String> {
    let matcher = crate::local_fs::SearchMatcher::new(pattern)?;
    let base_norm = normalize_remote_path(base);
    let mut outcome = SearchOutcome::default();

    // Shared inner loop: match names in one listing, push results, and
    // return the subdirectories to descend into.
    let process_entries =
        |dir: &str, out: Vec<FileInfo>, outcome: &mut SearchOutcome| -> Vec<String> {
            let mut subdirs = Vec::new();
            for entry in out {
                if cancel.load(std::sync::atomic::Ordering::SeqCst) || outcome.truncated {
                    break;
                }
                if entry.name.is_empty() || entry.name == "." || entry.name == ".." {
                    continue;
                }
                if !include_hidden && is_hidden_name(&entry.name) {
                    continue;
                }
                let child = join_remote_path(dir, &entry.name);
                let child_norm = normalize_remote_path(&child);
                let rel = if base_norm == "/" {
                    child_norm.trim_start_matches('/').to_string()
                } else if let Some(stripped) = child_norm.strip_prefix(&format!("{base_norm}/")) {
                    stripped.to_string()
                } else {
                    child_norm.clone()
                };
                let rel = if rel.is_empty() {
                    entry.name.clone()
                } else {
                    rel
                };
                if matcher.matches(&entry.name) {
                    outcome.matches.push(rel);
                    if outcome.matches.len() >= crate::local_fs::MAX_SEARCH_MATCHES {
                        outcome.truncated = true;
                    }
                }
                let is_symlink = (entry.mode & 0o120000) == 0o120000;
                if entry.is_dir && !is_symlink {
                    subdirs.push(child_norm);
                }
            }
            subdirs
        };

    if !recursive {
        let entries = client
            .list(&base_norm)
            .await
            .map_err(|e| client_error_message(&e))?;
        process_entries(&base_norm, entries, &mut outcome);
        return Ok(outcome);
    }

    // BFS with a depth cap (the C++ used an explicit stack; order is not
    // part of the observable contract).
    let mut visited: HashMap<String, ()> = HashMap::new();
    let mut queue: std::collections::VecDeque<(String, usize)> = std::collections::VecDeque::new();
    queue.push_back((base_norm.clone(), 0));
    while let Some((current, depth)) = queue.pop_front() {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            outcome.canceled = true;
            break;
        }
        if outcome.truncated {
            break;
        }
        if visited.contains_key(&current) {
            continue;
        }
        visited.insert(current.clone(), ());
        let entries = match client.list(&current).await {
            Ok(entries) => entries,
            Err(_) => {
                // Port of the C++ `scanErrors` counter: a folder that could
                // not be listed counts once and is skipped.
                outcome.scan_errors += 1;
                continue;
            }
        };
        let subdirs = process_entries(&current, entries, &mut outcome);
        if depth + 1 < max_depth {
            for subdir in subdirs {
                queue.push_back((subdir, depth + 1));
            }
        }
    }
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// Create / rename / delete
// ---------------------------------------------------------------------------

/// Create a remote folder `parent/name` with mode `0755`.
///
/// Port of `MainWindow::newDirRight` (remote branch). The name is validated
/// with the same rules and wording as the C++ `isValidEntryName`.
pub async fn new_dir(client: &mut dyn SftpClient, parent: &str, name: &str) -> Result<(), String> {
    is_valid_entry_name(name)?;
    if name.trim().is_empty() {
        return Err("Invalid name: the name cannot be empty.".to_string());
    }
    let path = join_remote_path(parent, name);
    client.mkdir(&path, 0o755).await.map_err(|e| {
        format!(
            "Could not create the remote folder.\n{}",
            client_error_message(&e)
        )
    })
}

/// Create a new empty remote file `parent/name`.
///
/// Port of `MainWindow::newFileRight` (remote branch): the C++ code checked
/// existence first (to surface transport errors with a specific message),
/// then uploaded an empty temporary file, then removed the temporary file.
/// The overwrite confirmation prompt of the C++ version is UI state and
/// stays the caller's responsibility: if the file already exists it is
/// overwritten, exactly like answering "Yes" to the C++ prompt.
pub async fn new_file(client: &mut dyn SftpClient, parent: &str, name: &str) -> Result<(), String> {
    is_valid_entry_name(name)?;
    if name.trim().is_empty() {
        return Err("Invalid name: the name cannot be empty.".to_string());
    }
    let remote_path = join_remote_path(parent, name);

    // Mirror C++: probe existence so transport failures use the C++ wording.
    // An existing file is not an error here (see doc comment above).
    if let Err(e) = client.exists(&remote_path).await {
        return Err(format!(
            "Could not check whether the remote file already exists.\n{}",
            client_error_message(&e)
        ));
    }

    let tmp_path =
        create_empty_temp_file().map_err(|_| "Could not create a temporary file.".to_string())?;
    let result = client.put(&tmp_path, &remote_path, None, None, false).await;
    let _ = std::fs::remove_file(&tmp_path);
    result.map_err(|e| {
        format!(
            "Could not upload the temporary file to the server.\n{}",
            client_error_message(&e)
        )
    })
}

/// Rename `parent/from` to `parent/to`.
///
/// Port of `MainWindow::renameRightSelected` (remote branch). The C++ code
/// always passed `overwrite = false`; the contract exposes the flag so the
/// caller can mirror its own overwrite-confirmation UI. `from == to` is a
/// successful no-op (the C++ code returned early in that case).
pub async fn rename_entry(
    client: &mut dyn SftpClient,
    parent: &str,
    from: &str,
    to: &str,
    overwrite: bool,
) -> Result<(), String> {
    is_valid_entry_name(from)?;
    is_valid_entry_name(to)?;
    if to.trim().is_empty() {
        return Err("Invalid name: the new name cannot be empty.".to_string());
    }
    if from == to {
        return Ok(());
    }
    let src = join_remote_path(parent, from);
    let dst = join_remote_path(parent, to);
    client.rename(&src, &dst, overwrite).await.map_err(|e| {
        format!(
            "Could not rename the remote item.\n{}",
            client_error_message(&e)
        )
    })
}

/// Delete `parent/...` entries recursively (directories are emptied
/// depth-first before `remove_dir`, mirroring `MainWindow::deleteRightSelected`).
///
/// The `is_dir` flag of each entry is advisory: the actual type is resolved
/// with `exists()` like the C++ code did, so a stale flag cannot cause a
/// wrong operation.
///
/// Returns the number of top-level entries deleted (missing entries count as
/// deleted when `skip_missing` is true, mirroring the C++ "not found is not
/// an error" rule). If any entry fails, `Err` carries the C++ status-bar
/// wording with the counts and last error:
/// `"Deleted OK: {ok} | Failed: {fail}\nLast error: {last}"`.
pub async fn delete_entries(
    client: &mut dyn SftpClient,
    parent: &str,
    entries: &[(String, bool)],
    skip_missing: bool,
) -> Result<usize, String> {
    let mut ok = 0usize;
    let mut fail = 0usize;
    let mut last_error = String::new();
    for (name, _is_dir) in entries {
        let path = join_remote_path(parent, name);
        match delete_one(client, &path, skip_missing).await {
            Ok(()) => ok += 1,
            Err(e) => {
                fail += 1;
                last_error = e;
            }
        }
    }
    if fail > 0 {
        Err(format!(
            "Deleted OK: {ok} | Failed: {fail}\nLast error: {last_error}"
        ))
    } else {
        Ok(ok)
    }
}

/// Recursive delete of a single path. `Ok(())` means "gone" (deleted or
/// skipped as missing); `Err` carries the short user-facing message.
async fn delete_one(
    client: &mut dyn SftpClient,
    path: &str,
    skip_missing: bool,
) -> Result<(), String> {
    match client
        .exists(path)
        .await
        .map_err(|e| client_error_message(&e))?
    {
        Some(is_dir) => {
            if is_dir {
                let children = client
                    .list(path)
                    .await
                    .map_err(|e| client_error_message(&e))?;
                for child in children {
                    if child.name == "." || child.name == ".." {
                        continue;
                    }
                    let child_path = join_remote_path(path, &child.name);
                    Box::pin(delete_one(client, &child_path, skip_missing)).await?;
                }
                client
                    .remove_dir(path)
                    .await
                    .map_err(|e| client_error_message(&e))?;
            } else {
                client
                    .remove_file(path)
                    .await
                    .map_err(|e| client_error_message(&e))?;
            }
            Ok(())
        }
        None => {
            if skip_missing {
                Ok(())
            } else {
                Err("File or folder does not exist.".to_string())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

/// Change the permissions of a remote entry.
///
/// Port of `MainWindow::changeRemotePermissions`: the current mode is read
/// with `stat()` first and the file-type bits (`!0o777`) are preserved, so
/// `mode` only supplies the `0o777` permission bits.
pub async fn change_permissions(
    client: &mut dyn SftpClient,
    remote_path: &str,
    mode: u32,
) -> Result<(), String> {
    let stat = client
        .stat(remote_path)
        .await
        .map_err(|e| format!("Could not read permissions.\n{}", client_error_message(&e)))?;
    let new_mode = (stat.mode & !0o777u32) | (mode & 0o777);
    client.chmod(remote_path, new_mode).await.map_err(|e| {
        let item = remote_path.rsplit('/').next().unwrap_or(remote_path);
        let item = if item.is_empty() { remote_path } else { item };
        format!(
            "Could not apply permissions to \"{item}\".\n{}",
            client_error_message(&e)
        )
    })
}

/// Recursive variant used when the permissions dialog's "Apply recursively
/// to subfolders" checkbox is enabled.
///
/// Supplementary to the exact workstream contract (which only lists
/// [`change_permissions`]); mirrors the C++ `changeRemotePermissions`
/// recursive branch, including its quirk: the composed mode (top entry's
/// type bits + new permission bits) is applied to every descendant.
pub async fn change_permissions_recursive(
    client: &mut dyn SftpClient,
    remote_dir: &str,
    mode: u32,
) -> Result<(), String> {
    let stat = client
        .stat(remote_dir)
        .await
        .map_err(|e| format!("Could not read permissions.\n{}", client_error_message(&e)))?;
    let new_mode = (stat.mode & !0o777u32) | (mode & 0o777);

    let mut stack = vec![remote_dir.to_string()];
    while let Some(cur) = stack.pop() {
        client.chmod(&cur, new_mode).await.map_err(|e| {
            let item = cur.rsplit('/').next().unwrap_or(&cur);
            let item = if item.is_empty() { cur.as_str() } else { item };
            format!(
                "Could not apply permissions to \"{item}\".\n{}",
                client_error_message(&e)
            )
        })?;
        let children = client
            .list(&cur)
            .await
            .map_err(|e| client_error_message(&e))?;
        for child in children {
            if child.name == "." || child.name == ".." {
                continue;
            }
            let child_path = join_remote_path(&cur, &child.name);
            if child.is_dir {
                stack.push(child_path);
            } else {
                client.chmod(&child_path, new_mode).await.map_err(|e| {
                    format!(
                        "Could not apply permissions to \"{}\".\n{}",
                        child.name,
                        client_error_message(&e)
                    )
                })?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Writeability probe + cache
// ---------------------------------------------------------------------------

/// Probe whether `remote_dir` is writable by creating and removing a
/// temporary folder inside it.
///
/// Port of the probe half of `MainWindow::updateRemoteWriteability`
/// (`.freescp-write-test-<ms-timestamp>` + `mkdir` + best-effort `removeDir`).
/// Any `mkdir` failure maps to `Ok(false)` exactly like the C++ code (both
/// "permission denied" and transport errors mean "not writable"); `Err` is
/// reserved for cases where no probe could run at all (no connected
/// session). The C++ version ran the probe on a dedicated fresh connection
/// (`CreateConnectedClient`); the caller may pass a probe client created via
/// `freescp_core::client_factory::create_connected_client` to mirror that.
pub async fn probe_writeability(
    client: &mut dyn SftpClient,
    remote_dir: &str,
) -> Result<bool, String> {
    if !client.is_connected() {
        return Err("No active remote session.".to_string());
    }
    let base = normalize_remote_path(remote_dir);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let test_name = format!(".freescp-write-test-{ts}");
    let test_path = join_remote_path(&base, &test_name);
    match client.mkdir(&test_path, 0o755).await {
        Ok(()) => {
            let _ = client.remove_dir(&test_path).await;
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// In-memory cache of writeability probe results with a 15-second TTL,
/// mirroring `MainWindow::m_remoteWriteabilityCache_` +
/// `m_remoteWriteabilityTtlMs_ = 15000` (and the "clear when larger than
/// 256 entries" behavior).
///
/// The C++ UI also kept an "optimistic" current value (last known result,
/// defaulting to writable while the background probe ran); that is panel
/// state owned by the caller — see [`RemoteWriteabilityCache::get`].
#[derive(Clone)]
pub struct RemoteWriteabilityCache {
    entries: HashMap<String, WriteabilityCacheEntry>,
    /// Entry lifetime; from `Network/remoteWriteabilityTtlMs` (C++
    /// `m_remoteWriteabilityTtlMs_`, refreshed by `applyPreferences`).
    ttl: Duration,
}

impl Default for RemoteWriteabilityCache {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            ttl: REMOTE_WRITEABILITY_TTL,
        }
    }
}

#[derive(Clone)]
struct WriteabilityCacheEntry {
    writable: bool,
    checked_at: Instant,
}

/// Default TTL for cached writeability results (15 s, C++
/// `m_remoteWriteabilityTtlMs_` default).
pub const REMOTE_WRITEABILITY_TTL: Duration = Duration::from_secs(15);

/// Maximum cache size before it is cleared (256, C++ behavior).
pub const REMOTE_WRITEABILITY_MAX_ENTRIES: usize = 256;

impl RemoteWriteabilityCache {
    /// Create an empty cache with `Network/remoteWriteabilityTtlMs` clamped
    /// to the C++ range (1000..=120000 ms).
    pub fn with_ttl_ms(ttl_ms: i64) -> Self {
        let mut cache = Self::default();
        cache.set_ttl_ms(ttl_ms);
        cache
    }

    /// Update the TTL (called when Settings is applied).
    pub fn set_ttl_ms(&mut self, ttl_ms: i64) {
        self.ttl = Duration::from_millis(ttl_ms.clamp(1_000, 120_000) as u64);
    }

    /// Fetch the cached writeability of `dir` when it is still fresh
    /// (checked less than the configured TTL ago). Stale entries are removed
    /// on access, like the C++ TTL check.
    pub fn get(&mut self, dir: &str) -> Option<bool> {
        let dir = normalize_remote_path(dir);
        let entry = self.entries.get(&dir)?;
        if entry.checked_at.elapsed() > self.ttl {
            self.entries.remove(&dir);
            return None;
        }
        Some(entry.writable)
    }

    /// Store (or refresh) the writeability of `dir`.
    pub fn store(&mut self, dir: &str, writable: bool) {
        let dir = normalize_remote_path(dir);
        self.entries.insert(
            dir,
            WriteabilityCacheEntry {
                writable,
                checked_at: Instant::now(),
            },
        );
        if self.entries.len() > REMOTE_WRITEABILITY_MAX_ENTRIES {
            self.entries.clear();
        }
    }

    /// Drop the cached entry for `dir` (e.g. after a permission-denied
    /// error, mirroring `invalidateRemoteWriteabilityFromError`).
    pub fn invalidate(&mut self, dir: &str) {
        self.entries.remove(&normalize_remote_path(dir));
    }

    /// Drop all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of cached entries.
    #[allow(dead_code)] // diagnostic/logging hook; no caller yet
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    #[allow(dead_code)] // diagnostic/logging hook; no caller yet
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Session health / transport-error classification
// ---------------------------------------------------------------------------

/// Health probe — port of the probe half of
/// `MainWindow::runRemoteSessionHealthCheck`.
///
/// Verifies the session still answers by querying `probe_path` (the C++
/// code probed the current remote root with `exists`, treating "not found"
/// as healthy because the session responded). The reconnect half of the C++
/// logic (`reconnectActiveRemoteSession`: build a fresh client with
/// `freescp_core::client_factory::create_connected_client`, swap it in,
/// restore the panel path, re-arm monitoring) involves the transfer manager
/// and panel state owned by the main-window / app-chrome workstreams, so
/// this function is intentionally the documented probe stub the contract
/// asks for.
pub async fn ensure_session_healthy(
    client: &mut dyn SftpClient,
    probe_path: &str,
) -> Result<(), String> {
    let probe = normalize_remote_path(probe_path);
    match client.exists(&probe).await {
        Ok(_) => Ok(()),
        Err(e) => Err(client_error_message(&e)),
    }
}

/// Whether an error message looks like a lost/transport-level connection,
/// as opposed to a permission/auth/path problem.
///
/// Port of `MainWindow::isLikelyRemoteTransportError` (same marker list and
/// same negative list).
pub fn is_likely_transport_error(msg: &str) -> bool {
    const NEGATIVES: [&str; 6] = [
        "permission denied",
        "read-only",
        "no such file",
        "not found",
        "auth fail",
        "authentication failed",
    ];
    const MARKERS: [&str; 17] = [
        "socket send",
        "socket recv",
        "socket error",
        "session disconnected",
        "channel closed",
        "connection lost",
        "connection reset",
        "connection aborted",
        "broken pipe",
        "transport endpoint is not connected",
        "end of file",
        "timeout",
        "timed out",
        "rc=-7",  // LIBSSH2_ERROR_SOCKET_SEND
        "rc=-34", // LIBSSH2_ERROR_SOCKET_RECV
        "rc=-37", // LIBSSH2_ERROR_CHANNEL_CLOSED
        "rc=-13", // LIBSSH2_ERROR_SOCKET_DISCONNECT
    ];
    let lower = msg.trim().to_lowercase();
    if lower.is_empty() {
        return false;
    }
    if NEGATIVES.iter().any(|m| lower.contains(m)) {
        return false;
    }
    MARKERS.iter().any(|m| lower.contains(m))
}

/// Whether an error message indicates the remote location rejected a write
/// operation. Port of `indicatesRemoteWriteabilityDenied`, used to decide
/// whether to invalidate the writeability cache after an operation error.
pub fn indicates_writeability_denied(msg: &str) -> bool {
    const MARKERS: [&str; 5] = [
        "permission denied",
        "read-only",
        "operation not permitted",
        "access denied",
        "sftp protocol error 3",
    ];
    let lower = msg.trim().to_lowercase();
    if lower.is_empty() {
        return false;
    }
    MARKERS.iter().any(|m| lower.contains(m))
}

// ---------------------------------------------------------------------------
// Error message mapping (port of `shortRemoteError`)
// ---------------------------------------------------------------------------

/// Map a raw backend error string to a short user-facing message.
///
/// Port of the C++ `shortRemoteError` heuristic; the empty-input fallback is
/// `"Remote error."` (call sites may prefer their own fallback by using
/// [`short_remote_error_with_fallback`]). Added vs C++: a `"host key"`
/// branch mapping to `"Host key verification failed."`.
pub fn short_remote_error(raw: &str) -> String {
    short_remote_error_with_fallback(raw, "Remote error.")
}

/// [`short_remote_error`] with an explicit fallback for empty input, as the
/// C++ helper took one.
pub fn short_remote_error_with_fallback(raw: &str, fallback: &str) -> String {
    let msg = raw.trim();
    if msg.is_empty() {
        return fallback.to_string();
    }
    let lower = msg.to_lowercase();
    if lower.contains("host key") {
        return "Host key verification failed.".to_string();
    }
    if lower.contains("permission denied") {
        return "Permission denied.".to_string();
    }
    if lower.contains("read-only") {
        return "Location is read-only.".to_string();
    }
    if lower.contains("no such file") || lower.contains("not found") {
        return "File or folder does not exist.".to_string();
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return "Connection timed out.".to_string();
    }
    if lower.contains("could not resolve")
        || lower.contains("name or service not known")
        || lower.contains("nodename nor servname")
    {
        return "Could not resolve the server hostname.".to_string();
    }
    if lower.contains("connection refused") {
        return "Connection refused by the server.".to_string();
    }
    if lower.contains("network is unreachable") || lower.contains("host is unreachable") {
        return "Network unavailable or host unreachable.".to_string();
    }
    if lower.contains("authentication failed") || lower.contains("auth fail") {
        return "Authentication failed.".to_string();
    }

    // First line, whitespace collapsed, truncated to 96 chars (93 + "...").
    let first_line = msg.split('\n').next().unwrap_or("");
    let simplified: String = first_line.split_whitespace().collect::<Vec<_>>().join(" ");
    if simplified.chars().count() > 96 {
        let mut truncated: String = simplified.chars().take(93).collect();
        truncated.push_str("...");
        truncated
    } else {
        simplified
    }
}

/// Map a `ClientError` to a user-facing message using the
/// `shortRemoteError` wording. The `AuthFailed` and `Cancelled` variants map
/// to fixed sentences (they cannot carry transport detail).
pub fn client_error_message(err: &ClientError) -> String {
    match err {
        ClientError::AuthFailed(_) => "Authentication failed.".to_string(),
        ClientError::HostKeyRejected(detail) => {
            let short = short_remote_error(detail);
            if short.is_empty() {
                "Host key verification failed.".to_string()
            } else {
                short
            }
        }
        ClientError::Cancelled => "Operation cancelled.".to_string(),
        ClientError::Unsupported(detail) => {
            if detail.trim().is_empty() {
                "This operation is not supported by the server.".to_string()
            } else {
                format!(
                    "This operation is not supported by the server.\n{}",
                    short_remote_error(detail)
                )
            }
        }
        ClientError::Io(e) => short_remote_error(&e.to_string()),
        ClientError::OperationFailed(detail) | ClientError::Other(detail) => {
            short_remote_error(detail)
        }
    }
}

// ---------------------------------------------------------------------------
// Sorting and filtering
// ---------------------------------------------------------------------------

/// Sort remote entries: directories first, then name case-insensitive
/// ascending. Mirrors the `RemoteModel` default (column 0, ascending).
/// Ties on the case-insensitive name are broken case-sensitively for
/// deterministic output.
pub fn sort_entries(entries: &mut [FileInfo]) {
    sort_entries_by(entries, 0, true);
}

/// Column-aware sort mirroring `RemoteModel::sortItemsVector`
/// (0 = name, 1 = size, 2 = mtime, 3 = mode). Directories always sort
/// before files regardless of column/order.
pub fn sort_entries_by(entries: &mut [FileInfo], column: usize, ascending: bool) {
    entries.sort_by(|a, b| {
        if a.is_dir != b.is_dir {
            return if a.is_dir {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        let ord = match column {
            0 => compare_names(a, b),
            1 => a.size.cmp(&b.size),
            2 => a.mtime.cmp(&b.mtime),
            3 => a.mode.cmp(&b.mode),
            _ => compare_names(a, b),
        };
        if ascending {
            ord
        } else {
            ord.reverse()
        }
    });
}

fn compare_names(a: &FileInfo, b: &FileInfo) -> Ordering {
    let al = a.name.to_lowercase();
    let bl = b.name.to_lowercase();
    match al.cmp(&bl) {
        Ordering::Equal => a.name.cmp(&b.name),
        other => other,
    }
}

/// Filter entries by a case-insensitive substring match on the name.
///
/// Mirrors the panel search (the C++ implementation matched a regex, but
/// the workstream contract specifies substring matching; the case-insensitive
/// part is shared). An empty needle returns all entries. Kept for the unit
/// tests; the interactive search path uses `SearchMatcher` +
/// `search_remote_recursive`.
#[cfg(test)]
pub fn filter_entries(entries: &[FileInfo], needle: &str) -> Vec<FileInfo> {
    let needle = needle.trim();
    if needle.is_empty() {
        return entries.to_vec();
    }
    let lower = needle.to_lowercase();
    entries
        .iter()
        .filter(|e| e.name.to_lowercase().contains(&lower))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Display formatting (RemoteModel::data + TimeUtils)
// ---------------------------------------------------------------------------

/// Column headers used by `RemoteModel::headerData`.
#[allow(dead_code)] // column headers are declared in main-window-parts.slint; kept for C++ parity
pub const REMOTE_COLUMNS: [&str; 4] = ["Name", "Size", "Date", "Permissions"];

/// Whether a mode has the symlink type bits (`S_IFLNK`), using the same
/// mask as the C++ model (`mode & 0120000 == 0120000`).
#[allow(dead_code)] // symlink badges/tooltips are not in the Slint model yet
pub fn is_symlink(mode: u32) -> bool {
    mode & 0o120000 == 0o120000
}

/// Name as displayed in column 0: symlinks get a trailing `@`, directories
/// a trailing `/`.
#[allow(dead_code)] // remote pane renders raw names; decorated column is a future workstream
pub fn display_name(info: &FileInfo) -> String {
    if is_symlink(info.mode) {
        format!("{}@", info.name)
    } else if info.is_dir {
        format!("{}/", info.name)
    } else {
        info.name.clone()
    }
}

/// Human-readable IEC size (1 decimal, `QLocale::formattedDataSize` with
/// `DataSizeIecFormat`). The decimal separator is always `.` — locale-aware
/// output is TODO for the i18n workstream.
#[allow(dead_code)] // remote pane formats sizes via main-window.slint callbacks for now
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
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

/// Format an epoch-seconds timestamp in local time, short form.
///
/// Port of `TimeUtils::localShortTime`: `0` or an invalid value renders as
/// `"—"`. The C++ used the OS locale's `QLocale::ShortFormat`
/// (12/24 h per system preference); this port uses a fixed
/// `%m/%d/%y %H:%M` until the i18n workstream wires locale-aware output.
#[allow(dead_code)] // remote pane formats dates via main-window.slint callbacks for now
pub fn format_mtime(epoch: u64) -> String {
    if epoch == 0 {
        return "—".to_string();
    }
    match chrono::Local.timestamp_opt(epoch as i64, 0) {
        chrono::LocalResult::Single(dt) => dt.format("%m/%d/%y %H:%M").to_string(),
        _ => "—".to_string(),
    }
}

/// Date column value exactly like `RemoteModel::data`: empty when the mtime
/// is unknown/absent, [`format_mtime`] otherwise.
#[allow(dead_code)] // date column is rendered by main-window.slint for now
pub fn display_mtime(epoch: u64) -> String {
    if epoch == 0 {
        String::new()
    } else {
        format_mtime(epoch)
    }
}

/// Size column value exactly like `RemoteModel::data`: empty for
/// directories, `"—"` when the server did not provide a size.
#[allow(dead_code)] // size column is rendered by main-window.slint for now
pub fn display_size(info: &FileInfo) -> String {
    if info.is_dir {
        String::new()
    } else if !info.has_size {
        "—".to_string()
    } else {
        format_size(info.size)
    }
}

/// Permissions column value in `rwxr-xr-x` style with the file-type
/// character (`l`/`d`/`-`), port of `RemoteModel::data` column 3.
#[allow(dead_code)] // permissions column is rendered by main-window.slint for now
pub fn format_mode_string(mode: u32, is_dir: bool) -> String {
    let mut chars = ['-'; 10];
    chars[0] = if is_symlink(mode) {
        'l'
    } else if is_dir {
        'd'
    } else {
        '-'
    };
    let bits = [
        (1usize, 0o400u32, 'r'),
        (2, 0o200, 'w'),
        (3, 0o100, 'x'),
        (4, 0o040, 'r'),
        (5, 0o020, 'w'),
        (6, 0o010, 'x'),
        (7, 0o004, 'r'),
        (8, 0o002, 'w'),
        (9, 0o001, 'x'),
    ];
    for (pos, mask, ch) in bits {
        if mode & mask != 0 {
            chars[pos] = ch;
        }
    }
    chars.iter().collect()
}

/// Tooltip text port of `RemoteModel::data` `Qt::ToolTipRole`.
#[allow(dead_code)] // tooltips are not part of the Slint model yet
pub fn entry_tooltip(info: &FileInfo) -> String {
    if info.is_dir {
        return "Folder".to_string();
    }
    if !info.has_size {
        return "Size: unknown (not provided by the server)".to_string();
    }
    let mut tip = format!("File • {} ({} bytes)", format_size(info.size), info.size);
    if info.mtime > 0 {
        tip.push_str(&format!(" • {}", format_mtime(info.mtime)));
    }
    tip
}

// ---------------------------------------------------------------------------
// Path and name helpers
// ---------------------------------------------------------------------------

/// Normalize a remote path exactly like the C++ `normalizeRemotePath`
/// (trim, force leading `/`, collapse `//`, strip trailing `/` except root).
pub fn normalize_remote_path(raw: &str) -> String {
    let mut path = raw.trim().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    if path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    path
}

/// Join a base directory and an entry name, port of the C++
/// `joinRemotePath`.
pub fn join_remote_path(base: &str, name: &str) -> String {
    if base == "/" {
        format!("/{name}")
    } else if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Parent directory of a remote path, port of `MainWindow::goUpRight`
/// (returns `/` for the root and its children).
pub fn parent_remote_path(path: &str) -> String {
    let mut cur = normalize_remote_path(path);
    if cur == "/" {
        return "/".to_string();
    }
    if cur.ends_with('/') {
        cur.pop();
    }
    match cur.rfind('/') {
        None | Some(0) => "/".to_string(),
        Some(i) => cur[..i].to_string(),
    }
}

/// True when "Up" has a target (C++ `canGoUp()`: the parent differs from the
/// current folder, so the action is disabled at the remote root).
pub fn has_remote_parent(path: &str) -> bool {
    let cur = normalize_remote_path(path);
    parent_remote_path(&cur) != cur
}

/// Validate an entry name with the exact rules and wording of the C++
/// `isValidEntryName`.
pub fn is_valid_entry_name(name: &str) -> Result<(), String> {
    if name == "." || name == ".." {
        return Err("Invalid name: cannot be '.' or '..'.".to_string());
    }
    if name.contains('/') || name.contains('\\') {
        return Err("Invalid name: cannot contain separators ('/' or '\\').".to_string());
    }
    for ch in name.chars() {
        let u = ch as u32;
        if u < 0x20 || u == 0x7F {
            return Err("Invalid name: cannot contain control characters.".to_string());
        }
    }
    Ok(())
}

/// Whether a name is hidden (starts with `.`), for callers implementing the
/// C++ "show hidden" preference — `refresh_remote` itself returns all
/// entries.
pub fn is_hidden_name(name: &str) -> bool {
    name.starts_with('.') && name != "." && name != ".."
}

// ---------------------------------------------------------------------------
// Permissions dialog
// ---------------------------------------------------------------------------

/// Non-blocking handle to an open permissions dialog.
///
/// The dialog mirrors the C++ `PermissionsDialog` non-modal style: the
/// window is shown and control returns immediately. Poll it from the UI
/// event loop (a timer or the main-window's idle callback):
///
/// ```ignore
/// let flow = remote::open_permissions_dialog(&ui, &entry, entry.mode);
/// // in a callback:
/// match flow.poll() {
///     None => {}                                   // dialog still open
///     Some(Some(new_mode)) => { /* apply chmod */ }
///     Some(None) => {}                             // cancelled or closed
/// }
/// let recursive = flow.recursive();
/// ```
///
/// `poll()` never blocks; it also reports `Some(None)` when the window was
/// hidden or destroyed without an explicit answer (e.g. the title-bar close
/// button), so the flow always terminates.
#[must_use]
pub struct PermissionsFlow {
    rx: std::sync::mpsc::Receiver<Option<u32>>,
    dialog: Option<crate::ui::permissions::PermissionsDialog>,
}

impl PermissionsFlow {
    /// Non-blocking poll for the dialog result.
    ///
    /// - `None` — no answer yet, dialog still open.
    /// - `Some(Some(mode))` — apply requested with the new `0o777` mode.
    /// - `Some(None)` — cancelled, closed, or the dialog was destroyed.
    pub fn poll(&self) -> Option<Option<u32>> {
        match self.rx.try_recv() {
            Ok(result) => return Some(result),
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return Some(None),
        }
        // Cover title-bar closes that bypass the callback: a hidden window
        // without a message counts as cancelled.
        if let Some(dialog) = &self.dialog {
            if !dialog.window().is_visible() {
                return Some(None);
            }
        }
        None
    }

    /// Blocking wait for the final result (`Some(mode)` applied,
    /// `None` cancelled). Prefer [`Self::poll`] in UI code.
    #[allow(dead_code)] // poll() covers the UI-thread flow; wait() remains for blocking callers
    pub fn wait(self) -> Option<u32> {
        self.rx.recv().unwrap_or(None)
    }

    /// Async version of [`Self::wait`] for tokio contexts (the dialog stays
    /// on the UI thread; this just parks on a blocking pool).
    #[allow(dead_code)] // poll() covers the UI-thread flow; wait_async() remains for tokio callers
    pub async fn wait_async(self) -> Option<u32> {
        tokio::task::spawn_blocking(move || self.rx.recv().unwrap_or(None))
            .await
            .unwrap_or(None)
    }

    /// Whether the "Apply recursively to subfolders" checkbox is checked.
    /// Meaningful when the result is `Some(Some(mode))`.
    pub fn recursive(&self) -> bool {
        self.dialog
            .as_ref()
            .map(|d| d.get_recursive())
            .unwrap_or(false)
    }

    /// Best-effort close of the dialog from the caller side (the receiver
    /// will then observe `Some(None)` on the next poll).
    pub fn dismiss(&self) {
        if let Some(dialog) = &self.dialog {
            let _ = dialog.hide();
        }
    }

    /// Access to the live dialog handle, if it was created (e.g. to read
    /// extra state before it is dropped).
    #[allow(dead_code)] // recursive()/poll() already expose what main.rs needs
    pub fn dialog(&self) -> Option<&crate::ui::permissions::PermissionsDialog> {
        self.dialog.as_ref()
    }
}

/// Open the non-modal permissions dialog for `entry` and return a
/// [`PermissionsFlow`] handle for the result.
///
/// `current_mode` is the entry's mode; the dialog shows and returns only
/// the `0o777` permission bits (the type bits are preserved later by
/// [`change_permissions`]). The dialog is centered on `win` best-effort;
/// `win` is otherwise unused because Slint windows are top-level.
pub fn open_permissions_dialog(
    win: &crate::ui::main_window::MainWindow,
    entry: &FileInfo,
    current_mode: u32,
) -> PermissionsFlow {
    let (tx, rx) = std::sync::mpsc::channel::<Option<u32>>();
    let dialog = match crate::ui::permissions::PermissionsDialog::new() {
        Ok(dialog) => Some(dialog),
        Err(_) => {
            // Without a window there is nothing to answer; complete the
            // flow immediately as cancelled.
            let _ = tx.send(None);
            return PermissionsFlow { rx, dialog: None };
        }
    };
    let dialog = dialog.unwrap();
    dialog.set_path(entry.name.clone().into());
    dialog.set_mode((current_mode & 0o777) as i32);
    dialog.set_recursive(false);

    let weak = dialog.as_weak();
    let apply_tx = tx.clone();
    dialog.on_apply_requested(move || {
        if let Some(d) = weak.upgrade() {
            let mode = (d.get_mode() & 0o777) as u32;
            let _ = apply_tx.send(Some(mode));
            let _ = d.hide();
        }
    });
    let weak = dialog.as_weak();
    dialog.on_close_requested(move || {
        if let Some(d) = weak.upgrade() {
            let _ = tx.send(None);
            let _ = d.hide();
        }
    });

    center_over(win, &dialog);
    let _ = dialog.show();
    PermissionsFlow {
        rx,
        dialog: Some(dialog),
    }
}

/// Best-effort centering of a dialog window over the main window
/// (approximate: uses the preferred size before the window is shown).
///
/// Slint windows are top-level and cannot be truly parented, so this
/// mirrors the C++ modal placement by positioning instead.
pub fn center_window_over(win: &crate::ui::main_window::MainWindow, dlg: &slint::Window) {
    let w = win.window();
    let wpos = w.position();
    let wsize = w.size();
    let dsize = dlg.size();
    let x = wpos.x as f32 + ((wsize.width as f32 - dsize.width as f32) / 2.0).max(0.0);
    let y = wpos.y as f32 + ((wsize.height as f32 - dsize.height as f32) / 2.0).max(0.0);
    dlg.set_position(slint::LogicalPosition::new(x, y));
}

/// Centering helper for the permissions dialog.
fn center_over(
    win: &crate::ui::main_window::MainWindow,
    dlg: &crate::ui::permissions::PermissionsDialog,
) {
    center_window_over(win, dlg.window());
}

// ---------------------------------------------------------------------------
// Main-window integration helpers
// ---------------------------------------------------------------------------

/// Opens the non-modal permissions dialog for a pane entry
/// (`crate::ui::main_window::FileEntry`, as produced by the main-window
/// workstream) and returns a [`PermissionsFlow`] for the result.
///
/// Called by the main window's "Permissions" action with the selected row.
/// `mode` supplies the current `0o777` permission bits. The caller is
/// responsible for polling the returned flow and invoking
/// [`change_permissions`] / [`change_permissions_recursive`] with the
/// confirmed mode (the main window's `PERMISSION_FLOWS` loop does this).
pub fn open_permissions(
    win: &crate::ui::main_window::MainWindow,
    entry: crate::ui::main_window::FileEntry,
    mode: u32,
) -> PermissionsFlow {
    let info = FileInfo {
        name: entry.name.to_string(),
        is_dir: entry.is_dir,
        size: entry.size.max(0) as u64,
        has_size: entry.size >= 0,
        mtime: entry.mtime.max(0) as u64,
        mode: entry.mode.max(0) as u32,
        uid: 0,
        gid: 0,
    };
    tracing::debug!(path = %info.name, mode, "opening permissions dialog");
    open_permissions_dialog(win, &info, mode)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Create an empty temporary file (the C++ `newFileRight` used a
/// `QTemporaryFile` with the same purpose) and return its path.
fn create_empty_temp_file() -> Result<String, std::io::Error> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("freescp-newfile-{}-{nanos}", std::process::id()));
    std::fs::File::create(&path)?;
    Ok(path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fi(name: &str, is_dir: bool) -> FileInfo {
        FileInfo {
            name: name.to_string(),
            is_dir,
            ..FileInfo::default()
        }
    }

    #[test]
    fn sort_puts_dirs_first_case_insensitive() {
        let mut entries = vec![
            fi("zeta.txt", false),
            fi("Alpha", true),
            fi("beta", true),
            fi("a.txt", false),
        ];
        sort_entries(&mut entries);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["Alpha", "beta", "a.txt", "zeta.txt"]);
    }

    #[test]
    fn sort_by_size_ascending_keeps_dirs_first() {
        let mut a = fi("a", false);
        a.size = 100;
        let mut b = fi("b", false);
        b.size = 10;
        let mut entries = vec![a, fi("dir", true), b];
        sort_entries_by(&mut entries, 1, true);
        assert!(entries[0].is_dir);
        assert_eq!(entries[1].size, 10);
        assert_eq!(entries[2].size, 100);
    }

    #[test]
    fn format_size_iec_units() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(1048576), "1.0 MiB");
    }

    #[test]
    fn format_mtime_unknown_is_em_dash() {
        assert_eq!(format_mtime(0), "—");
        // 2023-11-14T22:13:20Z is a valid epoch; only check it renders.
        assert_ne!(format_mtime(1_700_000_000), "—");
    }

    #[test]
    fn filter_is_case_insensitive_substring() {
        let entries = vec![
            fi("README.md", false),
            fi("todo.txt", false),
            fi("img.png", false),
        ];
        let hits = filter_entries(&entries, "read");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "README.md");
        assert_eq!(filter_entries(&entries, "").len(), 3);
    }

    #[test]
    fn short_error_mapping_matches_cpp() {
        assert_eq!(
            short_remote_error("Permission denied"),
            "Permission denied."
        );
        assert_eq!(
            short_remote_error("No such file or directory"),
            "File or folder does not exist."
        );
        assert_eq!(short_remote_error(""), "Remote error.");
        assert_eq!(short_remote_error("timed out"), "Connection timed out.");
        assert_eq!(
            short_remote_error("connection refused"),
            "Connection refused by the server."
        );
        assert_eq!(short_remote_error("auth failed"), "Authentication failed.");
    }

    #[test]
    fn transport_error_classification() {
        assert!(is_likely_transport_error("socket send error"));
        assert!(is_likely_transport_error("connection reset by peer"));
        assert!(is_likely_transport_error("Connection timed out."));
        assert!(!is_likely_transport_error("permission denied"));
        assert!(!is_likely_transport_error("no such file"));
        assert!(!is_likely_transport_error(""));
    }

    #[test]
    fn writeability_denied_markers() {
        assert!(indicates_writeability_denied("Permission denied"));
        assert!(indicates_writeability_denied("sftp protocol error 3"));
        assert!(!indicates_writeability_denied(""));
        assert!(!indicates_writeability_denied("socket send"));
    }

    #[test]
    fn writeability_cache_uses_configured_ttl() {
        let mut cache = RemoteWriteabilityCache::with_ttl_ms(120_000);
        cache.store("/tmp", true);
        assert_eq!(cache.get("/tmp"), Some(true));

        // The TTL is clamped to the C++ `qBound(1000, .., 120000)` range, so
        // an entry stored just now stays fresh even for an out-of-range
        // request.
        let mut clamped = RemoteWriteabilityCache::with_ttl_ms(0);
        clamped.store("/tmp", false);
        assert_eq!(clamped.get("/tmp"), Some(false));

        cache.invalidate("/tmp");
        assert_eq!(cache.get("/tmp"), None);
    }

    #[test]
    fn path_helpers() {
        assert_eq!(normalize_remote_path(""), "/");
        assert_eq!(normalize_remote_path("a/b"), "/a/b");
        assert_eq!(normalize_remote_path("//a//b/"), "/a/b");
        assert_eq!(join_remote_path("/", "x"), "/x");
        assert_eq!(join_remote_path("/a", "x"), "/a/x");
        assert_eq!(join_remote_path("/a/", "x"), "/a/x");
        assert_eq!(parent_remote_path("/"), "/");
        assert_eq!(parent_remote_path("/a"), "/");
        assert_eq!(parent_remote_path("/a/b"), "/a");
    }

    #[test]
    fn name_validation() {
        assert!(is_valid_entry_name("ok.txt").is_ok());
        assert_eq!(
            is_valid_entry_name("..").unwrap_err(),
            "Invalid name: cannot be '.' or '..'."
        );
        assert!(is_valid_entry_name("a/b").is_err());
        assert!(is_valid_entry_name("a\\b").is_err());
        assert!(is_valid_entry_name("a\nb").is_err());
    }

    #[test]
    fn hidden_names() {
        assert!(is_hidden_name(".bashrc"));
        assert!(!is_hidden_name(".."));
        assert!(!is_hidden_name("plain"));
    }

    #[test]
    fn mode_string_formatting() {
        assert_eq!(format_mode_string(0o644, false), "-rw-r--r--");
        assert_eq!(format_mode_string(0o755, true), "drwxr-xr-x");
        assert_eq!(format_mode_string(0o120777, false), "lrwxrwxrwx");
    }

    #[test]
    fn display_helpers() {
        let dir = fi("folder", true);
        assert_eq!(display_name(&dir), "folder/");
        assert_eq!(display_size(&dir), "");
        assert_eq!(display_mtime(0), "");
        assert_eq!(entry_tooltip(&dir), "Folder");

        let mut file = fi("file.bin", false);
        file.size = 1536;
        file.has_size = true;
        file.mtime = 0;
        assert_eq!(display_size(&file), "1.5 KiB");
        assert_eq!(entry_tooltip(&file), "File • 1.5 KiB (1536 bytes)");
    }
}
