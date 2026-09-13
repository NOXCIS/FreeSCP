//! FreeSCP main window (Slint UI) — runtime integration.
//!
//! This file owns the event-loop wiring between the Slint `main-window.slint`
//! component and the sibling modules (`connect`, `transfer`, `remote`,
//! `local_fs`, `site_manager`, `settings`, `secrets`, `history`, `state`).
//!
//! Threading model
//! ---------------
//! - `AppState` is shared as `Rc<RefCell<AppState>>`; it is *never* sent to
//!   another thread (it contains `Rc`-based models and `!Send` state).
//! - Network work runs on the tokio runtime stored in `AppState::runtime`.
//!   The active `SftpClient` is *taken* out of `AppState` before the first
//!   `.await` (take-client-put-back) so no `RefCell` borrow is held across a
//!   suspension point; workers hand it back through the `UiEvent` channel.
//! - Worker threads post `UiEvent` messages into an unbounded mpsc channel;
//!   a `slint::spawn_local` loop (UI-thread executor, no `Send` bound)
//!   drains it and mutates the window/`AppState` directly.
//! - Blocking sub-dialogs (text prompts, conflict asks) use
//!   `connect::prompt_user_sync` / `rfd` from a tokio worker, so Slint
//!   callbacks (which run on the UI thread) never block.
//! - Slint `Timer`s handle periodic work: session indicators, window
//!   geometry autosave, session health checks, and the
//!   `PERMISSION_FLOWS` poll for confirmed chmod dialogs.

mod connect;
mod history;
mod local_fs;
mod remote;
mod secrets;
mod settings;
mod site_manager;
mod state;
mod terminal;
mod transfer;
mod watcher;

mod ui {
    #![allow(unused_imports)] // generated modules re-export via `use ...::*`
    slint::include_modules!();
}

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use slint::{ComponentHandle, Model, SharedString, Timer, TimerMode, VecModel};

use crate::state::{AppState, UiEvent};
use freescp_core::client_factory;
use freescp_core::{
    capabilities_for_protocol, protocol_display_name, KnownHostsPolicy, Protocol, ScpTransferMode,
    SessionOptions,
};

// ---------------------------------------------------------------------------
// Formatting bridges (Slint has no string formatting; the UI asks Rust).
// ---------------------------------------------------------------------------

/// Byte count in 1024-based units with one decimal when the value is < 10.
fn format_size(bytes: i32) -> SharedString {
    local_fs_format_size(bytes.max(0) as u64).into()
}

/// Formats `local_fs::format_size` output so the pane column text matches
/// the C++ table (kept as a thin bridge over the sibling helper).
fn local_fs_format_size(bytes: u64) -> String {
    crate::local_fs::format_size(bytes)
}

/// Formats a modification time (Unix epoch seconds) as `YYYY-MM-DD HH:MM`.
fn format_mtime(unix_secs: i32) -> SharedString {
    crate::local_fs::format_mtime(unix_secs.max(0) as u64).into()
}

/// Formats a Unix mode as an `ls`-style permissions string (`drwxr-xr-x`).
fn format_permissions(mode: i32) -> SharedString {
    let m = mode.max(0) as u32;
    let triplet = |shift: u32| {
        let v = (m >> shift) & 0o7;
        format!(
            "{}{}{}",
            if v & 0o4 != 0 { 'r' } else { '-' },
            if v & 0o2 != 0 { 'w' } else { '-' },
            if v & 0o1 != 0 { 'x' } else { '-' }
        )
    };
    let kind = if m & 0o170000 == 0o040000 { 'd' } else { '-' };
    format!("{kind}{}{}{}", triplet(6), triplet(3), triplet(0)).into()
}

/// Local-pane "Kind" column label, matching the Qt `QFileSystemModel` Kind
/// column: "Folder" for directories, the detected MIME type otherwise.
fn type_label_for(is_dir: bool, name: &str) -> SharedString {
    if is_dir {
        return "Folder".into();
    }
    mime_guess::from_path(name)
        .first_raw()
        .unwrap_or("application/octet-stream")
        .into()
}

/// Formats a session duration as `HH:MM:SS`.
fn format_elapsed(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Clamps a `u64` into Slint's `i32` (sizes, timestamps, modes).
fn clamp_u64(value: u64) -> i32 {
    value.min(i32::MAX as u64) as i32
}

// ---------------------------------------------------------------------------
// Configurable shortcuts (Transfers / History).
// ---------------------------------------------------------------------------

const QUEUE_SHORTCUT_CANDIDATES: [&str; 4] = ["F12", "Ctrl+Shift+T", "Ctrl+Alt+T", "Ctrl+J"];
const HISTORY_SHORTCUT_CANDIDATES: [&str; 3] = ["Ctrl+Shift+H", "Ctrl+H", "Ctrl+Alt+H"];

/// Upper bound for the path-field recent-path dropdowns (the history stores up
/// to 20 entries; the dropdown shows the newest dozen).
const RECENT_PATH_MENU_LIMIT: usize = 12;

/// Normalizes a stored shortcut string (Qt portable text) into one of the
/// Slint candidate identifiers. Invalid or unsupported values fall back to
/// `default`. "Cmd" is normalized to "Ctrl" (Qt portable text uses "Ctrl"
/// on all platforms) and modifier order is canonicalized.
fn normalized_shortcut(value: &str, candidates: &[&str], default: &str) -> String {
    const MODIFIER_ORDER: [&str; 3] = ["Ctrl", "Alt", "Shift"];
    let mut tokens: Vec<String> = value
        .split('+')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(|part| match part.to_lowercase().as_str() {
            "cmd" | "command" | "meta" | "ctrl" | "control" => "Ctrl".to_string(),
            "alt" | "option" => "Alt".to_string(),
            "shift" => "Shift".to_string(),
            other if other.len() == 1 => other.to_uppercase(),
            other => other.to_uppercase(),
        })
        .collect();
    tokens.sort_by_key(|token| {
        MODIFIER_ORDER
            .iter()
            .position(|m| *m == token)
            .unwrap_or(MODIFIER_ORDER.len())
    });
    let normalized = tokens.join("+");
    if candidates.contains(&normalized.as_str()) {
        normalized
    } else {
        default.to_string()
    }
}

/// Pushes the Transfers/History shortcut preferences into the UI (the Slint
/// side has `KeyBinding`s for a curated candidate set, so only candidates
/// can be selected).
///
/// Called at startup and again whenever Settings is applied (the C++
/// `applyPreferences` re-arms the two `QAction` shortcuts the same way).
pub(crate) fn apply_shortcut_prefs(
    ui: &crate::ui::main_window::MainWindow,
    prefs: &settings::Preferences,
) {
    let queue = normalized_shortcut(
        &prefs.open_transfers_shortcut,
        &QUEUE_SHORTCUT_CANDIDATES,
        "F12",
    );
    let history = normalized_shortcut(
        &prefs.open_history_shortcut,
        &HISTORY_SHORTCUT_CANDIDATES,
        "Ctrl+Shift+H",
    );
    ui.set_queue_shortcut(queue.into());
    ui.set_history_shortcut(history.into());
}

// ---------------------------------------------------------------------------
// FileEntry plumbing.
// ---------------------------------------------------------------------------

/// The synthetic ".." parent row shown at the top of each pane.
fn parent_entry() -> crate::ui::main_window::FileEntry {
    crate::ui::main_window::FileEntry {
        name: "..".into(),
        is_dir: true,
        size: 0,
        has_size: false,
        mtime: 0,
        mode: 0,
        type_label: "Folder".into(),
        permissions: "".into(),
    }
}

fn local_to_file_entry(entry: &local_fs::LocalEntry) -> crate::ui::main_window::FileEntry {
    crate::ui::main_window::FileEntry {
        name: entry.name.clone().into(),
        is_dir: entry.is_dir,
        size: clamp_u64(entry.size),
        has_size: true,
        mtime: clamp_u64(entry.mtime),
        mode: clamp_u64(u64::from(entry.mode)),
        type_label: type_label_for(entry.is_dir, &entry.name),
        permissions: "".into(),
    }
}

fn remote_to_file_entry(info: &freescp_core::FileInfo) -> crate::ui::main_window::FileEntry {
    crate::ui::main_window::FileEntry {
        name: info.name.clone().into(),
        is_dir: info.is_dir,
        size: clamp_u64(info.size),
        has_size: info.has_size,
        mtime: clamp_u64(info.mtime),
        mode: clamp_u64(u64::from(info.mode)),
        type_label: "".into(),
        permissions: format_permissions(info.mode as i32),
    }
}

/// Sorts a pane listing: the synthetic ".." row stays first, directories group
/// ahead of files, then `column` decides the order (`remote` selects the right
/// pane's remote column semantics, where column 3 means Permissions instead of
/// Kind). Name order is the stable tie-break, mirroring the Qt views.
fn sort_entries_for(
    entries: &mut [crate::ui::main_window::FileEntry],
    pane: usize,
    remote: bool,
    column: i32,
    ascending: bool,
) {
    entries.sort_by(|a, b| compare_entries(a, b, pane, remote, column, ascending));
}

fn compare_entries(
    a: &crate::ui::main_window::FileEntry,
    b: &crate::ui::main_window::FileEntry,
    pane: usize,
    remote: bool,
    column: i32,
    ascending: bool,
) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let a_parent = a.name.as_str() == "..";
    let b_parent = b.name.as_str() == "..";
    if a_parent != b_parent {
        return if a_parent {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    if a.is_dir != b.is_dir {
        return if a.is_dir {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    let order = match (pane, column) {
        (0, 1) => a.size.cmp(&b.size),
        (0, 2) => entry_kind_label(a).cmp(&entry_kind_label(b)),
        (0, 3) => a.mtime.cmp(&b.mtime),
        (_, 1) => a.size.cmp(&b.size),
        (_, 2) => a.mtime.cmp(&b.mtime),
        (_, 3) if remote => a.permissions.cmp(&b.permissions),
        (_, 3) => entry_kind_label(a).cmp(&entry_kind_label(b)),
        _ => Ordering::Equal,
    };
    let order = if ascending { order } else { order.reverse() };
    if order == Ordering::Equal {
        a.name.to_lowercase().cmp(&b.name.to_lowercase())
    } else {
        order
    }
}

fn entry_kind_label(entry: &crate::ui::main_window::FileEntry) -> String {
    entry.type_label.to_lowercase()
}

/// Re-sorts a pane's visible listing in place (no directory I/O), mirroring a
/// click on a sortable Qt header, and keeps the selected entries selected by
/// name so they survive the reorder.
fn resort_pane(ui: &crate::ui::main_window::MainWindow, pane: usize) {
    let (column, ascending) = if pane == 0 {
        (ui.get_left_sort_column(), ui.get_left_sort_ascending())
    } else {
        (ui.get_right_sort_column(), ui.get_right_sort_ascending())
    };
    let remote = pane == 1 && ui.get_remote_connected();
    let (model, parent_row) = pane_entries(ui, pane);
    let mut entries: Vec<crate::ui::main_window::FileEntry> = model.iter().collect();
    if entries.is_empty() {
        return;
    }
    let selected: Vec<SharedString> = pane_selection(ui, pane)
        .rows
        .iter()
        .filter_map(|row| entries.get(*row as usize).map(|entry| entry.name.clone()))
        .collect();
    sort_entries_for(&mut entries, pane, remote, column, ascending);
    let rows: Vec<i32> = entries
        .iter()
        .enumerate()
        .filter(|(index, entry)| {
            Some(*index as i32) != parent_row && selected.iter().any(|name| name == &entry.name)
        })
        .map(|(index, _)| index as i32)
        .collect();
    let anchor = rows.first().copied().unwrap_or(-1);
    let model = Rc::new(VecModel::from(entries));
    if pane == 0 {
        ui.set_left_entries(model.into());
    } else {
        ui.set_right_entries(model.into());
    }
    apply_pane_selection(ui, pane, &PaneSelection::new(anchor, rows));
}

/// Persists a pane's sort state together with the window geometry.
fn persist_pane_sort(
    ui: &crate::ui::main_window::MainWindow,
    state: &Rc<RefCell<AppState>>,
    pane: usize,
) {
    let sort = crate::state::SortState {
        column: if pane == 0 {
            ui.get_left_sort_column()
        } else {
            ui.get_right_sort_column()
        },
        ascending: if pane == 0 {
            ui.get_left_sort_ascending()
        } else {
            ui.get_right_sort_ascending()
        },
    };
    let mut st = state.borrow_mut();
    if pane == 0 {
        st.window_state.left_sort = Some(sort);
    } else {
        st.window_state.right_sort = Some(sort);
    }
    st.persist_window_state();
}

// ---------------------------------------------------------------------------
// Breadcrumbs.
// ---------------------------------------------------------------------------

/// Caps a crumb list for display: when it grows beyond 8 segments, keep the
/// first, an ellipsis marker, and the last 6 (port of the C++ crumb elision).
fn cap_breadcrumbs(mut parts: Vec<SharedString>) -> Vec<SharedString> {
    if parts.len() > 8 {
        let tail = parts.split_off(parts.len() - 6);
        parts.push("…".into());
        parts.extend(tail);
    }
    parts
}

/// Breadcrumb labels for a local path (`/`, then each directory name) paired
/// with the absolute path each label navigates to (the C++ crumbs store the
/// accumulated path per item, `MainWindow::rebuildLocalBreadcrumbs`).
fn local_breadcrumb_pairs(path: &str) -> (Vec<SharedString>, Vec<String>) {
    let mut labels: Vec<SharedString> = Vec::new();
    let mut targets: Vec<String> = Vec::new();
    let ancestors: Vec<PathBuf> = Path::new(path).ancestors().map(Path::to_path_buf).collect();
    for anc in ancestors.iter().rev() {
        let s = anc.to_string_lossy().to_string();
        if s.is_empty() {
            continue;
        }
        // The label is the segment this path adds to its parent, so labels are
        // relative to the previous breadcrumb rather than cumulative.
        let label = match targets.last() {
            Some(prev_path) => s
                .strip_prefix(prev_path.as_str())
                .unwrap_or(&s)
                .trim_start_matches(['/', '\\'])
                .to_string(),
            None => s.clone(),
        };
        if label.is_empty() {
            continue;
        }
        labels.push(label.into());
        targets.push(s);
    }
    if labels.len() > 8 {
        let tail_labels = labels.split_off(labels.len() - 6);
        let tail_targets = targets.split_off(targets.len() - 6);
        labels.push("…".into());
        targets.push(String::new()); // the ellipsis is not clickable
        labels.extend(tail_labels);
        targets.extend(tail_targets);
    }
    (labels, targets)
}

/// Breadcrumb segments for a remote path (`/`, then each directory name).
fn remote_breadcrumbs(path: &str) -> Vec<SharedString> {
    let mut parts: Vec<SharedString> = Vec::new();
    for seg in path.split('/') {
        if !seg.is_empty() {
            parts.push(seg.to_string().into());
        }
    }
    if parts.is_empty() {
        parts.push("/".into());
    } else {
        parts.insert(0, "/".into());
    }
    cap_breadcrumbs(parts)
}

thread_local! {
    /// Absolute paths for the local breadcrumbs currently on screen; the Slint
    /// model only carries the labels (Slint has no pair model here).
    static LEFT_CRUMB_TARGETS: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn update_left_breadcrumbs(ui: &crate::ui::main_window::MainWindow, path: &str) {
    let (labels, targets) = local_breadcrumb_pairs(path);
    LEFT_CRUMB_TARGETS.with(|cell| *cell.borrow_mut() = targets);
    ui.set_left_breadcrumbs(Rc::new(VecModel::from(labels)).into());
}

fn update_right_breadcrumbs(ui: &crate::ui::main_window::MainWindow, path: &str) {
    ui.set_right_breadcrumbs(Rc::new(VecModel::from(remote_breadcrumbs(path))).into());
}

thread_local! {
    /// Absolute paths for the local breadcrumbs shown in the right pane while
    /// it is in local mode (the right-pane counterpart of
    /// `LEFT_CRUMB_TARGETS`).
    static RIGHT_CRUMB_TARGETS: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Local-mode counterpart of [`update_right_breadcrumbs`]: the C++
/// `setRightRoot` rebuilds the same local crumb strip as the left pane.
fn update_right_local_breadcrumbs(ui: &crate::ui::main_window::MainWindow, path: &str) {
    let (labels, targets) = local_breadcrumb_pairs(path);
    RIGHT_CRUMB_TARGETS.with(|cell| *cell.borrow_mut() = targets);
    ui.set_right_breadcrumbs(Rc::new(VecModel::from(labels)).into());
}

/// True while the right pane browses local folders (the C++
/// `rightIsRemote_ == false` state): before the first connect and after
/// disconnect.
fn right_pane_is_local(ui: &crate::ui::main_window::MainWindow) -> bool {
    !ui.get_remote_connected()
}

/// Rebuilds a remote path from breadcrumb segments `0..=index` (`None` when
/// the click lands on the ellipsis marker).
fn remote_path_from_crumbs(crumbs: &[SharedString], index: usize) -> Option<String> {
    if crumbs.get(index)?.as_str() == "…" {
        return None;
    }
    let segs: Vec<&str> = crumbs
        .iter()
        .take(index + 1)
        .map(|c| c.as_str())
        .filter(|c| *c != "/")
        .collect();
    if segs.is_empty() {
        Some("/".to_string())
    } else {
        Some(format!("/{}", segs.join("/")))
    }
}

// ---------------------------------------------------------------------------
// Path helpers.
// ---------------------------------------------------------------------------

/// Parent of a local path; `None` at the filesystem root.
fn parent_of_local(path: &str) -> Option<String> {
    let parent = Path::new(path).parent()?;
    if parent.as_os_str().is_empty() {
        Some(".".to_string())
    } else {
        Some(parent.to_string_lossy().to_string())
    }
}

/// Joins a local entry name onto the current directory; `".."` resolves to
/// the parent.
fn join_local(current: &str, name: &str) -> String {
    if name == ".." {
        parent_of_local(current).unwrap_or_else(|| current.to_string())
    } else {
        Path::new(current).join(name).to_string_lossy().to_string()
    }
}

/// Parent of a remote path; `None` at the remote root.
fn parent_of_remote(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rfind('/') {
        Some(index) if index > 0 => Some(trimmed[..index].to_string()),
        Some(_) => Some("/".to_string()),
        None => Some(String::new()),
    }
}

/// Joins a remote entry name onto the current directory; `".."` resolves to
/// the parent. Absolute names win.
fn join_remote(current: &str, name: &str) -> String {
    if name == ".." {
        return parent_of_remote(current).unwrap_or_else(|| current.to_string());
    }
    if name.starts_with('/') {
        return name.to_string();
    }
    let base = current.trim_end_matches('/');
    if base.is_empty() {
        format!("/{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Collapses `.`/`..` segments and duplicate separators of a remote path.
fn normalize_remote_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

// ---------------------------------------------------------------------------
// Pane reload / filter helpers.
// ---------------------------------------------------------------------------

/// Reads and sorts the local pane entries (including the ".." parent row),
/// honoring the show-hidden preference and the pane's current sort state.
fn fetch_local_entries(
    path: &Path,
    show_hidden: bool,
    pane: usize,
    remote: bool,
    sort_column: i32,
    sort_ascending: bool,
) -> Vec<crate::ui::main_window::FileEntry> {
    let mut mapped: Vec<crate::ui::main_window::FileEntry> =
        local_fs::list_dir_with(path, show_hidden)
            .unwrap_or_else(|err| {
                tracing::warn!("local list_dir({}) failed: {err}", path.display());
                Vec::new()
            })
            .iter()
            .map(local_to_file_entry)
            .collect();
    sort_entries_for(&mut mapped, pane, remote, sort_column, sort_ascending);
    // The synthetic ".." row is only offered when the path has a parent
    // (C++ has no parent row at all; at the filesystem root there is nowhere
    // to go).
    if path.parent().is_some() {
        mapped.insert(0, parent_entry());
    }
    mapped
}

thread_local! {
    /// Filesystem watchers for the local panes (index 0 = left, 1 = right).
    /// Kept per thread because the Slint UI owns them; created on the first
    /// reload of a pane and re-pointed on every navigation.
    static LOCAL_WATCHERS: std::cell::RefCell<Vec<Option<watcher::DirWatcher>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Points the local-pane watcher at `display` so external changes refresh the
/// listing (the C++ `FileSystemWatcher` behavior). The watcher posts
/// [`UiEvent::LocalDirChanged`]; the UI thread ignores it when the pane has
/// since navigated elsewhere.
fn watch_local_dir(pane: usize, path_str: &str, state: &Rc<RefCell<AppState>>) {
    let path = PathBuf::from(path_str);
    let tx = state.borrow().ui_event_tx();
    LOCAL_WATCHERS.with(|watchers| {
        let mut watchers = watchers.borrow_mut();
        if watchers.len() <= pane {
            watchers.resize_with(pane + 1, || None);
        }
        if let Some(existing) = &watchers[pane] {
            if let Err(err) = existing.set_path(path) {
                tracing::warn!("cannot watch {}: {err}", path_str);
            }
            return;
        }
        let watched = path_str.to_string();
        let on_change = move || {
            if let Some(tx) = &tx {
                let _ = tx.send(UiEvent::LocalDirChanged {
                    pane,
                    path: watched.clone(),
                });
            }
        };
        match watcher::DirWatcher::start(path, on_change) {
            Ok(handle) => watchers[pane] = Some(handle),
            Err(err) => tracing::warn!("cannot watch {}: {err}", path_str),
        }
    });
}

/// Stops watching the given local pane (the right pane while it is remote).
fn stop_local_watcher(pane: usize) {
    LOCAL_WATCHERS.with(|watchers| {
        if let Some(slot) = watchers.borrow_mut().get_mut(pane) {
            *slot = None;
        }
    });
}

/// Reloads the local pane from `requested_path` (canonicalized), updates the
/// path edit, breadcrumbs, and the recent-local-path history.
pub(crate) fn reload_local(
    ui: &crate::ui::main_window::MainWindow,
    state: &Rc<RefCell<AppState>>,
    requested_path: &str,
) {
    let cleaned = std::fs::canonicalize(Path::new(requested_path))
        .unwrap_or_else(|_| PathBuf::from(requested_path));
    let display = cleaned.to_string_lossy().to_string();
    ui.set_left_path(display.clone().into());
    ui.set_left_can_go_up(cleaned.parent().is_some());
    update_left_breadcrumbs(ui, &display);
    let entries = fetch_local_entries(
        &cleaned,
        state.borrow().prefs.show_hidden,
        0,
        false,
        ui.get_left_sort_column(),
        ui.get_left_sort_ascending(),
    );
    ui.set_left_entries(Rc::new(VecModel::from(entries)).into());
    reset_pane_selection(ui, 0);
    // C++ setLeftRoot reports the new folder on the status bar.
    ui.set_status_text(format!("Left: {display}").into());
    state.borrow_mut().push_recent_local_path(display.clone());
    watch_local_dir(0, &display, state);
}

/// Reloads the right pane as a local directory — the "local/local" layout the
/// C++ app keeps until a session connects and restores on disconnect.
pub(crate) fn reload_right_local(
    ui: &crate::ui::main_window::MainWindow,
    state: &Rc<RefCell<AppState>>,
    requested_path: &str,
) {
    let cleaned = std::fs::canonicalize(Path::new(requested_path))
        .unwrap_or_else(|_| PathBuf::from(requested_path));
    let display = cleaned.to_string_lossy().to_string();
    ui.set_right_path(display.clone().into());
    ui.set_right_can_go_up(cleaned.parent().is_some());
    update_right_local_breadcrumbs(ui, &display);
    let entries = fetch_local_entries(
        &cleaned,
        state.borrow().prefs.show_hidden,
        1,
        false,
        ui.get_right_sort_column(),
        ui.get_right_sort_ascending(),
    );
    ui.set_right_entries(Rc::new(VecModel::from(entries)).into());
    reset_pane_selection(ui, 1);
    ui.set_status_text(format!("Right: {display}").into());
    let mut st = state.borrow_mut();
    st.right_local_path = Some(display.clone());
    st.push_recent_local_path(display.clone());
    drop(st);
    watch_local_dir(1, &display, state);
}

/// Reloads the remote pane. The client is taken out of `AppState` and the
/// SFTP work runs on the tokio runtime (russh-sftp requires a reactor for
/// timeouts); results are awaited back on the UI thread via `spawn_local`.
/// Also refreshes the writeability cache for the current directory (port of
/// the C++ background probe).
fn request_remote_reload(ui: &crate::ui::main_window::MainWindow, state: &Rc<RefCell<AppState>>) {
    if state.borrow().client.is_none() {
        ui.set_status_text("Not connected".into());
        return;
    }
    let path = ui.get_right_path().to_string();
    let show_hidden = state.borrow().prefs.show_hidden;
    let sort_column = ui.get_right_sort_column();
    let sort_ascending = ui.get_right_sort_ascending();
    let client = {
        let mut st = state.borrow_mut();
        st.client.take()
    };
    let Some(mut client) = client else {
        tracing::warn!("remote refresh dropped: no active client for {path}");
        return;
    };
    let handle = state.borrow().runtime_handle();
    let ui_weak = ui.as_weak();
    let state = state.clone();
    let task = handle.spawn(async move {
        let mut entries: Vec<crate::ui::main_window::FileEntry> = Vec::new();
        let mut status_err: Option<String> = None;
        let mut writable: Option<bool> = None;

        match remote::refresh_remote(&mut *client, &path).await {
            Ok(mut infos) => {
                if !show_hidden {
                    infos.retain(|info| !remote::is_hidden_name(&info.name));
                }
                let mut mapped: Vec<crate::ui::main_window::FileEntry> =
                    infos.iter().map(remote_to_file_entry).collect();
                sort_entries_for(&mut mapped, 1, true, sort_column, sort_ascending);
                mapped.insert(0, parent_entry());
                entries = mapped;
            }
            Err(err) => {
                let message = format!("Could not refresh the remote folder.\n{err}");
                tracing::warn!("remote refresh_remote({path}) failed: {err}");
                status_err = Some(message);
            }
        }
        match remote::probe_writeability(&mut *client, &path).await {
            Ok(result) => writable = Some(result),
            Err(err) => tracing::debug!("writeability probe for {path} failed: {err}"),
        }
        (client, path, entries, writable, status_err)
    });

    let _ = slint::spawn_local(async move {
        let (client, path, entries, writable, status_err) = match task.await {
            Ok(v) => v,
            Err(join_error) => {
                tracing::error!("remote refresh task panicked: {join_error}");
                return;
            }
        };
        {
            let mut st = state.borrow_mut();
            if st.client.is_none() {
                st.client = Some(client);
            }
            if let Some(writable) = writable {
                st.writeability.store(&path, writable);
            }
        }
        let Some(ui) = ui_weak.upgrade() else {
            return;
        };
        if let Some(message) = status_err {
            ui.set_status_text(message.into());
        }
        ui.set_right_entries(Rc::new(VecModel::from(entries)).into());
        reset_pane_selection(&ui, 1);
        let right_path = ui.get_right_path().to_string();
        ui.set_right_can_go_up(remote::has_remote_parent(&right_path));
        update_right_breadcrumbs(&ui, &right_path);
    });
}

// ---------------------------------------------------------------------------
// Window geometry.
// ---------------------------------------------------------------------------

/// Restores position/size from `AppState::window_state` (logical units so
/// HiDPI scaling is preserved) plus the pane splitter position.
fn restore_window_geometry(ui: &crate::ui::main_window::MainWindow, state: &Rc<RefCell<AppState>>) {
    let st = state.borrow();
    let ws = &st.window_state;
    if let (Some(x), Some(y)) = (ws.x, ws.y) {
        ui.window()
            .set_position(slint::LogicalPosition::new(x as f32, y as f32));
    }
    if let (Some(width), Some(height)) = (ws.width, ws.height) {
        ui.window()
            .set_size(slint::LogicalSize::new(width as f32, height as f32));
    }
    let restored_width = ws.width.map(|w| w as i32);
    let split = match ws.split_x {
        Some(split) => Some(split.clamp(260, restored_width.unwrap_or(1200) - 260)),
        None => restored_width.map(|w| (w / 2).clamp(260, w - 260)),
    };
    if let Some(split) = split {
        ui.set_left_pane_width(split as f32);
    }
    if let Some([size_w, type_w, mtime_w]) = ws.left_col_widths {
        ui.set_left_size_width(size_w.max(32) as f32);
        ui.set_left_type_width(type_w.max(32) as f32);
        ui.set_left_mtime_width(mtime_w.max(32) as f32);
    }
    if let Some([size_w, mtime_w, perm_w]) = ws.right_col_widths {
        ui.set_right_size_width(size_w.max(32) as f32);
        ui.set_right_mtime_width(mtime_w.max(32) as f32);
        ui.set_right_perm_width(perm_w.max(32) as f32);
    }
    if let Some([size_v, type_v, mtime_v]) = ws.left_col_visible {
        ui.set_left_col_size_visible(size_v);
        ui.set_left_col_type_visible(type_v);
        ui.set_left_col_mtime_visible(mtime_v);
    }
    if let Some([size_v, mtime_v, perm_v]) = ws.right_col_visible {
        ui.set_right_col_size_visible(size_v);
        ui.set_right_col_mtime_visible(mtime_v);
        ui.set_right_col_perm_visible(perm_v);
    }
    let left_sort = ws
        .left_sort
        .unwrap_or(crate::state::SortState::NAME_ASCENDING);
    ui.set_left_sort_column(left_sort.column.clamp(0, 3));
    ui.set_left_sort_ascending(left_sort.ascending);
    let right_sort = ws
        .right_sort
        .unwrap_or(crate::state::SortState::NAME_ASCENDING);
    ui.set_right_sort_column(right_sort.column.clamp(0, 3));
    ui.set_right_sort_ascending(right_sort.ascending);
}

/// Captures position/size into `AppState::window_state` and persists it.
fn capture_window_geometry(ui: &crate::ui::main_window::MainWindow, state: &Rc<RefCell<AppState>>) {
    let window = ui.window();
    let scale = window.scale_factor();
    let mut st = state.borrow_mut();
    let position = window.position();
    let logical = position.to_logical(scale);
    st.window_state.x = Some(logical.x as i32);
    st.window_state.y = Some(logical.y as i32);
    let size = window.size().to_logical(scale);
    st.window_state.width = Some(size.width.max(0.0) as u32);
    st.window_state.height = Some(size.height.max(0.0) as u32);
    st.window_state.split_x = Some(ui.get_left_pane_width().max(0.0) as i32);
    st.window_state.left_col_widths = Some([
        ui.get_left_size_width().round().max(32.0) as i32,
        ui.get_left_type_width().round().max(32.0) as i32,
        ui.get_left_mtime_width().round().max(32.0) as i32,
    ]);
    st.window_state.right_col_widths = Some([
        ui.get_right_size_width().round().max(32.0) as i32,
        ui.get_right_mtime_width().round().max(32.0) as i32,
        ui.get_right_perm_width().round().max(32.0) as i32,
    ]);
    st.window_state.left_col_visible = Some([
        ui.get_left_col_size_visible(),
        ui.get_left_col_type_visible(),
        ui.get_left_col_mtime_visible(),
    ]);
    st.window_state.right_col_visible = Some([
        ui.get_right_col_size_visible(),
        ui.get_right_col_mtime_visible(),
        ui.get_right_col_perm_visible(),
    ]);
    st.persist_window_state();
}

// ---------------------------------------------------------------------------
// Search dialogs.
// ---------------------------------------------------------------------------

thread_local! {
    /// Search dialogs kept alive on the event-loop thread while open
    /// (pane, dialog, cancel flag). Pruned when a new dialog opens.
    static SEARCH_DIALOGS: RefCell<Vec<(usize, crate::ui::main_window::SearchDialog, Arc<AtomicBool>)>> =
        const { RefCell::new(Vec::new()) };
}

// ---------------------------------------------------------------------------
// Translations (gettext catalogs shared with the C++/Qt build).
// ---------------------------------------------------------------------------

/// Looks `msgid` up in the gettext `MainWindow` context and substitutes the
/// Qt-style `%1`, `%2`, … placeholders. The catalogs under
/// `crates/freescp-app/translations/*/LC_MESSAGES` are generated from the Qt
/// `.ts` files, so every entry uses the `MainWindow` context and the C++
/// msgids. Slint's own formatter only understands `{}`, so `%N` is expanded
/// here to keep the exact C++ strings (lookup therefore always hits).
fn tr_main_window(msgid: &str, args: &[String]) -> String {
    crate::connect::tr(msgid, args)
}

// ---------------------------------------------------------------------------
// Recursive search summary (port of MainWindow.cpp search reporting).
// ---------------------------------------------------------------------------

/// Multi-line results summary, verbatim port of the C++
/// `showRecursiveSearchResultsDialog`:
///
/// ```text
/// Base: {base}
/// Matches: {n}
/// Scan errors: {n}                   (only when scan errors occurred)
/// Search canceled by user.           (only when canceled)
/// Results truncated to safety limit. (only when the cap was hit)
/// ```
fn search_results_summary(
    base: &str,
    matches: usize,
    scan_errors: usize,
    canceled: bool,
    truncated: bool,
) -> String {
    let mut summary = tr_main_window(
        "Base: %1\nMatches: %2",
        &[base.to_string(), matches.to_string()],
    );
    if scan_errors > 0 {
        summary.push('\n');
        summary.push_str(&tr_main_window(
            "Scan errors: %1",
            &[scan_errors.to_string()],
        ));
    }
    if canceled {
        summary.push('\n');
        summary.push_str(&tr_main_window("Search canceled by user.", &[]));
    }
    if truncated {
        summary.push('\n');
        summary.push_str(&tr_main_window("Results truncated to safety limit.", &[]));
    }
    summary
}

/// Status-bar message for a finished recursive search (port of the C++
/// `MainWindow.cpp:1914-1946` lines, including the `(Canceled)` marker).
fn search_status_text(
    panel_label: &str,
    matches: usize,
    outcome: &local_fs::SearchOutcome,
) -> String {
    // Empty result: the C++ returns after the "Folders with errors" suffix,
    // so the "(Canceled)" marker only appears with matches.
    if matches == 0 {
        let mut text = if outcome.canceled {
            tr_main_window("Search canceled in %1.", &[panel_label.to_string()])
        } else {
            tr_main_window(
                "No recursive matches found in %1.",
                &[panel_label.to_string()],
            )
        };
        if outcome.scan_errors > 0 {
            text.push_str("  ");
            text.push_str(&tr_main_window(
                "Folders with errors: %1",
                &[outcome.scan_errors.to_string()],
            ));
        }
        return text;
    }
    let mut text = tr_main_window(
        "Found %1 recursive match(es) in %2.",
        &[matches.to_string(), panel_label.to_string()],
    );
    if outcome.truncated {
        text.push_str("  ");
        text.push_str(&tr_main_window(
            "Results limited to %1.",
            &[local_fs::MAX_SEARCH_MATCHES.to_string()],
        ));
    }
    if outcome.scan_errors > 0 {
        text.push_str("  ");
        text.push_str(&tr_main_window(
            "Folders with errors: %1",
            &[outcome.scan_errors.to_string()],
        ));
    }
    if outcome.canceled {
        text.push_str("  ");
        text.push_str(&tr_main_window("(Canceled)", &[]));
    }
    text
}

/// Posts search results back onto the event loop and updates the dialog, plus
/// the pane status line for recursive searches.
fn post_search_results(
    dlg_weak: slint::Weak<crate::ui::main_window::SearchDialog>,
    base: String,
    panel_label: String,
    status_tx: Option<tokio::sync::mpsc::UnboundedSender<UiEvent>>,
    outcome: Result<local_fs::SearchOutcome, String>,
) {
    let _ = slint::invoke_from_event_loop(move || {
        let Some(dlg) = dlg_weak.upgrade() else {
            return;
        };
        dlg.set_busy(false);
        match outcome {
            Ok(outcome) => {
                let matches = outcome.matches.len();
                dlg.set_summary_text(
                    search_results_summary(
                        &base,
                        matches,
                        outcome.scan_errors,
                        outcome.canceled,
                        outcome.truncated,
                    )
                    .into(),
                );
                if let Some(tx) = &status_tx {
                    let _ = tx.send(UiEvent::Status {
                        message: search_status_text(&panel_label, matches, &outcome),
                    });
                }
                let mapped: Vec<SharedString> = outcome
                    .matches
                    .into_iter()
                    .map(SharedString::from)
                    .collect();
                dlg.set_results(Rc::new(VecModel::from(mapped)).into());
            }
            Err(err) => {
                dlg.set_summary_text(format!("Search error: {err}").into());
            }
        }
    });
}

/// Opens the "Search items" dialog for pane 0 (left/local) or 1 (right).
fn open_search_dialog(
    ui: &crate::ui::main_window::MainWindow,
    state: &Rc<RefCell<AppState>>,
    pane: usize,
) {
    let Ok(dialog) = crate::ui::main_window::SearchDialog::new() else {
        tracing::error!("failed to instantiate SearchDialog");
        return;
    };
    let title = if pane == 0 {
        "Search items (Local panel)"
    } else if state.borrow().client.is_some() {
        "Search items (Remote panel)"
    } else {
        "Search items (Local panel - right)"
    };
    dialog.set_title_text(title.into());
    crate::remote::center_window_over(ui, dialog.window());

    let cancel = Arc::new(AtomicBool::new(false));
    let state = state.clone();

    // Dialog bookkeeping: keep it alive while open, prune closed ones.
    SEARCH_DIALOGS.with(|dialogs| {
        let mut dialogs = dialogs.borrow_mut();
        dialogs.retain(|(_, d, _)| d.window().is_visible());
        dialogs.push((pane, dialog.clone_strong(), Arc::clone(&cancel)));
    });

    let ui_weak = ui.as_weak();
    {
        let dlg = dialog.clone_strong();
        let state = state.clone();
        let cancel = Arc::clone(&cancel);
        let ui_weak = ui_weak.clone();
        dialog.on_search_requested(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let pattern = dlg.get_pattern().trim().to_string();
            if pattern.is_empty() {
                return;
            }
            cancel.store(false, Ordering::SeqCst);
            dlg.set_busy(true);
            dlg.set_summary_text("".into());
            dlg.set_results(Rc::new(VecModel::<SharedString>::default()).into());
            let recursive = dlg.get_recursive();
            let base = if pane == 0 {
                ui.get_left_path().to_string()
            } else {
                ui.get_right_path().to_string()
            };
            let panel_label = if pane == 0 {
                "Local panel"
            } else if state.borrow().client.is_some() {
                "Remote panel"
            } else {
                "Local panel (right)"
            };
            // C++ searchItemsInCurrentFolder: without the recursive checkbox
            // the matches are selected in the pane itself (status-bar count)
            // instead of scanning subfolders into a results dialog.
            if !recursive {
                let matcher = match local_fs::SearchMatcher::new(&pattern) {
                    Ok(matcher) => matcher,
                    Err(err) => {
                        crate::connect::show_alert(
                            "Invalid pattern",
                            &crate::connect::tr(
                                "The pattern is not valid.\n%1",
                                std::slice::from_ref(&err.to_string()),
                            ),
                        );
                        dlg.set_busy(false);
                        return;
                    }
                };
                let model = if pane == 0 {
                    ui.get_left_entries()
                } else {
                    ui.get_right_entries()
                };
                let mut first: Option<usize> = None;
                let mut labels: Vec<SharedString> = Vec::new();
                for i in 0..model.row_count() {
                    let Some(entry) = model.row_data(i) else {
                        continue;
                    };
                    if entry.name == ".." || !matcher.matches(&entry.name) {
                        continue;
                    }
                    first.get_or_insert(i);
                    labels.push(entry.name.clone());
                }
                match first {
                    Some(row) => {
                        select_single_row(&ui, pane, row as i32);
                        state.borrow().set_status(&format!(
                            "Found {} match(es) in {panel_label}.",
                            labels.len()
                        ));
                    }
                    None => {
                        reset_pane_selection(&ui, pane);
                        state
                            .borrow()
                            .set_status(&format!("No matches found in {panel_label}."));
                    }
                }
                dlg.set_busy(false);
                dlg.set_summary_text(
                    search_results_summary(&base, labels.len(), 0, false, false).into(),
                );
                dlg.set_results(Rc::new(VecModel::from(labels)).into());
                return;
            }
            let dlg_weak = dlg.as_weak();
            let cancel = Arc::clone(&cancel);
            let prefs = settings::Preferences::load();
            let max_depth = prefs.max_folder_depth.clamp(4, 256) as usize;
            let include_hidden = prefs.show_hidden;
            let handle = state.borrow().runtime_handle();
            let status_tx = state.borrow().ui_event_tx();
            let panel_label = panel_label.to_string();
            if pane == 0 {
                let summary_base = base.clone();
                handle.spawn(async move {
                    let base_path = PathBuf::from(base);
                    let outcome = tokio::task::spawn_blocking(move || {
                        local_fs::search_local_recursive(
                            &base_path,
                            &pattern,
                            recursive,
                            max_depth,
                            include_hidden,
                            &cancel,
                        )
                    })
                    .await
                    .unwrap_or_else(|join_err| {
                        Err(format!("Local search task crashed: {join_err}"))
                    });
                    post_search_results(dlg_weak, summary_base, panel_label, status_tx, outcome);
                });
            } else {
                let session = state.borrow().session.clone();
                let summary_base = base.clone();
                handle.spawn(async move {
                    let outcome = match session {
                        Some(session) => {
                            match client_factory::create_connected_client(&session).await {
                                Ok(mut client) => {
                                    remote::search_remote_recursive(
                                        &mut *client,
                                        &base,
                                        &pattern,
                                        recursive,
                                        max_depth,
                                        include_hidden,
                                        &cancel,
                                    )
                                    .await
                                }
                                Err(err) => Err(format!("Could not start the search: {err}")),
                            }
                        }
                        None => Err("Not connected".to_string()),
                    };
                    post_search_results(dlg_weak, summary_base, panel_label, status_tx, outcome);
                });
            }
        });
    }
    {
        let cancel = Arc::clone(&cancel);
        dialog.on_cancel_requested(move || {
            cancel.store(true, Ordering::SeqCst);
        });
    }

    let _ = dialog.show();
}

// ---------------------------------------------------------------------------
// Permissions flows.
// ---------------------------------------------------------------------------

// Non-modal permissions dialogs opened by the main window, kept alive on
// the event-loop thread. `poll_permission_flows` (driven by a `Timer`)
// drains the confirmed ones and applies the mode through
// `remote::change_permissions[_recursive]`. The stored flag records whether
// the target is a directory: C++ only recurses when `st.is_dir`.
thread_local! {
    static PERMISSION_FLOWS: RefCell<Vec<(remote::PermissionsFlow, String, bool)>> =
        const { RefCell::new(Vec::new()) };
}

/// Polls the parked permission dialogs; confirmed flows are removed and
/// handed to `apply_permissions` with their target path.
fn poll_permission_flows(
    ui_weak: &slint::Weak<crate::ui::main_window::MainWindow>,
    state: &Rc<RefCell<AppState>>,
) {
    let mut confirmed: Vec<(String, u32, bool, bool)> = Vec::new();
    PERMISSION_FLOWS.with(|flows| {
        let mut flows = flows.borrow_mut();
        flows.retain(|(flow, target, is_dir)| match flow.poll() {
            None => true,
            Some(Some(mode)) => {
                confirmed.push((target.clone(), mode, flow.recursive(), *is_dir));
                false
            }
            Some(None) => false,
        });
    });
    for (path, mode, recursive, is_dir) in confirmed {
        apply_permissions(ui_weak, state, path, mode, recursive && is_dir);
    }
}

/// Applies a confirmed chmod to `path` on the session client (recursively
/// when the dialog's "recursive" box was checked), then reloads the pane.
fn apply_permissions(
    _ui_weak: &slint::Weak<crate::ui::main_window::MainWindow>,
    state: &Rc<RefCell<AppState>>,
    path: String,
    mode: u32,
    recursive: bool,
) {
    let client = {
        let mut st = state.borrow_mut();
        st.client.take()
    };
    let Some(client) = client else { return };
    let handle = state.borrow().runtime_handle();
    let tx = state.borrow().ui_event_tx();
    handle.spawn(async move {
        let mut client = client;
        let result = if recursive {
            remote::change_permissions_recursive(&mut *client, &path, mode).await
        } else {
            remote::change_permissions(&mut *client, &path, mode).await
        };
        let message = match result {
            Ok(()) => format!("Permissions updated: {path}"),
            Err(err) => {
                if remote::indicates_writeability_denied(&err) {
                    if let Some(tx) = &tx {
                        let _ = tx.send(UiEvent::InvalidateWriteability { dir: path.clone() });
                    }
                }
                format!("Could not apply permissions.\n{err}")
            }
        };
        if let Some(tx) = &tx {
            let _ = tx.send(UiEvent::Status { message });
            let _ = tx.send(UiEvent::ReturnClient(client));
            let _ = tx.send(UiEvent::ReloadRemote);
        }
    });
}

// ---------------------------------------------------------------------------
// Prompts and async local/remote operations.
// ---------------------------------------------------------------------------

/// Blocking text prompt for a tokio worker (must not run on the UI thread):
/// returns the trimmed answer, or `None` on cancel. `initial` prefills the
/// field (C++ `QInputDialog::getText(..., initial)`; rename passes the old
/// name so it can be edited in place).
fn prompt_for_text(title: &'static str, prompt: &'static str, initial: &str) -> Option<String> {
    match connect::prompt_user_sync(title, "Name", "", prompt, initial, false) {
        connect::PromptOutcome::Answered(name) => {
            let trimmed = name.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
        connect::PromptOutcome::Cancelled | connect::PromptOutcome::Unavailable => None,
    }
}

/// Puts a client back into `AppState` via the UI event channel.
fn return_client(
    tx: &Option<tokio::sync::mpsc::UnboundedSender<UiEvent>>,
    client: Box<dyn freescp_core::SftpClient>,
) {
    if let Some(tx) = tx {
        let _ = tx.send(UiEvent::ReturnClient(client));
    }
}

/// Runs `op` (which creates the new local item) on the tokio runtime after
/// prompting for a name, then posts a status update and a local reload.
fn run_prompted_local_op(
    state: &Rc<RefCell<AppState>>,
    pane: usize,
    title: &'static str,
    prompt: &'static str,
    initial: String,
    reload_path: String,
    op: impl FnOnce(
            String,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<String, String>> + Send>,
        > + Send
        + 'static,
) {
    let handle = state.borrow().runtime_handle();
    let tx = state.borrow().ui_event_tx();
    handle.spawn(async move {
        let Some(name) = prompt_for_text(title, prompt, &initial) else {
            return;
        };
        let mut why = None;
        let message = if !local_fs::is_valid_entry_name(&name, &mut why) {
            Err(format!(
                "Invalid name: {}",
                why.unwrap_or_else(|| "not allowed".to_string())
            ))
        } else {
            op(name).await
        };
        let message = match message {
            Ok(ok) => ok,
            Err(err) => err,
        };
        if let Some(tx) = &tx {
            // An empty message means "nothing to report" (e.g. the user
            // declined an overwrite prompt).
            if !message.is_empty() {
                let _ = tx.send(UiEvent::Status { message });
            }
            let reload = if pane == 0 {
                UiEvent::ReloadLocal { path: reload_path }
            } else {
                UiEvent::ReloadRightLocal { path: reload_path }
            };
            let _ = tx.send(reload);
        }
    });
}

/// Opens a local file with the user's `open_behavior` preference ("ask" |
/// "reveal" | "open"), shared by both panes' local listings.
fn open_local_file(
    ui: &crate::ui::main_window::MainWindow,
    state: &Rc<RefCell<AppState>>,
    target: &str,
) {
    let behavior = state.borrow().prefs.open_behavior.clone();
    let behavior = if behavior == "ask" {
        let choice = rfd::MessageDialog::new()
            .set_title("Opening preference")
            .set_description("How do you want to open this file?")
            .set_buttons(rfd::MessageButtons::OkCancelCustom(
                "Open file".to_string(),
                "Show folder".to_string(),
            ))
            .show();
        if choice == rfd::MessageDialogResult::Ok {
            "open".to_string()
        } else {
            "reveal".to_string()
        }
    } else {
        behavior
    };
    match local_fs::open_in_os(Path::new(target), &behavior) {
        Ok(()) => {}
        Err(err) => {
            ui.set_status_text(format!("Could not open the file: {err}").into());
        }
    }
}

/// Remote counterpart of `run_prompted_local_op`: takes the session client
/// through the prompt + operation and posts status/return-client/reload
/// events. `client` must be `None` when there is no active session.
fn run_prompted_remote_op(
    state: &Rc<RefCell<AppState>>,
    client: Option<Box<dyn freescp_core::SftpClient>>,
    title: &'static str,
    prompt: &'static str,
    initial: String,
    reload_remote: bool,
    op: impl for<'a> FnOnce(
            &'a mut (dyn freescp_core::SftpClient + 'a),
            String,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>,
        > + Send
        + 'static,
) {
    let handle = state.borrow().runtime_handle();
    let tx = state.borrow().ui_event_tx();
    handle.spawn(async move {
        let Some(mut client) = client else {
            return;
        };
        let Some(name) = prompt_for_text(title, prompt, &initial) else {
            return_client(&tx, client);
            return;
        };
        let message = match op(&mut *client, name).await {
            Ok(ok) => ok,
            Err(err) => err,
        };
        if let Some(tx) = &tx {
            let _ = tx.send(UiEvent::Status { message });
        }
        return_client(&tx, client);
        if reload_remote {
            if let Some(tx) = &tx {
                let _ = tx.send(UiEvent::ReloadRemote);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Pane selection (port of the Qt ExtendedSelection model).
// ---------------------------------------------------------------------------
//
// Rust owns the selection for both panes: it is written back into the Slint
// `*-selected-rows` set, the parallel `*-selected-flags` render array, and the
// `*-selected-row` current/anchor scalar. The synthetic ".." row is never part
// of the set (Qt's parent row is not a real entry).

/// How a row click combines with the existing selection (Qt
/// `QItemSelectionModel` semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectionMode {
    /// Plain click: replace the selection and move the anchor.
    Replace,
    /// Ctrl/Cmd-click: toggle the row in/out and move the anchor.
    Toggle,
    /// Shift-click: select the range from the anchor to the clicked row.
    Extend,
}

/// Multi-row selection model for one pane. `anchor` is the row a Shift-click
/// extends from (also the "current" row, mirrored to the Slint scalar); `rows`
/// is the sorted, deduplicated set of selected view rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PaneSelection {
    anchor: i32,
    rows: Vec<i32>,
}

impl PaneSelection {
    /// Rebuilds a selection from the Slint properties (sorted + deduplicated
    /// so a stale model can never produce duplicate transfer seeds).
    fn new(anchor: i32, mut rows: Vec<i32>) -> Self {
        rows.sort_unstable();
        rows.dedup();
        Self { anchor, rows }
    }

    /// Applies a click on `row` with the given mode. `parent_row` is the index
    /// of the synthetic ".." row when the pane has one; `len` is the number of
    /// rows currently listed.
    fn click(&mut self, row: i32, mode: SelectionMode, parent_row: Option<i32>, len: usize) {
        if row < 0 || row as usize >= len {
            self.anchor = -1;
            self.rows.clear();
            return;
        }
        let is_parent = Some(row) == parent_row;
        match mode {
            SelectionMode::Replace => {
                self.anchor = row;
                self.rows.clear();
                // ".." is leave-only: it never counts as an actionable
                // selection.
                if !is_parent {
                    self.rows.push(row);
                }
            }
            SelectionMode::Toggle => {
                self.anchor = row;
                if is_parent {
                    // The parent row cannot join the set, so the toggle is a
                    // no-op for the selection itself.
                    return;
                }
                if let Some(pos) = self.rows.iter().position(|r| *r == row) {
                    self.rows.remove(pos);
                } else {
                    self.rows.push(row);
                    self.rows.sort_unstable();
                }
            }
            SelectionMode::Extend => {
                let anchor = if self.anchor >= 0 && (self.anchor as usize) < len {
                    self.anchor
                } else {
                    row
                };
                let (lo, hi) = (anchor.min(row), anchor.max(row));
                // The range is exactly the Qt behavior minus the parent row,
                // which must never be part of a multi-selection.
                self.rows = (lo..=hi).filter(|r| Some(*r) != parent_row).collect();
                self.anchor = row;
            }
        }
    }

    /// Ctrl/Cmd+A: every entry except the synthetic parent row. The anchor
    /// stays when it still points at a listed non-parent row, otherwise it
    /// moves to the first selected row.
    fn select_all(&mut self, parent_row: Option<i32>, len: usize) {
        self.rows = (0..len as i32).filter(|r| Some(*r) != parent_row).collect();
        let anchor_ok =
            self.anchor >= 0 && (self.anchor as usize) < len && Some(self.anchor) != parent_row;
        if !anchor_ok {
            self.anchor = self.rows.first().copied().unwrap_or(-1);
        }
    }

    /// Escape: collapse the multi-selection back to the current/anchor row.
    fn collapse(&mut self, parent_row: Option<i32>, len: usize) {
        let anchor_ok =
            self.anchor >= 0 && (self.anchor as usize) < len && Some(self.anchor) != parent_row;
        self.rows.clear();
        if anchor_ok {
            self.rows.push(self.anchor);
        }
    }
}

/// The pane's entries model plus the synthetic ".." row index (`Some(0)` when
/// the parent row is present).
fn pane_entries(
    ui: &crate::ui::main_window::MainWindow,
    pane: usize,
) -> (
    slint::ModelRc<crate::ui::main_window::FileEntry>,
    Option<i32>,
) {
    let entries = if pane == 0 {
        ui.get_left_entries()
    } else {
        ui.get_right_entries()
    };
    let parent_row = entries.row_data(0).filter(|e| e.name == "..").map(|_| 0);
    (entries, parent_row)
}

/// Reads a pane's selection out of the Slint properties.
fn pane_selection(ui: &crate::ui::main_window::MainWindow, pane: usize) -> PaneSelection {
    let (anchor, rows) = if pane == 0 {
        (ui.get_left_selected_row(), ui.get_left_selected_rows())
    } else {
        (ui.get_right_selected_row(), ui.get_right_selected_rows())
    };
    PaneSelection::new(anchor, rows.iter().collect())
}

/// Writes a pane's selection back into the Slint properties: the sorted row
/// set, the per-row render flags (always as long as the entries model), the
/// current/anchor scalar, and the parent-row gate.
fn apply_pane_selection(
    ui: &crate::ui::main_window::MainWindow,
    pane: usize,
    selection: &PaneSelection,
) {
    let (entries, parent_row) = pane_entries(ui, pane);
    let len = entries.row_count();
    let flags: Vec<bool> = (0..len)
        .map(|i| selection.rows.contains(&(i as i32)))
        .collect();
    let rows: Vec<i32> = selection.rows.clone();
    let anchor = if selection.anchor >= 0 && (selection.anchor as usize) < len {
        selection.anchor
    } else {
        -1
    };
    let is_parent = anchor >= 0 && Some(anchor) == parent_row;
    if pane == 0 {
        ui.set_left_selected_flags(Rc::new(VecModel::from(flags)).into());
        ui.set_left_selected_rows(Rc::new(VecModel::from(rows)).into());
        ui.set_left_selected_row(anchor);
        ui.set_left_selected_is_parent(is_parent);
    } else {
        ui.set_right_selected_flags(Rc::new(VecModel::from(flags)).into());
        ui.set_right_selected_rows(Rc::new(VecModel::from(rows)).into());
        ui.set_right_selected_row(anchor);
        ui.set_right_selected_is_parent(is_parent);
    }
}

/// Clears a pane's selection (called on every pane reload, exactly like the
/// old `set_*_selected_row(-1)`).
fn reset_pane_selection(ui: &crate::ui::main_window::MainWindow, pane: usize) {
    apply_pane_selection(ui, pane, &PaneSelection::default());
}

/// Shared click handling for both panes (row callbacks + keyboard navigation).
fn handle_pane_row_click(
    ui: &crate::ui::main_window::MainWindow,
    pane: usize,
    row: i32,
    ctrl: bool,
    shift: bool,
) {
    let (entries, parent_row) = pane_entries(ui, pane);
    let len = entries.row_count();
    if row < 0 || row as usize >= len {
        return;
    }
    let mode = if shift {
        SelectionMode::Extend
    } else if ctrl {
        SelectionMode::Toggle
    } else {
        SelectionMode::Replace
    };
    let mut selection = pane_selection(ui, pane);
    selection.click(row, mode, parent_row, len);
    apply_pane_selection(ui, pane, &selection);
    ui.set_focused_pane(pane as i32);
}

/// Ctrl/Cmd+A handler: selects every non-parent entry of the pane.
fn handle_pane_select_all(ui: &crate::ui::main_window::MainWindow, pane: usize) {
    let (entries, parent_row) = pane_entries(ui, pane);
    let len = entries.row_count();
    let mut selection = pane_selection(ui, pane);
    selection.select_all(parent_row, len);
    apply_pane_selection(ui, pane, &selection);
}

/// Escape handler: collapses the multi-selection to the current row.
fn handle_pane_collapse_selection(ui: &crate::ui::main_window::MainWindow, pane: usize) {
    let (entries, parent_row) = pane_entries(ui, pane);
    let len = entries.row_count();
    let mut selection = pane_selection(ui, pane);
    selection.collapse(parent_row, len);
    apply_pane_selection(ui, pane, &selection);
}

/// Replaces a pane's selection with a single row (non-recursive search jumps
/// to the first match, mirroring the C++ `setCurrentIndex`).
fn select_single_row(ui: &crate::ui::main_window::MainWindow, pane: usize, row: i32) {
    let (entries, parent_row) = pane_entries(ui, pane);
    let len = entries.row_count();
    let mut selection = PaneSelection::default();
    selection.click(row, SelectionMode::Replace, parent_row, len);
    apply_pane_selection(ui, pane, &selection);
}

// ---------------------------------------------------------------------------
// Transfers (toolbar + pane activation).
// ---------------------------------------------------------------------------

/// The left pane's selected entries as transfer seeds `(path, is_dir)`, in
/// list order. The synthetic ".." row is never a seed.
fn selected_left_seeds(ui: &crate::ui::main_window::MainWindow) -> Vec<(PathBuf, bool)> {
    let rows: Vec<i32> = ui.get_left_selected_rows().iter().collect();
    let entries = ui.get_left_entries();
    let current = ui.get_left_path().to_string();
    rows.into_iter()
        .filter(|row| *row >= 0)
        .filter_map(|row| entries.row_data(row as usize))
        .filter(|entry| entry.name != "..")
        .map(|entry| {
            (
                PathBuf::from(join_local(&current, &entry.name)),
                entry.is_dir,
            )
        })
        .collect()
}

/// The right pane's selected entries as transfer seeds `(remote_path, is_dir)`,
/// in list order. The synthetic ".." row is never a seed.
fn selected_right_seeds(ui: &crate::ui::main_window::MainWindow) -> Vec<(String, bool)> {
    let rows: Vec<i32> = ui.get_right_selected_rows().iter().collect();
    let entries = ui.get_right_entries();
    let current = ui.get_right_path().to_string();
    rows.into_iter()
        .filter(|row| *row >= 0)
        .filter_map(|row| entries.row_data(row as usize))
        .filter(|entry| entry.name != "..")
        .map(|entry| (join_remote(&current, &entry.name), entry.is_dir))
        .collect()
}

/// The right pane's selected entries as local filesystem paths (used while
/// the pane is in local mode). The synthetic ".." row is never a seed.
fn selected_right_local_seeds(ui: &crate::ui::main_window::MainWindow) -> Vec<PathBuf> {
    let rows: Vec<i32> = ui.get_right_selected_rows().iter().collect();
    let entries = ui.get_right_entries();
    let current = ui.get_right_path().to_string();
    rows.into_iter()
        .filter(|row| *row >= 0)
        .filter_map(|row| entries.row_data(row as usize))
        .filter(|entry| entry.name != "..")
        .map(|entry| PathBuf::from(join_local(&current, &entry.name)))
        .collect()
}

/// Local→local copy/move of selected pane entries into `dest_dir` (the
/// local/local branch of the C++ copy/move actions). Runs on the tokio runtime
/// and reloads the affected panes when it finishes.
fn run_local_copy_move(
    state: &Rc<RefCell<AppState>>,
    sources: Vec<PathBuf>,
    dest_dir: PathBuf,
    move_files: bool,
    reload: Vec<(usize, String)>,
) {
    if sources.is_empty() {
        return;
    }
    let handle = state.borrow().runtime_handle();
    let tx = state.borrow().ui_event_tx();
    handle.spawn(async move {
        let mut ok = 0usize;
        let mut failed = 0usize;
        let mut skipped = 0usize;
        for src in &sources {
            let Some(name) = src.file_name() else {
                failed += 1;
                continue;
            };
            let target = dest_dir.join(name);
            let identical = match (src.canonicalize(), target.canonicalize()) {
                (Ok(a), Ok(b)) => a == b,
                _ => *src == target,
            };
            if identical {
                skipped += 1;
                continue;
            }
            let exists = target.exists();
            if exists
                && !crate::connect::confirm_sync(
                    "Conflict",
                    &tr_main_window(
                        "“%1” already exists at destination.\nOverwrite?",
                        &[name.to_string_lossy().into_owned()],
                    ),
                    "Yes",
                    "No",
                )
            {
                skipped += 1;
                continue;
            }
            let progress = |_done: u64, _total: u64| {};
            let should_cancel = || false;
            let result = if move_files {
                local_fs::move_local_async(src, &target, true, false, progress, should_cancel).await
            } else {
                local_fs::copy_local_async(src, &target, true, false, progress, should_cancel).await
            };
            match result {
                Ok(_) => ok += 1,
                Err(err) => {
                    tracing::warn!("local copy/move failed for {}: {err}", src.display());
                    failed += 1;
                }
            }
        }
        if let Some(tx) = &tx {
            let verb = if move_files { "Moved" } else { "Copied" };
            let mut message = format!("{verb}: {ok}  |  Failed: {failed}");
            if skipped > 0 {
                message.push_str(&format!("  |  Skipped: {skipped}"));
            }
            let _ = tx.send(UiEvent::Status { message });
            for (pane, path) in reload {
                let event = if pane == 0 {
                    UiEvent::ReloadLocal { path }
                } else {
                    UiEvent::ReloadRightLocal { path }
                };
                let _ = tx.send(event);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Drag and drop between the panes (port of MainWindow::handlePanelDrop)
// ---------------------------------------------------------------------------

/// Marker stored in the shared `DataTransfer` payload. Slint needs a non-empty
/// payload to start a drag; the payload carries no data (so external apps
/// ignore the drag) because the selection is read from the pane state on drop.
struct PaneDragMarker;

/// Resolves a drop onto `pane` to the receiving directory: the hovered folder
/// row's path when `row >= 0` (a file row rejects the drop, like the C++
/// `isDir` check), else the pane's current folder. The flag reports whether
/// that directory lives on a remote server.
fn drop_target_dir(
    ui: &crate::ui::main_window::MainWindow,
    pane: usize,
    row: i32,
) -> Option<(String, bool)> {
    let (entries, current, remote) = if pane == 0 {
        (ui.get_left_entries(), ui.get_left_path().to_string(), false)
    } else {
        (
            ui.get_right_entries(),
            ui.get_right_path().to_string(),
            ui.get_remote_connected(),
        )
    };
    if row < 0 {
        return Some((current, remote));
    }
    let entry = entries.row_data(row as usize)?;
    if !entry.is_dir {
        return None;
    }
    let child = if remote {
        join_remote(&current, &entry.name)
    } else {
        join_local(&current, &entry.name)
    };
    Some((child, remote))
}

/// Builds the `(from, to)` rename pairs for a same-session remote→remote drop
/// (port of the C++ `handlePanelDrop` remote branch): entries that would move
/// onto themselves or into their own subtree are skipped, and the skipped
/// count drives the C++ `Drop ignored: nothing to move (%1 skipped)` status.
fn remote_move_renames(seeds: &[(String, bool)], dest_dir: &str) -> (Vec<(String, String)>, usize) {
    let mut renames = Vec::new();
    let mut skipped = 0usize;
    for (from, _is_dir) in seeds {
        let name = from.rsplit('/').next().unwrap_or_default();
        if name.is_empty() || name == ".." {
            skipped += 1;
            continue;
        }
        let to = join_remote(dest_dir, name);
        if *from == to || to.starts_with(&format!("{from}/")) {
            skipped += 1;
            continue;
        }
        renames.push((from.clone(), to));
    }
    (renames, skipped)
}

/// Server-side move (rename) of same-session remote entries: the C++
/// `moveRemoteEntriesOnServer` used by remote-to-remote drag-and-drop. Same-model
/// drops are always moves (`preferredPanelDropAction`), never copies.
fn move_remote_entries_on_server(
    ui: &crate::ui::main_window::MainWindow,
    state: &Rc<RefCell<AppState>>,
    renames: Vec<(String, String)>,
    skipped: usize,
) {
    if renames.is_empty() {
        ui.set_status_text(format!("Drop ignored: nothing to move ({skipped} skipped)").into());
        return;
    }
    let client = {
        let mut st = state.borrow_mut();
        st.client.take()
    };
    let Some(client) = client else {
        ui.set_status_text("Not connected".into());
        return;
    };
    let handle = state.borrow().runtime_handle();
    let tx = state.borrow().ui_event_tx();
    handle.spawn(async move {
        let mut client = client;
        let mut ok = 0usize;
        let mut failed = 0usize;
        for (from, to) in &renames {
            match client.rename(from, to, false).await {
                Ok(()) => ok += 1,
                Err(err) => {
                    tracing::warn!("remote move failed for {from}: {err}");
                    failed += 1;
                }
            }
        }
        if let Some(tx) = &tx {
            let message = if failed == 0 {
                format!("Moved: {ok}")
            } else {
                format!("Moved: {ok}  |  Failed: {failed}")
            };
            let _ = tx.send(UiEvent::Status { message });
            let _ = tx.send(UiEvent::ReloadRemote);
        }
        return_client(&tx, client);
    });
}

/// Port of `MainWindow::handlePanelDrop` for in-app drags: `target_row` is the
/// hovered folder row or `-1` for the pane root, and `move` follows the C++
/// Ctrl/Cmd-at-press rule (except same-session remote→remote, which always
/// moves server-side).
fn handle_pane_drop(
    ui: &crate::ui::main_window::MainWindow,
    state: &Rc<RefCell<AppState>>,
    target_pane: usize,
    target_row: i32,
    move_intent: bool,
) {
    let source_pane = ui.get_drag_source_pane();
    // Only in-app pane drags (external drags cannot carry the selection).
    if source_pane < 0 {
        return;
    }
    let source_pane = if source_pane == 0 { 0usize } else { 1usize };
    let Some((dest_dir, _dest_remote)) = drop_target_dir(ui, target_pane, target_row) else {
        ui.set_status_text("Drop ignored: the target is not a folder".into());
        return;
    };
    let right_is_remote = ui.get_remote_connected();
    let right_is_local = target_pane == 1 && !right_is_remote;
    // A drop inside the right pane while it is remote is a server-side move.
    if source_pane == 1 && target_pane == 1 && right_is_remote {
        let (renames, skipped) = remote_move_renames(&selected_right_seeds(ui), &dest_dir);
        move_remote_entries_on_server(ui, state, renames, skipped);
        return;
    }
    // Remote→remote from the right pane into the left pane is impossible
    // (the left pane is always local), so everything else is local-to-local or
    // a transfer.
    let reload = vec![
        (0usize, ui.get_left_path().to_string()),
        (1usize, ui.get_right_path().to_string()),
    ];
    match (source_pane, target_pane, right_is_local) {
        // Local→local inside either pane.
        (0, 0, _) | (1, 1, true) | (0, 1, true) | (1, 0, true) => {
            let sources: Vec<PathBuf> = if source_pane == 0 {
                selected_left_seeds(ui)
                    .into_iter()
                    .map(|(path, _)| path)
                    .collect()
            } else {
                selected_right_local_seeds(ui)
            };
            if sources.is_empty() {
                ui.set_status_text("No selection to drop".into());
                return;
            }
            // Dropping into the folder the entries already live in is a no-op;
            // `run_local_copy_move` reports it as skipped.
            run_local_copy_move(
                state,
                sources,
                PathBuf::from(&dest_dir),
                move_intent,
                reload,
            );
        }
        (0, 1, false) => queue_uploads_to(ui, state, Some(dest_dir), move_intent),
        (1, 0, false) => queue_downloads_to(ui, state, Some(PathBuf::from(dest_dir)), move_intent),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Overwrite-conflict prompt (Qt Yes / No / Yes to All / No to All)
// ---------------------------------------------------------------------------

/// Serialized overwrite prompt with "apply to all" support. Transfer workers
/// call this from tokio threads; it blocks (like the C++ transfer manager's
/// condition-variable wait) while the Slint `OverwriteDialog` is shown.
fn prompt_overwrite_choice(question: &str) -> transfer::ConflictChoice {
    // Workers run concurrently (max_concurrent > 1); serialize so two tasks
    // never stack two dialogs. The second worker re-checks the sticky policy
    // after the first prompt resolves.
    static PROMPT_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _serial = PROMPT_SERIAL.lock().unwrap_or_else(|e| e.into_inner());

    if let Ok(sticky) = transfer::sticky_conflict().lock() {
        if let Some(policy) = *sticky {
            return policy;
        }
    }

    let (answer_tx, answer_rx) = std::sync::mpsc::sync_channel::<transfer::ConflictChoice>(1);
    type DialogWeak = slint::Weak<crate::ui::overwrite_dialog::OverwriteDialog>;
    let pending: Arc<std::sync::Mutex<Option<DialogWeak>>> = Arc::new(std::sync::Mutex::new(None));
    let question = question.to_string();

    let posted = slint::invoke_from_event_loop({
        let pending = Arc::clone(&pending);
        let answer_tx = answer_tx.clone();
        move || {
            let Ok(dialog) = crate::ui::overwrite_dialog::OverwriteDialog::new() else {
                let _ = answer_tx.send(transfer::ConflictChoice::Skip);
                return;
            };
            dialog.set_message(question.into());
            if let Ok(mut slot) = pending.lock() {
                *slot = Some(dialog.as_weak());
            }
            let weak = dialog.as_weak();
            let answer = |choice: transfer::ConflictChoice| {
                let weak = weak.clone();
                let answer_tx = answer_tx.clone();
                let pending = Arc::clone(&pending);
                move || {
                    if let Some(d) = weak.upgrade() {
                        let _ = d.hide();
                    }
                    if let Ok(mut slot) = pending.lock() {
                        *slot = None;
                    }
                    let _ = answer_tx.send(choice);
                }
            };
            let answer_all = |choice: transfer::ConflictChoice| {
                let weak = weak.clone();
                let answer_tx = answer_tx.clone();
                let pending = Arc::clone(&pending);
                move || {
                    if let Ok(mut slot) = transfer::sticky_conflict().lock() {
                        *slot = Some(choice);
                    }
                    if let Some(d) = weak.upgrade() {
                        let _ = d.hide();
                    }
                    if let Ok(mut slot) = pending.lock() {
                        *slot = None;
                    }
                    let _ = answer_tx.send(choice);
                }
            };
            dialog.on_overwrite(answer(transfer::ConflictChoice::Overwrite));
            dialog.on_skip(answer(transfer::ConflictChoice::Skip));
            dialog.on_overwrite_all(answer_all(transfer::ConflictChoice::OverwriteAll));
            dialog.on_skip_all(answer_all(transfer::ConflictChoice::SkipAll));
            let _ = dialog.show();
        }
    });
    if posted.is_err() {
        return transfer::ConflictChoice::Skip;
    }
    match answer_rx.recv_timeout(Duration::from_secs(120)) {
        Ok(choice) => choice,
        Err(_) => {
            // The user never answered; hide the orphaned dialog (best effort).
            let pending_cleanup = Arc::clone(&pending);
            let _ = slint::invoke_from_event_loop(move || {
                let orphan = pending_cleanup
                    .lock()
                    .ok()
                    .and_then(|mut slot| slot.take())
                    .and_then(|weak| weak.upgrade());
                if let Some(d) = orphan {
                    let _ = d.hide();
                }
            });
            transfer::ConflictChoice::Skip
        }
    }
}

// ---------------------------------------------------------------------------
// About dialog helpers (diagnostics, licenses folder, issue tracker)
// ---------------------------------------------------------------------------

/// Human-readable OS description (`QSysInfo::prettyProductName` in the C++
/// diagnostics text).
fn pretty_os_name() -> String {
    #[cfg(target_os = "macos")]
    if let Ok(output) = std::process::Command::new("sw_vers").output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut name = String::new();
            let mut version = String::new();
            for line in text.lines() {
                if let Some(value) = line.strip_prefix("ProductName:") {
                    name = value.trim().to_string();
                } else if let Some(value) = line.strip_prefix("ProductVersion:") {
                    version = value.trim().to_string();
                }
            }
            if !name.is_empty() {
                return if version.is_empty() {
                    name
                } else {
                    format!("{name} {version}")
                };
            }
        }
    }
    #[cfg(target_os = "linux")]
    if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
                let value = value.trim().trim_matches('"');
                if !value.is_empty() {
                    return value.to_string();
                }
            }
        }
    }
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Version/environment details copied to the clipboard by the About dialog
/// (port of `buildDiagnosticsText` in ui/AboutDialog.cpp).
fn diagnostics_text() -> String {
    let build_type = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    format!(
        "FreeSCP version: {}\n\
         OS: {}\n\
         CPU architecture: {}\n\
         Build type: {}\n\
         Git commit: {}\n\
         Repository: https://github.com/Noxcis/freescp",
        env!("CARGO_PKG_VERSION"),
        pretty_os_name(),
        std::env::consts::ARCH,
        build_type,
        env!("FREESCP_GIT_COMMIT"),
    )
}

/// Locates the third-party licenses directory using the same candidate list
/// and search order as `findLicensesDir` in ui/AboutDialog.cpp (searches up
/// to 5 levels above each base).
fn find_licenses_dir() -> Option<PathBuf> {
    const CANDIDATES: [&str; 9] = [
        "docs/credits/LICENSES",
        "docs/licenses",
        "usr/share/licenses",
        "share/licenses",
        "LICENSES",
        "licenses",
        "Licenses",
        "Resources/licenses",
        "Resources/LICENSES",
    ];
    let mut bases: Vec<PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        bases.push(cwd);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            bases.push(exe_dir.to_path_buf());
            if let Some(parent) = exe_dir.parent() {
                bases.push(parent.to_path_buf());
            }
            bases.push(exe_dir.join("../Resources")); // macOS bundle Resources
        }
    }
    for base in bases {
        let mut dir = base;
        for _ in 0..5 {
            for rel in CANDIDATES {
                let candidate = dir.join(rel);
                if candidate.is_dir() {
                    return Some(candidate);
                }
            }
            if !dir.pop() {
                break;
            }
        }
    }
    None
}

/// Wires the About dialog's action buttons/link (port of the button/link
/// handlers in ui/AboutDialog.cpp).
fn wire_about_dialog(dialog: &crate::ui::about::AboutDialog) {
    dialog.set_version_text(format!("{} (Rust rewrite)", env!("CARGO_PKG_VERSION")).into());
    let licenses_available = find_licenses_dir().is_some();
    dialog.set_licenses_available(licenses_available);
    {
        let weak = dialog.as_weak();
        dialog.on_close_requested(move || {
            if let Some(d) = weak.upgrade() {
                let _ = d.hide();
            }
        });
    }
    {
        let _weak = dialog.as_weak();
        dialog.on_author_link_requested(move || {
            if let Err(err) = local_fs::open_url("https://github.com/luiscuellar31") {
                tracing::warn!("Could not open the author page: {err}");
            }
        });
    }
    {
        let _weak = dialog.as_weak();
        dialog.on_copy_diagnostics_requested(move || {
            let text = diagnostics_text();
            let copied = arboard::Clipboard::new()
                .and_then(|mut clipboard| clipboard.set_text(text))
                .is_ok();
            if copied {
                connect::show_alert(
                    "Diagnostics copied",
                    "Diagnostic information was copied to your clipboard.",
                );
            } else {
                connect::show_alert(
                    "Diagnostics unavailable",
                    "Could not access the system clipboard.",
                );
            }
        });
    }
    {
        let _weak = dialog.as_weak();
        dialog.on_open_licenses_requested(move || match find_licenses_dir() {
            Some(dir) => {
                let path = dir.to_string_lossy().into_owned();
                if local_fs::open_url(&path).is_err() {
                    connect::show_alert(
                        "Licenses folder not found",
                        "No license files were found in this installation.",
                    );
                }
            }
            None => connect::show_alert(
                "Licenses folder not found",
                "No license files were found in this installation.",
            ),
        });
    }
    {
        let _weak = dialog.as_weak();
        dialog.on_report_issue_requested(move || {
            if let Err(err) = local_fs::open_url("https://github.com/Noxcis/freescp/issues") {
                tracing::warn!("Could not open the issue tracker: {err}");
            }
        });
    }
}

/// Enqueues the left selection as uploads into the right pane directory.
/// When `move_after` is set, the local sources are removed once every
/// enqueued task completes successfully (port of the C++ move semantics).
fn queue_uploads(
    ui: &crate::ui::main_window::MainWindow,
    state: &Rc<RefCell<AppState>>,
    move_after: bool,
) {
    queue_uploads_to(ui, state, None, move_after);
}

/// Uploads the left selection into `dest` — the right pane directory when
/// `None`, or an explicit remote folder (drag-and-drop onto a folder row).
fn queue_uploads_to(
    ui: &crate::ui::main_window::MainWindow,
    state: &Rc<RefCell<AppState>>,
    dest: Option<String>,
    move_after: bool,
) {
    let Some(session) = state.borrow().session.clone() else {
        ui.set_status_text("Not connected".into());
        return;
    };
    let dest = dest.unwrap_or_else(|| ui.get_right_path().to_string());
    let seeds = selected_left_seeds(ui);
    if seeds.is_empty() {
        ui.set_status_text("No selection to upload".into());
        return;
    }
    // The writeability cache is refreshed by every remote reload; a fresh
    // "read-only" verdict blocks uploads before anything is queued (port of
    // the C++ drag-and-drop guard).
    if state.borrow_mut().writeability.get(&dest) == Some(false) {
        ui.set_status_text("The remote folder appears to be read-only".into());
        return;
    }
    let handle = state.borrow().runtime_handle();
    let mgr = Arc::clone(&state.borrow().transfer_manager);
    let tx = state.borrow().ui_event_tx();
    let show_queue = state.borrow().prefs.show_queue_on_enqueue;
    let prefs = settings::Preferences::load();
    let confirm_items = prefs.staging_confirm_items.clamp(50, 100_000) as usize;
    let confirm_mib = prefs.staging_confirm_mib.clamp(128, 65_536) as u64;
    let ui_weak = ui.as_weak();

    handle.spawn(async move {
        // Prescan on the blocking pool so the confirmation counts match
        // what will actually be enqueued.
        let mut total_files = 0usize;
        let mut total_bytes = 0u64;
        for (seed, _) in &seeds {
            let seed_path = seed.clone();
            match tokio::task::spawn_blocking(move || transfer::upload_prescan(&seed_path)).await {
                Ok(Ok(scan)) => {
                    total_files += scan.files;
                    total_bytes += scan.bytes;
                }
                Ok(Err(err)) => {
                    tracing::warn!("upload prescan failed for {}: {err}", seed.display())
                }
                Err(err) => tracing::warn!("upload prescan panicked for {}: {err}", seed.display()),
            }
        }
        let mut files: Vec<(PathBuf, PathBuf)> = Vec::new();
        for (seed, is_dir) in &seeds {
            let seed_path = seed.clone();
            let collect_path = seed_path.clone();
            let list = match tokio::task::spawn_blocking(move || {
                transfer::collect_local_files(&collect_path)
            })
            .await
            {
                Ok(Ok(list)) => list,
                Ok(Err(err)) => {
                    tracing::warn!("upload collect failed for {}: {err}", seed_path.display());
                    continue;
                }
                Err(err) => {
                    tracing::warn!("upload collect panicked for {}: {err}", seed_path.display());
                    continue;
                }
            };
            if *is_dir {
                let base_name = seed
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| seed.to_string_lossy().to_string());
                for file in list {
                    let rel = file.strip_prefix(seed).unwrap_or(&file);
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    files.push((file, PathBuf::from(format!("{}/{}", &base_name, rel_str))));
                }
            } else if let Some(file) = list.into_iter().next() {
                let name = file
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "upload".to_string());
                files.push((file, PathBuf::from(name)));
            }
        }
        let expected = files.len();

        let posted = slint::invoke_from_event_loop(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if total_files > confirm_items || total_bytes > confirm_mib * 1024 * 1024 {
                let question = format!(
                    "Upload {total_files} file(s), {} total?",
                    local_fs_format_size(total_bytes)
                );
                let proceed = rfd::MessageDialog::new()
                    .set_title("Confirm upload")
                    .set_description(&question)
                    .set_buttons(rfd::MessageButtons::YesNo)
                    .set_level(rfd::MessageLevel::Info)
                    .show()
                    == rfd::MessageDialogResult::Yes;
                if !proceed {
                    ui.set_status_text("Upload canceled".into());
                    return;
                }
            }
            mgr.set_session_options(Some(session.clone()));
            // A new user-initiated batch resets any remembered "apply to all"
            // overwrite policy (the C++ policy was scoped to one operation).
            transfer::reset_conflict_policy();
            for (source, relative) in &files {
                let target = join_remote(&dest, &relative.to_string_lossy());
                let client = match client_factory::create_client(session.protocol) {
                    Ok(client) => client,
                    Err(err) => {
                        tracing::error!("could not create an upload client: {err}");
                        continue;
                    }
                };
                mgr.enqueue_upload(client, source.to_string_lossy().into_owned(), target, false);
            }
            if move_after {
                if let Some(tx) = &tx {
                    watch_uploads_then_delete_local(
                        Arc::clone(&mgr),
                        expected,
                        seeds.iter().map(|(path, _)| path.clone()).collect(),
                        tx.clone(),
                    );
                }
            }
            if show_queue {
                if let Some(tx) = &tx {
                    let _ = tx.send(UiEvent::ShowQueue);
                }
            }
            ui.set_status_text(format!("Queued {} upload(s)", files.len()).into());
        });
        if posted.is_err() {
            tracing::error!("upload queueing dropped (event loop gone)");
        }
    });
}

/// Watches the upload queue and removes the local sources once every
/// enqueued task settles in `Completed` (partial failure keeps the files,
/// mirroring the C++ "move only on success" rule). The result message ports
/// `Moved OK: %1  |  Failed: %2  |  Skipped: %3` (MainWindowLocalOps.cpp).
fn watch_uploads_then_delete_local(
    mgr: Arc<transfer::TransferManager>,
    expected: usize,
    seeds: Vec<PathBuf>,
    tx: tokio::sync::mpsc::UnboundedSender<UiEvent>,
) {
    tokio::runtime::Handle::current().spawn(async move {
        // Only this batch counts: the queue keeps finished tasks from earlier
        // operations around (the C++ matched `t.src == p.localPath`).
        let batch_tasks = || -> Vec<transfer::TransferTask> {
            mgr.tasks()
                .into_iter()
                .filter(|task| {
                    matches!(task.direction, transfer::TransferDirection::Upload)
                        && seeds.iter().any(|seed| {
                            let source = Path::new(&task.source);
                            source == seed.as_path() || source.starts_with(seed)
                        })
                })
                .collect()
        };
        loop {
            let tasks = batch_tasks();
            let settled = tasks.len() >= expected
                && tasks.iter().all(|task| {
                    matches!(
                        task.state,
                        transfer::TransferState::Completed
                            | transfer::TransferState::Failed
                            | transfer::TransferState::Cancelled
                    )
                });
            if settled {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let tasks = batch_tasks();
        let completed = tasks
            .iter()
            .filter(|task| matches!(task.state, transfer::TransferState::Completed))
            .count();
        let expected = expected.max(tasks.len());
        let mut failed = expected.saturating_sub(completed);
        let mut last_error = tasks.iter().find_map(|task| task.error.clone());
        if failed == 0 {
            // Every upload succeeded: remove the local sources, exactly like
            // the C++ per-file cleanup. A failed removal counts as one failed
            // item and reports the C++ "Could not delete source" wording.
            if let Err(err) = local_fs::delete_batch_async(&seeds, true).await {
                failed += 1;
                last_error = Some(format!("Could not delete source: {err}"));
            }
        }
        // C++ wording (MainWindowLocalOps.cpp: `Moved OK: %1  |  Failed: %2  |  Skipped: %3`).
        let mut message = format!("Moved OK: {completed}  |  Failed: {failed}  |  Skipped: 0");
        if failed > 0 {
            if let Some(err) = last_error {
                message.push_str(&format!("\nLast error: {err}"));
            }
        }
        let _ = tx.send(UiEvent::Status { message });
        if let Some(seed) = seeds.first() {
            let reload_path = parent_of_local(&seed.to_string_lossy())
                .unwrap_or_else(|| seed.to_string_lossy().to_string());
            let _ = tx.send(UiEvent::ReloadLocal { path: reload_path });
        }
    });
}

thread_local! {
    /// Session-remembered download destination, the Rust counterpart of the
    /// C++ `MainWindow::downloadDir_` (seeded from the `UI/defaultDownloadDir`
    /// setting): every Download starts its folder picker here.
    static LAST_DOWNLOAD_DIR: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Prompts for a local download destination folder, porting the picker at the
/// top of the C++ `MainWindow::downloadRightToLeft()`
/// (`ui/MainWindowRemoteOps.cpp:966`): the dialog starts in the remembered
/// `downloadDir_` ([`LAST_DOWNLOAD_DIR`]), then the configured
/// `UI/defaultDownloadDir`, then the user's home directory. Returns `None`
/// when the user cancels or picks a folder that no longer exists (the C++
/// "Invalid destination" warning).
fn download_destination(title: &str) -> Option<PathBuf> {
    let start = LAST_DOWNLOAD_DIR
        .with(|dir| dir.borrow().clone())
        .unwrap_or_else(|| {
            let configured = settings::Preferences::load()
                .default_download_dir
                .trim()
                .to_string();
            if configured.is_empty() {
                local_fs::home_dir()
            } else {
                PathBuf::from(configured)
            }
        });
    let picked = rfd::FileDialog::new()
        .set_title(title)
        .set_directory(&start)
        .pick_folder()?;
    LAST_DOWNLOAD_DIR.with(|dir| *dir.borrow_mut() = Some(picked.clone()));
    if !picked.exists() {
        crate::connect::show_alert("Invalid destination", "Destination folder does not exist.");
        return None;
    }
    Some(picked)
}

/// Enqueues the right selection as downloads into a destination folder picked
/// by the user (the C++ `downloadRightToLeft()` flow; no longer the left pane
/// directory). When `move_after` is set, the remote sources are removed once
/// every enqueued task completes successfully.
fn queue_downloads(
    ui: &crate::ui::main_window::MainWindow,
    state: &Rc<RefCell<AppState>>,
    move_after: bool,
) {
    queue_downloads_to(ui, state, None, move_after);
}

/// Downloads the right selection into `dest` — an explicit local folder when a
/// drag-and-drop ended on one, else a folder picked by the user.
fn queue_downloads_to(
    ui: &crate::ui::main_window::MainWindow,
    state: &Rc<RefCell<AppState>>,
    dest: Option<PathBuf>,
    move_after: bool,
) {
    let Some(session) = state.borrow().session.clone() else {
        ui.set_status_text("Not connected".into());
        return;
    };
    let seeds = selected_right_seeds(ui);
    if seeds.is_empty() {
        ui.set_status_text("No selection to download".into());
        return;
    }
    let Some(dest) = dest.or_else(|| download_destination("Select destination folder (local)"))
    else {
        return;
    };
    let dest = dest.to_string_lossy().into_owned();
    let client = {
        let mut st = state.borrow_mut();
        st.client.take()
    };
    let Some(client) = client else {
        ui.set_status_text("Not connected".into());
        return;
    };
    let handle = state.borrow().runtime_handle();
    let mgr = Arc::clone(&state.borrow().transfer_manager);
    let tx = state.borrow().ui_event_tx();
    let show_queue = state.borrow().prefs.show_queue_on_enqueue;
    let prefs = settings::Preferences::load();
    let confirm_items = prefs.staging_confirm_items.clamp(50, 100_000) as usize;
    let confirm_mib = prefs.staging_confirm_mib.clamp(128, 65_536) as u64;
    let ui_weak = ui.as_weak();

    handle.spawn(async move {
        let mut client = client;
        // Prescan first (it also creates the local directory structure the
        // collect pass mirrors), so the confirmation counts match the queue.
        let plan = match transfer::download_prescan(&mut *client, &seeds, Path::new(&dest)).await {
            Ok(plan) => plan,
            Err(err) => {
                tracing::warn!("download prescan failed: {err}");
                transfer::DownloadPlan::default()
            }
        };
        let files =
            match transfer::collect_remote_files(&mut *client, &seeds, Path::new(&dest)).await {
                Ok(files) => files,
                Err(err) => {
                    tracing::warn!("download collect failed: {err}");
                    Vec::new()
                }
            };
        let expected = files.len();
        let total_files = plan.files;
        let total_bytes = plan.bytes;

        let posted = slint::invoke_from_event_loop(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if total_files > confirm_items || total_bytes > confirm_mib * 1024 * 1024 {
                let question = format!(
                    "Download {total_files} file(s), {} total?",
                    local_fs_format_size(total_bytes)
                );
                let proceed = rfd::MessageDialog::new()
                    .set_title("Confirm download")
                    .set_description(&question)
                    .set_buttons(rfd::MessageButtons::YesNo)
                    .set_level(rfd::MessageLevel::Info)
                    .show()
                    == rfd::MessageDialogResult::Yes;
                if !proceed {
                    ui.set_status_text("Download canceled".into());
                    if let Some(tx) = &tx {
                        let _ = tx.send(UiEvent::ReturnClient(client));
                    }
                    return;
                }
            }
            mgr.set_session_options(Some(session.clone()));
            // A new user-initiated batch resets any remembered "apply to all"
            // overwrite policy (the C++ policy was scoped to one operation).
            transfer::reset_conflict_policy();
            for (remote_path, local_dest) in &files {
                let client = match client_factory::create_client(session.protocol) {
                    Ok(client) => client,
                    Err(err) => {
                        tracing::error!("could not create a download client: {err}");
                        continue;
                    }
                };
                mgr.enqueue_download(
                    client,
                    remote_path.clone(),
                    local_dest.to_string_lossy().into_owned(),
                    false,
                );
            }
            if move_after {
                if let Some(tx) = &tx {
                    watch_downloads_then_delete_remote(
                        Arc::clone(&mgr),
                        expected,
                        session.clone(),
                        seeds.iter().map(|(path, _)| path.clone()).collect(),
                        tx.clone(),
                    );
                }
            }
            if show_queue {
                if let Some(tx) = &tx {
                    let _ = tx.send(UiEvent::ShowQueue);
                }
            }
            ui.set_status_text(format!("Queued {} download(s)", files.len()).into());
            if let Some(tx) = &tx {
                let _ = tx.send(UiEvent::ReturnClient(client));
            }
        });
        if posted.is_err() {
            tracing::error!("download queueing dropped (event loop gone)");
        }
    });
}

/// Watches the download queue and removes the remote sources (via a fresh
/// session connection) once every enqueued task settles in `Completed`.
fn watch_downloads_then_delete_remote(
    mgr: Arc<transfer::TransferManager>,
    expected: usize,
    session: SessionOptions,
    seeds: Vec<String>,
    tx: tokio::sync::mpsc::UnboundedSender<UiEvent>,
) {
    tokio::runtime::Handle::current().spawn(async move {
        loop {
            let tasks = mgr.tasks();
            let settled = tasks.len() >= expected
                && tasks.iter().all(|task| {
                    matches!(
                        task.state,
                        transfer::TransferState::Completed
                            | transfer::TransferState::Failed
                            | transfer::TransferState::Cancelled
                    )
                });
            if settled {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let all_ok = mgr.tasks().len() >= expected
            && mgr
                .tasks()
                .iter()
                .all(|task| matches!(task.state, transfer::TransferState::Completed));
        if !all_ok {
            let _ = tx.send(UiEvent::Status {
                message: "Move aborted: some downloads failed; remote files were kept".to_string(),
            });
            return;
        }
        match client_factory::create_connected_client(&session).await {
            Ok(mut client) => {
                let mut deleted = 0usize;
                for seed in &seeds {
                    let parent = remote::parent_remote_path(seed);
                    let Some(name) = seed.rsplit('/').next().filter(|n| !n.is_empty()) else {
                        continue;
                    };
                    match remote::delete_entries(
                        &mut *client,
                        &parent,
                        &[(name.to_string(), true)],
                        true,
                    )
                    .await
                    {
                        Ok(n) => deleted += n,
                        Err(err) => {
                            let _ = tx.send(UiEvent::Status {
                                message: format!(
                                    "Could not remove the remote source after move: {err}"
                                ),
                            });
                        }
                    }
                }
                let _ = tx.send(UiEvent::Status {
                    message: format!("Moved {deleted} item(s) locally"),
                });
            }
            Err(err) => {
                let _ = tx.send(UiEvent::Status {
                    message: format!(
                        "Could not reconnect to remove the remote source after move: {err}"
                    ),
                });
            }
        }
        let _ = tx.send(UiEvent::ReloadRemote);
    });
}

// ---------------------------------------------------------------------------
// Session health.
// ---------------------------------------------------------------------------

/// Probes the current remote directory with the active client; a
/// transport-level failure surfaces on the status line (the reconnect half
/// of the C++ monitor is intentionally out of scope — see
/// `remote::ensure_session_healthy`).
fn check_session_health(ui: &crate::ui::main_window::MainWindow, state: &Rc<RefCell<AppState>>) {
    if state.borrow().client.is_none() {
        return;
    }
    let path = ui.get_right_path().to_string();
    let client = {
        let mut st = state.borrow_mut();
        st.client.take()
    };
    let Some(client) = client else { return };
    let handle = state.borrow().runtime_handle();
    let tx = state.borrow().ui_event_tx();
    handle.spawn(async move {
        let mut client = client;
        let result = remote::ensure_session_healthy(&mut *client, &path).await;
        if let Err(err) = &result {
            let message = if remote::is_likely_transport_error(err) {
                "Session health check failed: the connection appears to be lost".to_string()
            } else {
                format!("Session health check failed: {err}")
            };
            if let Some(tx) = &tx {
                let _ = tx.send(UiEvent::Status { message });
            }
        }
        if let Some(tx) = &tx {
            let _ = tx.send(UiEvent::ReturnClient(client));
        }
    });
}

/// Tick closure of the session-health monitor, shared with the timer so the
/// interval can be retargeted in place.
type SessionHealthTick = Rc<dyn Fn()>;

thread_local! {
    /// Live session-health monitor: the timer plus its tick closure, kept so
    /// applying Settings can retarget the interval the way the C++
    /// `applyPreferences` calls `m_remoteSessionHealthTimer_->setInterval`.
    static SESSION_HEALTH_MONITOR: std::cell::RefCell<Option<(Timer, SessionHealthTick)>> =
        const { std::cell::RefCell::new(None) };
}

/// Clamps a configured session-health interval to the C++ range (60 s .. 1 d).
fn session_health_interval(secs: i64) -> Duration {
    Duration::from_secs(secs.clamp(60, 86_400) as u64)
}

/// Starts the session-health monitor (replacing any previous one).
pub(crate) fn start_session_health_timer(
    ui: &crate::ui::main_window::MainWindow,
    state: &Rc<RefCell<AppState>>,
    interval_sec: i64,
) {
    let ui_weak = ui.as_weak();
    let state = Rc::clone(state);
    let tick: SessionHealthTick = Rc::new(move || {
        if let Some(ui) = ui_weak.upgrade() {
            check_session_health(&ui, &state);
        }
    });
    SESSION_HEALTH_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        if let Some((timer, _)) = monitor.as_ref() {
            timer.stop();
        }
        let timer = Timer::default();
        {
            let tick = Rc::clone(&tick);
            timer.start(
                TimerMode::Repeated,
                session_health_interval(interval_sec),
                move || tick(),
            );
        }
        *monitor = Some((timer, tick));
    });
}

/// Retargets the running monitor with a new interval (no-op when the monitor
/// has not been started yet).
pub(crate) fn retarget_session_health_timer(interval_sec: i64) {
    SESSION_HEALTH_MONITOR.with(|monitor| {
        let monitor = monitor.borrow();
        let Some((timer, tick)) = monitor.as_ref() else {
            return;
        };
        timer.stop();
        let tick = Rc::clone(tick);
        timer.start(
            TimerMode::Repeated,
            session_health_interval(interval_sec),
            move || tick(),
        );
    });
}

/// Stops the monitor (shutdown).
fn stop_session_health_timer() {
    SESSION_HEALTH_MONITOR.with(|monitor| {
        if let Some((timer, _)) = monitor.borrow_mut().take() {
            timer.stop();
        }
    });
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

/// Resolve the gettext catalogs directory: the dev tree first, then the
/// macOS app bundle (Contents/Resources/translations).
fn translations_dir() -> std::path::PathBuf {
    let dev = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("translations");
    if dev.is_dir() {
        return dev;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(bundle_resources) = exe
            .parent()
            .and_then(|macos| macos.parent())
            .map(|contents| contents.join("Resources").join("translations"))
        {
            if bundle_resources.is_dir() {
                return bundle_resources;
            }
        }
    }
    dev
}

/// POSIX locale names tried, in order, before `LANGUAGE` can select a catalog.
///
/// GNU gettext ignores `LANGUAGE` while the process locale is `C`/`POSIX`/
/// `C.*`: the app would silently stay English when started without a locale in
/// the environment (a Finder-launched .app, launchd, some terminals). Setting
/// `LC_ALL` to a real locale fixes that; the language part of the locale is
/// then overridden by `LANGUAGE`, so any existing locale would do — the
/// language-specific names are just the nicer choice.
fn locale_candidates(language: &str) -> Vec<String> {
    let base = language
        .split(['_', '-', '.'])
        .next()
        .unwrap_or_default()
        .to_lowercase();
    let mut candidates: Vec<String> = match base.as_str() {
        "de" => vec!["de_DE.UTF-8".into(), "de_DE".into()],
        "es" => vec!["es_ES.UTF-8".into(), "es_ES".into()],
        "fr" => vec!["fr_FR.UTF-8".into(), "fr_FR".into()],
        "pt" => vec![
            "pt_PT.UTF-8".into(),
            "pt_BR.UTF-8".into(),
            "pt_PT".into(),
            "pt_BR".into(),
        ],
        _ => Vec::new(),
    };
    // Fallback: a real locale only there to make `LANGUAGE` effective.
    candidates.push("en_US.UTF-8".into());
    candidates.push("en_US.utf8".into());
    candidates
}

/// Applies the first candidate locale the C library accepts and mirrors it
/// into `LC_ALL`, so the `setlocale("")` inside Slint's `init_translations!`
/// re-reads the same locale instead of dropping back to `C`.
#[cfg(unix)]
fn install_ui_locale(language: &str) {
    for candidate in locale_candidates(language) {
        if gettextrs::setlocale(gettextrs::LocaleCategory::LcAll, candidate.as_str()).is_some() {
            std::env::set_var("LC_ALL", &candidate);
            return;
        }
    }
    tracing::warn!("no usable locale for UI language {language:?}; staying in the source language");
}

/// Non-Unix targets do not use the gettext catalogs (`slint`'s gettext feature
/// is Unix-only), so there is no locale to install.
#[cfg(not(unix))]
fn install_ui_locale(_language: &str) {}

// ---------------------------------------------------------------------------
// Startup staging cleanup
// ---------------------------------------------------------------------------

/// `yyyyMMdd-HHmmss` batch-directory names (C++ regex `^\d{8}-\d{6}$`).
fn is_staging_batch_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 15
        && bytes[8] == b'-'
        && bytes[..8].iter().all(u8::is_ascii_digit)
        && bytes[9..].iter().all(u8::is_ascii_digit)
}

/// Deferred startup purge of stale drag-out staging batches (port of the
/// `QTimer::singleShot(0, ...)` block in `MainWindow`'s constructor).
///
/// Runs only when `Advanced/autoCleanStaging` is set; removes
/// `yyyyMMdd-HHmmss` directories whose mtime is older than
/// `Advanced/stagingRetentionDays` (clamped 1..=365) without following
/// symlinks.
fn cleanup_staging_root(prefs: &settings::Preferences) {
    if !prefs.auto_clean_staging {
        return;
    }
    let configured = prefs.staging_root.trim();
    let root = if configured.is_empty() {
        settings::default_staging_root()
    } else {
        PathBuf::from(configured)
    };
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    let retention_days = prefs.staging_retention_days.clamp(1, 365) as u64;
    let max_age = Duration::from_secs(retention_days * 24 * 60 * 60);
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_staging_batch_name(name) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() || !file_type.is_dir() {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
            continue;
        };
        let is_stale = now
            .duration_since(modified)
            .map(|age| age > max_age)
            .unwrap_or(false);
        if is_stale {
            let path = entry.path();
            match std::fs::remove_dir_all(&path) {
                Ok(()) => tracing::info!("removed stale staging batch {}", path.display()),
                Err(err) => tracing::warn!(
                    "could not remove stale staging batch {}: {err}",
                    path.display()
                ),
            }
        }
    }
}

fn main() -> Result<(), slint::PlatformError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // First run: pull in any OpenSCP-era config (preferences, sites, window
    // state) before anything reads the FreeSCP store. Keychain secrets are
    // migrated lazily on first read (secrets::migrate_legacy_secret).
    settings::import_legacy_config_dir();

    // Port of ui/main.cpp: the `UI/language` preference picks the catalog
    // ("en" is the source language, so nothing needs to be loaded). The
    // system locale is not consulted for the app strings.
    let language = settings::Preferences::load().language.trim().to_lowercase();
    let language = if language.is_empty() {
        sys_locale::get_locale().unwrap_or_else(|| "en".to_string())
    } else {
        language
    };
    std::env::set_var("LANGUAGE", &language);
    // `LANGUAGE` alone is not enough: gettext ignores it in the C locale, so
    // the app also installs a real locale for the selected language.
    install_ui_locale(&language);
    // Translation catalogs (generated from the legacy Qt .ts files by
    // scripts/convert_translations.sh). Look in the dev tree first, then in
    // the macOS app bundle (Contents/Resources/translations).
    slint::init_translations!(translations_dir());

    let state = Rc::new(RefCell::new(AppState::new()));
    let ui = crate::ui::main_window::MainWindow::new()?;
    state.borrow_mut().attach_ui(ui.as_weak());

    // UI-event channel: worker threads post `UiEvent`s; the `spawn_local`
    // loop below drains them on the UI thread.
    let (ui_tx, mut ui_rx) = tokio::sync::mpsc::unbounded_channel::<UiEvent>();
    state.borrow_mut().attach_ui_events(ui_tx.clone());

    // Formatting bridges: Slint has no string formatting, so the file lists
    // ask Rust for display strings.
    ui.on_format_size(|bytes: i32| format_size(bytes));
    ui.on_format_size_remote(|bytes: i32| {
        crate::local_fs::format_size_remote(bytes.max(0) as u64).into()
    });
    ui.on_format_mtime(|unix_secs: i32| format_mtime(unix_secs));
    ui.on_format_permissions(|mode: i32| format_permissions(mode));

    // Initial UI state (defaults match, set explicitly for clarity).
    ui.set_status_text("Ready".into());
    ui.set_connection_type_text("Type: None".into());
    ui.set_connection_elapsed_text("Session: --:--:--".into());
    ui.set_risk_banner_visible(false);
    ui.set_remote_connected(false);
    ui.set_scp_panel_visible(false);
    ui.set_single_click_mode(state.borrow().prefs.single_click);
    ui.set_title_text(
        crate::connect::tr("FreeSCP — local/local (click Connect for remote)", &[]).into(),
    );
    ui.set_is_macos(cfg!(target_os = "macos"));
    ui.set_secrets_warning_visible(secrets::insecure_fallback_active());
    apply_shortcut_prefs(&ui, &settings::Preferences::load());

    // Restore the persisted window geometry.
    restore_window_geometry(&ui, &state);

    // Transfer-manager hooks: refresh the remote pane after uploads,
    // surface completion notifications on the status line, and ask the user
    // about overwrite conflicts (posted back to the UI thread).
    {
        let mgr = Arc::clone(&state.borrow().transfer_manager);
        let hook_tx = ui_tx.clone();
        mgr.set_refresh_hook(Some(Arc::new(move || {
            let _ = hook_tx.send(UiEvent::ReloadRemote);
        })));
    }
    {
        let mgr = Arc::clone(&state.borrow().transfer_manager);
        let hook_tx = ui_tx.clone();
        mgr.set_notify_hook(Some(Arc::new(move |message: String| {
            let _ = hook_tx.send(UiEvent::Status { message });
        })));
    }
    {
        let mgr = Arc::clone(&state.borrow().transfer_manager);
        mgr.set_conflict_hook(Some(Arc::new(|info: transfer::ConflictInfo| {
            let question = match info.direction {
                transfer::TransferDirection::Upload => format!(
                    "File \"{}\" already exists on the server.\n\nLocal: {}\nRemote: {}\n\nOverwrite?",
                    info.name, info.source_info, info.dest_info
                ),
                transfer::TransferDirection::Download => format!(
                    "File \"{}\" already exists locally.\n\nRemote: {}\nLocal: {}\n\nOverwrite?",
                    info.name, info.source_info, info.dest_info
                ),
            };
            prompt_overwrite_choice(&question)
        })));
    }

    // ---- UI event loop ------------------------------------------------------

    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        let _ = slint::spawn_local(async move {
            while let Some(event) = ui_rx.recv().await {
                let Some(ui) = ui_weak.upgrade() else {
                    break;
                };
                match event {
                    UiEvent::Session { opt, client } => {
                        let opt = *opt;
                        let scp_only = opt.protocol == Protocol::Scp
                            && opt.scp_transfer_mode == ScpTransferMode::ScpOnly;
                        let no_verify = opt.known_hosts_policy == KnownHostsPolicy::Off;
                        {
                            let mut st = state.borrow_mut();
                            st.session = Some(opt.clone());
                            st.client = Some(client);
                            st.connection_started_at = Some(std::time::Instant::now());
                            st.session_no_host_verification = no_verify;
                            st.transfer_manager.set_session_options(Some(opt.clone()));
                            st.writeability.clear();
                            st.push_recent_server(&opt);
                        }
                        ui.set_remote_connected(true);
                        // The right pane no longer browses a local folder.
                        stop_local_watcher(1);
                        // Permissions are only meaningful for protocols with
                        // a metadata/chmod contract (SSH family, FTP).
                        ui.set_right_supports_permissions(
                            capabilities_for_protocol(opt.protocol).supports_permissions,
                        );
                        ui.set_scp_panel_visible(scp_only);
                        ui.set_right_path("/".into());
                        ui.set_title_text(
                            crate::connect::tr(
                                "FreeSCP — local/remote (%1)",
                                std::slice::from_ref(
                                    &protocol_display_name(opt.protocol).to_string(),
                                ),
                            )
                            .into(),
                        );
                        request_remote_reload(&ui, &state);
                    }
                    UiEvent::ReloadLocal { path } => reload_local(&ui, &state, &path),
                    UiEvent::ReloadRightLocal { path } => reload_right_local(&ui, &state, &path),
                    UiEvent::LocalDirChanged { pane, path } => {
                        // The watcher may have fired for a directory the user
                        // already navigated away from; ignore stale events.
                        let current = if pane == 0 {
                            ui.get_left_path().to_string()
                        } else if right_pane_is_local(&ui) {
                            ui.get_right_path().to_string()
                        } else {
                            String::new()
                        };
                        if current == path {
                            if pane == 0 {
                                reload_local(&ui, &state, &path);
                            } else {
                                reload_right_local(&ui, &state, &path);
                            }
                        }
                    }
                    UiEvent::ReloadRemote => request_remote_reload(&ui, &state),
                    UiEvent::ShowQueue => {
                        let mgr = Arc::clone(&state.borrow().transfer_manager);
                        transfer::open_queue_dialog(&ui, mgr);
                    }
                    UiEvent::NavigateRemote { path } => {
                        let normalized = normalize_remote_path(&path);
                        state
                            .borrow_mut()
                            .push_recent_remote_path(normalized.clone());
                        ui.set_right_path(normalized.clone().into());
                        request_remote_reload(&ui, &state);
                    }
                    UiEvent::Status { message } => state.borrow().set_status(&message),
                    UiEvent::InvalidateWriteability { dir } => {
                        state.borrow_mut().writeability.invalidate(&dir);
                    }
                    UiEvent::ReturnClient(client) => {
                        let mut st = state.borrow_mut();
                        if st.client.is_none() {
                            st.client = Some(client);
                        }
                    }
                }
            }
        });
    }

    // ---- main toolbar -------------------------------------------------------

    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_connect_requested(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            connect::open(&ui, &state.borrow());
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_disconnect_requested(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let client = {
                let mut st = state.borrow_mut();
                st.session = None;
                let client = st.client.take();
                st.connection_started_at = None;
                st.session_no_host_verification = false;
                client
            };
            connect::reset_indicators(&state.borrow());
            // C++ disconnectSftp() calls transferMgr_->clearClient(), stopping
            // the active transfers before the session goes away.
            state.borrow().transfer_manager.cancel_all();
            if let Some(mut client) = client {
                let handle = state.borrow().runtime_handle();
                handle.spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(5), client.disconnect()).await;
                });
            }
            // Parked permission dialogs belong to the closed session.
            PERMISSION_FLOWS.with(|flows| {
                for (flow, _, _) in flows.borrow_mut().drain(..) {
                    flow.dismiss();
                }
            });
            ui.set_remote_connected(false);
            ui.set_scp_panel_visible(false);
            ui.set_connection_type_text("Type: None".into());
            ui.set_connection_elapsed_text("Session: --:--:--".into());
            ui.set_risk_banner_visible(false);
            ui.set_secrets_warning_visible(secrets::insecure_fallback_active());
            ui.set_title_text(crate::connect::tr("FreeSCP — local/local", &[]).into());
            // C++ disconnectSftp() puts the right pane back on the local
            // model at its previous root.
            let local_root = state
                .borrow()
                .right_local_path
                .clone()
                .unwrap_or_else(|| local_fs::home_dir().to_string_lossy().to_string());
            reload_right_local(&ui, &state, &local_root);
            state.borrow().set_status("Disconnected");
            if state.borrow().prefs.open_site_manager_on_disconnect {
                site_manager::open(&ui, &state.borrow());
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_upload_requested(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            queue_uploads(&ui, &state, false);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_download_requested(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            queue_downloads(&ui, &state, false);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_copy_left_to_right(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if right_pane_is_local(&ui) {
                let sources: Vec<PathBuf> = selected_left_seeds(&ui)
                    .into_iter()
                    .map(|(path, _)| path)
                    .collect();
                if sources.is_empty() {
                    crate::connect::show_alert("Copy", "No entries selected in the left panel.");
                    return;
                }
                let dest = PathBuf::from(ui.get_right_path().to_string());
                let reload = vec![
                    (0usize, ui.get_left_path().to_string()),
                    (1usize, ui.get_right_path().to_string()),
                ];
                run_local_copy_move(&state, sources, dest, false, reload);
                return;
            }
            queue_uploads(&ui, &state, false);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_copy_right_to_left(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if right_pane_is_local(&ui) {
                let sources = selected_right_local_seeds(&ui);
                if sources.is_empty() {
                    crate::connect::show_alert("Copy", "No entries selected in the right panel.");
                    return;
                }
                let dest = PathBuf::from(ui.get_left_path().to_string());
                let reload = vec![
                    (0usize, ui.get_left_path().to_string()),
                    (1usize, ui.get_right_path().to_string()),
                ];
                run_local_copy_move(&state, sources, dest, false, reload);
                return;
            }
            queue_downloads(&ui, &state, false);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_move_left_to_right(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if right_pane_is_local(&ui) {
                let sources: Vec<PathBuf> = selected_left_seeds(&ui)
                    .into_iter()
                    .map(|(path, _)| path)
                    .collect();
                if sources.is_empty() {
                    crate::connect::show_alert("Move", "No entries selected in the left panel.");
                    return;
                }
                let confirmed = rfd::MessageDialog::new()
                    .set_title("Confirm move")
                    .set_description(
                        "This will move the selected items to the right panel.\nContinue?",
                    )
                    .set_buttons(rfd::MessageButtons::YesNo)
                    .set_level(rfd::MessageLevel::Warning)
                    .show()
                    == rfd::MessageDialogResult::Yes;
                if !confirmed {
                    ui.set_status_text("Move canceled".into());
                    return;
                }
                let dest = PathBuf::from(ui.get_right_path().to_string());
                let reload = vec![
                    (0usize, ui.get_left_path().to_string()),
                    (1usize, ui.get_right_path().to_string()),
                ];
                run_local_copy_move(&state, sources, dest, true, reload);
                return;
            }
            // Qt-style "Confirm move" (MainWindowLocalOps.cpp: moveLeftToRight)
            // before an upload-and-delete move.
            let confirmed = rfd::MessageDialog::new()
                .set_title("Confirm move")
                .set_description(
                    "This will upload to the server and delete the local source.\nContinue?",
                )
                .set_buttons(rfd::MessageButtons::YesNo)
                .set_level(rfd::MessageLevel::Warning)
                .show()
                == rfd::MessageDialogResult::Yes;
            if !confirmed {
                ui.set_status_text("Move canceled".into());
                return;
            }
            queue_uploads(&ui, &state, true);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_move_right_to_left(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if right_pane_is_local(&ui) {
                let sources = selected_right_local_seeds(&ui);
                if sources.is_empty() {
                    crate::connect::show_alert("Move", "No entries selected in the right panel.");
                    return;
                }
                let confirmed = rfd::MessageDialog::new()
                    .set_title("Confirm move")
                    .set_description(
                        "This will move the selected items to the left panel.\nContinue?",
                    )
                    .set_buttons(rfd::MessageButtons::YesNo)
                    .set_level(rfd::MessageLevel::Warning)
                    .show()
                    == rfd::MessageDialogResult::Yes;
                if !confirmed {
                    ui.set_status_text("Move canceled".into());
                    return;
                }
                let dest = PathBuf::from(ui.get_left_path().to_string());
                let reload = vec![
                    (0usize, ui.get_left_path().to_string()),
                    (1usize, ui.get_right_path().to_string()),
                ];
                run_local_copy_move(&state, sources, dest, true, reload);
                return;
            }
            queue_downloads(&ui, &state, true);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_show_sites(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            site_manager::open(&ui, &state.borrow());
        });
    }
    {
        // Keep strong references so the modeless dialog stays alive.
        let open_dialogs: Rc<RefCell<Vec<crate::ui::main_window::HistoryDialog>>> =
            Rc::new(RefCell::new(Vec::new()));
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_show_history(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Ok(dialog) = crate::ui::main_window::HistoryDialog::new() else {
                tracing::error!("failed to instantiate HistoryDialog");
                return;
            };
            crate::remote::center_window_over(&ui, dialog.window());

            // Populate the three tabs (newest first, like the C++ lists).
            let locals: Vec<SharedString> = history::recent_local_paths()
                .into_iter()
                .map(SharedString::from)
                .collect();
            let remotes: Vec<SharedString> = history::recent_remote_paths()
                .into_iter()
                .map(SharedString::from)
                .collect();
            let servers = history::recent_servers_with_labels();
            let server_labels: Vec<SharedString> = servers
                .iter()
                .map(|(_opt, label)| SharedString::from(label.clone()))
                .collect();
            dialog.set_local_paths(Rc::new(VecModel::from(locals)).into());
            dialog.set_remote_paths(Rc::new(VecModel::from(remotes)).into());
            dialog.set_servers(Rc::new(VecModel::from(server_labels)).into());
            dialog.set_local_selected(-1);
            dialog.set_remote_selected(-1);
            dialog.set_server_selected(-1);
            dialog.set_active_tab(0);

            let ui_weak = ui_weak.clone();
            let state = state.clone();
            let servers = servers.clone();
            let dialog_open = dialog.clone_strong();
            let dialog_weak = dialog_open.as_weak();
            dialog_open.on_open_selected(move || {
                let Some(dialog_open) = dialog_weak.upgrade() else { return };
                let Some(ui) = ui_weak.upgrade() else { return };
                match dialog_open.get_active_tab() {
                    0 => {
                        let Some(idx) = usize::try_from(dialog_open.get_local_selected()).ok() else {
                            return;
                        };
                        let Some(path) = dialog_open.get_local_paths().row_data(idx) else {
                            return;
                        };
                        let state = state.clone();
                        reload_local(&ui, &state, &path);
                    }
                    1 => {
                        let Some(idx) = usize::try_from(dialog_open.get_remote_selected()).ok() else {
                            return;
                        };
                        let Some(path) = dialog_open.get_remote_paths().row_data(idx) else {
                            return;
                        };
                        {
                            let st = state.borrow();
                            if st.client.is_none() {
                                st.set_status(
                                    "Connect to a remote server to open remote path history.",
                                );
                                return;
                            }
                        }
                        let normalized = normalize_remote_path(&path);
                        ui.set_right_path(normalized.clone().into());
                        state.borrow_mut().push_recent_remote_path(normalized);
                        let state = state.clone();
                        request_remote_reload(&ui, &state);
                    }
                    2 => {
                        let Some(idx) = usize::try_from(dialog_open.get_server_selected()).ok() else {
                            return;
                        };
                        let Some(opt) = servers.get(idx).map(|(opt, _label)| opt.clone()) else {
                            return;
                        };
                        let st = state.borrow_mut();
                        if st.client.is_some() {
                            st.set_status(
                                "Disconnect the current remote session before opening another server.",
                            );
                            return;
                        }
                        connect::start_connect(&st, opt);
                    }
                    _ => return,
                }
                let _ = dialog_open.hide();
            });
            {
                let dialog_clear = dialog.clone_strong();
                let dialog_clear_weak = dialog_clear.as_weak();
                dialog_clear.on_clear_history(move || {
                    let Some(dialog_clear) = dialog_clear_weak.upgrade() else {
                        return;
                    };
                    let confirmed = rfd::MessageDialog::new()
                        .set_title("Clear history")
                        .set_description("Clear all history entries?")
                        .set_buttons(rfd::MessageButtons::YesNo)
                        .set_level(rfd::MessageLevel::Warning)
                        .show()
                        == rfd::MessageDialogResult::Yes;
                    if !confirmed {
                        return;
                    }
                    match history::clear_history() {
                        Ok(()) => {
                            dialog_clear.set_local_paths(Rc::new(VecModel::default()).into());
                            dialog_clear.set_remote_paths(Rc::new(VecModel::default()).into());
                            dialog_clear.set_servers(Rc::new(VecModel::default()).into());
                            dialog_clear.set_local_selected(-1);
                            dialog_clear.set_remote_selected(-1);
                            dialog_clear.set_server_selected(-1);
                        }
                        Err(err) => {
                            tracing::warn!("Could not clear history: {err}");
                        }
                    }
                });
            }
            let _ = dialog.show();
            open_dialogs.borrow_mut().push(dialog);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_show_queue(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let mgr = Arc::clone(&state.borrow().transfer_manager);
            transfer::open_queue_dialog(&ui, mgr);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_show_settings(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            settings::open(&ui, &state);
            // Shortcuts and the secrets-fallback warning may have changed.
            apply_shortcut_prefs(&ui, &settings::Preferences::load());
            ui.set_secrets_warning_visible(secrets::insecure_fallback_active());
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_quit_requested(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            capture_window_geometry(&ui, &state);
            let _ = slint::quit_event_loop();
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_report_bug_requested(move || {
            let Some(_ui) = ui_weak.upgrade() else { return };
            if let Err(err) = local_fs::open_url("https://github.com/Noxcis/freescp/issues") {
                tracing::warn!("Could not open the issue tracker: {err}");
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_fullscreen_toggle_requested(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let fullscreen = ui.window().is_fullscreen();
            ui.window().set_fullscreen(!fullscreen);
        });
    }
    {
        // Keep a strong reference so the modeless dialog stays alive
        // (mirrors the C++ non-modal AboutDialog).
        let open_dialogs: Rc<RefCell<Vec<Rc<crate::ui::about::AboutDialog>>>> =
            Rc::new(RefCell::new(Vec::new()));
        ui.on_show_about(move || {
            let Ok(dialog) = crate::ui::about::AboutDialog::new() else {
                return;
            };
            wire_about_dialog(&dialog);
            let _ = dialog.show();
            open_dialogs.borrow_mut().push(Rc::new(dialog));
        });
    }

    // ---- left pane (local) --------------------------------------------------

    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_go_up_left(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let current = ui.get_left_path().to_string();
            let Some(parent) = parent_of_local(&current) else {
                return;
            };
            reload_local(&ui, &state, &parent);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_go_home_left(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            reload_local(&ui, &state, &local_fs::home_dir().to_string_lossy());
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_choose_left_dir(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            // Blocking native folder picker (mirrors the C++ modal
            // QFileDialog::getExistingDirectory, which starts in the current
            // left-pane folder).
            let current = ui.get_left_path().to_string();
            let mut picker = rfd::FileDialog::new();
            if !current.is_empty() && Path::new(&current).is_dir() {
                picker = picker.set_directory(&current);
            }
            if let Some(dir) = picker.pick_folder() {
                reload_local(&ui, &state, &dir.to_string_lossy());
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_left_path_entered(move |path: SharedString| {
            let Some(ui) = ui_weak.upgrade() else { return };
            // C++ setLeftRoot refuses invalid paths and keeps the current
            // folder ("Invalid path" / "Folder does not exist.").
            if !local_fs::is_valid_local_path(Path::new(path.as_str())) {
                crate::connect::show_alert("Invalid path", "Folder does not exist.");
                return;
            }
            reload_local(&ui, &state, &path);
        });
    }
    {
        // Path-field recent-path dropdowns (recent local folders for the left
        // pane; recent remote folders for the right pane once connected).
        let ui_weak = ui.as_weak();
        ui.on_left_recent_paths_requested(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let paths: Vec<SharedString> = history::recent_local_paths()
                .into_iter()
                .take(RECENT_PATH_MENU_LIMIT)
                .map(SharedString::from)
                .collect();
            ui.set_left_recent_paths(Rc::new(VecModel::from(paths)).into());
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_left_recent_path_chosen(move |path: SharedString| {
            let Some(ui) = ui_weak.upgrade() else { return };
            reload_local(&ui, &state, &path);
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_right_recent_paths_requested(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let paths: Vec<SharedString> = history::recent_remote_paths()
                .into_iter()
                .take(RECENT_PATH_MENU_LIMIT)
                .map(SharedString::from)
                .collect();
            ui.set_right_recent_paths(Rc::new(VecModel::from(paths)).into());
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_right_recent_path_chosen(move |path: SharedString| {
            let Some(ui) = ui_weak.upgrade() else { return };
            if right_pane_is_local(&ui) {
                reload_right_local(&ui, &state, &path);
                return;
            }
            let normalized = normalize_remote_path(&path);
            ui.set_right_path(normalized.clone().into());
            state.borrow_mut().push_recent_remote_path(normalized);
            request_remote_reload(&ui, &state);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_pane_dropped(move |pane: i32, row: i32, move_intent: bool| {
            let Some(ui) = ui_weak.upgrade() else { return };
            handle_pane_drop(&ui, &state, pane.max(0) as usize, row, move_intent);
            // A finished drag can no longer be a drop source; a stale marker
            // would make the panes accept unrelated (external) drags.
            ui.set_drag_source_pane(-1);
        });
    }
    {
        // Drag payload marker: Slint's `data-transfer` is opaque in `.slint`
        // code, so all rows share this one payload and the drop handler reads
        // the live selection from the pane state. The payload deliberately
        // carries no text or file data, so external applications reject the
        // drag instead of pasting a marker string.
        let mut payload = slint::DataTransfer::default();
        payload.set_user_data(Rc::new(PaneDragMarker));
        ui.set_drag_payload(payload);
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_left_crumb_clicked(move |index| {
            let Some(ui) = ui_weak.upgrade() else { return };
            // Targets are kept alongside the labels when the breadcrumbs are
            // rebuilt; an empty target is the elision marker.
            let path = LEFT_CRUMB_TARGETS
                .with(|cell| cell.borrow().get(index.max(0) as usize).cloned())
                .filter(|target| !target.is_empty());
            let Some(path) = path else { return };
            reload_local(&ui, &state, &path);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_search_left_requested(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            open_search_dialog(&ui, &state, 0);
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_left_row_clicked(move |row, ctrl, shift| {
            let Some(ui) = ui_weak.upgrade() else { return };
            handle_pane_row_click(&ui, 0, row, ctrl, shift);
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_right_row_clicked(move |row, ctrl, shift| {
            let Some(ui) = ui_weak.upgrade() else { return };
            handle_pane_row_click(&ui, 1, row, ctrl, shift);
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_pane_select_all(move |pane| {
            let Some(ui) = ui_weak.upgrade() else { return };
            handle_pane_select_all(&ui, usize::from(pane > 0));
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_pane_collapse_selection(move |pane| {
            let Some(ui) = ui_weak.upgrade() else { return };
            handle_pane_collapse_selection(&ui, usize::from(pane > 0));
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_pane_sort_requested(move |pane, column| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let pane = usize::from(pane > 0);
            let column = column.clamp(0, 3);
            let (current, ascending) = if pane == 0 {
                (ui.get_left_sort_column(), ui.get_left_sort_ascending())
            } else {
                (ui.get_right_sort_column(), ui.get_right_sort_ascending())
            };
            // Qt toggles a repeated click on the same header and starts a new
            // column ascending.
            let direction = if current == column { !ascending } else { true };
            if pane == 0 {
                ui.set_left_sort_column(column);
                ui.set_left_sort_ascending(direction);
            } else {
                ui.set_right_sort_column(column);
                ui.set_right_sort_ascending(direction);
            }
            resort_pane(&ui, pane);
            persist_pane_sort(&ui, &state, pane);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_left_item_activated(move |row| {
            let Some(ui) = ui_weak.upgrade() else { return };
            if row < 0 {
                return;
            }
            let Some(entry) = ui.get_left_entries().row_data(row as usize) else {
                return;
            };
            let current = ui.get_left_path().to_string();
            let target = join_local(&current, &entry.name);
            if entry.is_dir {
                reload_local(&ui, &state, &target);
            } else {
                open_local_file(&ui, &state, &target);
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_new_dir_left(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let parent = ui.get_left_path().to_string();
            run_prompted_local_op(
                &state,
                0,
                "New folder",
                "Name:",
                String::new(),
                parent.clone(),
                move |name| {
                    let target = PathBuf::from(join_local(&parent, &name));
                    Box::pin(async move {
                        local_fs::create_dir_async(&target)
                            .await
                            .map(|()| format!("Folder created: {name}"))
                            .map_err(|err| format!("Could not create the folder: {err}"))
                    })
                },
            );
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_new_file_left(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let parent = ui.get_left_path().to_string();
            run_prompted_local_op(
                &state,
                0,
                "New file",
                "Name:",
                String::new(),
                parent.clone(),
                move |name| {
                    let target = PathBuf::from(join_local(&parent, &name));
                    Box::pin(async move {
                        // C++ newFileLeft asks before truncating an existing
                        // file («%1» already exists. Overwrite?); declining
                        // leaves everything untouched.
                        if target.exists() {
                            let question = tr_main_window(
                                "«%1» already exists.\nOverwrite?",
                                std::slice::from_ref(&name),
                            );
                            if !crate::connect::confirm_sync("File exists", &question, "Yes", "No")
                            {
                                return Ok(String::new());
                            }
                        }
                        local_fs::create_file_async(&target)
                            .await
                            .map(|()| format!("File created: {name}"))
                            .map_err(|err| format!("Could not create the file: {err}"))
                    })
                },
            );
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_rename_left(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            // C++ renameLeftSelected: exactly one selected row, otherwise the
            // "Select exactly one item." information alert.
            let rows: Vec<i32> = ui.get_left_selected_rows().iter().collect();
            let parent = pane_entries(&ui, 0).1;
            let rows: Vec<i32> = rows
                .into_iter()
                .filter(|row| Some(*row) != parent)
                .collect();
            if rows.len() != 1 {
                crate::connect::show_alert("Rename", "Select exactly one item.");
                return;
            }
            let Some(entry) = ui.get_left_entries().row_data(rows[0] as usize) else {
                return;
            };
            let current = ui.get_left_path().to_string();
            let old_name = entry.name.to_string();
            let old_path = join_local(&current, &old_name);
            if !local_fs::is_valid_local_path(Path::new(&old_path)) {
                ui.set_status_text("The item no longer exists".into());
                return;
            }
            run_prompted_local_op(
                &state,
                0,
                "Rename",
                "New name:",
                old_name.clone(),
                current.clone(),
                move |new_name| {
                    let new_path = join_local(&current, &new_name);
                    let from = PathBuf::from(old_path);
                    let to = PathBuf::from(new_path);
                    let old_name = old_name.clone();
                    Box::pin(async move {
                        local_fs::rename_async(&from, &to, false)
                            .await
                            .map(|()| format!("Renamed {old_name}"))
                            .map_err(|err| format!("Could not rename: {err}"))
                    })
                },
            );
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_delete_left(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let targets: Vec<PathBuf> = selected_left_seeds(&ui)
                .into_iter()
                .map(|(path, _)| path)
                .collect();
            if targets.is_empty() {
                crate::connect::show_alert("Delete", "No entries selected in the left panel.");
                return;
            }
            // C++ deleteFromLeft: one confirmation for the whole selection.
            let question = "This will permanently delete the selected items in the \
                            left panel.\nContinue?";
            let confirmed = rfd::MessageDialog::new()
                .set_title("Confirm delete")
                .set_description(question)
                .set_buttons(rfd::MessageButtons::YesNo)
                .set_level(rfd::MessageLevel::Warning)
                .show()
                == rfd::MessageDialogResult::Yes;
            if !confirmed {
                return;
            }
            let reload_path = targets
                .first()
                .and_then(|target| parent_of_local(&target.to_string_lossy()))
                .unwrap_or_else(|| ui.get_left_path().to_string());
            let handle = state.borrow().runtime_handle();
            let tx = state.borrow().ui_event_tx();
            handle.spawn(async move {
                // C++ counts every entry and reports
                // `Deleted: %1  |  Failed: %2` (missing entries count as
                // failures, exactly like QFile::remove).
                let mut ok = 0usize;
                let mut fail = 0usize;
                for target in &targets {
                    match local_fs::remove_async(target).await {
                        Ok(()) => ok += 1,
                        Err(err) => {
                            tracing::warn!("delete failed for {}: {err}", target.display());
                            fail += 1;
                        }
                    }
                }
                let message = format!("Deleted: {ok}  |  Failed: {fail}");
                if let Some(tx) = &tx {
                    let _ = tx.send(UiEvent::Status { message });
                    let _ = tx.send(UiEvent::ReloadLocal { path: reload_path });
                }
            });
        });
    }

    // ---- right pane (remote) ------------------------------------------------

    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_refresh_right(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if right_pane_is_local(&ui) {
                let path = ui.get_right_path().to_string();
                reload_right_local(&ui, &state, &path);
            } else {
                request_remote_reload(&ui, &state);
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_go_up_right(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let current = ui.get_right_path().to_string();
            if right_pane_is_local(&ui) {
                let Some(parent) = parent_of_local(&current) else {
                    return;
                };
                reload_right_local(&ui, &state, &parent);
                return;
            }
            let Some(parent) = parent_of_remote(&current) else {
                return;
            };
            ui.set_right_path(parent.clone().into());
            state.borrow_mut().push_recent_remote_path(parent);
            request_remote_reload(&ui, &state);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_go_home_right(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if right_pane_is_local(&ui) {
                let home = local_fs::home_dir().to_string_lossy().to_string();
                reload_right_local(&ui, &state, &home);
                return;
            }
            // The SFTP realpath contract is not ported yet; the remote root
            // is the closest approximation of "home" until it lands.
            ui.set_right_path("/".into());
            state.borrow_mut().push_recent_remote_path("/".to_string());
            request_remote_reload(&ui, &state);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_choose_right_dir(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if right_pane_is_local(&ui) {
                // Local mode: the C++ actChooseRight_ opens a folder picker
                // rooted at the pane's current folder.
                let current = ui.get_right_path().to_string();
                let mut picker = rfd::FileDialog::new();
                if !current.is_empty() && Path::new(&current).is_dir() {
                    picker = picker.set_directory(&current);
                }
                if let Some(dir) = picker.pick_folder() {
                    reload_right_local(&ui, &state, &dir.to_string_lossy());
                }
                return;
            }
            // Text-based server-side chooser: the browse-dialog port is not
            // available yet, so ask for the remote path directly.
            let handle = state.borrow().runtime_handle();
            let tx = state.borrow().ui_event_tx();
            handle.spawn(async move {
                match connect::prompt_user_sync(
                    "Choose remote folder",
                    "Path",
                    "",
                    "Remote folder path:",
                    "",
                    false,
                ) {
                    connect::PromptOutcome::Answered(path) => {
                        let normalized = remote::normalize_remote_path(&path);
                        if let Some(tx) = &tx {
                            let _ = tx.send(UiEvent::NavigateRemote { path: normalized });
                        }
                    }
                    connect::PromptOutcome::Cancelled | connect::PromptOutcome::Unavailable => {}
                }
            });
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_right_path_entered(move |path: SharedString| {
            let Some(ui) = ui_weak.upgrade() else { return };
            if right_pane_is_local(&ui) {
                // C++ setRightRoot refuses invalid local paths and keeps the
                // current folder.
                if !local_fs::is_valid_local_path(Path::new(path.as_str())) {
                    crate::connect::show_alert("Invalid path", "Folder does not exist.");
                    return;
                }
                reload_right_local(&ui, &state, &path);
                return;
            }
            let normalized = normalize_remote_path(&path);
            ui.set_right_path(normalized.clone().into());
            state.borrow_mut().push_recent_remote_path(normalized);
            request_remote_reload(&ui, &state);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_right_crumb_clicked(move |index| {
            let Some(ui) = ui_weak.upgrade() else { return };
            if right_pane_is_local(&ui) {
                // Local crumbs keep their absolute targets beside the labels
                // (same contract as the left pane).
                let path = RIGHT_CRUMB_TARGETS
                    .with(|cell| cell.borrow().get(index.max(0) as usize).cloned())
                    .filter(|target| !target.is_empty());
                let Some(path) = path else { return };
                reload_right_local(&ui, &state, &path);
                return;
            }
            let crumbs: Vec<SharedString> = ui.get_right_breadcrumbs().iter().collect();
            let Some(path) = remote_path_from_crumbs(&crumbs, index as usize) else {
                return;
            };
            let normalized = normalize_remote_path(&path);
            ui.set_right_path(normalized.clone().into());
            state.borrow_mut().push_recent_remote_path(normalized);
            request_remote_reload(&ui, &state);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_search_right_requested(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            open_search_dialog(&ui, &state, 1);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_right_item_activated(move |row| {
            let Some(ui) = ui_weak.upgrade() else { return };
            if row < 0 {
                return;
            }
            let Some(entry) = ui.get_right_entries().row_data(row as usize) else {
                return;
            };
            if right_pane_is_local(&ui) {
                let current = ui.get_right_path().to_string();
                let target = join_local(&current, &entry.name);
                if entry.is_dir {
                    reload_right_local(&ui, &state, &target);
                } else {
                    open_local_file(&ui, &state, &target);
                }
                return;
            }
            let current = ui.get_right_path().to_string();
            let target = join_remote(&current, &entry.name);
            if entry.is_dir {
                ui.set_right_path(target.clone().into());
                state.borrow_mut().push_recent_remote_path(target);
                request_remote_reload(&ui, &state);
            } else {
                // Double-click on a file downloads it into the local pane.
                let Some(session) = state.borrow().session.clone() else {
                    ui.set_status_text("Not connected".into());
                    return;
                };
                let local_dest = Path::new(&ui.get_left_path().to_string())
                    .join(&entry.name)
                    .to_string_lossy()
                    .into_owned();
                let mgr = Arc::clone(&state.borrow().transfer_manager);
                mgr.set_session_options(Some(session.clone()));
                let client = match client_factory::create_client(session.protocol) {
                    Ok(client) => client,
                    Err(err) => {
                        tracing::error!("could not create a download client: {err}");
                        ui.set_status_text("Could not start the download".into());
                        return;
                    }
                };
                mgr.enqueue_download(client, target.clone(), local_dest, false);
                if state.borrow().prefs.show_queue_on_enqueue {
                    state.borrow().request_show_queue();
                }
                ui.set_status_text(format!("Queued download: {}", entry.name).into());
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_new_dir_right(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let parent = ui.get_right_path().to_string();
            if right_pane_is_local(&ui) {
                run_prompted_local_op(
                    &state,
                    1,
                    "New folder",
                    "Name:",
                    String::new(),
                    parent.clone(),
                    move |name| {
                        let target = PathBuf::from(join_local(&parent, &name));
                        Box::pin(async move {
                            local_fs::create_dir_async(&target)
                                .await
                                .map(|()| format!("Folder created: {name}"))
                                .map_err(|err| format!("Could not create the folder: {err}"))
                        })
                    },
                );
                return;
            }
            let client = {
                let mut st = state.borrow_mut();
                st.client.take()
            };
            if client.is_none() {
                ui.set_status_text("Not connected".into());
                return;
            }
            run_prompted_remote_op(
                &state,
                client,
                "New folder",
                "Name:",
                String::new(),
                true,
                move |client, name| {
                    let parent = parent.clone();
                    Box::pin(async move {
                        remote::new_dir(client, &parent, &name)
                            .await
                            .map(|()| format!("Folder created: {name}"))
                    })
                },
            );
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_new_file_right(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let parent = ui.get_right_path().to_string();
            if right_pane_is_local(&ui) {
                run_prompted_local_op(
                    &state,
                    1,
                    "New file",
                    "Name:",
                    String::new(),
                    parent.clone(),
                    move |name| {
                        let target = PathBuf::from(join_local(&parent, &name));
                        Box::pin(async move {
                            if target.exists() {
                                let question = tr_main_window(
                                    "«%1» already exists.\nOverwrite?",
                                    std::slice::from_ref(&name),
                                );
                                if !crate::connect::confirm_sync(
                                    "File exists",
                                    &question,
                                    "Yes",
                                    "No",
                                ) {
                                    return Ok(String::new());
                                }
                            }
                            local_fs::create_file_async(&target)
                                .await
                                .map(|()| format!("File created: {name}"))
                                .map_err(|err| format!("Could not create the file: {err}"))
                        })
                    },
                );
                return;
            }
            let client = {
                let mut st = state.borrow_mut();
                st.client.take()
            };
            if client.is_none() {
                ui.set_status_text("Not connected".into());
                return;
            }
            run_prompted_remote_op(
                &state,
                client,
                "New file",
                "Name:",
                String::new(),
                true,
                move |client, name| {
                    let parent = parent.clone();
                    Box::pin(async move {
                        let target = join_remote(&parent, &name);
                        // C++ newFileRight checks remotely whether the item
                        // already exists and asks before overwriting.
                        match client.exists(&target).await {
                            Ok(Some(true)) => {
                                let question = tr_main_window(
                                    "«%1» already exists.\nOverwrite?",
                                    std::slice::from_ref(&name),
                                );
                                if !crate::connect::confirm_sync(
                                    "File exists",
                                    &question,
                                    "Yes",
                                    "No",
                                ) {
                                    return Ok(String::new());
                                }
                            }
                            Ok(_) => {}
                            Err(err) => {
                                return Err(format!(
                                    "Could not check whether the remote file already exists.\n{err}"
                                ));
                            }
                        }
                        remote::new_file(client, &parent, &name)
                            .await
                            .map(|()| format!("File created: {name}"))
                    })
                },
            );
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_rename_right(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            // C++ renameRightSelected: exactly one selected row, otherwise the
            // "Select exactly one item." information alert.
            let rows: Vec<i32> = ui.get_right_selected_rows().iter().collect();
            let parent = pane_entries(&ui, 1).1;
            let rows: Vec<i32> = rows
                .into_iter()
                .filter(|row| Some(*row) != parent)
                .collect();
            if rows.len() != 1 {
                crate::connect::show_alert("Rename", "Select exactly one item.");
                return;
            }
            let Some(entry) = ui.get_right_entries().row_data(rows[0] as usize) else {
                return;
            };
            let parent = ui.get_right_path().to_string();
            let old_name = entry.name.to_string();
            if right_pane_is_local(&ui) {
                let old_path = join_local(&parent, &old_name);
                if !local_fs::is_valid_local_path(Path::new(&old_path)) {
                    ui.set_status_text("The item no longer exists".into());
                    return;
                }
                run_prompted_local_op(
                    &state,
                    1,
                    "Rename",
                    "New name:",
                    old_name.clone(),
                    parent.clone(),
                    move |new_name| {
                        let from = PathBuf::from(old_path);
                        let to = PathBuf::from(join_local(&parent, &new_name));
                        let old_name = old_name.clone();
                        Box::pin(async move {
                            local_fs::rename_async(&from, &to, false)
                                .await
                                .map(|()| format!("Renamed {old_name}"))
                                .map_err(|err| format!("Could not rename: {err}"))
                        })
                    },
                );
                return;
            }
            let client = {
                let mut st = state.borrow_mut();
                st.client.take()
            };
            if client.is_none() {
                ui.set_status_text("Not connected".into());
                return;
            }
            run_prompted_remote_op(
                &state,
                client,
                "Rename",
                "New name:",
                old_name.clone(),
                true,
                move |client, new_name| {
                    let parent = parent.clone();
                    let old_name = old_name.clone();
                    Box::pin(async move {
                        remote::rename_entry(client, &parent, &old_name, &new_name, false)
                            .await
                            .map(|()| format!("Renamed {old_name}"))
                    })
                },
            );
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_delete_right(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if right_pane_is_local(&ui) {
                let targets = selected_right_local_seeds(&ui);
                if targets.is_empty() {
                    crate::connect::show_alert("Delete", "No entries selected in the right panel.");
                    return;
                }
                let question = "This will permanently delete the selected items in the \
                                right panel.\nContinue?";
                let confirmed = rfd::MessageDialog::new()
                    .set_title("Confirm delete")
                    .set_description(question)
                    .set_buttons(rfd::MessageButtons::YesNo)
                    .set_level(rfd::MessageLevel::Warning)
                    .show()
                    == rfd::MessageDialogResult::Yes;
                if !confirmed {
                    return;
                }
                let reload_path = targets
                    .first()
                    .and_then(|target| parent_of_local(&target.to_string_lossy()))
                    .unwrap_or_else(|| ui.get_right_path().to_string());
                let handle = state.borrow().runtime_handle();
                let tx = state.borrow().ui_event_tx();
                handle.spawn(async move {
                    let mut ok = 0usize;
                    let mut fail = 0usize;
                    for target in &targets {
                        match local_fs::remove_async(target).await {
                            Ok(()) => ok += 1,
                            Err(err) => {
                                tracing::warn!("delete failed for {}: {err}", target.display());
                                fail += 1;
                            }
                        }
                    }
                    if let Some(tx) = &tx {
                        let _ = tx.send(UiEvent::Status {
                            message: format!("Deleted: {ok}  |  Failed: {fail}"),
                        });
                        let _ = tx.send(UiEvent::ReloadRightLocal { path: reload_path });
                    }
                });
                return;
            }
            let seeds = selected_right_seeds(&ui);
            if seeds.is_empty() {
                crate::connect::show_alert("Delete", "Nothing selected.");
                return;
            }
            // C++ deleteRightSelected: one confirmation for the whole
            // selection ("items on the remote server").
            let question = "This will permanently delete items on the \
                            remote server.\nContinue?";
            let confirmed = rfd::MessageDialog::new()
                .set_title("Confirm delete")
                .set_description(question)
                .set_buttons(rfd::MessageButtons::YesNo)
                .set_level(rfd::MessageLevel::Warning)
                .show()
                == rfd::MessageDialogResult::Yes;
            if !confirmed {
                return;
            }
            let parent = ui.get_right_path().to_string();
            let client = {
                let mut st = state.borrow_mut();
                st.client.take()
            };
            let Some(client) = client else {
                ui.set_status_text("Not connected".into());
                return;
            };
            let handle = state.borrow().runtime_handle();
            let tx = state.borrow().ui_event_tx();
            handle.spawn(async move {
                let mut client = client;
                // C++ reports `Deleted OK: %1  |  Failed: %2` (plus the last
                // error) for the batch; `delete_entries` already formats the
                // failure wording, so only the success path is built here.
                let message =
                    match remote::delete_entries(&mut *client, &parent, &seeds, true).await {
                        Ok(n) => format!("Deleted OK: {n}  |  Failed: 0"),
                        Err(err) => err,
                    };
                if let Some(tx) = &tx {
                    let _ = tx.send(UiEvent::Status { message });
                    let _ = tx.send(UiEvent::ReturnClient(client));
                    let _ = tx.send(UiEvent::ReloadRemote);
                }
            });
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_permissions_right(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            // C++ changeRemotePermissions: capability gate, then exactly one
            // selected row.
            let supports =
                state.borrow().session.as_ref().is_some_and(|opt| {
                    capabilities_for_protocol(opt.protocol).supports_permissions
                });
            if !supports {
                crate::connect::show_alert(
                    "Permissions",
                    "Permissions are not supported for the active protocol.",
                );
                return;
            }
            // C++ changeRemotePermissions: exactly one selected row.
            let rows: Vec<i32> = ui.get_right_selected_rows().iter().collect();
            let parent = pane_entries(&ui, 1).1;
            let rows: Vec<i32> = rows
                .into_iter()
                .filter(|row| Some(*row) != parent)
                .collect();
            if rows.len() != 1 {
                crate::connect::show_alert("Permissions", "Select only one item.");
                return;
            }
            let Some(entry) = ui.get_right_entries().row_data(rows[0] as usize) else {
                return;
            };
            let current = ui.get_right_path().to_string();
            let target = join_remote(&current, &entry.name);
            let flow = remote::open_permissions(&ui, entry.clone(), entry.mode.max(0) as u32);
            PERMISSION_FLOWS.with(|flows| {
                flows.borrow_mut().push((flow, target, entry.is_dir));
            });
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_open_terminal_right(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            // Port of MainWindowRemoteOps.cpp:openRightRemoteTerminal — the
            // command builder honors Terminal/forceInteractiveLogin and
            // Terminal/enableSftpCliFallback (ssh with an sftp CLI fallback).
            let session = state.borrow().session.clone();
            let Some(session) = session else {
                crate::connect::show_alert(
                    "Open in terminal",
                    "The right panel must be connected as remote.",
                );
                return;
            };
            let prefs = settings::Preferences::load();
            let remote_path = normalize_remote_path(ui.get_right_path().as_ref());
            match terminal::open_remote_terminal(&session, &prefs, &remote_path) {
                Ok(status) => ui.set_status_text(status.into()),
                Err(err) if err.starts_with("Could not launch") => {
                    crate::connect::show_alert(
                        "Open in terminal",
                        &crate::connect::tr(
                            "Could not open a remote terminal.\n%1",
                            std::slice::from_ref(&err),
                        ),
                    );
                }
                Err(err) => {
                    crate::connect::show_alert(
                        "Open in terminal",
                        &crate::connect::tr(
                            "Could not prepare the terminal command.\n%1",
                            std::slice::from_ref(&err),
                        ),
                    );
                }
            }
        });
    }

    // ---- window lifecycle ----------------------------------------------------

    // Persist geometry when the window closes.
    ui.window().on_close_requested({
        let ui_weak = ui.as_weak();
        let state = state.clone();
        move || {
            if let Some(ui) = ui_weak.upgrade() {
                capture_window_geometry(&ui, &state);
            }
            slint::CloseRequestResponse::HideWindow
        }
    });

    // Periodic geometry autosave.
    let geometry_timer = Timer::default();
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        geometry_timer.start(TimerMode::Repeated, Duration::from_secs(60), move || {
            if let Some(ui) = ui_weak.upgrade() {
                capture_window_geometry(&ui, &state);
            }
        });
    }

    // Status-bar timer: session elapsed label, connection type, remote
    // enabled state, and the host-key risk banner. Also refreshes the
    // connection indicator labels (port of the C++ indicator timer).
    let elapsed_timer = Timer::default();
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        elapsed_timer.start(TimerMode::Repeated, Duration::from_secs(1), move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            connect::update_indicators(&st);
            if st.connection_started_at.is_some() {
                let secs = connect::indicators_elapsed_secs();
                ui.set_connection_elapsed_text(
                    format!("Session: {}", format_elapsed(Duration::from_secs(secs))).into(),
                );
            }
            let type_text = match &st.session {
                Some(opts) => format!(
                    "Type: {}",
                    freescp_core::protocol_display_name(opts.protocol)
                ),
                None => "Type: None".to_string(),
            };
            ui.set_connection_type_text(type_text.into());
            ui.set_remote_connected(st.client.is_some());
            ui.set_risk_banner_visible(st.session_no_host_verification);
        });
    }

    // Session health monitor (port of the C++ periodic transport probe).
    start_session_health_timer(
        &ui,
        &state,
        settings::Preferences::load().session_health_interval_sec,
    );

    // Permissions-dialog poller: applies confirmed chmod results.
    let permissions_timer = Timer::default();
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        permissions_timer.start(TimerMode::Repeated, Duration::from_millis(500), move || {
            poll_permission_flows(&ui_weak, &state);
        });
    }

    // Initial local pane load (home directory). The right pane starts local
    // too, like the C++ local/local layout before a session connects.
    let initial = local_fs::home_dir().to_string_lossy().to_string();
    reload_local(&ui, &state, &initial);
    reload_right_local(&ui, &state, &initial);

    // Deferred so the main window is shown before the dialog: mirror the
    // C++ `prefOpenSiteManagerOnStartup` behavior.
    let startup_timer = Timer::default();
    startup_timer.start(TimerMode::SingleShot, Duration::from_millis(0), {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        let open_on_startup = state.borrow().prefs.open_site_manager_on_startup;
        move || {
            // Deferred startup purge of stale drag-out staging batches
            // (port of the C++ `QTimer::singleShot(0, ...)` block).
            cleanup_staging_root(&settings::Preferences::load());
            if !open_on_startup {
                return;
            }
            let Some(ui) = ui_weak.upgrade() else { return };
            site_manager::open(&ui, &state.borrow());
        }
    });

    // Run the event loop (blocks until the last window closes).
    ui.run()?;

    // Shutdown: stop periodic work, dismiss parked dialogs, then persist
    // geometry one final time.
    elapsed_timer.stop();
    geometry_timer.stop();
    startup_timer.stop();
    stop_session_health_timer();
    permissions_timer.stop();
    PERMISSION_FLOWS.with(|flows| {
        for (flow, _, _) in flows.borrow_mut().drain(..) {
            flow.dismiss();
        }
    });
    capture_window_geometry(&ui, &state);

    Ok(())
}

#[cfg(test)]
mod layout_tests {
    use crate::ui::main_window::MainWindow;
    use slint::platform::WindowEvent;
    use slint::ComponentHandle;

    /// The right pane must stretch to fill the window next to the fixed-width
    /// left pane and the splitter: 1200 - 691 - 7 = 502.
    #[test]
    fn right_pane_stretches_to_window_edge() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().dispatch_event(WindowEvent::Resized {
            size: slint::LogicalSize::new(1200.0, 700.0),
        });
        ui.set_left_pane_width(691.0);
        // Force a layout pass via events (same sequence as the splitter repro).
        ui.window().dispatch_event(WindowEvent::PointerMoved {
            position: slint::LogicalPosition::new(100.0, 100.0),
        });
        ui.window().dispatch_event(WindowEvent::PointerPressed {
            position: slint::LogicalPosition::new(100.0, 100.0),
            button: slint::platform::PointerEventButton::Left,
        });
        ui.window().dispatch_event(WindowEvent::PointerReleased {
            position: slint::LogicalPosition::new(100.0, 100.0),
            button: slint::platform::PointerEventButton::Left,
        });
        println!("window size: {:?}", ui.window().size());
        let left = ui.get_left_pane_width();
        let right = ui.get_right_pane_w();
        println!(
            "left pane: {left}, right pane: {right}, panes HLayout: {}, VLayout: {}, scope: {}",
            ui.get_panes_w(),
            ui.get_vlayout_w(),
            ui.get_scope_w()
        );
        assert!(
            (right - (1200.0 - left - 7.0)).abs() < 2.0,
            "right pane should fill the window (expected {}, got {right})",
            1200.0 - left - 7.0
        );
    }

    /// Dragging the splitter must track the cursor 1:1 (the incremental
    /// anchor-based math exists precisely to avoid half-speed convergence).
    #[test]
    fn splitter_drag_resizes_panes_1to1() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().dispatch_event(WindowEvent::Resized {
            size: slint::LogicalSize::new(1200.0, 700.0),
        });
        ui.set_left_pane_width(691.0);
        // Panes row starts below menu bar (27px) + main toolbar (38px).
        // Drag +60px (stays above the right pane's ~430px content minimum).
        let (x, y) = (691.0 + 3.5, 400.0);
        ui.window().dispatch_event(WindowEvent::PointerPressed {
            position: slint::LogicalPosition::new(x, y),
            button: slint::platform::PointerEventButton::Left,
        });
        for dx in [10.0, 25.0, 45.0, 60.0] {
            ui.window().dispatch_event(WindowEvent::PointerMoved {
                position: slint::LogicalPosition::new(x + dx, y),
            });
        }
        ui.window().dispatch_event(WindowEvent::PointerReleased {
            position: slint::LogicalPosition::new(x + 60.0, y),
            button: slint::platform::PointerEventButton::Left,
        });
        let left = ui.get_left_pane_width();
        assert!(
            (left - 751.0).abs() < 2.0,
            "60px drag should move the divider 60px (expected 751, got {left})"
        );
        let right = ui.get_right_pane_w();
        assert!(
            (right - (1200.0 - 751.0 - 7.0)).abs() < 2.0,
            "right pane should refill after the drag (got {right})"
        );
    }

    /// Dragging a column boundary in the right-pane header must resize the
    /// column 1:1. The permissions column is the rightmost: its handle sits
    /// at pane_width - perm_width from the pane's left edge.
    #[test]
    fn column_handle_drag_resizes_permissions_column() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().dispatch_event(WindowEvent::Resized {
            size: slint::LogicalSize::new(1200.0, 700.0),
        });
        ui.set_left_pane_width(691.0);
        // Right pane spans x = 698..1200. Row offsets inside the pane:
        // toolbar 32 + breadcrumbs 24 + path 30 -> header center at y = 65 + 32 + 24 + 30 + 12.
        let handle_x = 698.0 + (1200.0 - 698.0) - 120.0;
        let y = 65.0 + 32.0 + 24.0 + 30.0 + 12.0;
        ui.window().dispatch_event(WindowEvent::PointerPressed {
            position: slint::LogicalPosition::new(handle_x, y),
            button: slint::platform::PointerEventButton::Left,
        });
        for dx in [-10.0, -25.0, -50.0] {
            ui.window().dispatch_event(WindowEvent::PointerMoved {
                position: slint::LogicalPosition::new(handle_x + dx, y),
            });
        }
        ui.window().dispatch_event(WindowEvent::PointerReleased {
            position: slint::LogicalPosition::new(handle_x - 50.0, y),
            button: slint::platform::PointerEventButton::Left,
        });
        let perm = ui.get_right_perm_width();
        assert!(
            (perm - 170.0).abs() < 2.0,
            "50px left drag should widen the permissions column by 50px (expected 170, got {perm})"
        );
        // Dragging back right must shrink it again (no rubber-banding).
        ui.window().dispatch_event(WindowEvent::PointerPressed {
            position: slint::LogicalPosition::new(handle_x - 50.0, y),
            button: slint::platform::PointerEventButton::Left,
        });
        ui.window().dispatch_event(WindowEvent::PointerMoved {
            position: slint::LogicalPosition::new(handle_x - 20.0, y),
        });
        ui.window().dispatch_event(WindowEvent::PointerReleased {
            position: slint::LogicalPosition::new(handle_x - 20.0, y),
            button: slint::platform::PointerEventButton::Left,
        });
        let perm = ui.get_right_perm_width();
        assert!(
            (perm - 140.0).abs() < 2.0,
            "30px right drag should shrink the column to 140px (got {perm})"
        );
    }
}

#[cfg(test)]
mod dnd_tests {
    use super::{drop_target_dir, remote_move_renames};
    use crate::ui::main_window::{FileEntry, MainWindow};
    use slint::VecModel;
    use std::rc::Rc;

    fn entry(name: &str, is_dir: bool) -> FileEntry {
        FileEntry {
            name: name.into(),
            is_dir,
            size: 0,
            has_size: true,
            mtime: 0,
            mode: 0,
            type_label: if is_dir {
                "Folder".into()
            } else {
                "Text".into()
            },
            permissions: "".into(),
        }
    }

    /// The hovered folder row wins over the pane root; file rows reject the
    /// drop (the C++ `isDir` check) and the remote pane resolves the child with
    /// the remote path rules.
    #[test]
    fn drop_targets_resolve_to_the_hovered_folder_row() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.set_left_path("/tmp/freescp-src".into());
        ui.set_left_entries(
            Rc::new(VecModel::from(vec![
                entry("..", true),
                entry("a.txt", false),
                entry("sub", true),
            ]))
            .into(),
        );
        assert_eq!(
            drop_target_dir(&ui, 0, -1),
            Some(("/tmp/freescp-src".to_string(), false))
        );
        assert_eq!(
            drop_target_dir(&ui, 0, 2),
            Some(("/tmp/freescp-src/sub".to_string(), false))
        );
        assert_eq!(
            drop_target_dir(&ui, 0, 1),
            None,
            "a file row is not a target"
        );

        // Right pane while it is remote: the hovered folder joins with the
        // remote path rules.
        ui.set_remote_connected(true);
        ui.set_right_path("/srv/data".into());
        ui.set_right_entries(Rc::new(VecModel::from(vec![entry("incoming", true)])).into());
        assert_eq!(
            drop_target_dir(&ui, 1, -1),
            Some(("/srv/data".to_string(), true))
        );
        assert_eq!(
            drop_target_dir(&ui, 1, 0),
            Some(("/srv/data/incoming".to_string(), true))
        );
        // A drop on ".." targets the parent folder, like QFileSystemModel
        // (the remote join normalizes the `..` segment away).
        ui.set_right_entries(
            Rc::new(VecModel::from(vec![
                entry("..", true),
                entry("incoming", true),
            ]))
            .into(),
        );
        assert_eq!(drop_target_dir(&ui, 1, 0), Some(("/srv".to_string(), true)));
    }

    /// Remote→remote drops are server-side renames; self/own-subtree targets and
    /// the synthetic `..` row are skipped (C++ `handlePanelDrop` guards).
    #[test]
    fn remote_move_renames_skip_self_targets_and_the_parent_row() {
        let seeds = vec![
            ("/srv/a/f1.txt".to_string(), false),
            ("/srv/b".to_string(), true),
            ("/srv/..".to_string(), true),
        ];
        // Into a sibling folder: both real entries move, ".." is skipped.
        let (renames, skipped) = remote_move_renames(&seeds, "/srv/dest");
        assert_eq!(skipped, 1);
        assert_eq!(
            renames,
            vec![
                ("/srv/a/f1.txt".to_string(), "/srv/dest/f1.txt".to_string()),
                ("/srv/b".to_string(), "/srv/dest/b".to_string()),
            ]
        );
        // Into the folder `f1.txt` already lives in: that one is a no-op, but
        // the dragged folder `/srv/b` still moves in as `/srv/a/b`.
        let (renames, skipped) = remote_move_renames(&seeds, "/srv/a");
        assert_eq!(
            renames,
            vec![("/srv/b".to_string(), "/srv/a/b".to_string())]
        );
        assert_eq!(skipped, 2);
        // Into the dragged folder itself: `/srv/b` cannot move into its own
        // subtree, the other entry can.
        let (renames, skipped) = remote_move_renames(&seeds, "/srv/b");
        assert_eq!(
            renames,
            vec![("/srv/a/f1.txt".to_string(), "/srv/b/f1.txt".to_string())]
        );
        assert_eq!(skipped, 2);
        // Into the dragged folder's own subtree: same guard.
        let (renames, skipped) = remote_move_renames(&seeds, "/srv/b/nested");
        assert_eq!(
            renames,
            vec![(
                "/srv/a/f1.txt".to_string(),
                "/srv/b/nested/f1.txt".to_string()
            )]
        );
        assert_eq!(skipped, 2);
        // A pure self-drop (the only selection lands in its own subtree) is
        // ignored entirely, with the C++ skipped count.
        let (renames, skipped) = remote_move_renames(&[("/srv/b".to_string(), true)], "/srv/b/n");
        assert!(renames.is_empty());
        assert_eq!(skipped, 1);
    }
}

#[cfg(test)]
mod staging_cleanup_tests {
    use super::is_staging_batch_name;

    #[test]
    fn staging_batch_names_match_cpp_regex() {
        assert!(is_staging_batch_name("20260912-102700"));
        assert!(!is_staging_batch_name("2026912-102700"));
        assert!(!is_staging_batch_name("20260912-10270"));
        assert!(!is_staging_batch_name("20260912_102700"));
        assert!(!is_staging_batch_name("batch-20260912-102700"));
        assert!(!is_staging_batch_name("20260912-10270a"));
        assert!(!is_staging_batch_name(""));
    }
}

#[cfg(test)]
mod locale_tests {
    use super::locale_candidates;

    #[test]
    fn locale_candidates_prefer_the_ui_language_then_a_real_fallback() {
        assert_eq!(locale_candidates("fr")[0], "fr_FR.UTF-8");
        assert_eq!(locale_candidates("pt-BR")[0], "pt_PT.UTF-8");
        assert_eq!(locale_candidates("es_ES.UTF-8")[0], "es_ES.UTF-8");
        // Unknown languages still get a non-C fallback so `LANGUAGE` applies.
        let unknown = locale_candidates("nl");
        assert!(unknown.contains(&"en_US.UTF-8".to_string()));
        assert!(!unknown.iter().any(|candidate| candidate == "C"));
    }
}

#[cfg(test)]
mod translation_catalog_tests {
    use std::path::PathBuf;

    /// Qt's PO writer appends `|` to context-only entries, but Slint's
    /// generated `@tr` calls look the context up as the bare `.slint` name.
    /// A catalog carrying the marker silently disables every UI translation
    /// (the app falls back to the English source text), so guard the checked-in
    /// catalogs against a regenerated-with-pipes regression.
    #[test]
    fn catalogs_use_bare_slint_contexts() {
        for lang in ["es", "fr", "pt"] {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("translations")
                .join(lang)
                .join("LC_MESSAGES")
                .join("freescp-app.po");
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
            for (index, line) in text.lines().enumerate() {
                if let Some(rest) = line.strip_prefix("msgctxt \"") {
                    assert!(
                        !rest.ends_with("|\""),
                        "{}:{}: Qt context marker in {line}",
                        path.display(),
                        index + 1
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod breadcrumb_tests {
    use super::local_breadcrumb_pairs;

    #[test]
    fn local_breadcrumbs_are_relative_with_absolute_targets() {
        let (labels, targets) = local_breadcrumb_pairs("/Users/nemo/Documents");
        let labels: Vec<&str> = labels.iter().map(|label| label.as_str()).collect();
        assert_eq!(labels, vec!["/", "Users", "nemo", "Documents"]);
        assert_eq!(
            targets,
            vec!["/", "/Users", "/Users/nemo", "/Users/nemo/Documents"]
        );
    }

    #[test]
    fn local_breadcrumbs_elide_long_paths_with_matching_targets() {
        let (labels, targets) = local_breadcrumb_pairs("/a/b/c/d/e/f/g/h/i/j");
        assert_eq!(labels.len(), targets.len());
        assert!(labels.iter().any(|label| label.as_str() == "…"));
        // The elision marker has no navigation target.
        let marker = labels
            .iter()
            .position(|label| label.as_str() == "…")
            .unwrap();
        assert!(targets[marker].is_empty());
        assert_eq!(labels.last().unwrap().as_str(), "j");
        assert_eq!(targets.last().unwrap(), "/a/b/c/d/e/f/g/h/i/j");
        assert_eq!(labels.first().unwrap().as_str(), "/");
    }
}

#[cfg(test)]
mod selection_tests {
    use super::{search_results_summary, search_status_text, PaneSelection, SelectionMode};
    use crate::local_fs::SearchOutcome;

    /// Row layout used by the tests: the synthetic ".." row sits at index 0.
    const PARENT: Option<i32> = Some(0);

    #[test]
    fn plain_click_replaces_the_selection_and_moves_the_anchor() {
        let mut sel = PaneSelection::new(5, vec![2, 5]);
        sel.click(3, SelectionMode::Replace, PARENT, 8);
        assert_eq!(sel.anchor, 3);
        assert_eq!(sel.rows, vec![3]);
    }

    #[test]
    fn ctrl_click_toggles_rows_and_moves_the_anchor() {
        let mut sel = PaneSelection::default();
        sel.click(2, SelectionMode::Toggle, PARENT, 8);
        sel.click(4, SelectionMode::Toggle, PARENT, 8);
        assert_eq!(sel.rows, vec![2, 4]);
        assert_eq!(sel.anchor, 4);
        sel.click(2, SelectionMode::Toggle, PARENT, 8);
        assert_eq!(sel.rows, vec![4]);
        assert_eq!(sel.anchor, 2);
    }

    #[test]
    fn shift_click_extends_the_range_from_the_anchor() {
        let mut sel = PaneSelection::default();
        sel.click(2, SelectionMode::Replace, PARENT, 8);
        sel.click(5, SelectionMode::Extend, PARENT, 8);
        assert_eq!(sel.rows, vec![2, 3, 4, 5]);
        assert_eq!(sel.anchor, 5);
        sel.click(4, SelectionMode::Extend, PARENT, 8);
        assert_eq!(sel.rows, vec![4, 5]);
        assert_eq!(sel.anchor, 4);
    }

    #[test]
    fn parent_row_never_joins_a_multi_selection() {
        let mut sel = PaneSelection::default();
        sel.click(2, SelectionMode::Replace, PARENT, 8);
        sel.click(5, SelectionMode::Extend, PARENT, 8);
        // Shift-extending onto ".." keeps the range and excludes the parent.
        sel.click(0, SelectionMode::Extend, PARENT, 8);
        assert_eq!(sel.rows, vec![1, 2, 3, 4, 5]);
        assert_eq!(sel.anchor, 0);
        // Ctrl-clicking ".." cannot add it, so the set is left alone.
        sel.click(0, SelectionMode::Toggle, PARENT, 8);
        assert_eq!(sel.rows, vec![1, 2, 3, 4, 5]);
        assert_eq!(sel.anchor, 0);
        // A plain click on ".." is a single (non-actionable) selection.
        sel.click(0, SelectionMode::Replace, PARENT, 8);
        assert!(sel.rows.is_empty());
        assert_eq!(sel.anchor, 0);
    }

    #[test]
    fn select_all_skips_the_parent_row() {
        let mut sel = PaneSelection::new(3, vec![3]);
        sel.select_all(PARENT, 4);
        assert_eq!(sel.rows, vec![1, 2, 3]);
        assert_eq!(sel.anchor, 3);
        // A parent-row anchor moves to the first selected row.
        sel.anchor = 0;
        sel.select_all(PARENT, 4);
        assert_eq!(sel.rows, vec![1, 2, 3]);
        assert_eq!(sel.anchor, 1);
    }

    #[test]
    fn collapse_keeps_only_the_anchor_row() {
        let mut sel = PaneSelection::new(3, vec![1, 2, 3]);
        sel.collapse(PARENT, 5);
        assert_eq!(sel.rows, vec![3]);
        assert_eq!(sel.anchor, 3);
        sel.anchor = 0;
        sel.collapse(PARENT, 5);
        assert!(sel.rows.is_empty());
    }

    #[test]
    fn out_of_range_clicks_clear_the_selection() {
        let mut sel = PaneSelection::new(2, vec![2]);
        sel.click(9, SelectionMode::Replace, PARENT, 4);
        assert_eq!(sel.anchor, -1);
        assert!(sel.rows.is_empty());
    }

    #[test]
    fn search_summary_matches_the_cpp_lines() {
        assert_eq!(
            search_results_summary("/base", 3, 0, false, false),
            "Base: /base\nMatches: 3"
        );
        assert_eq!(
            search_results_summary("/base", 2, 0, true, false),
            "Base: /base\nMatches: 2\nSearch canceled by user."
        );
        assert_eq!(
            search_results_summary("/base", 0, 2, true, true),
            "Base: /base\nMatches: 0\nScan errors: 2\nSearch canceled by user.\n\
             Results truncated to safety limit."
        );
    }

    #[test]
    fn search_status_matches_the_cpp_lines() {
        let outcome = SearchOutcome {
            matches: vec!["a.txt".to_string()],
            truncated: true,
            scan_errors: 2,
            canceled: true,
        };
        assert_eq!(
            search_status_text("Local panel", 1, &outcome),
            "Found 1 recursive match(es) in Local panel.  Results limited to 5000.  \
             Folders with errors: 2  (Canceled)"
        );
        let canceled = SearchOutcome {
            canceled: true,
            ..SearchOutcome::default()
        };
        assert_eq!(
            search_status_text("Remote panel", 0, &canceled),
            "Search canceled in Remote panel."
        );
        assert_eq!(
            search_status_text("Remote panel", 0, &SearchOutcome::default()),
            "No recursive matches found in Remote panel."
        );
    }
}
