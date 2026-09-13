//! Shared application state for the FreeSCP Slint UI.
//!
//! Owned by the main-window workstream. `AppState` is created once in
//! `main.rs`, kept in `Rc<RefCell<AppState>>`, and handed to every sibling
//! module on the UI thread. All network work is spawned onto
//! [`AppState::runtime`] so the UI thread never blocks on I/O.
//!
//! # Design notes
//!
//! * The tokio runtime is built in [`AppState::new`] with
//!   `Builder::new_multi_thread().enable_all()`. The UI event loop runs on the
//!   calling thread; sibling modules spawn blocking/async work via
//!   `state.runtime.handle()` (or `slint::spawn_local` for futures that only
//!   touch UI state).
//! * Window geometry is persisted by this module to
//!   `<config-dir>/FreeSCP/window-state.toml` (serde + TOML), mirroring the
//!   C++ `QSettings("OpenSCP", "OpenSCP")` key
//!   `UI/mainWindow/geometry`+`windowState`. `main.rs` owns when saves
//!   happen (window close + a periodic timer).
//! * Preferences here are a port of the `MainWindow.hpp` preference fields.
//!   [`AppPreferences::from_settings`] converts the canonical serde
//!   [`crate::settings::Preferences`] struct (owned by `src/settings.rs`)
//!   into this UI-behavior subset; `main.rs` applies saves via
//!   [`AppState::apply_preferences`].
//! * History lists are owned in memory here (capped at
//!   [`MAX_RECENT_ENTRIES`]) and kept in sync with the persistence owned by
//!   `src/history.rs`: the `push_recent_*` methods forward every entry.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use freescp_core::{SessionOptions, SftpClient};
use tokio::sync::mpsc::UnboundedSender;

/// Commands delivered from worker threads to the UI-thread event loop.
///
/// `main.rs` creates the channel, hands the sender to
/// [`AppState::attach_ui_events`], and drains the receiver inside a
/// `slint::spawn_local` loop (non-`Send`, so it has full access to the
/// `Rc<RefCell<AppState>>` and the main window).
pub enum UiEvent {
    /// A freshly connected session ready to install into the right pane
    /// (port of `applyRemoteConnectedUI`). `opt` is boxed to keep the
    /// event small (the channel is unbounded).
    Session {
        opt: Box<SessionOptions>,
        client: Box<dyn SftpClient>,
    },
    /// Reload the local pane after an async local operation finished.
    ReloadLocal { path: String },
    /// Reload the right pane while it browses local folders (local/local
    /// mode, before a session connects or after disconnect).
    ReloadRightLocal { path: String },
    /// A watched local directory changed on disk; refresh `pane` (0 = left,
    /// 1 = right) only if it still shows `path` (stale watcher guard).
    LocalDirChanged { pane: usize, path: String },
    /// Reload the remote pane (upload-completion refresh hook).
    ReloadRemote,
    /// Re-raise the transfer queue dialog (show-on-enqueue preference).
    ShowQueue,
    /// Navigate the remote pane to `path` (used by the text-based
    /// server-side directory chooser).
    NavigateRemote { path: String },
    /// Update the status line.
    Status { message: String },
    /// Invalidate the cached writeability verdict for a remote directory
    /// (after a remote operation reported a denied write).
    InvalidateWriteability { dir: String },
    /// Put a client taken from the UI thread back into `AppState` (a newer
    /// session wins, so a stale return is dropped).
    ReturnClient(Box<dyn SftpClient>),
}

/// Maximum number of entries kept per history list (mirrors the C++
/// `kRecentHistoryMaxEntries` constant).
pub const MAX_RECENT_ENTRIES: usize = 20;

/// User preferences, ported from the `MainWindow.hpp` preference fields
/// (`prefShowHidden_`, `prefSingleClick_`, `prefOpenBehaviorMode_`,
/// `prefShowQueueOnEnqueue_`, `prefNoHostVerificationTtlMin_`,
/// `m_openSiteManagerOnDisconnect`, `m_openSiteManagerOnStartup`).
///
/// TODO(integration): reconcile with `settings::Preferences`
/// (`src/settings.rs`); the settings workstream owns the serde shape. Field
/// names and meanings must stay aligned.
#[derive(Debug, Clone)]
pub struct AppPreferences {
    /// Show dotfiles in the local pane listings.
    pub show_hidden: bool,
    /// Activate items on a single click instead of a double click.
    pub single_click: bool,
    /// What happens when a local file is activated: `"ask" | "reveal" | "open"`.
    pub open_behavior: String,
    /// Auto-show the transfer queue when a transfer is enqueued.
    pub show_queue_on_enqueue: bool,
    /// TTL (minutes) for the "no host verification" accept choice.
    pub no_host_verification_ttl_min: i64,
    /// Open the Site Manager automatically after a disconnect.
    pub open_site_manager_on_disconnect: bool,
    /// Open the Site Manager automatically at startup.
    pub open_site_manager_on_startup: bool,
}

impl Default for AppPreferences {
    /// Defaults match the C++ in-class initializers.
    fn default() -> Self {
        AppPreferences {
            show_hidden: false,
            single_click: false,
            open_behavior: "ask".to_string(),
            show_queue_on_enqueue: true,
            no_host_verification_ttl_min: 15,
            open_site_manager_on_disconnect: true,
            open_site_manager_on_startup: true,
        }
    }
}

impl AppPreferences {
    /// Converts the settings workstream's persisted
    /// [`crate::settings::Preferences`] into the UI-behavior subset (port of
    /// the preference reads in `MainWindow.hpp`).
    pub fn from_settings(prefs: &crate::settings::Preferences) -> Self {
        AppPreferences {
            show_hidden: prefs.show_hidden,
            single_click: prefs.single_click,
            open_behavior: prefs.open_behavior.clone(),
            show_queue_on_enqueue: prefs.show_queue_on_enqueue,
            no_host_verification_ttl_min: prefs.no_host_verification_ttl_min,
            open_site_manager_on_disconnect: prefs.open_site_manager_on_disconnect,
            open_site_manager_on_startup: prefs.open_site_manager_on_startup,
        }
    }
}

/// Persisted per-pane sort state (port of the Qt header sort indicator that
/// the C++ build stores inside `UI/mainWindow/*Header*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SortState {
    pub column: i32,
    pub ascending: bool,
}

impl SortState {
    pub const NAME_ASCENDING: Self = Self {
        column: 0,
        ascending: true,
    };
}

/// Saved main-window geometry. `None` fields mean "never saved"; `main.rs`
/// then leaves the platform default position/size in place.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct WindowState {
    pub x: Option<i32>,
    pub y: Option<i32>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// Splitter position in logical pixels (left pane width).
    pub split_x: Option<i32>,
    /// Left pane file-column widths in logical pixels (Size, Type, Modified).
    pub left_col_widths: Option<[i32; 3]>,
    /// Right pane file-column widths in logical pixels (Size, Modified,
    /// Permissions).
    pub right_col_widths: Option<[i32; 3]>,
    /// Left pane sort column + direction (defaults to name ascending).
    pub left_sort: Option<SortState>,
    /// Right pane sort column + direction (defaults to name ascending).
    pub right_sort: Option<SortState>,
    /// Left pane visible info columns (Size, Type, Modified); `None` keeps
    /// the all-visible default.
    pub left_col_visible: Option<[bool; 3]>,
    /// Right pane visible info columns (Size, Date, Permissions); `None`
    /// keeps the all-visible default.
    pub right_col_visible: Option<[bool; 3]>,
}

impl WindowState {
    /// File name inside the settings directory.
    const FILE_NAME: &'static str = "window-state.toml";

    /// Loads persisted geometry; returns [`WindowState::default`] when the
    /// file is missing, unreadable, or malformed.
    pub fn load_from(settings_dir: &Path) -> Self {
        let path = settings_dir.join(Self::FILE_NAME);
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Persists geometry as TOML, creating the settings directory on demand.
    pub fn save_to(&self, settings_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(settings_dir)?;
        let text = toml::to_string_pretty(self)
            .map_err(|err| std::io::Error::other(format!("serialize window state: {err}")))?;
        std::fs::write(settings_dir.join(Self::FILE_NAME), text)
    }
}

/// Application-wide state shared by the UI and the sibling workstreams.
pub struct AppState {
    /// Async runtime for all network backends (shared via `Arc` so the
    /// state stays cheaply cloneable for worker tasks).
    pub runtime: Arc<tokio::runtime::Runtime>,
    /// The active remote session, if any.
    pub client: Option<Box<dyn SftpClient>>,
    /// Options of the active session (for reconnects, history, TOFU state).
    pub session: Option<SessionOptions>,
    /// User preferences (see [`AppPreferences`]).
    pub prefs: AppPreferences,
    /// Most recently used local paths (newest first).
    pub recent_local_paths: Vec<String>,
    /// Most recently used remote paths (newest first).
    pub recent_remote_paths: Vec<String>,
    /// Most recently used servers. Storage form is the encoded
    /// `SessionOptions` string; decode via `history.rs`.
    /// TODO(integration): confirm the encoding with `src/history.rs`.
    pub recent_servers: Vec<String>,
    /// Persisted window geometry.
    pub window_state: WindowState,
    /// Directory holding persisted app state (window-state.toml, settings).
    pub settings_dir: PathBuf,
    /// Set when a session connects; drives the status-bar elapsed timer in
    /// `main.rs`.
    pub connection_started_at: Option<Instant>,
    /// True while the active session runs without host-key verification;
    /// drives the status-bar risk banner.
    pub session_no_host_verification: bool,
    /// Weak handle to the main window, attached by `main.rs` right after the
    /// window is created. Lets sibling modules (`connect`, ...) update the
    /// status bar from any thread via [`AppState::set_status`].
    ui: Option<slint::Weak<crate::ui::main_window::MainWindow>>,
    /// Transfer queue manager shared with the queue dialog and the worker
    /// tasks (`Arc` so tokio tasks and the UI thread share one instance).
    pub transfer_manager: Arc<crate::transfer::TransferManager>,
    /// Cached remote writeability probe results (see `remote.rs`).
    pub writeability: crate::remote::RemoteWriteabilityCache,
    /// Last local directory shown in the right pane (the C++ `rightLocalModel_`
    /// root, restored when a session disconnects).
    pub right_local_path: Option<String>,
    /// Sender half of the UI event channel; the receiver loop lives in
    /// `main.rs` (see [`UiEvent`]).
    ui_events_tx: Option<UnboundedSender<UiEvent>>,
}

impl Clone for AppState {
    /// Hand-written clone: the tokio runtime is shared (`Arc`), and the
    /// session fields — which are not `Clone` and must stay owned by the
    /// UI-thread original — are reset on the copy. Sibling workstreams hold
    /// such copies for status updates and tokio tasks.
    fn clone(&self) -> Self {
        AppState {
            runtime: Arc::clone(&self.runtime),
            client: None,
            session: None,
            prefs: self.prefs.clone(),
            recent_local_paths: self.recent_local_paths.clone(),
            recent_remote_paths: self.recent_remote_paths.clone(),
            recent_servers: self.recent_servers.clone(),
            window_state: self.window_state.clone(),
            settings_dir: self.settings_dir.clone(),
            connection_started_at: None,
            session_no_host_verification: self.session_no_host_verification,
            ui: self.ui.clone(),
            transfer_manager: Arc::clone(&self.transfer_manager),
            writeability: self.writeability.clone(),
            right_local_path: self.right_local_path.clone(),
            ui_events_tx: self.ui_events_tx.clone(),
        }
    }
}

impl AppState {
    /// Creates the application state, including the tokio multi-thread
    /// runtime and the persisted window geometry.
    ///
    /// # Panics
    ///
    /// Panics if the tokio runtime cannot be created (unrecoverable).
    pub fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create the tokio runtime");
        let settings_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("FreeSCP");
        let window_state = WindowState::load_from(&settings_dir);
        let preferences = crate::settings::Preferences::load();
        AppState {
            runtime: Arc::new(runtime),
            client: None,
            session: None,
            prefs: AppPreferences::from_settings(&preferences),
            recent_local_paths: crate::history::recent_local_paths(),
            recent_remote_paths: crate::history::recent_remote_paths(),
            recent_servers: Vec::new(),
            window_state,
            settings_dir,
            connection_started_at: None,
            session_no_host_verification: false,
            ui: None,
            transfer_manager: Arc::new(crate::transfer::TransferManager::new()),
            writeability: crate::remote::RemoteWriteabilityCache::with_ttl_ms(
                preferences.remote_writeability_ttl_ms,
            ),
            right_local_path: None,
            ui_events_tx: None,
        }
    }

    /// Convenience: the tokio `Handle` for spawning background work.
    pub fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }

    /// Writes the current window geometry to disk (best effort).
    pub fn persist_window_state(&self) {
        if let Err(err) = self.window_state.save_to(&self.settings_dir) {
            tracing::warn!("failed to persist window state: {err}");
        }
    }

    /// Prepends `path` to the local-path history, deduplicating and capping
    /// the list at [`MAX_RECENT_ENTRIES`], and forwards it to
    /// [`crate::history::add_recent_local_path`] for persistence.
    pub fn push_recent_local_path(&mut self, path: String) {
        prepend_recent(&mut self.recent_local_paths, path.clone());
        crate::history::add_recent_local_path(&path);
    }

    /// Prepends `path` to the remote-path history, deduplicating and capping
    /// the list at [`MAX_RECENT_ENTRIES`], and forwards it to
    /// [`crate::history::add_recent_remote_path`] for persistence.
    pub fn push_recent_remote_path(&mut self, path: String) {
        prepend_recent(&mut self.recent_remote_paths, path.clone());
        crate::history::add_recent_remote_path(&path);
    }

    /// Records a server in the recent-servers history (in-memory list plus
    /// the persisted [`crate::history::add_recent_server`] encoding).
    pub fn push_recent_server(&mut self, opt: &SessionOptions) {
        let entry = format!(
            "{}://{}@{}:{}",
            freescp_core::protocol_storage_name(opt.protocol),
            opt.username,
            opt.host,
            opt.port
        );
        prepend_recent(&mut self.recent_servers, entry);
        crate::history::add_recent_server(opt);
    }

    /// Attaches the main-window weak handle so status updates can reach the
    /// status bar. Called once by `main.rs` after the window is created.
    pub fn attach_ui(&mut self, ui: slint::Weak<crate::ui::main_window::MainWindow>) {
        self.ui = Some(ui);
    }

    /// Attaches the sender half of the UI event channel; the matching
    /// receiver is drained by the `spawn_local` loop in `main.rs`.
    pub fn attach_ui_events(&mut self, tx: UnboundedSender<UiEvent>) {
        self.ui_events_tx = Some(tx);
    }

    /// Clone of the UI event sender, if attached (used by `main.rs` helper
    /// tasks to post status updates and reload requests).
    pub fn ui_event_tx(&self) -> Option<UnboundedSender<UiEvent>> {
        self.ui_events_tx.clone()
    }

    /// Asks the UI event loop to re-raise the transfer queue dialog
    /// (C++ `prefShowQueueOnEnqueue`). Safe to call from any thread.
    pub fn request_show_queue(&self) {
        if let Some(tx) = &self.ui_events_tx {
            if tx.send(UiEvent::ShowQueue).is_err() {
                tracing::debug!("show-queue request dropped (event loop not running)");
            }
        }
    }

    /// Status-bar message (mirrors `QStatusBar::showMessage`). Safe to call
    /// from any thread: the update is posted to the Slint event loop.
    ///
    /// Every C++ `showMessage` call passes a timeout (3–6 s), so the line is
    /// cleared again once it has been visible, unless a newer message
    /// replaced it in the meantime.
    pub fn set_status(&self, message: &str) {
        let message = message.to_string();
        if let Some(ui) = &self.ui {
            let ui = ui.clone();
            let shown = message.clone();
            if slint::invoke_from_event_loop(move || {
                let weak = ui.clone();
                if let Some(ui) = ui.upgrade() {
                    ui.set_status_text(shown.clone().into());
                    slint::Timer::single_shot(Duration::from_secs(5), move || {
                        if let Some(ui) = weak.upgrade() {
                            if ui.get_status_text().as_str() == shown.as_str() {
                                ui.set_status_text("".into());
                            }
                        }
                    });
                }
            })
            .is_err()
            {
                tracing::debug!("status update dropped (event loop not running)");
            }
        } else {
            tracing::debug!(status = %message, "status update dropped (UI not attached)");
        }
    }

    /// Show/hide the "Connecting…" progress affordance.
    ///
    /// TODO(integration): `main-window.slint` has no progress widget yet;
    /// only the status bar is driven until the main-window workstream adds
    /// one.
    pub fn set_connect_progress(&self, active: bool) {
        tracing::debug!(active, "connect progress indicator (not wired to UI yet)");
    }

    /// Applies freshly saved settings to the live state: UI-behavior prefs,
    /// the transfer manager limits, and the single-click mode of the main
    /// window.
    pub fn apply_preferences(&mut self, prefs: &crate::settings::Preferences) {
        self.prefs = AppPreferences::from_settings(prefs);
        self.writeability
            .set_ttl_ms(prefs.remote_writeability_ttl_ms);
        self.transfer_manager
            .set_max_concurrent(prefs.max_concurrent.clamp(1, 8) as usize);
        self.transfer_manager
            .set_global_speed_limit_kbps(prefs.global_speed_kbps.clamp(0, 1_000_000));
        self.transfer_manager
            .set_show_queue_on_enqueue(prefs.show_queue_on_enqueue);
        if let Some(ui) = &self.ui {
            let ui = ui.clone();
            let single_click = prefs.single_click;
            if slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui.upgrade() {
                    ui.set_single_click_mode(single_click);
                }
            })
            .is_err()
            {
                tracing::debug!("single-click mode update dropped (event loop not running)");
            }
        }
    }

    /// Installs a freshly connected session by forwarding it to the UI event
    /// loop; the main window switches the right pane into remote mode there
    /// (port of `applyRemoteConnectedUI`). Safe to call from any thread:
    /// `self` may be a clone of the UI-thread original.
    pub fn install_session(&self, opt: SessionOptions, client: Box<dyn SftpClient>) {
        let Some(tx) = &self.ui_events_tx else {
            tracing::warn!("session dropped: UI event channel not attached");
            return;
        };
        if tx
            .send(UiEvent::Session {
                opt: Box::new(opt),
                client,
            })
            .is_err()
        {
            tracing::warn!("session dropped: UI event loop gone");
        }
    }
}

/// Moves `value` to the front of `list`, dropping duplicates and trimming the
/// tail to [`MAX_RECENT_ENTRIES`]. Mirrors the C++ `prependRecentValue`.
fn prepend_recent(list: &mut Vec<String>, value: String) {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return;
    }
    list.retain(|entry| entry != &trimmed);
    list.insert(0, trimmed);
    list.truncate(MAX_RECENT_ENTRIES);
}
