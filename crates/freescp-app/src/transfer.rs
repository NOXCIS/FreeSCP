//! Transfer queue manager, queue dialog bridge, and drag-and-drop prescan
//! helpers — Rust port of `ui/TransferManager.cpp`, `ui/TransferQueueDialog.cpp`
//! and the transfer parts of `ui/MainWindowTransfers.cpp`.
//!
//! # Concurrency design
//!
//! The manager never blocks the Slint event loop and never runs transfers on
//! it. Ownership is split into three layers:
//!
//! * **Shared state** — an `Arc<Mutex<Shared>>` holding the task list, the
//!   per-task records (including the owned `Box<dyn SftpClient>` connection
//!   and per-task cancel/pause flags), queue ordering state, hooks, and the
//!   list of event subscribers. `paused` and `running` are lock-free atomics
//!   next to the mutex so the cancel-poll callback can be cheap.
//! * **Tokio worker tasks** — `enqueue_*` only appends a record and spawns
//!   the scheduler on the tokio runtime (`tokio::runtime::Handle::try_current`,
//!   falling back to a lazily-created shared runtime if `main.rs` has not
//!   created one yet). The scheduler launches up to `MAX_CONCURRENT` worker
//!   tasks in queue order (rotating cursor, port of
//!   `nextQueuedTaskIndexLocked`); each worker takes its client out of the
//!   record, runs precheck + transfer, and returns the client to the record
//!   so `retry_task`/`retry_failed` can run it again.
//! * **UI bridge** — the dialog subscribes to a tokio `mpsc` unbounded
//!   channel (`subscribe()`). Structural changes (enqueue/cancel/finish)
//!   emit `ManagerEvent`s; the dialog awaits them inside `slint::spawn_local`
//!   (unbounded channel receive needs no reactor). Because that future runs
//!   on the Slint event-loop thread, snapshots are applied to the (non-`Send`)
//!   dialog component directly — `slint::invoke_from_event_loop` is not used
//!   here since it requires `Send` closures. All bridge entry points
//!   (`open_queue_dialog`, `maybe_notify_completed`) therefore assume they
//!   are called from the event-loop thread, which is how the main-window
//!   workstream invokes them (from Slint callbacks). Progress ticks
//!   deliberately do *not* emit events to avoid flooding the channel; they
//!   only update the shared records and are picked up by a `slint::Timer`
//!   polling every 250 ms. `refresh_dialog` skips `set_rows` when nothing
//!   changed so the table keeps its scroll position.
//!
//! Cancellation is cooperative: each record owns an `Arc<AtomicBool>` that
//!   the worker passes to the backend as the `should_cancel` callback;
//!   pausing is the same mechanism plus a `pause_flag` so the finalizer can
//!   tell `Cancelled` from `Paused` apart. `TransferManager::drop` mirrors
//!   the C++ destructor: mark everything cancelled and let workers unwind
//!   (their tokio tasks are not joined — see DEVIATIONS below).
//!
//! # Deviations from the C++ implementation
//!
//! * Worker connections: the C++ manager created isolated connections per
//!   attempt from `setSessionOptions` behind a mutex (libssh2 thread-safety
//!   workaround). Here, when `set_session_options` is set, workers create a
//!   fresh connection via `new_connection_like` + `connect` with the same
//!   3-attempt backoff; otherwise they transfer directly over the client
//!   passed to `enqueue_*`. Creation is not serialized (russh is thread-safe).
//! * Overwrite conflicts: the C++ worker raised a blocking modal prompt.
//!   Here the worker invokes the `conflict_hook` if installed, otherwise
//!   defaults to `Skip`. `main.rs` installs an rfd-based prompt hook at
//!   startup, so the default only applies to workers started before the
//!   hook is attached.
//! * Speed limits: the global limit is ported (bucket throttling inside
//!   the progress callback, mirroring the C++ sleep-in-progress approach)
//!   and per-task limits are honored by the worker (`run_one`); the dialog
//!   drives both via the speed row (Apply limit / Limit selected).
//! * Post-download mtime restore needs the `filetime` crate (MISSING-DEP),
//!   not declared in `Cargo.toml`; currently logged and skipped.
//! * Auto-clear (`clearFinishedOlderThan`) is ported as
//!   [`TransferManager::maybe_auto_clear`], driven from the dialog's
//!   Auto clear row with the same QSettings fallback chain
//!   (`queue-ui-state.toml` + Transfer/defaultQueueAutoClear* preferences).
//! * `watchDownloadsAndDeleteRemoteSources` /
//!   `watchUploadsAndDeleteLocalSources` (move-after-transfer) are owned by
//!   the main-window workstream's drag-and-drop handling and not ported.
//! * `QueueRow.bytes-*` are Slint `int` (i32) per the fixed contract, so
//!   byte counts saturate at `i32::MAX` (2.1 GB) instead of `u64`.
//! * The C++ badge row collapses into the single `status-line` string.

use std::cell::RefCell;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local, Utc};
use freescp_core::{ClientError, SessionOptions, SftpClient};
use serde::{Deserialize, Serialize};
use slint::ComponentHandle;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::remote;
use crate::ui::connection_dialog;
use crate::ui::main_window;
use crate::ui::transfer_queue::{self, QueueRow};

/// Maximum number of concurrent transfers. Mirrors the C++ default
/// (`maxConcurrent_ = 2`); adjustable at runtime via
/// [`TransferManager::set_max_concurrent`].
pub const MAX_CONCURRENT: usize = 2;

/// Snapshot poll interval for the queue dialog (progress ticks are not
/// pushed through the event channel).
const DIALOG_POLL_INTERVAL_MS: u64 = 250;

/// Deferred remote-refresh delay after a completed upload; mirrors the C++
/// `QTimer::singleShot(150, ...)` in `maybeRefreshRemoteAfterCompletedUploads`.
const REFRESH_DEBOUNCE_MS: u64 = 150;

// ---------------------------------------------------------------------------
// Public task model
// ---------------------------------------------------------------------------

/// Lifecycle of a queued transfer (C++ `TransferTask::Status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    Queued,
    Active,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

/// Transfer direction (C++ `TransferTask::Type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Download,
    Upload,
}

/// Immutable snapshot of one queued transfer.
#[derive(Debug, Clone)]
pub struct TransferTask {
    pub id: u64,
    pub direction: TransferDirection,
    /// Local path for uploads, remote path for downloads.
    pub source: String,
    /// Remote path for uploads, local path for downloads.
    pub dest: String,
    /// File name shown in the queue (C++ `displayNameForTask`).
    pub name: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub state: TransferState,
    pub error: Option<String>,
    /// Enqueue time (C++ `queuedAtMs`).
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
    /// Attempt counter (C++ `attempts`, rendered as "n/3").
    pub attempts: u32,
    /// Measured transfer speed in bytes/second (C++ `currentSpeedKBps`).
    pub speed_bps: f64,
    /// Estimated seconds remaining; 0 = unknown (C++ `etaSeconds`, -1
    /// unknown there, normalized to 0 here).
    pub eta_secs: f64,
    /// Per-task speed limit in KB/s; 0 = unlimited.
    pub speed_limit_kbps: i64,
    /// Epoch ms when the task entered a final state; 0 = not finished
    /// (C++ `finishedAtMs`, drives auto-clear).
    pub finished_at_ms: i64,
}

/// User decision for an overwrite conflict prompt (C++ Skip/Overwrite/Resume
/// plus the "apply to all" answers of the Qt QMessageBox: Yes/No/YesToAll/
/// NoToAll). `OverwriteAll`/`SkipAll` behave like `Overwrite`/`Skip` for the
/// current task; the prompting side remembers them for later conflicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictChoice {
    Skip,
    Overwrite,
    /// Answer once more conflicts the same way (Qt "Yes to All").
    OverwriteAll,
    /// Skip every later conflict too (Qt "No to All").
    SkipAll,
    /// Resume an interrupted download/upload; the resume flow is not wired
    /// into the conflict prompt yet (it currently offers Skip/Overwrite).
    #[allow(dead_code)]
    Resume,
}

/// Sticky "apply to all" overwrite policy shared by the conflict hook
/// (main.rs) and the queue dialog (retry). `None` = ask every time.
static STICKY_CONFLICT: OnceLock<Mutex<Option<ConflictChoice>>> = OnceLock::new();

/// Returns the global sticky overwrite policy slot.
pub fn sticky_conflict() -> &'static Mutex<Option<ConflictChoice>> {
    STICKY_CONFLICT.get_or_init(|| Mutex::new(None))
}

/// Clears any remembered "apply to all" overwrite policy. Called at the start
/// of every user-initiated batch (F5/F6/F7/F8 queueing) and before retries,
/// mirroring the C++ per-operation `OverwritePolicy` scope.
pub fn reset_conflict_policy() {
    if let Some(slot) = STICKY_CONFLICT.get() {
        if let Ok(mut guard) = slot.lock() {
            *guard = None;
        }
    }
}

/// Context passed to the conflict hook when a destination already exists.
#[derive(Debug, Clone)]
pub struct ConflictInfo {
    pub name: String,
    pub source_info: String,
    pub dest_info: String,
    pub direction: TransferDirection,
}

/// Events pushed from the manager to subscribers (the queue dialog).
#[derive(Debug, Clone)]
pub enum ManagerEvent {
    /// Task list/state changed structurally; re-snapshot.
    Changed,
    /// A transfer reached the `Completed` state.
    Completed {
        direction: TransferDirection,
        name: String,
    },
}

/// Summary of a remote download pre-scan
/// (port of `runRemoteDownloadPrescan`'s counting loop).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DownloadPlan {
    pub files: usize,
    pub bytes: u64,
}

/// Summary of a local upload pre-scan.
///
/// Delegates to [`crate::local_fs::prescan`] (the local-panel workstream's
/// canonical tree walk) and drops the `dirs` count this module does not
/// need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Prescan {
    pub files: usize,
    pub bytes: u64,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Mutable record for one task. The public `TransferTask` is a projection of
/// this; the rest is worker bookkeeping.
struct TaskRecord {
    task: TransferTask,
    /// Owned connection. `None` only while a worker holds it.
    client: Option<Box<dyn SftpClient>>,
    /// Cooperative cancel flag, passed to the backend as `should_cancel`.
    cancel_flag: Arc<AtomicBool>,
    /// Cooperative pause flag; distinguishes `Paused` from `Cancelled`.
    pause_flag: Arc<AtomicBool>,
    /// Resume on the next attempt (C++ `resumeHint`).
    resume_hint: bool,
    /// Attempt counter (C++ `attempts`, display-only there; logged here).
    attempts: u32,
    /// Per-task speed limit in KB/s; 0 = unlimited (C++ `speedLimitKBps`).
    speed_limit_kbps: i64,
    /// Speed measurement state: last sampled byte count + timestamp, and the
    /// EMA-smoothed bytes/second value (refreshed by [`TransferManager::tasks`]).
    last_done: u64,
    last_time: Instant,
    speed_bps: f64,
}

struct Shared {
    tasks: Vec<TaskRecord>,
    next_id: u64,
    /// Rotating scheduling cursor (C++ `schedulingCursor_`).
    cursor: usize,
    max_concurrent: usize,
    global_speed_kbps: i64,
    /// Queue-dialog auto-clear state (C++ UI/transferQueue/autoClearMode +
    /// autoClearMinutes): 0 Off, 1 Completed, 2 Failed/Canceled, 3 All
    /// finished; minutes 1..=1440.
    auto_clear_mode: i32,
    auto_clear_minutes: i32,
    session_options: Option<SessionOptions>,
    refresh_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    notify_hook: Option<Arc<dyn Fn(String) + Send + Sync>>,
    conflict_hook: Option<Arc<dyn Fn(ConflictInfo) -> ConflictChoice + Send + Sync>>,
    /// C++ `UI/showQueueOnEnqueue` (default true).
    show_queue_on_enqueue: bool,
    /// Completed ids already announced via `maybe_notify_completed`.
    seen_notified: HashSet<u64>,
    /// Upload ids that already triggered the refresh hook.
    seen_refreshed: HashSet<u64>,
    subscribers: Vec<UnboundedSender<ManagerEvent>>,
}

impl Shared {
    fn task(&self, id: u64) -> Option<&TaskRecord> {
        self.tasks.iter().find(|t| t.task.id == id)
    }

    fn task_mut(&mut self, id: u64) -> Option<&mut TaskRecord> {
        self.tasks.iter_mut().find(|t| t.task.id == id)
    }

    /// Port of `nextQueuedTaskIndexLocked`: round-robin cursor over queued
    /// tasks so the head of the queue cannot starve later entries.
    fn next_queued_index(&mut self) -> Option<usize> {
        if self.tasks.is_empty() {
            self.cursor = 0;
            return None;
        }
        if self.cursor >= self.tasks.len() {
            self.cursor = 0;
        }
        let total = self.tasks.len();
        for off in 0..total {
            let idx = (self.cursor + off) % total;
            if self.tasks[idx].task.state == TransferState::Queued {
                self.cursor = (idx + 1) % total;
                return Some(idx);
            }
        }
        None
    }
}

/// Everything a spawned worker needs for one attempt.
struct WorkerArgs {
    id: u64,
    direction: TransferDirection,
    source: String,
    dest: String,
    client: Box<dyn SftpClient>,
    resume: bool,
}

/// Result of one worker attempt; the finalizer maps this onto the record.
#[derive(Debug)]
enum Outcome {
    Done,
    Failed(String),
    /// Cancel/pause was requested during the attempt (C++ `shouldCancel()`).
    Stopped,
}

/// Bucket-throttle state captured by the progress callback.
struct Throttle {
    last_done: AtomicU64,
    last_tick: Mutex<Instant>,
}

// ---------------------------------------------------------------------------
// TransferManager
// ---------------------------------------------------------------------------

/// Transfer queue manager: schedules concurrent worker transfers on the
/// tokio runtime with per-task cancel/pause, retry, and completion events.
pub struct TransferManager {
    shared: Arc<Mutex<Shared>>,
    paused: Arc<AtomicBool>,
    running: Arc<AtomicUsize>,
}

impl TransferManager {
    pub fn new() -> Self {
        TransferManager {
            shared: Arc::new(Mutex::new(Shared {
                tasks: Vec::new(),
                next_id: 1,
                cursor: 0,
                max_concurrent: MAX_CONCURRENT,
                global_speed_kbps: 0,
                auto_clear_mode: 0,
                auto_clear_minutes: 15,
                session_options: None,
                refresh_hook: None,
                notify_hook: None,
                conflict_hook: None,
                show_queue_on_enqueue: true,
                seen_notified: HashSet::new(),
                seen_refreshed: HashSet::new(),
                subscribers: Vec::new(),
            })),
            paused: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Thread-safe snapshot of the task list in queue order. Also refreshes
    /// the per-task speed/ETA measurement (EMA over progress deltas).
    pub fn tasks(&self) -> Vec<TransferTask> {
        let mut s = self.shared.lock().unwrap();
        let now = Instant::now();
        s.tasks
            .iter_mut()
            .map(|r| {
                let active = r.task.state == TransferState::Active;
                let dt = now.duration_since(r.last_time).as_secs_f64();
                let inst = if active && dt > 0.05 {
                    r.task.bytes_done.saturating_sub(r.last_done) as f64 / dt
                } else {
                    0.0
                };
                r.speed_bps = if active {
                    r.speed_bps * 0.7 + inst * 0.3
                } else {
                    0.0
                };
                r.last_done = r.task.bytes_done;
                r.last_time = now;
                let eta = if r.speed_bps > 0.0 && r.task.bytes_total > r.task.bytes_done {
                    (r.task.bytes_total - r.task.bytes_done) as f64 / r.speed_bps
                } else {
                    0.0
                };
                let mut t = r.task.clone();
                t.name = display_name(&t.source);
                t.attempts = r.attempts;
                t.speed_bps = r.speed_bps;
                t.eta_secs = eta;
                t.speed_limit_kbps = r.speed_limit_kbps;
                t
            })
            .collect()
    }

    /// Queue a remote-to-local download. Returns immediately; the transfer
    /// runs on the tokio runtime. `resume` tries to continue a partial file.
    pub fn enqueue_download(
        &self,
        client: Box<dyn SftpClient>,
        remote: String,
        local: String,
        resume: bool,
    ) -> u64 {
        self.enqueue(TransferDirection::Download, client, remote, local, resume)
    }

    /// Queue a local-to-remote upload. Returns immediately; the transfer
    /// runs on the tokio runtime. `resume` tries to continue a partial file.
    pub fn enqueue_upload(
        &self,
        client: Box<dyn SftpClient>,
        local: String,
        remote: String,
        resume: bool,
    ) -> u64 {
        self.enqueue(TransferDirection::Upload, client, local, remote, resume)
    }

    fn enqueue(
        &self,
        direction: TransferDirection,
        client: Box<dyn SftpClient>,
        source: String,
        dest: String,
        resume: bool,
    ) -> u64 {
        let id = {
            let mut s = self.shared.lock().unwrap();
            let id = s.next_id;
            s.next_id += 1;
            s.tasks.push(TaskRecord {
                task: TransferTask {
                    id,
                    direction,
                    source,
                    dest,
                    name: String::new(), // refreshed by `tasks()` from source
                    bytes_done: 0,
                    bytes_total: 0,
                    state: TransferState::Queued,
                    error: None,
                    created_at: Utc::now(),
                    attempts: 0,
                    speed_bps: 0.0,
                    eta_secs: 0.0,
                    speed_limit_kbps: 0,
                    finished_at_ms: 0,
                },
                client: Some(client),
                cancel_flag: Arc::new(AtomicBool::new(false)),
                pause_flag: Arc::new(AtomicBool::new(false)),
                resume_hint: resume,
                attempts: 0,
                speed_limit_kbps: 0,
                last_done: 0,
                last_time: Instant::now(),
                speed_bps: 0.0,
            });
            id
        };
        self.notify_changed();
        self.schedule();
        id
    }

    /// Cancel one queued/active/paused task. Active workers observe the
    /// cancel flag through the backend's `should_cancel` callback.
    pub fn cancel(&self, id: u64) {
        let mut changed = false;
        {
            let mut s = self.shared.lock().unwrap();
            if let Some(rec) = s.task_mut(id) {
                if matches!(
                    rec.task.state,
                    TransferState::Queued | TransferState::Active | TransferState::Paused
                ) {
                    rec.task.state = TransferState::Cancelled;
                    rec.task.error = None;
                    rec.task.finished_at_ms = now_epoch_ms();
                    rec.cancel_flag.store(true, Ordering::SeqCst);
                    rec.pause_flag.store(false, Ordering::SeqCst);
                    changed = true;
                }
            }
        }
        if changed {
            self.notify_changed();
        }
    }

    /// Cancel all queued, active, and paused tasks (C++ `cancelAll`).
    pub fn cancel_all(&self) {
        let mut changed = false;
        {
            let mut s = self.shared.lock().unwrap();
            for rec in &mut s.tasks {
                if matches!(
                    rec.task.state,
                    TransferState::Queued | TransferState::Active | TransferState::Paused
                ) {
                    rec.task.state = TransferState::Cancelled;
                    rec.task.error = None;
                    rec.task.finished_at_ms = now_epoch_ms();
                    rec.cancel_flag.store(true, Ordering::SeqCst);
                    rec.pause_flag.store(false, Ordering::SeqCst);
                    changed = true;
                }
            }
        }
        if changed {
            self.notify_changed();
        }
    }

    /// Remove `Completed` tasks (C++ `clearCompleted`).
    pub fn clear_finished(&self) {
        let changed = {
            let mut s = self.shared.lock().unwrap();
            let before = s.tasks.len();
            s.tasks.retain(|r| r.task.state != TransferState::Completed);
            let changed = s.tasks.len() != before;
            if changed {
                prune_seen_sets(&mut s);
            }
            changed
        };
        if changed {
            self.notify_changed();
        }
    }

    /// Remove `Failed` and `Cancelled` tasks (C++ `clearFailedCanceled`).
    pub fn clear_failed_cancelled(&self) {
        let changed = {
            let mut s = self.shared.lock().unwrap();
            let before = s.tasks.len();
            s.tasks.retain(|r| {
                !matches!(
                    r.task.state,
                    TransferState::Failed | TransferState::Cancelled
                )
            });
            let changed = s.tasks.len() != before;
            if changed {
                prune_seen_sets(&mut s);
            }
            changed
        };
        if changed {
            self.notify_changed();
        }
    }

    /// Pause the whole queue (C++ `pauseAll`). Running tasks transition to
    /// `Paused` and their workers unwind via the pause flag.
    pub fn pause_all(&self) {
        self.paused.store(true, Ordering::SeqCst);
        let mut changed = false;
        {
            let mut s = self.shared.lock().unwrap();
            for rec in &mut s.tasks {
                if rec.task.state == TransferState::Active {
                    rec.pause_flag.store(true, Ordering::SeqCst);
                    rec.task.state = TransferState::Paused;
                    changed = true;
                }
            }
        }
        if changed {
            self.notify_changed();
        }
    }

    /// Resume the queue and all paused tasks (C++ `resumeAll`). Resumed
    /// tasks are requeued with the resume hint armed.
    pub fn resume_all(&self) {
        self.paused.store(false, Ordering::SeqCst);
        let mut changed = false;
        {
            let mut s = self.shared.lock().unwrap();
            for rec in &mut s.tasks {
                if rec.task.state == TransferState::Paused {
                    rec.pause_flag.store(false, Ordering::SeqCst);
                    rec.task.state = TransferState::Queued;
                    rec.resume_hint = true;
                    changed = true;
                }
            }
        }
        if changed {
            self.notify_changed();
        }
        self.schedule();
    }

    /// Pause one task (C++ `pauseTask`).
    pub fn pause_task(&self, id: u64) {
        let mut changed = false;
        {
            let mut s = self.shared.lock().unwrap();
            if let Some(rec) = s.task_mut(id) {
                if matches!(
                    rec.task.state,
                    TransferState::Queued | TransferState::Active
                ) {
                    rec.pause_flag.store(true, Ordering::SeqCst);
                    rec.task.state = TransferState::Paused;
                    changed = true;
                }
            }
        }
        if changed {
            self.notify_changed();
        }
    }

    /// Resume one paused task (C++ `resumeTask`). If the worker is still
    /// unwinding from the pause, the finalizer notices the fresh `Queued`
    /// state and leaves it alone.
    pub fn resume_task(&self, id: u64) {
        let mut changed = false;
        {
            let mut s = self.shared.lock().unwrap();
            if let Some(rec) = s.task_mut(id) {
                if rec.task.state == TransferState::Paused {
                    rec.pause_flag.store(false, Ordering::SeqCst);
                    rec.task.state = TransferState::Queued;
                    rec.resume_hint = true;
                    changed = true;
                }
            }
        }
        if changed {
            self.notify_changed();
        }
        self.schedule();
    }

    /// Requeue all failed/cancelled tasks (C++ `retryFailed`).
    pub fn retry_failed(&self) {
        let mut changed = false;
        {
            let mut s = self.shared.lock().unwrap();
            for rec in &mut s.tasks {
                if matches!(
                    rec.task.state,
                    TransferState::Failed | TransferState::Cancelled
                ) {
                    reset_for_retry(rec);
                    changed = true;
                }
            }
        }
        if changed {
            self.notify_changed();
        }
        self.schedule();
    }

    /// Requeue a single failed/cancelled task (C++ `retryTask`).
    pub fn retry_task(&self, id: u64) {
        // A retry is a fresh user-initiated operation: any remembered
        // "apply to all" overwrite policy from a previous batch no longer
        // applies (the C++ policy was scoped to one operation loop).
        reset_conflict_policy();
        let mut changed = false;
        {
            let mut s = self.shared.lock().unwrap();
            if let Some(rec) = s.task_mut(id) {
                if matches!(
                    rec.task.state,
                    TransferState::Failed | TransferState::Cancelled
                ) {
                    reset_for_retry(rec);
                    changed = true;
                }
            }
        }
        if changed {
            self.notify_changed();
        }
        self.schedule();
    }

    /// Maximum number of simultaneous transfers.
    #[allow(dead_code)] // the queue dialog shows the limits via the status line instead
    pub fn max_concurrent(&self) -> usize {
        let s = self.shared.lock().unwrap();
        s.max_concurrent
    }

    /// Set the parallel transfer limit (clamped to >= 1, like the C++ setter).
    pub fn set_max_concurrent(&self, n: usize) {
        let mut s = self.shared.lock().unwrap();
        s.max_concurrent = n.max(1);
        drop(s);
        self.schedule();
    }

    /// Global speed limit in KB/s; 0 = unlimited.
    pub fn global_speed_limit_kbps(&self) -> i64 {
        let s = self.shared.lock().unwrap();
        s.global_speed_kbps
    }

    /// Set the global speed limit (KB/s, 0 = unlimited).
    pub fn set_global_speed_limit_kbps(&self, kbps: i64) {
        let mut s = self.shared.lock().unwrap();
        s.global_speed_kbps = kbps.max(0);
    }

    /// Set a per-task speed limit (KB/s, 0 = unlimited; C++
    /// `setTaskSpeedLimit`).
    pub fn set_task_speed_limit(&self, id: u64, kbps: i64) {
        let mut s = self.shared.lock().unwrap();
        if let Some(rec) = s.task_mut(id) {
            rec.speed_limit_kbps = kbps.max(0);
        }
    }

    /// Set the queue auto-clear state (C++ UI/transferQueue/autoClearMode +
    /// autoClearMinutes): mode 0 Off, 1 Completed, 2 Failed/Canceled,
    /// 3 All finished; minutes 1..=1440.
    pub fn set_auto_clear(&self, mode: i32, minutes: i32) {
        let mut s = self.shared.lock().unwrap();
        s.auto_clear_mode = mode.clamp(0, 3);
        s.auto_clear_minutes = minutes.clamp(1, 1440);
    }

    /// Port of `TransferManager::clearFinishedOlderThan` driven by the
    /// dialog's auto-clear state: drops terminal tasks finished at least
    /// `auto_clear_minutes` ago according to the mode. Called from the
    /// dialog refresh loop (mirrors the C++ `maybeAutoClear` in `refresh`).
    pub fn maybe_auto_clear(&self) {
        let (mode, minutes) = {
            let s = self.shared.lock().unwrap();
            (s.auto_clear_mode, s.auto_clear_minutes)
        };
        if mode == 0 || minutes <= 0 {
            return;
        }
        let clear_done = mode == 1 || mode == 3;
        let clear_failed = mode == 2 || mode == 3;
        let cutoff = now_epoch_ms() - i64::from(minutes) * 60_000;
        let changed = {
            let mut s = self.shared.lock().unwrap();
            let before = s.tasks.len();
            s.tasks.retain(|r| {
                let finished = r.task.finished_at_ms;
                let candidate = (clear_done && r.task.state == TransferState::Completed)
                    || (clear_failed
                        && matches!(
                            r.task.state,
                            TransferState::Failed | TransferState::Cancelled
                        ));
                !(candidate && finished > 0 && finished <= cutoff)
            });
            let changed = s.tasks.len() != before;
            if changed {
                prune_seen_sets(&mut s);
            }
            changed
        };
        if changed {
            self.notify_changed();
        }
    }

    /// Whether the whole queue is paused.
    pub fn is_queue_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Session options used to create isolated worker connections, port of
    /// the C++ `setSessionOptions`. When unset, workers transfer directly
    /// over the client passed to `enqueue_*`.
    pub fn set_session_options(&self, opt: Option<SessionOptions>) {
        let mut s = self.shared.lock().unwrap();
        s.session_options = opt;
    }

    /// Refresh-after-upload hook, port of
    /// `MainWindow::maybeRefreshRemoteAfterCompletedUploads`. Invoked once
    /// per newly-completed upload (seen-id dedup + 150 ms debounce); the
    /// main-window workstream sets it to its remote panel refresh and is
    /// responsible for the "upload target inside current root" check.
    pub fn set_refresh_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        let mut s = self.shared.lock().unwrap();
        s.refresh_hook = hook;
    }

    /// Hook that receives the "Upload completed: name" / "N transfers
    /// completed" message computed by `maybe_notify_completed`. The
    /// main-window workstream sets it to its status line.
    pub fn set_notify_hook(&self, hook: Option<Arc<dyn Fn(String) + Send + Sync>>) {
        let mut s = self.shared.lock().unwrap();
        s.notify_hook = hook;
    }

    /// Overwrite-conflict prompt hook. Invoked synchronously from the worker
    /// (like the C++ modal prompt). When unset, conflicts are skipped.
    pub fn set_conflict_hook(
        &self,
        hook: Option<Arc<dyn Fn(ConflictInfo) -> ConflictChoice + Send + Sync>>,
    ) {
        let mut s = self.shared.lock().unwrap();
        s.conflict_hook = hook;
    }

    /// C++ `UI/showQueueOnEnqueue` preference (default true).
    pub fn set_show_queue_on_enqueue(&self, on: bool) {
        let mut s = self.shared.lock().unwrap();
        s.show_queue_on_enqueue = on;
    }

    pub fn show_queue_on_enqueue(&self) -> bool {
        let s = self.shared.lock().unwrap();
        s.show_queue_on_enqueue
    }

    /// Subscribe to manager events (used by the queue dialog). Senders of
    /// dead receivers are pruned lazily on emit.
    pub fn subscribe(&self) -> UnboundedReceiver<ManagerEvent> {
        let (tx, rx) = unbounded_channel();
        let mut s = self.shared.lock().unwrap();
        s.subscribers.push(tx);
        rx
    }

    fn notify_hook(&self) -> Option<Arc<dyn Fn(String) + Send + Sync>> {
        let s = self.shared.lock().unwrap();
        s.notify_hook.clone()
    }

    fn notify_changed(&self) {
        notify_subscribers(&self.shared, vec![ManagerEvent::Changed]);
    }

    /// Port of `TransferManager::schedule()`: launch workers while capacity
    /// remains. Safe to call from any thread; workers are spawned on the
    /// tokio runtime.
    fn schedule(&self) {
        schedule(
            self.shared.clone(),
            self.paused.clone(),
            self.running.clone(),
        );
    }

    /// Port of `maybeNotifyCompletedTransfers`: returns the message for
    /// tasks that newly reached `Completed` since the last call.
    fn take_completed_notice(&self) -> Option<String> {
        let mut s = self.shared.lock().unwrap();
        // Collect the newly-completed tasks under an immutable borrow first,
        // then mutate `seen_notified` in a second pass.
        let fresh: Vec<(u64, TransferDirection, String)> = s
            .tasks
            .iter()
            .filter(|rec| rec.task.state == TransferState::Completed)
            .filter(|rec| !s.seen_notified.contains(&rec.task.id))
            .map(|rec| {
                let upload = rec.task.direction == TransferDirection::Upload;
                let path = if upload {
                    rec.task.source.as_str()
                } else {
                    rec.task.dest.as_str()
                };
                (rec.task.id, rec.task.direction, display_name(path))
            })
            .collect();
        let newly = fresh.len();
        for (id, _direction, _name) in &fresh {
            s.seen_notified.insert(*id);
        }
        let ids: HashSet<u64> = s.tasks.iter().map(|t| t.task.id).collect();
        s.seen_notified.retain(|x| ids.contains(x));
        if newly == 0 {
            None
        } else if newly == 1 {
            let (_, direction, name) = &fresh[0];
            Some(if *direction == TransferDirection::Upload {
                format!("Upload completed: {name}")
            } else {
                format!("Download completed: {name}")
            })
        } else {
            Some(format!("{newly} transfers completed"))
        }
    }
}

impl Default for TransferManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TransferManager {
    fn drop(&mut self) {
        // Port of ~TransferManager: cancel everything and let workers unwind.
        // Their tokio tasks are not joined here (their handles are not
        // stored); they hold their own Arc clones of the shared state and
        // observe the flags set below.
        self.paused.store(true, Ordering::SeqCst);
        let mut s = self.shared.lock().unwrap();
        for rec in &mut s.tasks {
            rec.cancel_flag.store(true, Ordering::SeqCst);
            if matches!(
                rec.task.state,
                TransferState::Queued | TransferState::Active | TransferState::Paused
            ) {
                rec.task.state = TransferState::Cancelled;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduler + worker
// ---------------------------------------------------------------------------

/// Returns the ambient tokio runtime handle, creating a process-wide shared
/// runtime if `main.rs` has not created one yet.
fn runtime_handle() -> tokio::runtime::Handle {
    tokio::runtime::Handle::try_current().unwrap_or_else(|_| {
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to create tokio runtime"))
            .handle()
            .clone()
    })
}

fn schedule(shared: Arc<Mutex<Shared>>, paused: Arc<AtomicBool>, running: Arc<AtomicUsize>) {
    if paused.load(Ordering::SeqCst) {
        return;
    }
    loop {
        let worker = {
            let mut s = shared.lock().unwrap();
            if paused.load(Ordering::SeqCst) || running.load(Ordering::SeqCst) >= s.max_concurrent {
                return;
            }
            let Some(idx) = s.next_queued_index() else {
                return;
            };
            let rec = &mut s.tasks[idx];
            rec.task.state = TransferState::Active;
            rec.task.bytes_done = 0;
            rec.task.bytes_total = 0;
            rec.task.error = None;
            rec.attempts += 1;
            let client = rec
                .client
                .take()
                .expect("queued task always owns its client");
            WorkerArgs {
                id: rec.task.id,
                direction: rec.task.direction,
                source: rec.task.source.clone(),
                dest: rec.task.dest.clone(),
                client,
                resume: rec.resume_hint,
            }
        };
        running.fetch_add(1, Ordering::SeqCst);
        notify_subscribers(&shared, vec![ManagerEvent::Changed]);
        let rt = runtime_handle();
        rt.spawn(run_worker(
            shared.clone(),
            paused.clone(),
            running.clone(),
            worker,
        ));
    }
}

fn notify_subscribers(shared: &Mutex<Shared>, events: Vec<ManagerEvent>) {
    let mut s = shared.lock().unwrap();
    let mut dead: Vec<usize> = Vec::new();
    for ev in events {
        for (i, sub) in s.subscribers.iter().enumerate() {
            if sub.send(ev.clone()).is_err() {
                dead.push(i);
            }
        }
    }
    for i in dead.into_iter().rev() {
        s.subscribers.swap_remove(i);
    }
}

fn reset_for_retry(rec: &mut TaskRecord) {
    rec.task.state = TransferState::Queued;
    rec.task.bytes_done = 0;
    rec.task.bytes_total = 0;
    rec.task.error = None;
    rec.task.finished_at_ms = 0;
    rec.attempts = 0;
    rec.speed_bps = 0.0;
    rec.last_done = 0;
    rec.last_time = Instant::now();
    rec.cancel_flag.store(false, Ordering::SeqCst);
    rec.pause_flag.store(false, Ordering::SeqCst);
}

/// Current wall-clock time in epoch milliseconds (C++
/// `QDateTime::currentMSecsSinceEpoch`).
fn now_epoch_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn prune_seen_sets(s: &mut Shared) {
    let ids: HashSet<u64> = s.tasks.iter().map(|t| t.task.id).collect();
    s.seen_notified.retain(|x| ids.contains(x));
    s.seen_refreshed.retain(|x| ids.contains(x));
}

async fn run_worker(
    shared: Arc<Mutex<Shared>>,
    paused: Arc<AtomicBool>,
    running: Arc<AtomicUsize>,
    args: WorkerArgs,
) {
    let id = args.id;
    let (outcome, client) = run_one(shared.clone(), paused.clone(), args).await;

    // Finalize: map the outcome onto the record, return the client, trigger
    // the refresh hook for completed uploads, and emit events.
    let mut hook: Option<Arc<dyn Fn() + Send + Sync>> = None;
    let events = {
        let mut s = shared.lock().unwrap();
        let mut completed: Option<(TransferDirection, String)> = None;
        let mut upload_done = false;
        {
            if let Some(rec) = s.task_mut(id) {
                rec.client = client;
                match outcome {
                    Outcome::Done => {
                        rec.task.state = TransferState::Completed;
                        rec.task.finished_at_ms = now_epoch_ms();
                        if rec.task.bytes_total > 0 {
                            rec.task.bytes_done = rec.task.bytes_total;
                        }
                        upload_done = rec.task.direction == TransferDirection::Upload;
                        let path = if upload_done {
                            rec.task.source.clone()
                        } else {
                            rec.task.dest.clone()
                        };
                        completed = Some((rec.task.direction, display_name(&path)));
                    }
                    Outcome::Failed(_) | Outcome::Stopped => {
                        let cancel = rec.cancel_flag.load(Ordering::SeqCst);
                        let pause =
                            rec.pause_flag.load(Ordering::SeqCst) || paused.load(Ordering::SeqCst);
                        if cancel {
                            rec.task.state = TransferState::Cancelled;
                            rec.task.finished_at_ms = now_epoch_ms();
                        } else if pause {
                            rec.task.state = TransferState::Paused;
                        } else if rec.task.state == TransferState::Queued {
                            // Resumed/retried while this worker was
                            // unwinding; keep the fresh queued state and let
                            // the scheduler relaunch with resume enabled.
                        } else {
                            rec.task.state = TransferState::Failed;
                            rec.task.finished_at_ms = now_epoch_ms();
                            rec.task.error = match outcome {
                                Outcome::Failed(msg) => Some(msg),
                                _ => None,
                            };
                        }
                    }
                }
                tracing::debug!(
                    target: "freescp.transfer",
                    task_id = id,
                    attempt = rec.attempts,
                    state = ?rec.task.state,
                    "transfer worker finished"
                );
            }
        }
        let ids: HashSet<u64> = s.tasks.iter().map(|t| t.task.id).collect();
        s.seen_notified.retain(|x| ids.contains(x));
        s.seen_refreshed.retain(|x| ids.contains(x));
        if upload_done && s.seen_refreshed.insert(id) && s.refresh_hook.is_some() {
            hook = s.refresh_hook.clone();
        }
        let mut events = Vec::with_capacity(2);
        events.push(ManagerEvent::Changed);
        if let Some((direction, name)) = completed {
            events.push(ManagerEvent::Completed { direction, name });
        }
        events
    };
    notify_subscribers(&shared, events);

    if let Some(hook) = hook {
        let rt = runtime_handle();
        rt.spawn(async move {
            tokio::time::sleep(Duration::from_millis(REFRESH_DEBOUNCE_MS)).await;
            hook();
        });
    }

    running.fetch_sub(1, Ordering::SeqCst);
    schedule(shared, paused, running);
}

/// Port of `createWorkerClient`: build an isolated connected client from the
/// task's template client, with the C++ 3-attempt exponential backoff
/// (500 ms, 1000 ms). Creation is not serialized behind a mutex: the C++
/// `connFactoryMutex_` existed for libssh2 initialization; russh is
/// thread-safe.
async fn create_worker_client(
    base: &dyn SftpClient,
    opt: &SessionOptions,
    task_id: u64,
    shared: &Arc<Mutex<Shared>>,
    paused: &Arc<AtomicBool>,
) -> Result<Box<dyn SftpClient>, ClientError> {
    let mut last_err: Option<ClientError> = None;
    for attempt in 0..3u32 {
        if paused.load(Ordering::SeqCst) || task_cancel_requested(shared, task_id) {
            return Err(ClientError::Other("Transfer queue paused/canceled".into()));
        }
        match base.new_connection_like(opt).await {
            Ok(mut conn) => match conn.connect(opt).await {
                Ok(()) => return Ok(conn),
                Err(err) => last_err = Some(err),
            },
            Err(err) => last_err = Some(err),
        }
        if attempt < 2 {
            tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
        }
    }
    Err(last_err
        .unwrap_or_else(|| ClientError::Other("Could not create transfer connection".into())))
}

fn task_cancel_requested(shared: &Arc<Mutex<Shared>>, id: u64) -> bool {
    let s = shared.lock().unwrap();
    s.task(id)
        .map(|r| r.cancel_flag.load(Ordering::SeqCst))
        .unwrap_or(true)
}

/// One full transfer attempt: connection, precheck, transfer, teardown.
async fn run_one(
    shared: Arc<Mutex<Shared>>,
    paused: Arc<AtomicBool>,
    args: WorkerArgs,
) -> (Outcome, Option<Box<dyn SftpClient>>) {
    let WorkerArgs {
        id,
        direction,
        ref source,
        ref dest,
        client: base,
        resume,
    } = args;
    let (opts, conflict_hook, global_limit, task_limit) = {
        let s = shared.lock().unwrap();
        (
            s.session_options.clone(),
            s.conflict_hook.clone(),
            s.global_speed_kbps,
            s.task(id).map(|r| r.speed_limit_kbps).unwrap_or(0),
        )
    };
    // C++ applies min(taskLimit, globalLimit) when both are set; otherwise
    // whichever one is configured (TransferManager::effectiveSpeedLimit).
    let effective_limit = if task_limit > 0 && global_limit > 0 {
        task_limit.min(global_limit)
    } else {
        task_limit.max(global_limit)
    };

    // Prefer an isolated connection created from the template client when
    // session options are available; otherwise transfer over the enqueued
    // client directly.
    let (mut worker, base): (Box<dyn SftpClient>, Option<Box<dyn SftpClient>>) = match &opts {
        None => (base, None),
        Some(opt) => match create_worker_client(base.as_ref(), opt, id, &shared, &paused).await {
            Ok(w) => (w, Some(base)),
            Err(err) => {
                return (Outcome::Failed(transfer_error_for_ui(&err)), Some(base));
            }
        },
    };

    let cancel_flag = {
        let s = shared.lock().unwrap();
        s.task(id)
            .map(|r| r.cancel_flag.clone())
            .unwrap_or_default()
    };
    let should_cancel = {
        let paused = paused.clone();
        let flag = cancel_flag.clone();
        move || paused.load(Ordering::SeqCst) || flag.load(Ordering::SeqCst)
    };

    let caps = worker.capabilities();
    let mut resume = resume && caps.supports_resume;

    // ---- Precheck (port of the worker precheck / conflict prompts) ----
    match direction {
        TransferDirection::Upload => {
            if caps.supports_metadata {
                match worker.exists(dest).await {
                    Ok(Some(_)) => {
                        let name = display_name(source);
                        let src_info = local_file_info(source);
                        let dst_info = match worker.stat(dest).await {
                            Ok(fi) => {
                                format!("{} bytes, {}", fi.size, local_short_time(fi.mtime as i64))
                            }
                            Err(_) => "? bytes, ?".to_string(),
                        };
                        let choice = prompt_conflict(
                            &conflict_hook,
                            ConflictInfo {
                                name,
                                source_info: src_info,
                                dest_info: dst_info,
                                direction,
                            },
                        );
                        if should_cancel() {
                            return end_run(worker, base, Outcome::Stopped).await;
                        }
                        match choice {
                            ConflictChoice::Skip | ConflictChoice::SkipAll => {
                                return end_run(worker, base, Outcome::Done).await;
                            }
                            ConflictChoice::Resume if caps.supports_resume => resume = true,
                            _ => {}
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        if should_cancel() {
                            return end_run(worker, base, Outcome::Stopped).await;
                        }
                        return end_run(worker, base, Outcome::Failed(transfer_error_for_ui(&err)))
                            .await;
                    }
                }
                if let Err(msg) = ensure_remote_dir(&mut *worker, &parent_dir(dest)).await {
                    if should_cancel() {
                        return end_run(worker, base, Outcome::Stopped).await;
                    }
                    return end_run(worker, base, Outcome::Failed(msg)).await;
                }
            }
        }
        TransferDirection::Download => {
            if Path::new(dest).exists() {
                let name = display_name(dest);
                let src_info = match worker.stat(source).await {
                    Ok(fi) => format!("{} bytes, {}", fi.size, local_short_time(fi.mtime as i64)),
                    Err(_) => "? bytes, ?".to_string(),
                };
                let dst_info = local_file_info(dest);
                let choice = prompt_conflict(
                    &conflict_hook,
                    ConflictInfo {
                        name,
                        source_info: src_info,
                        dest_info: dst_info,
                        direction,
                    },
                );
                if should_cancel() {
                    return end_run(worker, base, Outcome::Stopped).await;
                }
                match choice {
                    ConflictChoice::Skip | ConflictChoice::SkipAll => {
                        return end_run(worker, base, Outcome::Done).await;
                    }
                    ConflictChoice::Resume if caps.supports_resume => resume = true,
                    _ => {}
                }
            }
            if let Some(parent) = Path::new(dest).parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(err) = std::fs::create_dir_all(parent) {
                        return end_run(
                            worker,
                            base,
                            Outcome::Failed(format!(
                                "Could not create local destination directory: {err}"
                            )),
                        )
                        .await;
                    }
                }
            }
        }
    }

    // ---- Transfer ----
    let progress = make_progress_cb(shared.clone(), id, effective_limit);
    let cancel_cb: Option<Box<dyn Fn() -> bool + Send + Sync>> = Some(Box::new(should_cancel));
    let result = match direction {
        TransferDirection::Upload => {
            worker
                .put(source, dest, Some(progress), cancel_cb, resume)
                .await
        }
        TransferDirection::Download => {
            worker
                .get(source, dest, Some(progress), cancel_cb, resume)
                .await
        }
    };

    match result {
        Ok(()) => {
            if direction == TransferDirection::Download {
                // C++ restored the remote mtime on the local file here.
                // TODO(MISSING-DEP): filetime (set local file mtime after
                // download; std::fs has no mtime setter).
                if let Ok(fi) = worker.stat(source).await {
                    if fi.mtime > 0 {
                        tracing::debug!(
                            target: "freescp.transfer",
                            task_id = id,
                            mtime = fi.mtime,
                            "local mtime restore skipped (filetime not available)"
                        );
                    }
                }
            }
            end_run(worker, base, Outcome::Done).await
        }
        Err(ClientError::Cancelled) => end_run(worker, base, Outcome::Stopped).await,
        Err(err) => end_run(worker, base, Outcome::Failed(transfer_error_for_ui(&err))).await,
    }
}

/// Disconnect the worker connection (best effort, bounded) and return the
/// client that must go back into the task record: the template when a fresh
/// connection was used, the worker itself otherwise.
async fn end_run(
    mut worker: Box<dyn SftpClient>,
    mut base: Option<Box<dyn SftpClient>>,
    outcome: Outcome,
) -> (Outcome, Option<Box<dyn SftpClient>>) {
    let _ = tokio::time::timeout(Duration::from_secs(5), worker.disconnect()).await;
    if base.is_none() {
        base = Some(worker);
    }
    (outcome, base)
}

fn prompt_conflict(
    hook: &Option<Arc<dyn Fn(ConflictInfo) -> ConflictChoice + Send + Sync>>,
    info: ConflictInfo,
) -> ConflictChoice {
    match hook {
        Some(hook) => hook(info),
        // The main window installs the prompt hook at startup; the fallback
        // only covers workers started before it is attached and never
        // overwrites existing data implicitly.
        None => ConflictChoice::Skip,
    }
}

/// Port of the C++ upload precheck's `ensureRemoteDir`: walk the parent path
/// components, creating missing remote directories (0755).
async fn ensure_remote_dir(client: &mut dyn SftpClient, dir: &str) -> Result<(), String> {
    if dir.is_empty() {
        return Ok(());
    }
    let mut cur = "/".to_string();
    for part in dir.split('/').filter(|p| !p.is_empty()) {
        let next = if cur == "/" {
            format!("/{part}")
        } else {
            format!("{cur}/{part}")
        };
        match client.exists(&next).await {
            Ok(Some(true)) => {}
            Ok(Some(false)) => {
                return Err(format!("Remote path component is not a directory: {next}"));
            }
            Ok(None) => {
                client
                    .mkdir(&next, 0o755)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Err(err) => return Err(err.to_string()),
        }
        cur = next;
    }
    Ok(())
}

/// Progress callback: updates the shared record's byte counters and applies
/// the global speed limit with bucket throttling (port of the C++ sleep-in-
/// progress loop). Deliberately does not emit events; the dialog's timer
/// picks up the counters.
fn make_progress_cb(
    shared: Arc<Mutex<Shared>>,
    id: u64,
    global_limit_kbps: i64,
) -> Box<dyn Fn(u64, u64) + Send + Sync> {
    let throttle = Arc::new(Throttle {
        last_done: AtomicU64::new(0),
        last_tick: Mutex::new(Instant::now()),
    });
    Box::new(move |done, total| {
        let now = Instant::now();
        let mut tick = throttle.last_tick.lock().unwrap();
        let elapsed = now.duration_since(*tick).as_secs_f64();
        let last_done = throttle.last_done.load(Ordering::Relaxed);
        let delta = done.saturating_sub(last_done) as f64;
        {
            let mut s = shared.lock().unwrap();
            if let Some(rec) = s.task_mut(id) {
                rec.task.bytes_done = done;
                rec.task.bytes_total = total;
            }
        }
        if global_limit_kbps > 0 && done > last_done {
            let expected_sec = delta / (global_limit_kbps as f64 * 1024.0);
            if elapsed < expected_sec {
                let sleep_sec = expected_sec - elapsed;
                if sleep_sec > 0.0005 {
                    // Blocks one tokio worker thread briefly, mirroring the
                    // C++ worker-thread sleep. Fine at MAX_CONCURRENT.
                    std::thread::sleep(Duration::from_secs_f64(sleep_sec));
                }
            }
        }
        *tick = Instant::now();
        throttle.last_done.store(done, Ordering::Relaxed);
    })
}

// ---------------------------------------------------------------------------
// Error mapping + formatting helpers
// ---------------------------------------------------------------------------

/// Port of `transferErrorForUi`: maps integrity-related failures to the
/// friendly C++ messages, otherwise returns the raw error text.
fn transfer_error_for_ui(err: &ClientError) -> String {
    let msg = match err {
        ClientError::Cancelled => "Operation cancelled".to_string(),
        other => other.to_string(),
    };
    let msg = msg.trim().to_string();
    if msg.is_empty() {
        return msg;
    }
    let lower = msg.to_lowercase();
    if lower.contains("checksum mismatch") {
        return "Integrity mismatch detected: local and remote checksums differ. \
                Transfer was stopped to prevent corrupted data."
            .to_string();
    }
    if lower.contains("prefix does not match") {
        return "Resume integrity mismatch detected between local and remote \
                partial data. Transfer was stopped."
            .to_string();
    }
    if lower.contains("could not verify final integrity")
        || lower.contains("could not validate resume integrity")
    {
        return format!(
            "Integrity verification is required but could not be completed. \
             Transfer failed.\n{msg}"
        );
    }
    msg
}

/// Port of `isValidEntryName`.
fn valid_entry_name(name: &str) -> bool {
    if name == "." || name == ".." {
        return false;
    }
    if name.contains('/') || name.contains('\\') {
        return false;
    }
    !name.chars().any(|c| {
        let u = c as u32;
        u < 0x20 || u == 0x7f
    })
}

/// Port of `joinRemotePath`.
fn join_remote_path(base: &str, name: &str) -> String {
    if base == "/" {
        format!("/{name}")
    } else if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Port of `displayNameForTask`.
fn display_name(path: &str) -> String {
    if let Some(name) = Path::new(path).file_name().and_then(|s| s.to_str()) {
        if !name.is_empty() {
            return name.to_string();
        }
    }
    let trimmed = path.trim_end_matches('/');
    if let Some(slash) = trimmed.rfind('/') {
        if slash + 1 < trimmed.len() {
            return trimmed[slash + 1..].to_string();
        }
    }
    if !trimmed.is_empty() {
        trimmed.to_string()
    } else {
        "(unnamed)".to_string()
    }
}

/// Parent directory of a remote path (`"a/b/c"` -> `"a/b"`, `"/a"` -> `"/"`,
/// `"a"` -> `""`).
fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(idx) => path[..idx].to_string(),
        None => String::new(),
    }
}

/// Port of the C++ conflict-info strings (`"%1 bytes, %2"`).
fn local_file_info(path: &str) -> String {
    match std::fs::metadata(path) {
        Ok(md) => {
            let mtime = md
                .modified()
                .ok()
                .map(local_short_time_sys)
                .unwrap_or_else(|| "?".to_string());
            format!("{} bytes, {}", md.len(), mtime)
        }
        Err(_) => "? bytes, ?".to_string(),
    }
}

fn local_short_time(secs: i64) -> String {
    match DateTime::from_timestamp(secs, 0) {
        Some(dt) => dt
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M")
            .to_string(),
        None => "?".to_string(),
    }
}

fn local_short_time_sys(time: std::time::SystemTime) -> String {
    let dt: DateTime<Utc> = time.into();
    dt.with_timezone(&Local)
        .format("%Y-%m-%d %H:%M")
        .to_string()
}

// ---------------------------------------------------------------------------
// Drag-and-drop prescan helpers
// ---------------------------------------------------------------------------

/// Port of the scan loop of `runRemoteDownloadPrescan`: walks `remote_seeds`
/// (`(remote_path, is_dir)`) into `local_root`, counting files and bytes.
/// Local directory structure is created as the remote tree is walked
/// (mirroring the C++ `QDir().mkpath`).
///
/// Deviation: the C++ scan was cancellable via a progress dialog; this
/// signature has no cancel slot (fixed contract). The caller (main-window)
/// may re-add one later.
pub async fn download_prescan(
    client: &mut dyn SftpClient,
    remote_seeds: &[(String, bool)],
    local_root: &Path,
) -> Result<DownloadPlan, String> {
    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut stack: Vec<(String, PathBuf)> = Vec::new();
    for (remote, is_dir) in remote_seeds {
        if *is_dir {
            stack.push((remote.clone(), local_root.to_path_buf()));
        } else {
            files += 1;
            if let Ok(fi) = client.stat(remote).await {
                bytes += fi.size;
            }
        }
    }
    while let Some((cur_remote, cur_local)) = stack.pop() {
        let _ = std::fs::create_dir_all(&cur_local);
        let entries = client.list(&cur_remote).await.map_err(|e| e.to_string())?;
        for entry in entries {
            if !valid_entry_name(&entry.name) {
                continue;
            }
            let child_remote = join_remote_path(&cur_remote, &entry.name);
            let child_local = cur_local.join(&entry.name);
            if entry.is_dir {
                stack.push((child_remote, child_local));
            } else {
                files += 1;
                if entry.has_size {
                    bytes += entry.size;
                }
            }
        }
    }
    Ok(DownloadPlan { files, bytes })
}

/// Port of the upload-side tree walk (local files to be transferred),
/// delegating to the canonical [`crate::local_fs::prescan`].
pub fn upload_prescan(local_root: &Path) -> Result<Prescan, String> {
    let scan = crate::local_fs::prescan(local_root).map_err(|e| e.to_string())?;
    Ok(Prescan {
        files: scan.files,
        bytes: scan.bytes,
    })
}

/// Expands a local seed (file or directory tree) into the flat list of
/// files the queue needs — one task per file, mirroring the C++
/// per-file queueing after the drag-and-drop prescan. Symlinks are not
/// followed.
pub fn collect_local_files(seed: &Path) -> Result<Vec<PathBuf>, String> {
    let meta = std::fs::symlink_metadata(seed).map_err(|e| e.to_string())?;
    if !meta.is_dir() {
        return Ok(vec![seed.to_path_buf()]);
    }
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(seed).follow_links(false) {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().is_file() {
            files.push(entry.into_path());
        }
    }
    Ok(files)
}

/// Walks remote seeds and returns `(remote_file, local_dest)` pairs,
/// creating the local directory structure like [`download_prescan`] does
/// (so both scans agree on where files land).
pub async fn collect_remote_files(
    client: &mut dyn SftpClient,
    remote_seeds: &[(String, bool)],
    local_root: &Path,
) -> Result<Vec<(String, PathBuf)>, String> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    let mut stack: Vec<(String, PathBuf)> = Vec::new();
    for (remote, is_dir) in remote_seeds {
        if *is_dir {
            let dir_name = Path::new(remote)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("download");
            stack.push((remote.clone(), local_root.join(dir_name)));
        } else {
            let file_name = Path::new(remote)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("download");
            files.push((remote.clone(), local_root.join(file_name)));
        }
    }
    while let Some((cur_remote, cur_local)) = stack.pop() {
        let _ = std::fs::create_dir_all(&cur_local);
        let entries = client.list(&cur_remote).await.map_err(|e| e.to_string())?;
        for entry in entries {
            if !valid_entry_name(&entry.name) {
                continue;
            }
            let child_remote = join_remote_path(&cur_remote, &entry.name);
            let child_local = cur_local.join(&entry.name);
            if entry.is_dir {
                stack.push((child_remote, child_local));
            } else {
                files.push((child_remote, child_local));
            }
        }
    }
    Ok(files)
}

// ---------------------------------------------------------------------------
// Queue dialog bridge
// ---------------------------------------------------------------------------

// Cache of the live queue dialog so repeated opens re-raise it (C++
// `transferDlg_` behavior) and `maybe_notify_completed` can show it when
// the show-on-enqueue preference is on. Slint components are !Send, so the
// cache is thread-local to the event-loop thread.
thread_local! {
    static QUEUE_DIALOG: RefCell<Option<QueueDialogEntry>> = const { RefCell::new(None) };
}

struct QueueDialogEntry {
    dlg: slint::Weak<transfer_queue::TransferQueueDialog>,
    // Kept alive for the lifetime of the dialog: dropping the timer would
    // stop the 250 ms snapshot poll.
    _timer: slint::Timer,
    prev_rows: Vec<QueueRow>,
    prev_status: String,
    /// Currently selected task ids (multi-select via Ctrl/Cmd-click).
    selected: HashSet<u64>,
}

/// Open (or re-raise) the transfer queue dialog. Creates the component on
/// the first call, wires callbacks, subscribes to manager events, and starts
/// the 250 ms snapshot poll; later calls re-show the cached window. Must be
/// called from the Slint event-loop thread (the dialog component is not
/// `Send`), e.g. from a main-window callback.
pub fn open_queue_dialog(win: &main_window::MainWindow, mgr: Arc<TransferManager>) {
    let existing =
        QUEUE_DIALOG.with(|cell| cell.borrow().as_ref().and_then(|entry| entry.dlg.upgrade()));
    if let Some(dlg) = existing {
        refresh_dialog(&dlg, &mgr);
        let _ = dlg.show(); // already open; re-raise (errors are cosmetic here)
        return;
    }

    let dlg =
        transfer_queue::TransferQueueDialog::new().expect("failed to create TransferQueueDialog");
    let weak = dlg.as_weak();
    let win_weak = win.as_weak();
    remote::center_window_over(win, dlg.window());

    {
        let mgr = mgr.clone();
        dlg.on_cancel_requested(move |id| {
            if id >= 0 {
                mgr.cancel(id as u64);
            }
        });
    }
    {
        let mgr = mgr.clone();
        dlg.on_pause_all(move || mgr.pause_all());
    }
    {
        let mgr = mgr.clone();
        dlg.on_resume_all(move || mgr.resume_all());
    }
    {
        let mgr = mgr.clone();
        dlg.on_retry_all(move || mgr.retry_failed());
    }
    {
        let mgr = mgr.clone();
        dlg.on_cancel_all(move || mgr.cancel_all());
    }
    {
        let mgr = mgr.clone();
        dlg.on_clear_completed(move || mgr.clear_finished());
    }
    {
        let mgr = mgr.clone();
        dlg.on_clear_failed_cancelled(move || mgr.clear_failed_cancelled());
    }
    {
        let mgr = mgr.clone();
        dlg.on_clear_finished(move || {
            mgr.clear_finished();
            mgr.clear_failed_cancelled();
        });
    }
    // Row selection: left-click selects (Ctrl/Cmd toggles multi-select),
    // right-click opens the context menu anchored to that row (the popup
    // itself is Slint-native; this just aligns the selection with it, like
    // the C++ `selectRow(idx.row())` before `QMenu::exec`).
    {
        let mgr = mgr.clone();
        let weak_row = weak.clone();
        dlg.on_row_clicked(move |id, multi| {
            let Some(d) = weak_row.upgrade() else { return };
            let changed = QUEUE_DIALOG.with(|cell| {
                let mut slot = cell.borrow_mut();
                let Some(entry) = slot.as_mut() else {
                    return false;
                };
                let id = id as u64;
                if multi {
                    if !entry.selected.insert(id) {
                        entry.selected.remove(&id);
                    }
                } else {
                    entry.selected.clear();
                    entry.selected.insert(id);
                }
                true
            });
            if changed {
                refresh_dialog(&d, &mgr);
            }
        });
    }
    {
        let mgr = mgr.clone();
        let weak_ctx = weak.clone();
        dlg.on_row_context_requested(move |id| {
            let Some(d) = weak_ctx.upgrade() else { return };
            QUEUE_DIALOG.with(|cell| {
                let mut slot = cell.borrow_mut();
                if let Some(entry) = slot.as_mut() {
                    let id = id as u64;
                    if !entry.selected.contains(&id) {
                        entry.selected.clear();
                        entry.selected.insert(id);
                    }
                }
            });
            refresh_dialog(&d, &mgr);
        });
    }
    {
        let mgr = mgr.clone();
        dlg.on_pause_selected(move || {
            for_selected(&mgr, |mgr, id| mgr.pause_task(id), can_pause_state)
        });
    }
    {
        let mgr = mgr.clone();
        dlg.on_resume_selected(move || {
            for_selected(&mgr, |mgr, id| mgr.resume_task(id), can_resume_state)
        });
    }
    {
        let mgr = mgr.clone();
        dlg.on_cancel_selected(move || {
            for_selected(&mgr, |mgr, id| mgr.cancel(id), can_cancel_state)
        });
    }
    {
        let mgr = mgr.clone();
        dlg.on_retry_selected(move || {
            for_selected(&mgr, |mgr, id| mgr.retry_task(id), can_retry_state)
        });
    }
    {
        let mgr = mgr.clone();
        dlg.on_limit_selected(move || prompt_limit_selected(mgr.clone()));
    }
    {
        let mgr = mgr.clone();
        dlg.on_open_destination_selected(move || open_destinations_for_selected(&mgr));
    }
    {
        let mgr = mgr.clone();
        dlg.on_copy_source_selected(move || copy_selected_paths(&mgr, CopyPathKind::Source));
    }
    {
        let mgr = mgr.clone();
        dlg.on_copy_dest_selected(move || copy_selected_paths(&mgr, CopyPathKind::Dest));
    }
    // Speed + auto-clear footer row.
    {
        let mgr = mgr.clone();
        let weak_speed = weak.clone();
        dlg.on_apply_speed_limit(move |kbps| {
            mgr.set_global_speed_limit_kbps(i64::from(kbps));
            if let Some(d) = weak_speed.upgrade() {
                refresh_dialog(&d, &mgr);
            }
        });
    }
    {
        let mgr = mgr.clone();
        let weak_ac = weak.clone();
        dlg.on_auto_clear_changed(move || {
            let Some(d) = weak_ac.upgrade() else { return };
            let mode = d.get_auto_clear_mode();
            let minutes = d.get_auto_clear_minutes();
            mgr.set_auto_clear(mode, minutes);
            save_queue_ui_state(mode, minutes, d.get_filter());
        });
    }
    {
        let mgr = mgr.clone();
        let weak_filter = weak.clone();
        dlg.on_filter_changed(move || {
            // C++ onFilterChanged clears the table selection so hidden tasks
            // cannot be acted on.
            QUEUE_DIALOG.with(|cell| {
                if let Some(entry) = cell.borrow_mut().as_mut() {
                    entry.selected.clear();
                }
            });
            if let Some(d) = weak_filter.upgrade() {
                // C++ persists the filter on every change.
                save_queue_ui_state(
                    d.get_auto_clear_mode(),
                    d.get_auto_clear_minutes(),
                    d.get_filter(),
                );
                refresh_dialog(&d, &mgr);
            }
        });
    }
    {
        let weak_close = weak.clone();
        dlg.on_close_requested(move || {
            if let Some(d) = weak_close.upgrade() {
                let _ = d.hide(); // hide-only; the dialog survives for re-show
            }
        });
    }
    // OS close button: hide only; the modeless dialog survives for re-show,
    // mirroring the C++ show/hide behavior.
    dlg.window()
        .on_close_requested(|| slint::CloseRequestResponse::HideWindow);

    // Initialize the speed/auto-clear row from the manager and the
    // persisted queue UI state (port of TransferQueueDialog::loadUiState).
    dlg.set_speed_value(mgr.global_speed_limit_kbps() as i32);
    let (auto_mode, auto_minutes, filter) = load_queue_ui_state();
    dlg.set_filter(filter);
    dlg.set_auto_clear_mode(auto_mode);
    dlg.set_auto_clear_minutes(auto_minutes);
    mgr.set_auto_clear(auto_mode, auto_minutes);

    refresh_dialog(&dlg, &mgr);

    // Event pump: structural changes arrive here; progress ticks only mutate
    // shared state and are picked up by the timer below (if awaiting the
    // receiver ever misbehaves outside a runtime, the poll keeps the UI
    // correct).
    let mut events = mgr.subscribe();
    let weak_events = weak.clone();
    let mgr_events = mgr.clone();
    let _ = slint::spawn_local(async move {
        while let Some(event) = events.recv().await {
            if let Some(d) = weak_events.upgrade() {
                let mgr = mgr_events.clone();
                // We are on the event-loop thread (spawn_local); touch the
                // component directly rather than via invoke_from_event_loop,
                // which requires a `Send` closure.
                refresh_dialog(&d, &mgr);
                if let ManagerEvent::Completed { direction, name } = event {
                    tracing::debug!(?direction, name, "transfer completed");
                    if let Some(win) = win_weak.upgrade() {
                        maybe_notify_completed(&win, &mgr);
                    }
                }
            }
        }
    });

    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(DIALOG_POLL_INTERVAL_MS),
        {
            let mgr = mgr.clone();
            let weak_timer = weak.clone();
            move || {
                if let Some(d) = weak_timer.upgrade() {
                    refresh_dialog(&d, &mgr);
                }
            }
        },
    );

    QUEUE_DIALOG.with(|cell| {
        *cell.borrow_mut() = Some(QueueDialogEntry {
            dlg: weak,
            _timer: timer,
            prev_rows: Vec::new(),
            prev_status: String::new(),
            selected: HashSet::new(),
        });
    });
    let _ = dlg.show(); // first show; a failure only means no visible dialog
}

fn refresh_dialog(dlg: &transfer_queue::TransferQueueDialog, mgr: &TransferManager) {
    // Auto-clear terminal tasks before snapshotting (C++ maybeAutoClear).
    mgr.maybe_auto_clear();

    let filter = dlg.get_filter();
    let selected: HashSet<u64> = QUEUE_DIALOG.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|entry| entry.selected.clone())
            .unwrap_or_default()
    });
    let tasks = mgr.tasks();
    let rows: Vec<QueueRow> = tasks
        .iter()
        .filter(|t| matches_filter(t.state, filter))
        .map(|t| task_to_row(t, selected.contains(&t.id)))
        .collect();
    let status = build_status_line(&tasks, mgr.is_queue_paused(), mgr.global_speed_limit_kbps());

    // Footer button eligibility (C++ updateCounts setEnabled calls).
    let has_pause = tasks.iter().any(|t| can_pause_state(t.state));
    let has_resume = tasks.iter().any(|t| can_resume_state(t.state));
    let has_cancel = tasks.iter().any(|t| can_cancel_state(t.state));
    let has_retry = tasks.iter().any(|t| can_retry_state(t.state));
    let has_completed = tasks.iter().any(|t| t.state == TransferState::Completed);
    let has_failed = tasks
        .iter()
        .any(|t| matches!(t.state, TransferState::Failed | TransferState::Cancelled));
    let selected_tasks = || tasks.iter().filter(|t| selected.contains(&t.id));
    dlg.set_can_pause_all(has_pause);
    dlg.set_can_resume_all(has_resume);
    dlg.set_can_cancel_all(has_cancel);
    dlg.set_can_retry(has_retry);
    dlg.set_can_clear_completed(has_completed);
    dlg.set_can_clear_failed_cancelled(has_failed);
    dlg.set_can_pause_selected(selected_tasks().any(|t| can_pause_state(t.state)));
    dlg.set_can_resume_selected(selected_tasks().any(|t| can_resume_state(t.state)));
    dlg.set_can_cancel_selected(selected_tasks().any(|t| can_cancel_state(t.state)));
    dlg.set_can_limit_selected(selected_tasks().any(|t| can_limit_state(t.state)));
    dlg.set_can_retry_selected(selected_tasks().any(|t| can_retry_state(t.state)));
    dlg.set_can_open_destination_selected(
        selected_tasks().any(|t| t.direction == TransferDirection::Download),
    );

    let (rows_changed, status_changed) = QUEUE_DIALOG.with(|cell| {
        let mut slot = cell.borrow_mut();
        let Some(entry) = slot.as_mut() else {
            return (true, true);
        };
        let rows_changed = !same_rows(&entry.prev_rows, &rows);
        if rows_changed {
            entry.prev_rows = rows.clone();
        }
        let status_changed = entry.prev_status != status;
        if status_changed {
            entry.prev_status = status.clone();
        }
        (rows_changed, status_changed)
    });
    if rows_changed {
        dlg.set_rows((&rows[..]).into());
    }
    if status_changed {
        dlg.set_status_line(status.into());
    }
}

fn task_to_row(t: &TransferTask, selected: bool) -> QueueRow {
    // Clamp: bytes_done can transiently exceed a stale bytes_total after a
    // resume re-stats the file, and QueueRow.progress is a 0..1 contract.
    let progress = if t.state == TransferState::Completed {
        1.0
    } else if t.bytes_total > 0 {
        ((t.bytes_done as f64 / t.bytes_total as f64) as f32).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let transferred = if t.bytes_total > 0 {
        format!(
            "{} / {}",
            format_bytes(t.bytes_done),
            format_bytes(t.bytes_total)
        )
    } else {
        format_bytes(t.bytes_done)
    };
    QueueRow {
        id: clamp_i32(t.id),
        direction: match t.direction {
            TransferDirection::Upload => "Upload".into(),
            TransferDirection::Download => "Download".into(),
        },
        name: t.name.clone().into(),
        source: t.source.clone().into(),
        dest: t.dest.clone().into(),
        progress,
        transferred: transferred.into(),
        speed: format_speed(t.speed_bps).into(),
        eta: format_eta(t.eta_secs, t.state == TransferState::Completed).into(),
        attempts: format!("{}/3", t.attempts).into(),
        error: t.error.clone().unwrap_or_default().into(),
        state: state_display(t.state).into(),
        selected,
    }
}

fn same_rows(a: &[QueueRow], b: &[QueueRow]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b.iter()).all(|(x, y)| {
            x.id == y.id
                && x.direction == y.direction
                && x.name == y.name
                && x.source == y.source
                && x.dest == y.dest
                && x.progress == y.progress
                && x.transferred == y.transferred
                && x.speed == y.speed
                && x.eta == y.eta
                && x.attempts == y.attempts
                && x.error == y.error
                && x.state == y.state
                && x.selected == y.selected
        })
}

fn matches_filter(state: TransferState, filter: i32) -> bool {
    match filter {
        0 => true,
        1 => matches!(
            state,
            TransferState::Queued | TransferState::Active | TransferState::Paused
        ),
        2 => state == TransferState::Failed,
        3 => state == TransferState::Completed,
        4 => state == TransferState::Cancelled,
        _ => true,
    }
}

fn state_display(state: TransferState) -> &'static str {
    match state {
        TransferState::Queued => "Queued",
        TransferState::Active => "Running",
        TransferState::Paused => "Paused",
        TransferState::Completed => "Completed",
        TransferState::Failed => "Error",
        TransferState::Cancelled => "Canceled",
    }
}

fn clamp_i32(v: u64) -> i32 {
    v.min(i32::MAX as u64) as i32
}

/// Port of the C++ queue `formatBytes` (its own units/precision, distinct
/// from the file-pane formatting in `local_fs`).
fn format_bytes(v: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = v as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let precision = if value < 10.0 && unit > 0 { 1 } else { 0 };
    format!("{value:.precision$} {}", UNITS[unit])
}

/// Port of `formatSpeed`: "1.5 MB/s" ("—" when not measurable, like the C++
/// em dash).
fn format_speed(bps: f64) -> String {
    if bps <= 0.0 {
        return "—".to_string();
    }
    format!("{}/s", format_bytes(bps.round() as u64))
}

/// Port of `formatEta`: "42s", "2m 03s", "1h 05m"; "0s" once the task is
/// finished ("—" while unknown).
fn format_eta(secs: f64, completed: bool) -> String {
    if secs <= 0.0 {
        return if completed { "0s" } else { "—" }.to_string();
    }
    let s = secs.round() as u64;
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {sec:02}s")
    } else {
        format!("{sec}s")
    }
}

// ---------------------------------------------------------------------------
// Selection-driven queue actions (C++ onPauseSelected / onResumeSelected /
// onLimitSelected / onStopSelected / onRetrySelected / onOpenDestination /
// onCopySourcePath / onCopyDestinationPath).
// ---------------------------------------------------------------------------

fn can_pause_state(s: TransferState) -> bool {
    matches!(s, TransferState::Queued | TransferState::Active)
}

fn can_resume_state(s: TransferState) -> bool {
    s == TransferState::Paused
}

fn can_limit_state(s: TransferState) -> bool {
    matches!(
        s,
        TransferState::Queued | TransferState::Active | TransferState::Paused
    )
}

fn can_cancel_state(s: TransferState) -> bool {
    can_limit_state(s)
}

fn can_retry_state(s: TransferState) -> bool {
    matches!(s, TransferState::Failed | TransferState::Cancelled)
}

/// Currently selected task ids (empty when the dialog is not open).
fn selected_ids() -> Vec<u64> {
    QUEUE_DIALOG.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|entry| entry.selected.iter().copied().collect())
            .unwrap_or_default()
    })
}

/// Applies `act` to every selected task whose state passes `eligible`
/// (mirrors the C++ selectedTaskIds + can*Status loops).
fn for_selected(
    mgr: &TransferManager,
    act: impl Fn(&TransferManager, u64),
    eligible: impl Fn(TransferState) -> bool,
) {
    let ids = selected_ids();
    if ids.is_empty() {
        return;
    }
    let tasks = mgr.tasks();
    for id in ids {
        if let Some(t) = tasks.iter().find(|t| t.id == id) {
            if eligible(t.state) {
                act(mgr, id);
            }
        }
    }
}

/// "Limit selected": blocking-style prompt rendered as a modeless
/// [`connection_dialog::KbdIntPromptDialog`] (the same component used by the
/// connect workstream's `prompt_user_sync`; here answered asynchronously
/// because the queue dialog lives on the event-loop thread).
fn prompt_limit_selected(mgr: Arc<TransferManager>) {
    let ids = selected_ids();
    if ids.is_empty() {
        return;
    }
    let eligible: Vec<u64> = mgr
        .tasks()
        .into_iter()
        .filter(|t| ids.contains(&t.id) && can_limit_state(t.state))
        .map(|t| t.id)
        .collect();
    if eligible.is_empty() {
        return;
    }
    let Ok(dlg) = connection_dialog::KbdIntPromptDialog::new() else {
        tracing::warn!("could not create limit prompt dialog");
        return;
    };
    dlg.set_title_text(crate::connect::translate_alert_text("Limit for task(s)").into());
    dlg.set_prompt(crate::connect::translate_alert_text("KB/s (0 = no limit)").into());
    dlg.set_answer("0".into());
    dlg.set_mask_input(false); // numeric input, like QInputDialog::getInt
    let weak = dlg.as_weak();
    dlg.on_accepted({
        let mgr = mgr.clone();
        let weak = weak.clone();
        move || {
            let answer = weak
                .upgrade()
                .map(|d| d.get_answer().to_string())
                .unwrap_or_default();
            // QInputDialog::getInt range in the C++ dialog (0..=1,000,000).
            let kbps: i64 = answer
                .trim()
                .parse::<i64>()
                .unwrap_or(0)
                .clamp(0, 1_000_000);
            for id in &eligible {
                mgr.set_task_speed_limit(*id, kbps);
            }
            if let Some(d) = weak.upgrade() {
                let _ = d.hide();
            }
        }
    });
    dlg.on_rejected({
        let weak = weak.clone();
        move || {
            if let Some(d) = weak.upgrade() {
                let _ = d.hide();
            }
        }
    });
    let _ = dlg.show();
}

/// "Open destination": opens each selected download's local destination
/// (or its parent when the file does not exist) with the OS default handler
/// (C++ `QDesktopServices::openUrl(QUrl::fromLocalFile(...))`).
fn open_destinations_for_selected(mgr: &TransferManager) {
    let ids = selected_ids();
    if ids.is_empty() {
        return;
    }
    let mut opened: HashSet<String> = HashSet::new();
    for t in mgr.tasks().into_iter().filter(|t| ids.contains(&t.id)) {
        if t.direction != TransferDirection::Download {
            continue;
        }
        let mut path = t.dest.clone();
        if !Path::new(&path).exists() {
            if let Some(parent) = Path::new(&path).parent() {
                if parent.as_os_str().is_empty() || !parent.exists() {
                    continue;
                }
                path = parent.to_string_lossy().to_string();
            }
        }
        let canonical = std::fs::canonicalize(&path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or(path);
        if canonical.is_empty() || opened.contains(&canonical) {
            continue;
        }
        opened.insert(canonical.clone());
        if let Err(err) = crate::local_fs::open_url(&canonical) {
            tracing::warn!(path = %canonical, "could not open destination: {err}");
        }
    }
}

/// Which side of the task's paths to copy (context-menu clipboard actions).
enum CopyPathKind {
    Source,
    Dest,
}

/// Copies the selected tasks' source/destination paths (newline-joined) to
/// the system clipboard (C++ `onCopySourcePath` / `onCopyDestinationPath`).
fn copy_selected_paths(mgr: &TransferManager, kind: CopyPathKind) {
    let ids = selected_ids();
    if ids.is_empty() {
        return;
    }
    let lines: Vec<String> = mgr
        .tasks()
        .into_iter()
        .filter(|t| ids.contains(&t.id))
        .map(|t| match kind {
            CopyPathKind::Source => t.source.clone(),
            CopyPathKind::Dest => t.dest.clone(),
        })
        .collect();
    if lines.is_empty() {
        return;
    }
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => {
            if let Err(err) = clipboard.set_text(lines.join("\n")) {
                tracing::warn!("could not copy to clipboard: {err}");
            }
        }
        Err(err) => tracing::warn!("clipboard unavailable: {err}"),
    }
}

// ---------------------------------------------------------------------------
// Queue UI state persistence (port of the QSettings keys
// UI/transferQueue/autoClearMode + autoClearMinutes, with the same fallback
// chain to the Transfer/defaultQueueAutoClear* preferences).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct QueueUiStateFile {
    mode: Option<i32>,
    minutes: Option<i32>,
    /// `UI/transferQueue/filterMode` (0 = All .. 4 = Canceled).
    filter: Option<i32>,
}

fn queue_ui_state_path() -> PathBuf {
    crate::settings::config_dir().join("queue-ui-state.toml")
}

/// Loads (auto-clear mode, auto-clear minutes, filter) with the C++ fallback
/// chain and clamps.
fn load_queue_ui_state() -> (i32, i32, i32) {
    let prefs = crate::settings::Preferences::load();
    let default_mode = prefs.default_queue_auto_clear_mode.clamp(0, 3) as i32;
    let default_minutes = prefs.default_queue_auto_clear_minutes.clamp(1, 1440) as i32;
    let file: Option<QueueUiStateFile> = std::fs::read_to_string(queue_ui_state_path())
        .ok()
        .and_then(|text| toml::from_str(&text).ok());
    match file {
        Some(f) => (
            f.mode.unwrap_or(default_mode).clamp(0, 3),
            f.minutes.unwrap_or(default_minutes).clamp(1, 1440),
            f.filter.unwrap_or(0).clamp(0, 4),
        ),
        None => (default_mode, default_minutes, 0),
    }
}

fn save_queue_ui_state(mode: i32, minutes: i32, filter: i32) {
    let path = queue_ui_state_path();
    let text = toml::to_string_pretty(&QueueUiStateFile {
        mode: Some(mode),
        minutes: Some(minutes),
        filter: Some(filter.clamp(0, 4)),
    })
    .unwrap_or_default();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(err) = std::fs::write(&path, text) {
        tracing::warn!(path = %path.display(), "could not save queue UI state: {err}");
    }
}

/// Port of the C++ badge row, collapsed into the dialog's status line.
fn build_status_line(tasks: &[TransferTask], paused: bool, global_kbps: i64) -> String {
    let (mut queued, mut running, mut paused_n, mut done, mut error, mut cancelled) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    for t in tasks {
        match t.state {
            TransferState::Queued => queued += 1,
            TransferState::Active => running += 1,
            TransferState::Paused => paused_n += 1,
            TransferState::Completed => done += 1,
            TransferState::Failed => error += 1,
            TransferState::Cancelled => cancelled += 1,
        }
    }
    let mut parts = vec![
        format!("Total: {}", tasks.len()),
        format!("Active: {}", queued + running + paused_n),
        format!("Running: {running}"),
        format!("Paused: {paused_n}"),
        format!("Errors: {error}"),
        format!("Completed: {done}"),
        format!("Canceled: {cancelled}"),
    ];
    parts.push(if global_kbps > 0 {
        format!("Global limit: {global_kbps} KB/s")
    } else {
        "Global limit: off".to_string()
    });
    if paused {
        parts.push("Queue paused".to_string());
    }
    parts.join("  \u{b7}  ")
}

fn show_queue_if_open() {
    // Must be called from the event-loop thread: the dialog component is
    // not `Send`, so `invoke_from_event_loop` cannot transport it (nor its
    // `Weak`). The only call site is `maybe_notify_completed`, which the
    // main-window workstream invokes from Slint callbacks.
    let weak_opt = QUEUE_DIALOG.with(|cell| cell.borrow().as_ref().map(|e| e.dlg.clone()));
    if let Some(weak) = weak_opt {
        if let Some(dlg) = weak.upgrade() {
            let _ = dlg.show(); // re-raise; cosmetic failure is fine
        }
    }
}

/// Port of `maybeNotifyCompletedTransfers` + `maybeShowTransferQueue`.
///
/// Computes the "Upload completed: name" / "Download completed: name" /
/// "N transfers completed" message for tasks that completed since the last
/// call, delivers it through the notify hook (or logs it), and re-raises the
/// queue dialog when the show-on-enqueue preference is on. Call this from
/// the main window on manager events (or periodically).
pub fn maybe_notify_completed(win: &main_window::MainWindow, mgr: &TransferManager) {
    // Delivered through the notify hook, which main.rs points at the status
    // line; the window handle is kept for the eventual in-window banner.
    let _ = win;

    let Some(message) = mgr.take_completed_notice() else {
        return;
    };
    match mgr.notify_hook() {
        Some(hook) => hook(message),
        None => tracing::info!(target: "freescp.transfer", "{message}"),
    }
    if mgr.show_queue_on_enqueue() {
        show_queue_if_open();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_name_validation_matches_cpp() {
        assert!(valid_entry_name("report.txt"));
        assert!(valid_entry_name("file with spaces"));
        assert!(!valid_entry_name("."));
        assert!(!valid_entry_name(".."));
        assert!(!valid_entry_name("a/b"));
        assert!(!valid_entry_name("a\\b"));
        assert!(!valid_entry_name("a\nb"));
        assert!(!valid_entry_name("a\x7fb"));
    }

    #[test]
    fn remote_path_join() {
        assert_eq!(join_remote_path("/", "a"), "/a");
        assert_eq!(join_remote_path("/a", "b"), "/a/b");
        assert_eq!(join_remote_path("/a/", "b"), "/a/b");
    }

    #[test]
    fn display_name_falls_back() {
        assert_eq!(display_name("/home/user/report.txt"), "report.txt");
        assert_eq!(display_name("/remote/dir/"), "dir");
        assert_eq!(display_name("/"), "(unnamed)");
        assert_eq!(display_name(""), "(unnamed)");
    }

    #[test]
    fn error_mapping_for_ui() {
        let mismatch = ClientError::Other("final checksum mismatch detected".into());
        assert!(transfer_error_for_ui(&mismatch).contains("Integrity mismatch"));
        let prefix = ClientError::Other("resume prefix does not match".into());
        assert!(transfer_error_for_ui(&prefix).contains("Resume integrity"));
        let required = ClientError::Other("could not verify final integrity".into());
        assert!(transfer_error_for_ui(&required).contains("required"));
        let plain = ClientError::Other("  connection refused  ".into());
        assert_eq!(transfer_error_for_ui(&plain), "connection refused");
    }

    #[test]
    fn state_display_names() {
        assert_eq!(state_display(TransferState::Queued), "Queued");
        assert_eq!(state_display(TransferState::Active), "Running");
        assert_eq!(state_display(TransferState::Completed), "Completed");
        assert_eq!(state_display(TransferState::Failed), "Error");
        assert_eq!(state_display(TransferState::Cancelled), "Canceled");
    }

    #[test]
    fn speed_and_eta_formatting_matches_cpp() {
        assert_eq!(format_speed(0.0), "—");
        assert_eq!(format_speed(-1.0), "—");
        assert_eq!(format_speed(2048.0), "2.0 KB/s");
        assert_eq!(format_eta(0.0, false), "—");
        assert_eq!(format_eta(0.0, true), "0s");
        assert_eq!(format_eta(42.0, false), "42s");
        assert_eq!(format_eta(123.0, false), "2m 03s");
        assert_eq!(format_eta(3900.0, false), "1h 05m");
    }

    #[test]
    fn filter_matching() {
        assert!(matches_filter(TransferState::Active, 0));
        assert!(matches_filter(TransferState::Paused, 1));
        assert!(!matches_filter(TransferState::Completed, 1));
        assert!(matches_filter(TransferState::Failed, 2));
        assert!(matches_filter(TransferState::Completed, 3));
        assert!(matches_filter(TransferState::Cancelled, 4));
    }

    #[test]
    fn parent_dir_matches_remote_paths() {
        assert_eq!(parent_dir("/a/b/c.txt"), "/a/b");
        assert_eq!(parent_dir("/a"), "/");
        assert_eq!(parent_dir("a"), "");
        assert_eq!(parent_dir(""), "");
    }
}
