//! Debounced local-directory watcher for the file panes.
//!
//! Watches one directory non-recursively and invokes a callback on a
//! background thread once the directory has been quiet for [`DEBOUNCE`].

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use notify::{recommended_watcher, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

/// Quiet period that coalesces a burst of filesystem events into one callback.
const DEBOUNCE: Duration = Duration::from_millis(400);

/// Upper bound for the join in [`DirWatcher::stop`] so shutdown cannot hang.
const JOIN_TIMEOUT: Duration = Duration::from_secs(2);

const THREAD_NAME: &str = "freescp-dir-watcher";

/// Watches a single local directory and reports settled changes.
pub struct DirWatcher {
    inner: Arc<Inner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

struct Inner {
    watch: Mutex<WatchState>,
    events: Sender<Wake>,
    stop: AtomicBool,
    on_change: Box<dyn Fn() + Send + Sync>,
}

struct WatchState {
    watcher: RecommendedWatcher,
    current: Option<PathBuf>,
}

enum Wake {
    Changed,
    Stop,
}

impl DirWatcher {
    /// Starts watching `path` non-recursively. `on_change` is invoked on a
    /// background thread after the directory settles (debounced).
    pub fn start(
        path: impl Into<PathBuf>,
        on_change: impl Fn() + Send + Sync + 'static,
    ) -> Result<Self, notify::Error> {
        let (events, incoming) = mpsc::channel();
        let mut watcher = recommended_watcher({
            let events = events.clone();
            move |result: notify::Result<notify::Event>| {
                if let Ok(event) = result {
                    if !matches!(event.kind, EventKind::Access(_)) {
                        let _ = events.send(Wake::Changed);
                    }
                }
            }
        })?;

        let path = path.into();
        watcher.watch(&path, RecursiveMode::NonRecursive)?;

        let inner = Arc::new(Inner {
            watch: Mutex::new(WatchState {
                watcher,
                current: Some(path),
            }),
            events,
            stop: AtomicBool::new(false),
            on_change: Box::new(on_change),
        });

        let handle = thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn({
                let inner = Arc::clone(&inner);
                move || debounce_loop(&incoming, &inner)
            })
            .map_err(|err| {
                notify::Error::generic(&format!("cannot spawn watcher thread: {err}"))
            })?;

        Ok(Self {
            inner,
            thread: Mutex::new(Some(handle)),
        })
    }

    /// Switches the watched directory (no-op if unchanged).
    pub fn set_path(&self, path: impl Into<PathBuf>) -> Result<(), notify::Error> {
        let path = path.into();
        let mut state = lock(&self.inner.watch);
        if state.current.as_deref() == Some(path.as_path()) {
            return Ok(());
        }

        match state.watcher.watch(&path, RecursiveMode::NonRecursive) {
            Ok(()) => {
                if let Some(old) = state.current.replace(path) {
                    let _ = state.watcher.unwatch(&old);
                }
                Ok(())
            }
            // A directory that vanished before the UI could navigate to it is
            // not actionable: drop the stale watch and stay quiet.
            Err(err) if matches!(err.kind, notify::ErrorKind::PathNotFound) => {
                if let Some(old) = state.current.take() {
                    let _ = state.watcher.unwatch(&old);
                }
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Stops the background watcher.
    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        let _ = self.inner.events.send(Wake::Stop);
        let handle = lock(&self.thread).take();
        if let Some(handle) = handle {
            join_bounded(handle);
        }
    }
}

impl Drop for DirWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

fn debounce_loop(events: &Receiver<Wake>, inner: &Inner) {
    loop {
        match events.recv() {
            Ok(Wake::Changed) => {}
            Ok(Wake::Stop) | Err(_) => return,
        }
        if !settle(events, inner) {
            return;
        }
        (inner.on_change)();
    }
}

/// Blocks until the directory has been quiet for one debounce interval.
/// Returns false when the watcher was stopped or the channel hung up.
fn settle(events: &Receiver<Wake>, inner: &Inner) -> bool {
    loop {
        match events.recv_timeout(DEBOUNCE) {
            Ok(Wake::Changed) => {
                if inner.stop.load(Ordering::SeqCst) {
                    return false;
                }
            }
            Ok(Wake::Stop) | Err(RecvTimeoutError::Disconnected) => return false,
            Err(RecvTimeoutError::Timeout) => return true,
        }
    }
}

fn join_bounded(handle: JoinHandle<()>) {
    if handle.thread().id() == thread::current().id() {
        return;
    }
    let deadline = Instant::now() + JOIN_TIMEOUT;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let _ = handle.join();
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::AtomicU64;
    use std::thread::ThreadId;

    use super::*;

    const CALLBACK_TIMEOUT: Duration = Duration::from_secs(3);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "freescp-watcher-{tag}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn start_counting(dir: &Path) -> (DirWatcher, mpsc::Receiver<()>) {
        let (tx, rx) = mpsc::channel();
        let tx = Arc::new(Mutex::new(tx));
        let watcher = DirWatcher::start(dir, move || {
            if let Ok(tx) = tx.lock() {
                let _ = tx.send(());
            }
        })
        .expect("start watcher");
        (watcher, rx)
    }

    #[test]
    fn fires_after_file_creation() {
        let dir = TempDir::new("create");
        let (tx, rx) = mpsc::channel::<ThreadId>();
        let tx = Arc::new(Mutex::new(tx));
        let watcher = DirWatcher::start(dir.path(), {
            let tx = Arc::clone(&tx);
            move || {
                if let Ok(tx) = tx.lock() {
                    let _ = tx.send(thread::current().id());
                }
            }
        })
        .expect("start watcher");

        fs::write(dir.path().join("hello.txt"), b"hi").expect("write file");

        let callback_thread = rx
            .recv_timeout(CALLBACK_TIMEOUT)
            .expect("callback within timeout");
        assert_ne!(
            callback_thread,
            thread::current().id(),
            "callback must not run on the caller thread"
        );
        watcher.stop();
    }

    #[test]
    fn coalesces_bursts_and_is_quiet_after_stop() {
        let dir = TempDir::new("burst");
        let (watcher, rx) = start_counting(dir.path());

        for index in 0..5 {
            fs::write(dir.path().join(format!("file-{index}.txt")), b"data").expect("write file");
        }
        rx.recv_timeout(CALLBACK_TIMEOUT)
            .expect("at least one coalesced callback for the burst");

        watcher.stop();
        while rx.try_recv().is_ok() {}

        fs::write(dir.path().join("after-stop.txt"), b"data").expect("write file");
        thread::sleep(DEBOUNCE * 3);
        assert!(
            matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "watcher fired after stop"
        );
    }

    #[test]
    fn set_path_moves_the_watch() {
        let dir_a = TempDir::new("a");
        let dir_b = TempDir::new("b");
        let (watcher, rx) = start_counting(dir_a.path());

        fs::write(dir_a.path().join("a.txt"), b"a").expect("write file");
        rx.recv_timeout(CALLBACK_TIMEOUT)
            .expect("callback for the first directory");

        watcher.set_path(dir_b.path()).expect("switch directory");
        thread::sleep(DEBOUNCE * 2);
        while rx.try_recv().is_ok() {}

        fs::write(dir_a.path().join("a-again.txt"), b"a").expect("write file");
        assert!(
            matches!(
                rx.recv_timeout(DEBOUNCE * 2),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "old directory must no longer fire"
        );

        fs::write(dir_b.path().join("b.txt"), b"b").expect("write file");
        rx.recv_timeout(CALLBACK_TIMEOUT)
            .expect("callback for the second directory");
        watcher.stop();
    }
}
