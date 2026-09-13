//! Local-filesystem operations for the local panel.
//!
//! Pure-Rust port of `ui/MainWindowLocalOps.cpp` (local browse/refresh,
//! mkdir/new-file/rename/delete with batch + skip handling, local copy/move,
//! breadcrumbs helpers, preferred home path), `ui/TimeUtils.hpp` (local short
//! time formatting) and the local-side transfer bookkeeping of
//! `ui/MainWindowTransfers.cpp` (pre-scan of a local tree, skip-on-exists and
//! overwrite policy).
//!
//! Everything here is synchronous. The `*_async` wrappers at the bottom run
//! the sync functions through [`tokio::task::spawn_blocking`] so the Slint UI
//! thread can call them without blocking; progress/cancel callbacks used from
//! async code must therefore be `Send + Sync + 'static` (see
//! [`copy_local_async`] and [`move_local_async`]).
//!
//! Message wording mirrors the user-facing strings in `ui/UiAlerts.cpp` /
//! `ui/MainWindowLocalOps.cpp` (e.g. "Could not create folder."), so the
//! Rust app shows the same alerts as the Qt app.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use walkdir::WalkDir;

/// A single entry in a local directory listing (the local-panel model row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// Last modification time, seconds since the Unix epoch (0 if unknown).
    pub mtime: u64,
    /// Unix mode bits (best-effort; 0 on non-Unix platforms).
    pub mode: u32,
}

/// Result of a local pre-scan (port of the C++ pre-scan used before queueing
/// local copy/move jobs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Prescan {
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
}

/// Errors for local-filesystem operations, with user-friendly messages that
/// mirror the wording of the Qt `UiAlerts` dialogs.
///
/// Note: the public API returns `std::io::Result`, so this enum is converted
/// to [`io::Error`] via [`From`]; the message is preserved in the OS error's
/// display string.
#[derive(Debug)]
pub enum LocalFsError {
    List(PathBuf),
    CreateDir,
    CreateFile,
    Rename,
    Delete(PathBuf),
    Copy(PathBuf),
    Move(PathBuf),
    Prescan(PathBuf),
    Open(PathBuf),
    Cancelled,
    AlreadyExists(PathBuf),
    InvalidName(&'static str),
    InvalidBehavior(String),
    /// Wrapped OS error; displayed as the OS message (no prefix), matching the
    /// plain-text style of `UiAlerts`.
    Io(io::Error),
}

impl std::fmt::Display for LocalFsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalFsError::List(path) => {
                write!(f, "Could not list folder: {}", path.display())
            }
            LocalFsError::CreateDir => write!(f, "Could not create folder."),
            LocalFsError::CreateFile => write!(f, "Could not create file."),
            LocalFsError::Rename => write!(f, "Could not rename."),
            LocalFsError::Delete(path) => {
                write!(f, "Could not delete: {}", path.display())
            }
            LocalFsError::Copy(path) => write!(f, "Could not copy: {}", path.display()),
            LocalFsError::Move(path) => write!(f, "Could not move: {}", path.display()),
            LocalFsError::Prescan(path) => {
                write!(f, "Could not scan folder: {}", path.display())
            }
            LocalFsError::Open(path) => write!(f, "Could not open file: {}", path.display()),
            LocalFsError::Cancelled => write!(f, "Operation canceled"),
            LocalFsError::AlreadyExists(path) => {
                write!(
                    f,
                    "\u{201c}{}\u{201d} already exists at destination.",
                    path.display()
                )
            }
            LocalFsError::InvalidName(reason) => write!(f, "Invalid name: {}", reason),
            LocalFsError::InvalidBehavior(behavior) => {
                write!(f, "Unknown open behavior: {}", behavior)
            }
            LocalFsError::Io(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for LocalFsError {}

/// The public API returns `std::io::Result`, so `LocalFsError` converts into
/// `io::Error`. The message is preserved in the OS error's display string.
/// (`LocalFsError::Io` is constructed explicitly when an underlying OS error
/// must be surfaced verbatim, e.g. by the UI layer.)
impl From<LocalFsError> for io::Error {
    fn from(err: LocalFsError) -> io::Error {
        let kind = match err {
            LocalFsError::AlreadyExists(_) => io::ErrorKind::AlreadyExists,
            LocalFsError::Cancelled => io::ErrorKind::Interrupted,
            LocalFsError::InvalidBehavior(_) | LocalFsError::InvalidName(_) => {
                io::ErrorKind::InvalidInput
            }
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, err.to_string())
    }
}

/// Case-insensitive comparison of two entry names.
fn name_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.to_lowercase()
        .cmp(&b.to_lowercase())
        .then_with(|| a.cmp(b))
}

/// Sort entries: directories first, then by name (case-insensitive), matching
/// the Qt file-system model's default ordering.
fn sort_entries(entries: &mut [LocalEntry]) {
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| name_cmp(&a.name, &b.name))
    });
}

/// Build a [`LocalEntry`] from a directory entry, following symlinks the same
/// way `QFileSystemModel` does.
fn entry_from(dir_entry: &fs::DirEntry) -> Option<LocalEntry> {
    let name = dir_entry.file_name().to_string_lossy().into_owned();
    let md = dir_entry.metadata().ok()?;
    let is_dir = md.is_dir();
    let size = if is_dir { 0 } else { md.len() };
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mode = mode_of(&md);
    Some(LocalEntry {
        name,
        is_dir,
        size,
        mtime,
        mode,
    })
}

/// Best-effort Unix mode bits of `md` (0 on non-Unix platforms).
fn mode_of(md: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        md.mode()
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        0
    }
}

/// List a directory: directories first, then by name, dotfiles hidden.
///
/// The path must exist and be a directory, otherwise the returned error is
/// "Could not list folder: <path>" (mirrors the Qt "Folder does not exist."
/// warning path).
pub fn list_dir(path: &Path) -> io::Result<Vec<LocalEntry>> {
    list_dir_with(path, false)
}

/// Like [`list_dir`], with control over hidden (dotfile) entries.
pub fn list_dir_with(path: &Path, show_hidden: bool) -> io::Result<Vec<LocalEntry>> {
    let read = fs::read_dir(path).map_err(|_| LocalFsError::List(path.to_path_buf()))?;

    let mut entries = Vec::new();
    for dir_entry in read {
        let dir_entry = dir_entry.map_err(|_| LocalFsError::List(path.to_path_buf()))?;
        let name = dir_entry.file_name().to_string_lossy().into_owned();
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        if let Some(entry) = entry_from(&dir_entry) {
            entries.push(entry);
        }
    }
    sort_entries(&mut entries);
    Ok(entries)
}

/// Preferred home directory for the local panel (port of
/// `MainWindow::preferredLocalHomePath`): `$HOME` if it exists, else the
/// filesystem root.
pub fn home_dir() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        if home.exists() {
            return home;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        if home.exists() {
            return home;
        }
    }
    PathBuf::from("/")
}

/// Whether `path` exists (port of the Qt `QDir(path).exists()` guard).
pub fn is_valid_local_path(path: &Path) -> bool {
    path.exists()
}

/// Validate a single entry name (no paths) exactly like the C++
/// `isValidEntryName`: rejects ".", "..", path separators and ASCII control
/// characters.
pub fn is_valid_entry_name(name: &str, why: &mut Option<String>) -> bool {
    if name == "." || name == ".." {
        *why = Some("cannot be '.' or '..'.".to_string());
        return false;
    }
    if name.contains('/') || name.contains('\\') {
        *why = Some("cannot contain separators ('/' or '\\').".to_string());
        return false;
    }
    for ch in name.chars() {
        let u = ch as u32;
        if u < 0x20 || u == 0x7F {
            *why = Some("cannot contain control characters.".to_string());
            return false;
        }
    }
    *why = None;
    true
}

/// Create a directory, creating intermediate directories as needed (port of
/// `QDir::mkpath`).
pub fn create_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path).map_err(|_| LocalFsError::CreateDir.into())
}

/// Create (or truncate, like the Qt `QIODevice::Truncate` open) an empty file.
pub fn create_file(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map(|_| ())
        .map_err(|_| LocalFsError::CreateFile.into())
}

/// Rename a file or directory. When `overwrite` is set, an existing
/// destination is removed first (like the Qt local-move conflict handling).
pub fn rename(from: &Path, to: &Path, overwrite: bool) -> io::Result<()> {
    if from == to {
        return Ok(());
    }
    if to.exists() {
        if !overwrite {
            // QFile::rename fails when the destination exists; `fs::rename`
            // would silently replace it on POSIX, so enforce the contract.
            return Err(LocalFsError::Rename.into());
        }
        remove(to).map_err(|_| LocalFsError::Rename)?;
    }
    fs::rename(from, to).map_err(|_| LocalFsError::Rename.into())
}

/// Remove a file or a directory tree. Symlinks are removed without following
/// them.
pub fn remove(path: &Path) -> io::Result<()> {
    let symlink_meta =
        fs::symlink_metadata(path).map_err(|_| LocalFsError::Delete(path.to_path_buf()))?;
    let result = if symlink_meta.file_type().is_symlink() || symlink_meta.is_file() {
        fs::remove_file(path)
    } else if symlink_meta.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    result.map_err(|_| LocalFsError::Delete(path.to_path_buf()).into())
}

/// Copy a file or directory tree from `src` to `dst`.
///
/// Policy (ports the C++ local copy flow, including its per-file behavior):
/// - If `dst` exists and `skip_existing` is set, the entry is skipped and the
///   bytes already copied are returned.
/// - If `dst` exists and `overwrite` is set, the existing entry is removed
///   first (files and top-level directories) so the copy starts clean.
/// - Otherwise the first conflict aborts with "\u{2026} already exists at
///   destination." (callers surface the Qt-style conflict question).
/// - Nested files that exist are skipped unless `overwrite` is set (so a
///   non-overwrite copy of a whole directory never destroys existing data
///   mid-tree, deviating slightly from the Qt code which force-overwrote
///   nested files).
///
/// `progress(done, total)` is called before the copy starts and after each
/// chunk; `total` is the sum of regular-file sizes of the tree. `should_cancel`
/// is polled between files and between chunks; cancellation returns an
/// `Interrupted` error. Returns the number of bytes copied.
pub fn copy_local(
    src: &Path,
    dst: &Path,
    overwrite: bool,
    skip_existing: bool,
    progress: &dyn Fn(u64, u64),
    should_cancel: &dyn Fn() -> bool,
) -> io::Result<u64> {
    if should_cancel() {
        return Err(LocalFsError::Cancelled.into());
    }
    if same_path(src, dst) {
        return Err(LocalFsError::Copy(src.to_path_buf()).into());
    }
    if dst.exists() {
        if skip_existing {
            return Ok(0);
        }
        if !overwrite {
            return Err(LocalFsError::AlreadyExists(dst.to_path_buf()).into());
        }
    }

    let meta = fs::symlink_metadata(src).map_err(|_| LocalFsError::Copy(src.to_path_buf()))?;
    if meta.is_dir() {
        if dst.exists() {
            remove(dst).map_err(|_| LocalFsError::Copy(src.to_path_buf()))?;
        }
        fs::create_dir_all(dst).map_err(|_| LocalFsError::Copy(src.to_path_buf()))?;
        let total = prescan(src).map(|p| p.bytes).unwrap_or(0);
        let mut copied = 0u64;
        let walker = WalkDir::new(src).min_depth(1).follow_links(false);
        for item in walker {
            if should_cancel() {
                return Err(LocalFsError::Cancelled.into());
            }
            let item = item.map_err(|_| LocalFsError::Copy(src.to_path_buf()))?;
            let rel = item
                .path()
                .strip_prefix(src)
                .map_err(|_| LocalFsError::Copy(src.to_path_buf()))?;
            let target = dst.join(rel);
            if item.file_type().is_dir() {
                fs::create_dir_all(&target).map_err(|_| LocalFsError::Copy(src.to_path_buf()))?;
            } else if item.file_type().is_file() {
                copied += copy_one_file(
                    item.path(),
                    &target,
                    overwrite,
                    skip_existing,
                    copied,
                    total,
                    progress,
                    should_cancel,
                )?;
            }
        }
        Ok(copied)
    } else {
        copy_one_file(
            src,
            dst,
            overwrite,
            skip_existing,
            0,
            meta.len(),
            progress,
            should_cancel,
        )
    }
}

/// Copy a single file, returning the bytes copied (0 when skipped).
#[allow(clippy::too_many_arguments)] // mirrors the C++ signature; callers pass progress/cancel closures
fn copy_one_file(
    src: &Path,
    dst: &Path,
    overwrite: bool,
    skip_existing: bool,
    base_bytes: u64,
    total_bytes: u64,
    progress: &dyn Fn(u64, u64),
    should_cancel: &dyn Fn() -> bool,
) -> io::Result<u64> {
    if dst.exists() {
        if skip_existing {
            return Ok(0);
        }
        if !overwrite {
            return Err(LocalFsError::AlreadyExists(dst.to_path_buf()).into());
        }
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|_| LocalFsError::Copy(src.to_path_buf()))?;
    }
    if should_cancel() {
        return Err(LocalFsError::Cancelled.into());
    }

    let mut input = File::open(src).map_err(|_| LocalFsError::Copy(src.to_path_buf()))?;
    let mut output = File::create(dst).map_err(|_| LocalFsError::Copy(dst.to_path_buf()))?;

    let mut buf = [0u8; 128 * 1024];
    let mut written = 0u64;
    progress(base_bytes + written, total_bytes);
    loop {
        if should_cancel() {
            return Err(LocalFsError::Cancelled.into());
        }
        let n = input
            .read(&mut buf)
            .map_err(|_| LocalFsError::Copy(src.to_path_buf()))?;
        if n == 0 {
            break;
        }
        output
            .write_all(&buf[..n])
            .map_err(|_| LocalFsError::Copy(dst.to_path_buf()))?;
        written += n as u64;
        progress(base_bytes + written, total_bytes);
    }
    output
        .flush()
        .map_err(|_| LocalFsError::Copy(dst.to_path_buf()))?;
    Ok(written)
}

/// Move a file or directory tree. Tries a plain rename first; when the
/// rename fails because the destination is on another device, falls back to
/// [`copy_local`] followed by [`remove`] of the source (mirrors the Qt
/// copy-then-delete local move).
pub fn move_local(
    src: &Path,
    dst: &Path,
    overwrite: bool,
    skip_existing: bool,
    progress: &dyn Fn(u64, u64),
    should_cancel: &dyn Fn() -> bool,
) -> io::Result<u64> {
    if should_cancel() {
        return Err(LocalFsError::Cancelled.into());
    }
    if same_path(src, dst) {
        return Err(LocalFsError::Move(src.to_path_buf()).into());
    }
    if dst.exists() {
        if skip_existing {
            return Ok(0);
        }
        if !overwrite {
            return Err(LocalFsError::AlreadyExists(dst.to_path_buf()).into());
        }
        remove(dst).map_err(|_| LocalFsError::Move(src.to_path_buf()))?;
    }
    match fs::rename(src, dst) {
        Ok(()) => Ok(0),
        Err(err) if err.kind() == io::ErrorKind::CrossesDevices => {
            let bytes = copy_local(src, dst, overwrite, skip_existing, progress, should_cancel)?;
            remove(src).map_err(|_| LocalFsError::Move(src.to_path_buf()))?;
            Ok(bytes)
        }
        Err(_) => Err(LocalFsError::Move(src.to_path_buf()).into()),
    }
}

/// Whether two paths refer to the same filesystem entry (canonicalized where
/// possible) — guards against copying/moving an entry onto itself.
fn same_path(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

/// Pre-scan a local tree (files/dirs/bytes) before queueing a copy/move,
/// mirroring the C++ pre-scan. Symlinks are not followed (so cycles are
/// impossible); a visited-canonical-path guard is kept as defense-in-depth.
pub fn prescan(src: &Path) -> io::Result<Prescan> {
    let mut result = Prescan::default();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    // min_depth(1) skips the root itself: `dirs` counts the subdirectories
    // below `src` (the C++ pre-scan counted the tree under the selection).
    let walker = WalkDir::new(src).min_depth(1).follow_links(false);
    for item in walker {
        let item = item.map_err(|_| LocalFsError::Prescan(src.to_path_buf()))?;
        // Not strictly reachable without follow_links, but keep the guard so
        // the "skip symlink cycles" contract holds even if walkdir options
        // change.
        if let Ok(canon) = item.path().canonicalize() {
            if item.file_type().is_dir() && !visited.insert(canon) {
                continue;
            }
        }
        if item.file_type().is_dir() {
            result.dirs += 1;
        } else if item.file_type().is_file() {
            result.files += 1;
            result.bytes += item.metadata().map(|md| md.len()).unwrap_or(0);
        }
    }
    Ok(result)
}

/// Delete a batch of paths; `skip_missing` mirrors the batch delete with skip
/// handling. Returns the number of entries actually deleted.
pub fn delete_batch(paths: &[PathBuf], skip_missing: bool) -> io::Result<usize> {
    let mut deleted = 0usize;
    for path in paths {
        let missing = fs::symlink_metadata(path).is_err();
        if missing {
            if skip_missing {
                continue;
            }
            return Err(LocalFsError::Delete(path.clone()).into());
        }
        remove(path)?;
        deleted += 1;
    }
    Ok(deleted)
}

/// Case-insensitive substring search over the immediate entries of `dir`
/// (port of the non-recursive `searchItemsInCurrentFolder` match on the
/// entry name). Hidden files are included in the search.
pub fn find_in_dir(dir: &Path, needle: &str) -> io::Result<Vec<LocalEntry>> {
    let all = list_dir_with(dir, true)?;
    let needle = needle.to_lowercase();
    Ok(all
        .into_iter()
        .filter(|entry| entry.name.to_lowercase().contains(&needle))
        .collect())
}

// ---------------------------------------------------------------------------
// Search (Search items dialog)
// ---------------------------------------------------------------------------

/// Safety cap for recursive searches, port of `kRecursiveSearchMaxMatches`.
pub const MAX_SEARCH_MATCHES: usize = 5000;

/// Outcome of a recursive search: the matches plus the flags the C++
/// `showRecursiveSearchResultsDialog` summary reports (`scanErrors`,
/// `canceled`, `truncated`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchOutcome {
    /// Matches relative to the search base, in scan order.
    pub matches: Vec<String>,
    /// The [`MAX_SEARCH_MATCHES`] safety cap was hit.
    pub truncated: bool,
    /// Number of folders/entries the scan could not read.
    pub scan_errors: usize,
    /// The scan stopped early because the cancel flag was observed.
    pub canceled: bool,
}

/// Compiles the "Search items" pattern with the same semantics as the C++
/// `compilePanelSearchRegex`: raw regex when the pattern contains regex
/// metacharacters beyond `*`/`?`, anchored wildcard conversion when it
/// contains `*`/`?`, and case-insensitive substring matching otherwise.
#[derive(Debug, Clone)]
pub struct SearchMatcher {
    regex: Option<regex::Regex>,
    substr: Option<String>,
}

impl SearchMatcher {
    pub fn new(raw_pattern: &str) -> Result<Self, String> {
        let pattern = raw_pattern.trim();
        if pattern.is_empty() {
            return Err("The pattern is not valid.".to_string());
        }
        let build = |source: &str| {
            regex::RegexBuilder::new(source)
                .case_insensitive(true)
                .build()
                .map_err(|err| format!("The pattern is not valid.\n{err}"))
        };
        if has_regex_meta_beyond_wildcards(pattern) {
            Ok(Self {
                regex: Some(build(pattern)?),
                substr: None,
            })
        } else if pattern.contains('*') || pattern.contains('?') {
            Ok(Self {
                regex: Some(build(&wildcard_to_regex(pattern))?),
                substr: None,
            })
        } else {
            Ok(Self {
                regex: None,
                substr: Some(pattern.to_lowercase()),
            })
        }
    }

    /// Whether `name` matches the compiled pattern (C++ used
    /// `regex.match(name).hasMatch()`, i.e. a search, not a full match —
    /// except wildcard patterns, which are anchored).
    pub fn matches(&self, name: &str) -> bool {
        match (&self.regex, &self.substr) {
            (Some(re), _) => re.is_match(name),
            (None, Some(substr)) => name.to_lowercase().contains(substr.as_str()),
            (None, None) => false,
        }
    }
}

/// Port of the C++ `hasRegexMetaBeyondWildcards`.
fn has_regex_meta_beyond_wildcards(pattern: &str) -> bool {
    pattern.chars().any(|ch| {
        matches!(
            ch,
            '\\' | '.' | '^' | '$' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
        )
    })
}

/// Port of the C++ `wildcardPatternToRegex`: anchored, `*` → `.*`,
/// `?` → `.`, everything else escaped.
fn wildcard_to_regex(wildcard: &str) -> String {
    let mut out = String::with_capacity(wildcard.len() * 2 + 4);
    out.push('^');
    for ch in wildcard.chars() {
        match ch {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            other => out.push_str(&regex::escape(&other.to_string())),
        }
    }
    out.push('$');
    out
}

/// Recursive local search (port of the recursive branch of
/// `searchItemsInCurrentFolder`): walks subdirectories, matches entry names
/// against the pattern, and returns paths relative to `base` with `/`
/// separators. Recursion follows directories only (symlinks are not
/// followed), is capped at `max_depth`, honors the cancel flag, and stops
/// after [`MAX_SEARCH_MATCHES`] matches. The returned [`SearchOutcome`] also
/// carries the C++ `canceled` / `scanErrors` flags for the result summary.
pub fn search_local_recursive(
    base: &Path,
    pattern: &str,
    recursive: bool,
    max_depth: usize,
    include_hidden: bool,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<SearchOutcome, String> {
    let matcher = SearchMatcher::new(pattern)?;
    let mut outcome = SearchOutcome::default();
    let record = |outcome: &mut SearchOutcome, rel: String| {
        outcome.matches.push(rel);
        if outcome.matches.len() >= MAX_SEARCH_MATCHES {
            outcome.truncated = true;
        }
    };

    if !recursive {
        let entries = list_dir_with(base, true).map_err(|e| e.to_string())?;
        for entry in entries {
            if cancel.load(std::sync::atomic::Ordering::SeqCst) {
                outcome.canceled = true;
                break;
            }
            if !include_hidden && is_hidden_entry_name(&entry.name) {
                continue;
            }
            if matcher.matches(&entry.name) {
                record(&mut outcome, entry.name.clone());
                if outcome.truncated {
                    break;
                }
            }
        }
        return Ok(outcome);
    }

    let walker = walkdir::WalkDir::new(base)
        .follow_links(false)
        .max_depth(max_depth);
    for item in walker {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            outcome.canceled = true;
            break;
        }
        let item = match item {
            Ok(item) => item,
            Err(_) => {
                // Port of the C++ `scanErrors` counter: every entry the walk
                // could not read (permissions, races) counts once.
                outcome.scan_errors += 1;
                continue;
            }
        };
        if item.path() == base {
            continue;
        }
        let Some(name) = item.file_name().to_str() else {
            continue;
        };
        if !include_hidden && is_hidden_entry_name(name) {
            continue;
        }
        if matcher.matches(name) {
            let rel = item
                .path()
                .strip_prefix(base)
                .unwrap_or(item.path())
                .to_string_lossy()
                .replace('\\', "/");
            let rel = if rel.is_empty() {
                name.to_string()
            } else {
                rel
            };
            record(&mut outcome, rel);
            if outcome.truncated {
                break;
            }
        }
    }
    Ok(outcome)
}

/// Hidden-name check for search filtering (leading `.`).
pub fn is_hidden_entry_name(name: &str) -> bool {
    name.starts_with('.') && name != "." && name != ".."
}

/// Opens a URL in the default browser (used by the About "Report an issue"
/// link and similar affordances).
pub fn open_url(url: &str) -> io::Result<()> {
    let status = if cfg!(target_os = "macos") {
        Command::new("open").arg(url).status()
    } else if cfg!(target_os = "windows") {
        Command::new("explorer").arg(url).status()
    } else {
        Command::new("xdg-open").arg(url).status()
    };
    match status {
        Ok(st) if st.success() => Ok(()),
        _ => Err(LocalFsError::Open(PathBuf::from(url)).into()),
    }
}

/// Format a byte count like the Qt transfer queue (1024-based units, one
/// decimal when the value is < 10 and the unit is not bytes):
/// e.g. `"512 B"`, `"1.5 KB"`, `"4.2 MB"`.
pub fn format_size(bytes: u64) -> String {
    // QFileSystemModel renders local sizes with QLocale::formattedDataSize
    // (2 decimals, IEC units) and spells out byte counts ("5 bytes").
    const UNITS: [&str; 6] = ["bytes", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return if bytes == 1 {
            "1 byte".to_string()
        } else {
            format!("{bytes} bytes")
        };
    }
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

/// Remote-pane size text: `RemoteModel::data` formats sizes with
/// `QLocale::formattedDataSize(size, 1, DataSizeIecFormat)` — one decimal.
pub fn format_size_remote(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["bytes", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return if bytes == 1 {
            "1 byte".to_string()
        } else {
            format!("{bytes} bytes")
        };
    }
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Format an epoch-seconds timestamp for the local panel (port of
/// `TimeUtils.hpp::localShortTime`): local time, short format. Rust's chrono
/// has no locale database, so `QLocale::system().toString(ShortFormat)` is
/// approximated with `YYYY-MM-DD HH:MM` (24-hour); zero/out-of-range epochs
/// render as "—".
pub fn format_mtime(epoch_secs: u64) -> String {
    if epoch_secs == 0 {
        return "\u{2014}".to_string();
    }
    match chrono::DateTime::from_timestamp(epoch_secs as i64, 0) {
        Some(utc) => {
            let local = utc.with_timezone(&chrono::Local);
            local.format("%Y-%m-%d %H:%M").to_string()
        }
        None => "\u{2014}".to_string(),
    }
}

/// Open a path with the OS default handler (port of
/// `openLocalPathWithPreference`).
///
/// `behavior`: `"reveal"` selects the entry in the file manager (macOS
/// `open -R`, Windows `explorer /select,`, Linux opens the containing
/// folder); `"open"` opens the entry; `"ask"` behaves like `"open"` (the Qt
/// implementation popped a dialog, which the UI layer will do before calling
/// here — see deviations in the workstream report).
pub fn open_in_os(path: &Path, behavior: &str) -> io::Result<()> {
    let reveal = match behavior {
        "open" | "ask" => false,
        "reveal" => true,
        other => {
            return Err(LocalFsError::InvalidBehavior(other.to_string()).into());
        }
    };
    let status = if cfg!(target_os = "macos") {
        if reveal {
            Command::new("open").arg("-R").arg(path).status()
        } else {
            Command::new("open").arg(path).status()
        }
    } else if cfg!(target_os = "windows") {
        if reveal {
            Command::new("explorer")
                .arg(format!("/select,{}", path.display()))
                .status()
        } else {
            Command::new("explorer").arg(path).status()
        }
    } else {
        let dir = path.parent().unwrap_or(path);
        if reveal {
            Command::new("xdg-open").arg(dir).status()
        } else {
            Command::new("xdg-open").arg(path).status()
        }
    };
    match status {
        Ok(st) if st.success() => Ok(()),
        _ => Err(LocalFsError::Open(path.to_path_buf()).into()),
    }
}

// ---------------------------------------------------------------------------
// Async wrappers (spawn_blocking) for calling from the Slint UI thread.
// ---------------------------------------------------------------------------

/// [`list_dir`] on the blocking pool.
#[allow(dead_code)] // local pane reloads synchronously; kept for future non-blocking reloads
pub async fn list_dir_async(path: &Path) -> io::Result<Vec<LocalEntry>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || list_dir(&path))
        .await
        .map_err(io::Error::other)?
}

/// [`list_dir_with`] on the blocking pool.
#[allow(dead_code)] // local pane reloads synchronously; kept for future non-blocking reloads
pub async fn list_dir_with_async(path: &Path, show_hidden: bool) -> io::Result<Vec<LocalEntry>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || list_dir_with(&path, show_hidden))
        .await
        .map_err(io::Error::other)?
}

/// [`create_dir`] on the blocking pool.
pub async fn create_dir_async(path: &Path) -> io::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || create_dir(&path))
        .await
        .map_err(io::Error::other)?
}

/// [`create_file`] on the blocking pool.
pub async fn create_file_async(path: &Path) -> io::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || create_file(&path))
        .await
        .map_err(io::Error::other)?
}

/// [`rename`] on the blocking pool.
pub async fn rename_async(from: &Path, to: &Path, overwrite: bool) -> io::Result<()> {
    let (from, to) = (from.to_path_buf(), to.to_path_buf());
    tokio::task::spawn_blocking(move || rename(&from, &to, overwrite))
        .await
        .map_err(io::Error::other)?
}

/// [`remove`] on the blocking pool.
pub async fn remove_async(path: &Path) -> io::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || remove(&path))
        .await
        .map_err(io::Error::other)?
}

/// [`copy_local`] on the blocking pool. The closures must be
/// `Send + Sync + 'static`; use `Arc<Mutex<…>>`/atomics for progress state
/// or cancellation flags owned by the UI.
#[allow(dead_code)] // same-pane copy/move currently uses the transfer queue
pub async fn copy_local_async(
    src: &Path,
    dst: &Path,
    overwrite: bool,
    skip_existing: bool,
    progress: impl Fn(u64, u64) + Send + Sync + 'static,
    should_cancel: impl Fn() -> bool + Send + Sync + 'static,
) -> io::Result<u64> {
    let (src, dst) = (src.to_path_buf(), dst.to_path_buf());
    tokio::task::spawn_blocking(move || {
        copy_local(
            &src,
            &dst,
            overwrite,
            skip_existing,
            &progress,
            &should_cancel,
        )
    })
    .await
    .map_err(io::Error::other)?
}

/// [`move_local`] on the blocking pool. The closures must be
/// `Send + Sync + 'static` (see [`copy_local_async`]).
#[allow(dead_code)] // same-pane copy/move currently uses the transfer queue
pub async fn move_local_async(
    src: &Path,
    dst: &Path,
    overwrite: bool,
    skip_existing: bool,
    progress: impl Fn(u64, u64) + Send + Sync + 'static,
    should_cancel: impl Fn() -> bool + Send + Sync + 'static,
) -> io::Result<u64> {
    let (src, dst) = (src.to_path_buf(), dst.to_path_buf());
    tokio::task::spawn_blocking(move || {
        move_local(
            &src,
            &dst,
            overwrite,
            skip_existing,
            &progress,
            &should_cancel,
        )
    })
    .await
    .map_err(io::Error::other)?
}

/// [`prescan`] on the blocking pool.
#[allow(dead_code)] // uploads prescan via transfer::upload_prescan (C++-parity wrapper); kept for direct callers
pub async fn prescan_async(src: &Path) -> io::Result<Prescan> {
    let src = src.to_path_buf();
    tokio::task::spawn_blocking(move || prescan(&src))
        .await
        .map_err(io::Error::other)?
}

/// [`delete_batch`] on the blocking pool.
pub async fn delete_batch_async(paths: &[PathBuf], skip_missing: bool) -> io::Result<usize> {
    let paths = paths.to_vec();
    tokio::task::spawn_blocking(move || delete_batch(&paths, skip_missing))
        .await
        .map_err(io::Error::other)?
}

/// [`find_in_dir`] on the blocking pool.
#[allow(dead_code)] // local search runs synchronously on the UI thread
pub async fn find_in_dir_async(dir: &Path, needle: &str) -> io::Result<Vec<LocalEntry>> {
    let (dir, needle) = (dir.to_path_buf(), needle.to_string());
    tokio::task::spawn_blocking(move || find_in_dir(&dir, &needle))
        .await
        .map_err(io::Error::other)?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temp dir for a test; removed on drop.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "freescp_local_fs_{}_{}_{}",
                tag,
                std::process::id(),
                n
            ));
            fs::create_dir_all(&path).unwrap();
            TempDir { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    // Test fixture helper (used by newer listing tests as they land).
    #[allow(dead_code)]
    fn entry(name: &str, is_dir: bool) -> LocalEntry {
        LocalEntry {
            name: name.to_string(),
            is_dir,
            size: 0,
            mtime: 0,
            mode: 0,
        }
    }

    #[test]
    fn list_dir_sorts_dirs_first_and_hides_dotfiles() {
        let tmp = TempDir::new("list");
        fs::create_dir(tmp.path.join("zeta")).unwrap();
        fs::create_dir(tmp.path.join("Alpha")).unwrap();
        fs::write(tmp.path.join("mango.txt"), b"x").unwrap();
        fs::write(tmp.path.join("Beta.txt"), b"xx").unwrap();
        fs::write(tmp.path.join(".hidden"), b"").unwrap();

        let listed = list_dir(&tmp.path).unwrap();
        let names: Vec<&str> = listed.iter().map(|e| e.name.as_str()).collect();
        // Directories first (case-insensitive), then files (case-insensitive),
        // dotfile hidden.
        assert_eq!(names, vec!["Alpha", "zeta", "Beta.txt", "mango.txt"]);

        let with_hidden = list_dir_with(&tmp.path, true).unwrap();
        assert!(with_hidden.iter().any(|e| e.name == ".hidden"));

        // Not a directory.
        let file = tmp.path.join("mango.txt");
        assert!(list_dir(&file).is_err());
    }

    #[test]
    fn entry_metadata_fields_are_populated() {
        let tmp = TempDir::new("meta");
        let f = tmp.path.join("file.txt");
        fs::write(&f, b"hello").unwrap();
        let listed = list_dir(&tmp.path).unwrap();
        let e = listed.iter().find(|e| e.name == "file.txt").unwrap();
        assert_eq!(e.size, 5);
        assert!(!e.is_dir);
        assert!(e.mtime > 0);
    }

    #[test]
    fn create_rename_remove_roundtrip() {
        let tmp = TempDir::new("ops");
        let dir = tmp.path.join("newdir");
        create_dir(&dir).unwrap();
        assert!(dir.is_dir());

        let file = dir.join("a.txt");
        create_file(&file).unwrap();
        assert!(file.is_file());
        // Recreating truncates (Qt Truncate semantics).
        fs::write(&file, b"content").unwrap();
        create_file(&file).unwrap();
        assert_eq!(fs::metadata(&file).unwrap().len(), 0);

        let renamed = dir.join("b.txt");
        rename(&file, &renamed, false).unwrap();
        assert!(!file.exists() && renamed.exists());

        // Rename over an existing entry without overwrite fails.
        let other = dir.join("c.txt");
        create_file(&other).unwrap();
        assert!(rename(&other, &renamed, false).is_err());
        assert!(rename(&other, &renamed, true).is_ok());

        remove(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn copy_file_policies_and_progress() {
        let tmp = TempDir::new("copy");
        let src = tmp.path.join("src.bin");
        fs::write(&src, vec![0u8; 300 * 1024]).unwrap();
        let dst = tmp.path.join("dst.bin");

        let calls = std::cell::Cell::new(0u32);
        let progress = |done: u64, total: u64| {
            calls.set(calls.get() + 1);
            assert_eq!(total, 300 * 1024);
            assert!(done <= total);
        };
        let copied = copy_local(&src, &dst, false, false, &progress, &|| false).unwrap();
        assert_eq!(copied, 300 * 1024);
        assert!(calls.get() > 1);

        // Conflict without overwrite.
        assert!(copy_local(&src, &dst, false, false, &|_, _| {}, &|| false).is_err());
        // Skip existing.
        assert_eq!(
            copy_local(&src, &dst, false, true, &|_, _| {}, &|| false).unwrap(),
            0
        );
        // Overwrite succeeds.
        assert!(copy_local(&src, &dst, true, false, &|_, _| {}, &|| false).is_ok());

        // Cancellation.
        let n = std::cell::Cell::new(0u32);
        let should_cancel = || {
            n.set(n.get() + 1);
            n.get() > 2
        };
        let dst2 = tmp.path.join("dst2.bin");
        let err = copy_local(&src, &dst2, false, false, &|_, _| {}, &should_cancel).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn copy_directory_recurses_with_conflicts() {
        let tmp = TempDir::new("copydir");
        let src = tmp.path.join("tree");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("sub/inner.txt"), b"inner").unwrap();
        fs::write(src.join("top.txt"), b"top").unwrap();
        let dst = tmp.path.join("dst");

        let bytes = copy_local(&src, &dst, false, false, &|_, _| {}, &|| false).unwrap();
        assert_eq!(bytes, 8);
        assert!(dst.join("sub/inner.txt").exists() && dst.join("top.txt").exists());

        // Copy again without overwrite: top-level conflict aborts.
        assert!(copy_local(&src, &dst, false, false, &|_, _| {}, &|| false).is_err());
        // Overwrite refreshes the tree.
        assert!(copy_local(&src, &dst, true, false, &|_, _| {}, &|| false).is_ok());

        // Move: rename path + cross-device fallback logic (rename works here).
        let dst2 = tmp.path.join("moved");
        let bytes = move_local(&src, &dst2, false, false, &|_, _| {}, &|| false).unwrap();
        assert!(!src.exists() && dst2.join("top.txt").exists());
        let _ = bytes;
    }

    #[test]
    fn prescan_counts_tree() {
        let tmp = TempDir::new("prescan");
        fs::create_dir_all(tmp.path.join("a/b")).unwrap();
        fs::write(tmp.path.join("a/b/f.txt"), b"1234").unwrap();
        fs::write(tmp.path.join("a/top.txt"), b"12").unwrap();

        let p = prescan(&tmp.path).unwrap();
        assert_eq!(p.files, 2);
        assert_eq!(p.dirs, 2);
        assert_eq!(p.bytes, 6);

        // Missing path errors.
        assert!(prescan(&tmp.path.join("nope")).is_err());
    }

    #[test]
    fn delete_batch_skips_missing() {
        let tmp = TempDir::new("batch");
        let a = tmp.path.join("a.txt");
        let b = tmp.path.join("b.txt");
        fs::write(&a, b"x").unwrap();
        fs::write(&b, b"y").unwrap();
        let missing = tmp.path.join("missing.txt");

        let deleted = delete_batch(&[a.clone(), b.clone(), missing.clone()], true).unwrap();
        assert_eq!(deleted, 2);
        assert!(!a.exists() && !b.exists());

        assert!(delete_batch(&[missing], false).is_err());
    }

    #[test]
    fn find_in_dir_is_case_insensitive_substring() {
        let tmp = TempDir::new("find");
        fs::write(tmp.path.join("Report2026.txt"), b"").unwrap();
        fs::write(tmp.path.join("report-backup.txt"), b"").unwrap();
        fs::write(tmp.path.join("other.txt"), b"").unwrap();

        let hits = find_in_dir(&tmp.path, "REPORT").unwrap();
        let names: Vec<&str> = hits.iter().map(|e| e.name.as_str()).collect();
        // Ordering comes from `list_dir_with` (case-insensitive by name, so
        // '-' < '2'), not from the search itself.
        assert_eq!(names, vec!["report-backup.txt", "Report2026.txt"]);
    }

    #[test]
    fn entry_name_validation_matches_qt() {
        let mut why = None;
        assert!(is_valid_entry_name("ok name.txt", &mut why));
        assert!(!is_valid_entry_name(".", &mut why));
        assert!(why.is_some());
        assert!(!is_valid_entry_name("..", &mut why));
        assert!(!is_valid_entry_name("a/b", &mut why));
        assert!(!is_valid_entry_name("a\\b", &mut why));
        assert!(!is_valid_entry_name("ctrl\u{1}", &mut why));
        assert!(!is_valid_entry_name("del\u{7F}", &mut why));
    }

    #[test]
    fn size_formatting_matches_qt_panes() {
        assert_eq!(format_size(0), "0 bytes");
        assert_eq!(format_size(1), "1 byte");
        assert_eq!(format_size(512), "512 bytes");
        assert_eq!(format_size(1024), "1.00 KiB");
        assert_eq!(format_size(1536), "1.50 KiB");
        assert_eq!(format_size(1048576), "1.00 MiB");
        assert_eq!(format_size(4294967296), "4.00 GiB");
        assert_eq!(format_size(1099511627776), "1.00 TiB");
        assert_eq!(format_size(10240), "10.00 KiB");
        // RemoteModel uses one decimal (DataSizeIecFormat with precision 1).
        assert_eq!(format_size_remote(1536), "1.5 KiB");
        assert_eq!(format_size_remote(10240), "10.0 KiB");
        assert_eq!(format_size_remote(512), "512 bytes");
    }

    #[test]
    fn mtime_formatting_handles_zero_and_valid() {
        assert_eq!(format_mtime(0), "\u{2014}");
        // Local-timezone-independent checks: shape "YYYY-MM-DD HH:MM".
        let formatted = format_mtime(1_800_000_000);
        assert_eq!(formatted.len(), 16);
        assert_eq!(&formatted[4..5], "-");
        assert_eq!(&formatted[13..14], ":");
    }

    #[test]
    fn home_dir_exists() {
        let home = home_dir();
        assert!(home.exists(), "home dir {} should exist", home.display());
    }

    #[test]
    fn invalid_behavior_is_reported() {
        let err = open_in_os(Path::new("/tmp"), "frobnicate").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn recursive_search_reports_matches_truncation_and_cancel() {
        let tmp = TempDir::new("search");
        fs::create_dir_all(tmp.path.join("sub/deep")).unwrap();
        fs::write(tmp.path.join("sub/deep/match.txt"), b"x").unwrap();
        fs::write(tmp.path.join("sub/other.txt"), b"x").unwrap();

        let cancel = std::sync::atomic::AtomicBool::new(false);
        let outcome = search_local_recursive(&tmp.path, "match", true, 16, true, &cancel).unwrap();
        assert_eq!(outcome.matches, vec!["sub/deep/match.txt"]);
        assert!(!outcome.truncated);
        assert!(!outcome.canceled);
        assert_eq!(outcome.scan_errors, 0);

        // A pre-set cancel flag stops the walk and is reported in the outcome.
        let canceled = std::sync::atomic::AtomicBool::new(true);
        let outcome =
            search_local_recursive(&tmp.path, "match", true, 16, true, &canceled).unwrap();
        assert!(outcome.matches.is_empty());
        assert!(outcome.canceled);
        assert!(!outcome.truncated);
    }
}
