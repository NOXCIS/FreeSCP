//! SMB2/3 backend — pure-Rust client for SMB/CIFS shares backed by the
//! [smb2] crate (no SMB1; no proxy, jump-host, permissions, ownership, or
//! set-times support — see `ProtocolCapabilities` for `Protocol::Smb`).
//!
//! # Path semantics
//!
//! Remote paths have the form `/Share/sub/dir/file.txt`: the first component
//! after the root is the share name and the remainder is share-relative.
//! `list("/")` returns the server's shares (via `list_shares()`, an RPC
//! exchange over the IPC$ share) as directories.
//!
//! # Design notes
//!
//! * Unlike the FTP/WebDAV backends (sync crates bridged through
//!   `spawn_blocking`), `smb2` is natively async, so the client holds a
//!   persistent `smb2::SmbClient` across operations and awaits it directly.
//! * `auto_reconnect` is enabled, so a dead session (NAS reboot, Wi-Fi roam)
//!   is revived in place by the library; mutating operations are never
//!   replayed across a reconnect.
//! * Streaming transfers use the chunked `FileDownload`/`FileWriter` APIs
//!   (64 KiB chunks) with per-chunk progress and cancellation checks. Resume
//!   uses the positioned `FileReader`/`create_file_writer_at` APIs.
//! * SMB2 rename does not replace an existing destination, so
//!   `rename(.., overwrite=true)` deletes the target first.

use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use smb2::SmbClient as NativeSmbClient;
use tracing::{debug, info, warn};

use crate::client::{CancelCb, ClientError, ProgressCb, SftpClient};
use crate::types::{FileInfo, Protocol, SessionOptions};

/// Mirrors libcurl `CURLOPT_CONNECTTIMEOUT` (seconds).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Transfer chunk size used for progress and cancellation checks.
const TRANSFER_CHUNK: usize = 64 * 1024;
/// Safety cap for recursive `remove_dir` depth (mirrors the FTP backend).
const MAX_REMOVE_DEPTH: usize = 128;

/// Everything needed to establish a session. The native client keeps its own
/// copy for auto-reconnect; this snapshot is kept for diagnostics and
/// `new_connection_like`.
#[derive(Clone)]
struct SmbSessionConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    domain: String,
}

/// SMB2/3 client implementing [`SftpClient`].
pub struct SmbClient {
    inner: Option<NativeSmbClient>,
    config: Option<SmbSessionConfig>,
    connected: bool,
    interrupted: Arc<AtomicBool>,
}

impl Default for SmbClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SmbClient {
    /// Creates an unconnected SMB client.
    pub fn new() -> Self {
        Self {
            inner: None,
            config: None,
            connected: false,
            interrupted: Arc::new(AtomicBool::new(false)),
        }
    }

    fn not_connected() -> ClientError {
        ClientError::Other("Not connected.".into())
    }

    fn require_inner(&mut self) -> Result<&mut NativeSmbClient, ClientError> {
        if !self.connected {
            return Err(Self::not_connected());
        }
        self.inner.as_mut().ok_or_else(Self::not_connected)
    }
}

fn unsupported(what: &str) -> ClientError {
    ClientError::Unsupported(format!("SMB backend does not support {what}."))
}

// ---------------------------------------------------------------------------
// Path handling
// ---------------------------------------------------------------------------

/// Normalizes a user-supplied remote path: empty → `/`, no leading slash →
/// prefixed with `/` (mirrors the FTP backend helper).
///
/// Public so the integration-style unit tests in `tests/smb_tests.rs` can
/// exercise path handling directly.
pub fn normalize_remote_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// Splits `/Share/sub/dir` into `("Share", "sub/dir")`. The root (`/`) has no
/// share component and is rejected here; callers route the root to
/// `list_shares()` instead. Empty path components are ignored so `/Share///`
/// resolves to the share root (`""`).
///
/// Public so the integration-style unit tests in `tests/smb_tests.rs` can
/// exercise path handling directly.
pub fn split_share(path: &str) -> Result<(String, String), ClientError> {
    let normalized = normalize_remote_path(path);
    let mut components = normalized.split('/').filter(|c| !c.is_empty());
    let share = components
        .next()
        .ok_or_else(|| ClientError::Other("SMB path must include a share name.".into()))?;
    let subpath = components.collect::<Vec<_>>().join("/");
    Ok((share.to_string(), subpath))
}

/// Windows FILETIME → Unix epoch seconds (`0` when unset or pre-1970).
///
/// Public so the integration-style unit tests in `tests/smb_tests.rs` can
/// exercise the conversion directly.
pub fn filetime_to_epoch(filetime: smb2::pack::FileTime) -> u64 {
    use std::time::UNIX_EPOCH;
    filetime
        .to_system_time()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn strip_trailing_slash(path: &str) -> &str {
    if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    }
}

fn join_subpath(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_string()
    } else {
        format!("{base}/{name}")
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Maps a `smb2` error onto [`ClientError`]: auth/access failures become
/// `AuthFailed`, transport failures become `Io`, everything else is an
/// `OperationFailed` carrying the server-side reason.
///
/// Public so the integration-style unit tests in `tests/smb_tests.rs` can
/// exercise the mapping directly.
pub fn map_smb_error(e: smb2::Error) -> ClientError {
    match e {
        smb2::Error::Io(io) => ClientError::Io(io),
        other => match other.kind() {
            smb2::ErrorKind::AuthRequired
            | smb2::ErrorKind::SigningRequired
            | smb2::ErrorKind::AccessDenied => ClientError::AuthFailed(other.to_string()),
            smb2::ErrorKind::TimedOut => ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                other.to_string(),
            )),
            smb2::ErrorKind::ConnectionLost => ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                other.to_string(),
            )),
            _ => ClientError::OperationFailed(other.to_string()),
        },
    }
}

/// Whether an error means "path does not exist" for `exists()`.
fn is_not_found(e: &smb2::Error) -> bool {
    e.kind() == smb2::ErrorKind::NotFound
}

/// True for the synthetic `.`/`..` entries SMB2 directory listings include.
///
/// Public so the unit tests in `tests/smb_tests.rs` can exercise it.
pub fn is_dot_entry(name: &str) -> bool {
    name == "." || name == ".."
}

/// Resume decision for the SMB client's `put`: what to do with a remote file
/// of `remote_size` bytes when the local file holds `total` bytes.
///
/// Public so the unit tests in `tests/smb_tests.rs` can exercise the
/// data-safety rule directly (the integration suite is env-gated).
#[derive(Debug, PartialEq, Eq)]
pub enum ResumePlan {
    /// Remote size matches the local size: the upload is already complete.
    Complete,
    /// Send the remainder, starting at this offset.
    FromOffset(u64),
}

/// Classifies a remote size for a resuming upload. Sizes larger than the local
/// file are refused: writing would truncate data the caller did not intend to
/// lose.
pub fn plan_resume(remote_size: u64, total: u64) -> Result<ResumePlan, String> {
    if remote_size == total {
        Ok(ResumePlan::Complete)
    } else if remote_size < total {
        Ok(ResumePlan::FromOffset(remote_size))
    } else {
        Err(format!(
            "SMB resume failed: the remote file is larger ({remote_size}) than the local file ({total})"
        ))
    }
}

// ---------------------------------------------------------------------------
// Metadata mapping
// ---------------------------------------------------------------------------

fn mode_for(is_dir: bool) -> u32 {
    if is_dir {
        0o040000
    } else {
        0o100000
    }
}

fn file_info_from_directory_entry(entry: &smb2::DirectoryEntry) -> FileInfo {
    FileInfo {
        name: entry.name.clone(),
        is_dir: entry.is_directory,
        size: if entry.is_directory { 0 } else { entry.size },
        has_size: !entry.is_directory,
        mtime: filetime_to_epoch(entry.modified),
        mode: mode_for(entry.is_directory),
        uid: 0,
        gid: 0,
    }
}

fn file_info_from_stat(info: &smb2::client::tree::FileInfo, name: &str) -> FileInfo {
    FileInfo {
        name: name.to_string(),
        is_dir: info.is_directory,
        size: if info.is_directory { 0 } else { info.size },
        has_size: !info.is_directory,
        mtime: filetime_to_epoch(info.modified),
        mode: mode_for(info.is_directory),
        uid: 0,
        gid: 0,
    }
}

// ---------------------------------------------------------------------------
// File operations
// ---------------------------------------------------------------------------

/// Recursive bottom-up directory removal shared by `remove_dir` and
/// `rename(.., overwrite=true)` for directory targets.
async fn remove_dir_impl(
    client: &mut NativeSmbClient,
    tree: &mut smb2::Tree,
    dir: &str,
    context: &'static str,
) -> Result<(), ClientError> {
    async fn remove_recursive(
        client: &mut NativeSmbClient,
        tree: &mut smb2::Tree,
        dir: &str,
        depth: usize,
        context: &'static str,
    ) -> Result<(), ClientError> {
        if depth > MAX_REMOVE_DEPTH {
            return Err(ClientError::Other(format!(
                "SMB {context} failed: recursion limit exceeded at '{dir}'"
            )));
        }
        let entries = client
            .list_directory(tree, dir)
            .await
            .map_err(map_smb_error)?;
        for entry in &entries {
            // SMB2 QUERY_DIRECTORY includes `.`/`..`; recursing into them would
            // loop until the depth cap and fail on every nested directory.
            if is_dot_entry(&entry.name) {
                continue;
            }
            let child = join_subpath(dir, &entry.name);
            if entry.is_directory {
                Box::pin(remove_recursive(client, tree, &child, depth + 1, context)).await?;
            } else {
                client
                    .delete_file(tree, &child)
                    .await
                    .map_err(map_smb_error)?;
            }
        }
        client
            .delete_directory(tree, dir)
            .await
            .map_err(map_smb_error)
    }
    remove_recursive(client, tree, dir, 0, context).await
}

// ---------------------------------------------------------------------------
// SftpClient implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl SftpClient for SmbClient {
    fn protocol(&self) -> Protocol {
        Protocol::Smb
    }

    fn interrupt(&self) {
        self.interrupted.store(true, Ordering::SeqCst);
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    async fn connect(&mut self, opt: &SessionOptions) -> Result<(), ClientError> {
        self.interrupted.store(false, Ordering::SeqCst);
        if opt.host.is_empty() {
            return Err(ClientError::Other("Host is required.".into()));
        }
        if opt.jump_host.as_deref().is_some_and(|j| !j.is_empty()) {
            return Err(unsupported("SSH jump host"));
        }
        if !matches!(opt.proxy_type, crate::types::ProxyType::None) {
            return Err(unsupported("proxy tunneling"));
        }
        let port = if opt.port == 0 {
            crate::types::default_port_for_protocol(Protocol::Smb)
        } else {
            opt.port
        };
        let config = SmbSessionConfig {
            host: opt.host.clone(),
            port,
            username: opt.username.clone(),
            password: opt.password.clone().unwrap_or_default(),
            domain: opt.smb_domain.clone().unwrap_or_default(),
        };
        let native_config = smb2::ClientConfig {
            addr: format!("{}:{}", config.host, config.port),
            timeout: CONNECT_TIMEOUT,
            username: config.username.clone(),
            password: config.password.clone(),
            domain: config.domain.clone(),
            auto_reconnect: true,
            compression: true,
            dfs_enabled: true,
            dfs_target_overrides: Default::default(),
        };
        let mut client = NativeSmbClient::connect(native_config)
            .await
            .map_err(map_smb_error)?;
        // Probe: enumerating shares over IPC$ proves the connection and the
        // credentials work end-to-end (mirrors the FTP DIRLISTONLY probe).
        client.list_shares().await.map_err(|e| {
            debug!(error = %e, "SMB connect probe (share enumeration) failed");
            map_smb_error(e)
        })?;
        self.inner = Some(client);
        self.config = Some(config);
        self.connected = true;
        info!(host = %opt.host, port, "SMB connection established");
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
        self.interrupted.store(false, Ordering::SeqCst);
        self.inner = None;
        self.config = None;
        self.connected = false;
        Ok(())
    }

    async fn list(&mut self, remote_path: &str) -> Result<Vec<FileInfo>, ClientError> {
        let normalized = normalize_remote_path(remote_path);
        let client = self.require_inner()?;
        if normalized == "/" {
            let shares = client.list_shares().await.map_err(map_smb_error)?;
            debug!(count = shares.len(), "SMB root listing (shares)");
            return Ok(shares
                .iter()
                .map(|share| FileInfo {
                    name: share.name.clone(),
                    is_dir: true,
                    size: 0,
                    has_size: false,
                    mtime: 0,
                    mode: 0o040000,
                    uid: 0,
                    gid: 0,
                })
                .collect());
        }
        let (share, subpath) = split_share(remote_path)?;
        let mut tree = client.connect_share(&share).await.map_err(map_smb_error)?;
        let entries = client
            .list_directory(&mut tree, &subpath)
            .await
            .map_err(map_smb_error)?;
        // SMB2 listings include the `.`/`..` pseudo-entries; every other
        // backend filters them, and callers expect real children only.
        Ok(entries
            .iter()
            .filter(|entry| !is_dot_entry(&entry.name))
            .map(file_info_from_directory_entry)
            .collect())
    }

    async fn get(
        &mut self,
        remote: &str,
        local: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError> {
        self.interrupted.store(false, Ordering::SeqCst);
        let (share, subpath) = split_share(remote)?;
        let interrupted = Arc::clone(&self.interrupted);
        let client = self.require_inner()?;
        let tree = client.connect_share(&share).await.map_err(map_smb_error)?;

        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        let mut offset: u64 = 0;
        if resume {
            options.create(true).append(true);
            offset = std::fs::metadata(local).map(|m| m.len()).unwrap_or(0);
        } else {
            options.create(true).truncate(true);
        }
        let mut file = options.open(local).map_err(|e| {
            ClientError::Io(std::io::Error::new(
                e.kind(),
                format!("Could not open local file for writing: {e}"),
            ))
        })?;
        let check_cancel = |should_cancel: &Option<CancelCb>, interrupted: &Arc<AtomicBool>| {
            if interrupted.load(Ordering::SeqCst) {
                Err(ClientError::Other("Interrupted".into()))
            } else if should_cancel.as_ref().is_some_and(|cb| cb()) {
                Err(ClientError::Cancelled)
            } else {
                Ok(())
            }
        };

        if resume && offset > 0 {
            // Positioned reads over one open handle (SMB `pread` analog).
            let reader = client
                .open_file_reader(&tree, &subpath)
                .await
                .map_err(map_smb_error)?;
            let total = reader.size();
            if offset > total {
                warn!(
                    offset,
                    total, "resume offset exceeds remote size; restarting download"
                );
                offset = 0;
                file.set_len(0).map_err(ClientError::Io)?;
                file.seek(SeekFrom::Start(0)).map_err(ClientError::Io)?;
            } else if offset == total {
                debug!("download already complete (offset == remote size)");
                let _ = reader.close().await;
                return Ok(());
            }
            let mut done = offset;
            loop {
                check_cancel(&should_cancel, &interrupted)?;
                let want = std::cmp::min(TRANSFER_CHUNK as u64, total - done);
                let data = reader.read_at(done, want).await.map_err(map_smb_error)?;
                if data.is_empty() {
                    break;
                }
                file.write_all(&data).map_err(ClientError::Io)?;
                done += data.len() as u64;
                if let Some(cb) = progress.as_ref() {
                    cb(done, total);
                }
            }
            let _ = reader.close().await;
            if let Some(cb) = progress.as_ref() {
                cb(done, total);
            }
            return Ok(());
        }

        // Sequential streaming download (one chunk in memory at a time).
        let mut download = client
            .download(&tree, &subpath)
            .await
            .map_err(map_smb_error)?;
        let total = download.size();
        let mut done: u64 = 0;
        while let Some(chunk) = download.next_chunk().await {
            check_cancel(&should_cancel, &interrupted)?;
            let data = chunk.map_err(map_smb_error)?;
            file.write_all(&data).map_err(ClientError::Io)?;
            done += data.len() as u64;
            if let Some(cb) = progress.as_ref() {
                cb(done, total);
            }
        }
        if let Some(cb) = progress.as_ref() {
            cb(done, total);
        }
        Ok(())
    }

    async fn put(
        &mut self,
        local: &str,
        remote: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError> {
        self.interrupted.store(false, Ordering::SeqCst);
        let (share, subpath) = split_share(remote)?;
        let interrupted = Arc::clone(&self.interrupted);
        let client = self.require_inner()?;
        let mut tree = client.connect_share(&share).await.map_err(map_smb_error)?;

        let total = std::fs::metadata(local)
            .map_err(|e| {
                ClientError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Could not determine local file size: {e}"),
                ))
            })?
            .len();
        let mut file = std::fs::File::open(local).map_err(|e| {
            ClientError::Io(std::io::Error::new(
                e.kind(),
                format!("Could not open local file for reading: {e}"),
            ))
        })?;
        let mut offset: u64 = 0;
        if resume {
            match client.stat(&mut tree, &subpath).await {
                Ok(info) => match plan_resume(info.size, total) {
                    Ok(ResumePlan::Complete) => {
                        debug!("upload already complete (remote size matches local size)");
                        return Ok(());
                    }
                    Ok(ResumePlan::FromOffset(from)) => offset = from,
                    Err(message) => return Err(ClientError::Other(message)),
                },
                // Only "missing" starts from scratch; other stat failures must
                // not be mistaken for an absent file (that would truncate).
                Err(e) if is_not_found(&e) => offset = 0,
                Err(e) => return Err(map_smb_error(e)),
            }
        }
        let check_cancel = |should_cancel: &Option<CancelCb>, interrupted: &Arc<AtomicBool>| {
            if interrupted.load(Ordering::SeqCst) {
                Err(ClientError::Other("Interrupted".into()))
            } else if should_cancel.as_ref().is_some_and(|cb| cb()) {
                Err(ClientError::Cancelled)
            } else {
                Ok(())
            }
        };

        let mut writer = if offset > 0 {
            client
                .create_file_writer_at(&tree, &subpath, offset)
                .await
                .map_err(map_smb_error)?
        } else {
            client
                .create_file_writer(&tree, &subpath)
                .await
                .map_err(map_smb_error)?
        };
        file.seek(SeekFrom::Start(offset))
            .map_err(ClientError::Io)?;
        let mut buf = vec![0u8; TRANSFER_CHUNK];
        let mut done = offset;
        loop {
            if let Err(cancel_err) = check_cancel(&should_cancel, &interrupted) {
                let _ = writer.abort().await;
                return Err(cancel_err);
            }
            if done >= total {
                break;
            }
            let want = std::cmp::min(buf.len() as u64, total - done) as usize;
            match file.read(&mut buf[..want]) {
                Ok(0) => break,
                Ok(n) => {
                    writer.write_chunk(&buf[..n]).await.map_err(map_smb_error)?;
                    done += n as u64;
                    if let Some(cb) = progress.as_ref() {
                        cb(done, total);
                    }
                }
                Err(e) => {
                    let _ = writer.abort().await;
                    return Err(ClientError::Io(e));
                }
            }
        }
        writer.finish().await.map_err(map_smb_error)?;
        if let Some(cb) = progress.as_ref() {
            cb(done, total);
        }
        Ok(())
    }

    async fn exists(&mut self, remote_path: &str) -> Result<Option<bool>, ClientError> {
        let normalized = normalize_remote_path(remote_path);
        let normalized = strip_trailing_slash(&normalized);
        if normalized == "/" {
            return Ok(Some(true));
        }
        let (share, subpath) = split_share(remote_path)?;
        let client = self.require_inner()?;
        let mut tree = client.connect_share(&share).await.map_err(map_smb_error)?;
        match client.stat(&mut tree, &subpath).await {
            Ok(info) => Ok(Some(info.is_directory)),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(map_smb_error(e)),
        }
    }

    async fn stat(&mut self, remote_path: &str) -> Result<FileInfo, ClientError> {
        let (share, subpath) = split_share(remote_path)?;
        let client = self.require_inner()?;
        let mut tree = client.connect_share(&share).await.map_err(map_smb_error)?;
        let info = client
            .stat(&mut tree, &subpath)
            .await
            .map_err(map_smb_error)?;
        let name = subpath.rsplit('/').next().unwrap_or(&subpath);
        Ok(file_info_from_stat(&info, name))
    }

    async fn chmod(&mut self, _remote_path: &str, _mode: u32) -> Result<(), ClientError> {
        Err(unsupported("chmod (SMB2 has no POSIX permission model)"))
    }

    async fn chown(&mut self, _remote_path: &str, _uid: u32, _gid: u32) -> Result<(), ClientError> {
        Err(unsupported("chown"))
    }

    async fn set_times(
        &mut self,
        _remote_path: &str,
        _atime: u64,
        _mtime: u64,
    ) -> Result<(), ClientError> {
        Err(unsupported("set_times"))
    }

    async fn mkdir(&mut self, remote_dir: &str, mode: u32) -> Result<(), ClientError> {
        debug!(
            dir = remote_dir,
            mode, "SMB mkdir (mode ignored by the SMB protocol)"
        );
        let (share, subpath) = split_share(remote_dir)?;
        let client = self.require_inner()?;
        let mut tree = client.connect_share(&share).await.map_err(map_smb_error)?;
        client
            .create_directory(&mut tree, strip_trailing_slash(&subpath))
            .await
            .map_err(map_smb_error)
    }

    async fn remove_file(&mut self, remote_path: &str) -> Result<(), ClientError> {
        let (share, subpath) = split_share(remote_path)?;
        let client = self.require_inner()?;
        let mut tree = client.connect_share(&share).await.map_err(map_smb_error)?;
        client
            .delete_file(&mut tree, &subpath)
            .await
            .map_err(map_smb_error)
    }

    async fn remove_dir(&mut self, remote_dir: &str) -> Result<(), ClientError> {
        let (share, subpath) = split_share(remote_dir)?;
        let subpath = strip_trailing_slash(&subpath).to_string();
        let client = self.require_inner()?;
        let mut tree = client.connect_share(&share).await.map_err(map_smb_error)?;
        remove_dir_impl(client, &mut tree, &subpath, "removeDir").await
    }

    async fn rename(&mut self, from: &str, to: &str, overwrite: bool) -> Result<(), ClientError> {
        let (share, from_sub) = split_share(from)?;
        let (to_share, to_sub) = split_share(to)?;
        if !share.eq_ignore_ascii_case(&to_share) {
            return Err(ClientError::Other(
                "SMB rename failed: source and destination must be on the same share.".into(),
            ));
        }
        let client = self.require_inner()?;
        let mut tree = client.connect_share(&share).await.map_err(map_smb_error)?;
        if overwrite {
            // SMB2 rename does not replace an existing target; delete it first.
            match client.stat(&mut tree, &to_sub).await {
                Ok(info) => {
                    if info.is_directory {
                        let sub = strip_trailing_slash(&to_sub).to_string();
                        remove_dir_impl(client, &mut tree, &sub, "rename").await?;
                    } else {
                        client
                            .delete_file(&mut tree, &to_sub)
                            .await
                            .map_err(map_smb_error)?;
                    }
                }
                Err(e) if is_not_found(&e) => {}
                Err(e) => return Err(map_smb_error(e)),
            }
        }
        client
            .rename(&mut tree, &from_sub, &to_sub)
            .await
            .map_err(map_smb_error)
    }

    async fn new_connection_like(
        &self,
        opt: &SessionOptions,
    ) -> Result<Box<dyn SftpClient>, ClientError> {
        let mut client = SmbClient::new();
        client.connect(opt).await?;
        Ok(Box::new(client))
    }
}
