//! Pure-Rust SFTP backend on the russh + russh-sftp stack.
//!
//! Port of `core/src/libssh2/Libssh2SftpClient.cpp` onto russh 0.63 /
//! russh-sftp 3. The public surface is the [`SftpClient`] trait; the client
//! itself is [`RusshSftpClient`].
//!
//! Feature -> russh mapping (see the individual modules for details):
//!
//! * connection        -> `russh::client::connect_stream` over a plain TCP
//!   stream, a `crate::proxy` tunnel, or a `crate::jumphost` bastion tunnel
//! * host key check    -> [`crate::ssh_transport::SshHandler`]
//!   (`Handler::check_server_key`), known_hosts parsing/saving delegated to
//!   `crate::known_hosts`
//! * auth              -> `Handle::{authenticate_keyboard_interactive_*,
//!   authenticate_password, authenticate_publickey, authenticate_publickey_with}`
//!   (transport and auth live in [`crate::ssh_transport`], shared with the
//!   terminal workspace)
//! * SFTP              -> `russh_sftp::client::SftpSession` created from the
//!   `sftp` subsystem channel stream
//! * transfers         -> [`transfer`] (`get`/`put`), integrity via
//!   `crate::integrity`
//!
//! # Deviations from the C++ client
//!
//! * Authentication order is keyboard-interactive, then password, then
//!   private key file, then ssh-agent identities (mirrors the C++ order,
//!   with the agent as final fallback; there is no `use_agent` option in
//!   [`SessionOptions`], the agent is always consulted last).
//! * `interrupt()` sets an atomic flag that the transfer loops poll together
//!   with the `should_cancel` callback. russh has no equivalent of
//!   `libssh2_session_disconnect` from another thread; dropping the in-flight
//!   session state is deliberately avoided so the error propagates cleanly.
//! * Bastion TOFU: `crate::jumphost` verifies the bastion key against
//!   known_hosts but has no user-confirmation hook, so under `AcceptNew` an
//!   unknown bastion key is accepted without prompting (not saved); under
//!   `Strict` it is rejected. The target host keeps the full TOFU dialog.
//! * `mkdir(mode)` is `create_dir` followed by `set_metadata(permissions)`
//!   (two round trips) because russh-sftp's high-level `create_dir` does not
//!   take attributes.
//! * `remove_dir` is recursive (delete children first), matching the C++
//!   client's behaviour, even though the trait only promises empty dirs.
//! * `rename(overwrite=true)` deletes the destination first (file or empty
//!   directory), then renames, as the C++ client did.

mod transfer;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use russh::client::Handle;
use russh_sftp::client::SftpSession;
use tracing::{debug, info};

use crate::client::{CancelCb, ClientError, ProgressCb, SftpClient};
use crate::ssh_transport::SshHandler;
use crate::types::{FileInfo, SessionOptions, TransferIntegrityPolicy};

/// Live connection state: the SSH session handle and the multiplexed SFTP
/// session. Both are plain data; the mutex in [`RusshSftpClient`] guards
/// access, and operations temporarily move the whole struct out so no
/// guard is held across `.await` points.
struct SftpConnection {
    handle: Handle<SshHandler>,
    sftp: SftpSession,
}

/// SFTP backend implementation.
pub struct RusshSftpClient {
    conn: Mutex<Option<SftpConnection>>,
    connected: AtomicBool,
    /// Set by `interrupt()`; polled by the in-flight transfer loop.
    interrupted: Arc<AtomicBool>,
    /// Integrity policy snapshot from the last successful `connect()`.
    integrity_policy: Mutex<TransferIntegrityPolicy>,
}

impl Default for RusshSftpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RusshSftpClient {
    /// Create a fresh, disconnected client.
    pub fn new() -> Self {
        Self {
            conn: Mutex::new(None),
            connected: AtomicBool::new(false),
            interrupted: Arc::new(AtomicBool::new(false)),
            integrity_policy: Mutex::new(TransferIntegrityPolicy::Off),
        }
    }

    fn take_conn(&self) -> Option<SftpConnection> {
        self.conn.lock().unwrap().take()
    }

    fn put_conn(&self, conn: SftpConnection) {
        *self.conn.lock().unwrap() = Some(conn);
    }

    fn integrity_policy(&self) -> TransferIntegrityPolicy {
        *self.integrity_policy.lock().unwrap()
    }

    /// Combined cancellation predicate: user callback OR `interrupt()` flag.
    fn combined_cancel(&self, user: Option<CancelCb>) -> Option<CancelCb> {
        let flag = Arc::clone(&self.interrupted);
        Some(Box::new(move || {
            flag.load(Ordering::SeqCst) || user.as_ref().is_some_and(|cb| cb())
        }))
    }

    /// Build the SSH transport, authenticate, and start the SFTP session.
    async fn connect_inner(opt: &SessionOptions) -> Result<SftpConnection, ClientError> {
        let handle = crate::ssh_transport::connect_and_auth(opt).await?;

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| ClientError::Other(format!("failed to open session channel: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| ClientError::Other(format!("failed to start SFTP subsystem: {e}")))?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| ClientError::Other(format!("failed to initialize SFTP session: {e}")))?;
        sftp.set_timeout(30);

        Ok(SftpConnection { handle, sftp })
    }
}

// ---------------------------------------------------------------------------
// SftpClient trait
// ---------------------------------------------------------------------------

fn not_connected() -> ClientError {
    ClientError::Other("not connected".into())
}

/// Map russh-sftp operation errors. `Error::Status` carries the server
/// status code + message; everything else is client-side noise.
fn sftp_err(e: impl std::fmt::Display) -> ClientError {
    ClientError::OperationFailed(e.to_string())
}

/// `exists` distinguishes "no such file" (→ `Ok(None)`) from real failures.
fn is_no_such_file(e: &russh_sftp::client::error::Error) -> bool {
    matches!(
        e,
        russh_sftp::client::error::Error::Status(s)
            if s.status_code == russh_sftp::protocol::StatusCode::NoSuchFile
    )
}

async fn sftp_list(sess: &SftpSession, remote_path: &str) -> Result<Vec<FileInfo>, ClientError> {
    let readdir = sess.read_dir(remote_path).await.map_err(sftp_err)?;
    let mut out = Vec::new();
    for entry in readdir {
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let meta = entry.metadata();
        out.push(FileInfo {
            name,
            is_dir: meta.file_type().is_dir(),
            size: meta.size.unwrap_or(0),
            has_size: meta.size.is_some(),
            mtime: meta.mtime.map(u64::from).unwrap_or(0),
            mode: meta.permissions.unwrap_or(0),
            uid: meta.uid.unwrap_or(0),
            gid: meta.gid.unwrap_or(0),
        });
    }
    Ok(out)
}

fn meta_to_file_info(name: String, meta: &russh_sftp::client::fs::Metadata) -> FileInfo {
    FileInfo {
        name,
        is_dir: meta.file_type().is_dir(),
        size: meta.size.unwrap_or(0),
        has_size: meta.size.is_some(),
        mtime: meta.mtime.map(u64::from).unwrap_or(0),
        mode: meta.permissions.unwrap_or(0),
        uid: meta.uid.unwrap_or(0),
        gid: meta.gid.unwrap_or(0),
    }
}

/// Recursive directory removal: breadth-first traversal collecting
/// directories top-down, then rmdir deepest-first.
async fn sftp_remove_dir_recursive(sess: &SftpSession, dir: &str) -> Result<(), ClientError> {
    use std::collections::VecDeque;
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(dir.to_string());
    let mut dirs: Vec<String> = Vec::new(); // top-down order

    while let Some(current) = queue.pop_front() {
        let readdir = sess.read_dir(&current).await.map_err(sftp_err)?;
        for entry in readdir {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let child = format!("{}/{}", current.trim_end_matches('/'), name);
            let meta = entry.metadata();
            if meta.file_type().is_dir() {
                queue.push_back(child);
            } else {
                sess.remove_file(&child).await.map_err(sftp_err)?;
            }
        }
        dirs.push(current);
    }

    for d in dirs.into_iter().rev() {
        sess.remove_dir(&d).await.map_err(sftp_err)?;
    }
    Ok(())
}

#[async_trait]
impl SftpClient for RusshSftpClient {
    async fn connect(&mut self, opt: &SessionOptions) -> Result<(), ClientError> {
        // Drop any previous session first; failures below must leave no
        // partial state behind (trait contract).
        if let Some(prev) = self.take_conn() {
            let _ = prev
                .handle
                .disconnect(russh::Disconnect::ByApplication, "reconnect", "English")
                .await;
        }

        let conn = Self::connect_inner(opt).await?;
        *self.integrity_policy.lock().unwrap() = opt.transfer_integrity_policy;
        self.put_conn(conn);
        self.connected.store(true, Ordering::SeqCst);
        self.interrupted.store(false, Ordering::SeqCst);
        info!(host = %opt.host, port = opt.port, user = %opt.username, "SFTP session connected");
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
        if let Some(conn) = self.take_conn() {
            let _ = conn.sftp.close().await;
            let _ = conn
                .handle
                .disconnect(russh::Disconnect::ByApplication, "disconnect", "English")
                .await;
            info!("SFTP session disconnected");
        }
        self.connected.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Best-effort: sets the interrupt flag polled by in-flight transfers.
    /// russh offers no cross-task equivalent of
    /// `libssh2_session_disconnect`, and deliberately dropping the session
    /// out from under a running operation would replace a clean
    /// `ClientError::Cancelled` with arbitrary I/O errors.
    fn interrupt(&self) {
        debug!("interrupt requested");
        self.interrupted.store(true, Ordering::SeqCst);
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    async fn list(&mut self, remote_path: &str) -> Result<Vec<FileInfo>, ClientError> {
        let Some(conn) = self.take_conn() else {
            return Err(not_connected());
        };
        let res = sftp_list(&conn.sftp, remote_path).await;
        self.put_conn(conn);
        res
    }

    async fn get(
        &mut self,
        remote: &str,
        local: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError> {
        let Some(conn) = self.take_conn() else {
            return Err(not_connected());
        };
        self.interrupted.store(false, Ordering::SeqCst);
        let cancel = self.combined_cancel(should_cancel);
        let policy = self.integrity_policy();
        debug!(remote, local, resume, "SFTP get");
        let res = transfer::get(&conn.sftp, remote, local, progress, cancel, resume, policy).await;
        self.put_conn(conn);
        res
    }

    async fn put(
        &mut self,
        local: &str,
        remote: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError> {
        let Some(conn) = self.take_conn() else {
            return Err(not_connected());
        };
        self.interrupted.store(false, Ordering::SeqCst);
        let cancel = self.combined_cancel(should_cancel);
        let policy = self.integrity_policy();
        debug!(remote, local, resume, "SFTP put");
        let res = transfer::put(&conn.sftp, local, remote, progress, cancel, resume, policy).await;
        self.put_conn(conn);
        res
    }

    async fn exists(&mut self, remote_path: &str) -> Result<Option<bool>, ClientError> {
        let Some(conn) = self.take_conn() else {
            return Err(not_connected());
        };
        let res = match conn.sftp.metadata(remote_path).await {
            Ok(meta) => Ok(Some(meta.file_type().is_dir())),
            Err(e) if is_no_such_file(&e) => Ok(None),
            Err(e) => Err(sftp_err(e)),
        };
        self.put_conn(conn);
        res
    }

    async fn stat(&mut self, remote_path: &str) -> Result<FileInfo, ClientError> {
        let Some(conn) = self.take_conn() else {
            return Err(not_connected());
        };
        let res = conn
            .sftp
            .metadata(remote_path)
            .await
            .map_err(sftp_err)
            .map(|meta| meta_to_file_info(remote_path.to_string(), &meta));
        self.put_conn(conn);
        res
    }

    async fn chmod(&mut self, remote_path: &str, mode: u32) -> Result<(), ClientError> {
        let Some(conn) = self.take_conn() else {
            return Err(not_connected());
        };
        let attrs = russh_sftp::protocol::FileAttributes {
            permissions: Some(mode),
            ..Default::default()
        };
        let res = conn
            .sftp
            .set_metadata(remote_path, attrs)
            .await
            .map_err(sftp_err);
        self.put_conn(conn);
        res
    }

    async fn chown(&mut self, remote_path: &str, uid: u32, gid: u32) -> Result<(), ClientError> {
        let Some(conn) = self.take_conn() else {
            return Err(not_connected());
        };
        let attrs = russh_sftp::protocol::FileAttributes {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        };
        let res = conn
            .sftp
            .set_metadata(remote_path, attrs)
            .await
            .map_err(sftp_err);
        self.put_conn(conn);
        res
    }

    async fn set_times(
        &mut self,
        remote_path: &str,
        atime: u64,
        mtime: u64,
    ) -> Result<(), ClientError> {
        let Some(conn) = self.take_conn() else {
            return Err(not_connected());
        };
        let attrs = russh_sftp::protocol::FileAttributes {
            atime: Some(atime as u32),
            mtime: Some(mtime as u32),
            ..Default::default()
        };
        let res = conn
            .sftp
            .set_metadata(remote_path, attrs)
            .await
            .map_err(sftp_err);
        self.put_conn(conn);
        res
    }

    async fn mkdir(&mut self, remote_dir: &str, mode: u32) -> Result<(), ClientError> {
        let Some(conn) = self.take_conn() else {
            return Err(not_connected());
        };
        let res = async {
            conn.sftp.create_dir(remote_dir).await.map_err(sftp_err)?;
            let attrs = russh_sftp::protocol::FileAttributes {
                permissions: Some(mode),
                ..Default::default()
            };
            conn.sftp
                .set_metadata(remote_dir, attrs)
                .await
                .map_err(sftp_err)
        }
        .await;
        self.put_conn(conn);
        res
    }

    async fn remove_file(&mut self, remote_path: &str) -> Result<(), ClientError> {
        let Some(conn) = self.take_conn() else {
            return Err(not_connected());
        };
        let res = conn.sftp.remove_file(remote_path).await.map_err(sftp_err);
        self.put_conn(conn);
        res
    }

    async fn remove_dir(&mut self, remote_dir: &str) -> Result<(), ClientError> {
        let Some(conn) = self.take_conn() else {
            return Err(not_connected());
        };
        let res = sftp_remove_dir_recursive(&conn.sftp, remote_dir).await;
        self.put_conn(conn);
        res
    }

    async fn rename(&mut self, from: &str, to: &str, overwrite: bool) -> Result<(), ClientError> {
        let Some(conn) = self.take_conn() else {
            return Err(not_connected());
        };
        let res = async {
            if overwrite {
                match conn.sftp.metadata(to).await {
                    Ok(meta) => {
                        if meta.file_type().is_dir() {
                            conn.sftp.remove_dir(to).await.map_err(sftp_err)?;
                        } else {
                            conn.sftp.remove_file(to).await.map_err(sftp_err)?;
                        }
                    }
                    Err(e) if is_no_such_file(&e) => {}
                    Err(e) => return Err(sftp_err(e)),
                }
            }
            conn.sftp.rename(from, to).await.map_err(sftp_err)
        }
        .await;
        self.put_conn(conn);
        res
    }

    async fn new_connection_like(
        &self,
        _opt: &SessionOptions,
    ) -> Result<Box<dyn SftpClient>, ClientError> {
        // Per the trait contract the returned client is NOT connected.
        Ok(Box::new(RusshSftpClient::new()))
    }
}
