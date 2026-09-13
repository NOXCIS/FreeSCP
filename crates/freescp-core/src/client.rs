//! Protocol-agnostic remote operations trait — async port of the C++
//! `SftpClient` virtual interface (`core/include/freescp/SftpClient.hpp`).
//!
//! Concrete backends (`crate::backends::{mock, sftp, scp, ftp, webdav}`)
//! implement this trait so the app layer stays decoupled from any specific
//! protocol. The C++ `bool f(..., std::string &err)` convention becomes
//! `Result<_, ClientError>` and every blocking call becomes `async`.

/// Progress callback: `(done, total)` bytes transferred.
///
/// Backends must tolerate `total == 0` when the remote size is unknown.
pub type ProgressCb = Box<dyn Fn(u64, u64) + Send + Sync>;

/// Cancellation poll callback: return `true` to abort an in-flight operation
/// (transfers should then fail with [`ClientError::Cancelled`]).
pub type CancelCb = Box<dyn Fn() -> bool + Send + Sync>;

/// Backend-agnostic error, replacing the C++ `bool + std::string &err` result
/// convention.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Server rejected the credentials.
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    /// Host key verification/TOFU rejection.
    #[error("host key rejected: {0}")]
    HostKeyRejected(String),
    /// Remote operation failed (server-reported error).
    #[error("operation failed: {0}")]
    OperationFailed(String),
    /// Operation aborted via the cancel callback or `interrupt()`.
    #[error("operation cancelled")]
    Cancelled,
    /// The backend does not support this operation.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Any other error with a free-form message.
    #[error("{0}")]
    Other(String),
}

/// Abstract interface for remote operations. Concrete implementations (e.g.
/// russh-based SFTP/SCP backends) follow this API to keep the UI decoupled.
#[async_trait::async_trait]
pub trait SftpClient: Send + Sync {
    /// Protocol implemented by this backend (exposed to UI and orchestration
    /// layers).
    fn protocol(&self) -> crate::types::Protocol {
        crate::types::Protocol::Sftp
    }

    /// Feature flags for this backend's protocol.
    fn capabilities(&self) -> crate::types::ProtocolCapabilities {
        crate::types::capabilities_for_protocol(self.protocol())
    }

    /// Open a session with `opt`. On failure the backend must not leave any
    /// partial connection state behind.
    async fn connect(&mut self, opt: &crate::types::SessionOptions) -> Result<(), ClientError>;

    /// Close the session (best effort; closing an already-closed session must
    /// not be a hard error).
    async fn disconnect(&mut self) -> Result<(), ClientError>;

    /// Best-effort async interruption for active network I/O (used to speed
    /// up cancellation paths). Backends that cannot interrupt may keep no-op.
    fn interrupt(&self) {}

    /// Whether a session is currently open.
    fn is_connected(&self) -> bool;

    /// Remote directory listing. Whether `.`/`..` entries are included is
    /// backend-specific; the UI layer filters them.
    async fn list(&mut self, remote_path: &str)
        -> Result<Vec<crate::types::FileInfo>, ClientError>;

    /// Download a remote file to a local path; if `resume` is true, try to
    /// continue a partial download.
    async fn get(
        &mut self,
        remote: &str,
        local: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError>;

    /// Upload a local file to a remote path; if `resume` is true, try to
    /// continue a partial upload.
    async fn put(
        &mut self,
        local: &str,
        remote: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError>;

    /// Check existence. `Ok(None)` means "does not exist" (not an error);
    /// `Ok(Some(is_dir))` means it exists and reports whether it is a
    /// directory.
    async fn exists(&mut self, remote_path: &str) -> Result<Option<bool>, ClientError>;

    /// Detailed metadata (stat). Errors if the path does not exist.
    async fn stat(&mut self, remote_path: &str) -> Result<crate::types::FileInfo, ClientError>;

    /// Change permissions (POSIX mode, e.g. `0o644`).
    async fn chmod(&mut self, remote_path: &str, mode: u32) -> Result<(), ClientError>;

    /// Change owner/group (if supported by the server).
    async fn chown(&mut self, remote_path: &str, uid: u32, gid: u32) -> Result<(), ClientError>;

    /// Adjust remote atime/mtime (epoch seconds) if the server supports it.
    async fn set_times(
        &mut self,
        remote_path: &str,
        atime: u64,
        mtime: u64,
    ) -> Result<(), ClientError>;

    /// Create a remote directory (e.g. mode `0o755`).
    async fn mkdir(&mut self, remote_dir: &str, mode: u32) -> Result<(), ClientError>;

    /// Remove a remote file.
    async fn remove_file(&mut self, remote_path: &str) -> Result<(), ClientError>;

    /// Remove a remote directory (typically only when empty).
    async fn remove_dir(&mut self, remote_dir: &str) -> Result<(), ClientError>;

    /// Rename/move a remote path; `overwrite` allows replacing an existing
    /// target.
    async fn rename(&mut self, from: &str, to: &str, overwrite: bool) -> Result<(), ClientError>;

    /// Create a new connection of the same backend type with the given
    /// options. The returned client is not connected.
    async fn new_connection_like(
        &self,
        opt: &crate::types::SessionOptions,
    ) -> Result<Box<dyn SftpClient>, ClientError>;
}
