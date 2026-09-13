//! Simulated SFTP backend used for offline UI and unit testing, ported from
//! `core/src/mock/MockSftpClient.cpp`.
//!
//! Two modes:
//! - **Standalone** ([`MockSftpClient::new`]): a tiny in-memory remote
//!   filesystem mirroring the C++ mock — connect validation, directory
//!   listings with directories-first sorting, `set_times` as a no-op success,
//!   and "Mock no soporta ..." errors for unsupported operations.
//! - **Decorator** ([`MockSftpClient::with_delegate`]): transparently forwards
//!   every operation to another [`SftpClient`] while layering
//!   failure-injection knobs (`fail_connect`, `latency_ms`,
//!   `drop_mid_transfer`, `forced_error`, `force_disconnect`) on top. The
//!   knobs apply in both modes; they are additive over the C++ mock.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;

use crate::client::{CancelCb, ClientError, ProgressCb, SftpClient};
use crate::types::{FileInfo, Protocol, SessionOptions};

/// Mock SFTP backend for offline UI and unit tests.
pub struct MockSftpClient {
    /// Optional delegate; `None` selects the built-in simulated filesystem.
    delegate: Option<Box<dyn SftpClient>>,
    connected: bool,
    last_host: Option<String>,
    last_username: Option<String>,
    /// Simulated remote filesystem: absolute path -> directory entries.
    fs: HashMap<String, Vec<FileInfo>>,
    interrupted: AtomicBool,

    // Failure-injection knobs (additive over the C++ mock).
    /// If set, `connect` fails with this message (as `OperationFailed`).
    pub fail_connect: Option<String>,
    /// Simulated per-operation latency in milliseconds (0 disables it).
    pub latency_ms: u64,
    /// If true, `get`/`put` fail as if the connection dropped mid-transfer;
    /// the client ends up disconnected.
    pub drop_mid_transfer: bool,
    /// If set, every operation fails with this message (`OperationFailed`).
    /// Clear it (set to `None`) to restore normal behavior.
    pub forced_error: Option<String>,
    /// If true, the mock force-disconnects right after each successful
    /// operation, so the next operation observes a dead session.
    pub force_disconnect: bool,
}

impl MockSftpClient {
    /// Creates a standalone mock with the built-in simulated filesystem,
    /// mirroring the C++ default constructor.
    pub fn new() -> Self {
        Self {
            delegate: None,
            connected: false,
            last_host: None,
            last_username: None,
            fs: default_fs(),
            interrupted: AtomicBool::new(false),
            fail_connect: None,
            latency_ms: 0,
            drop_mid_transfer: false,
            forced_error: None,
            force_disconnect: false,
        }
    }

    /// Creates a decorator that forwards every operation to `delegate`,
    /// applying the failure-injection knobs on top.
    pub fn with_delegate(delegate: Box<dyn SftpClient>) -> Self {
        let mut this = Self::new();
        this.delegate = Some(delegate);
        this
    }

    /// Builder: sets [`Self::latency_ms`].
    pub fn with_latency_ms(mut self, ms: u64) -> Self {
        self.latency_ms = ms;
        self
    }

    /// Builder: sets [`Self::fail_connect`].
    pub fn with_failing_connect(mut self, msg: impl Into<String>) -> Self {
        self.fail_connect = Some(msg.into());
        self
    }

    /// Builder: sets [`Self::forced_error`].
    pub fn with_forced_error(mut self, msg: impl Into<String>) -> Self {
        self.forced_error = Some(msg.into());
        self
    }

    /// Builder: enables [`Self::drop_mid_transfer`].
    pub fn with_mid_transfer_drop(mut self) -> Self {
        self.drop_mid_transfer = true;
        self
    }

    /// Builder: enables [`Self::force_disconnect`].
    pub fn with_forced_disconnect(mut self) -> Self {
        self.force_disconnect = true;
        self
    }

    /// Host of the last successful `connect`, if any.
    pub fn last_host(&self) -> Option<&str> {
        self.last_host.as_deref()
    }

    /// Username of the last successful `connect`, if any.
    pub fn last_username(&self) -> Option<&str> {
        self.last_username.as_deref()
    }

    /// Whether [`SftpClient::interrupt`] has been called on this mock.
    pub fn was_interrupted(&self) -> bool {
        self.interrupted.load(Ordering::SeqCst)
    }

    async fn apply_latency(&self) {
        if self.latency_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.latency_ms)).await;
        }
    }

    fn injected_error(&self) -> Option<ClientError> {
        self.forced_error
            .as_ref()
            .map(|msg| ClientError::OperationFailed(msg.clone()))
    }

    async fn mark_disconnected(&mut self) {
        self.connected = false;
        if let Some(delegate) = self.delegate.as_mut() {
            let _ = delegate.disconnect().await;
        }
    }

    async fn after_op<T>(&mut self, res: Result<T, ClientError>) -> Result<T, ClientError> {
        if res.is_ok() && self.force_disconnect {
            self.mark_disconnected().await;
        }
        res
    }

    fn standalone_list(&self, remote_path: &str) -> Result<Vec<FileInfo>, ClientError> {
        if !self.connected {
            return Err(ClientError::OperationFailed("Not connected".to_string()));
        }
        let path = if remote_path.is_empty() {
            "/"
        } else {
            remote_path
        };
        match self.fs.get(path) {
            Some(entries) => {
                let mut sorted = entries.clone();
                // Directories first, then alphabetical by name (C++ sort).
                sorted.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
                Ok(sorted)
            }
            None => Err(ClientError::OperationFailed(format!(
                "Mock remote path not found: {}",
                path
            ))),
        }
    }
}

impl Default for MockSftpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SftpClient for MockSftpClient {
    fn protocol(&self) -> Protocol {
        match &self.delegate {
            Some(delegate) => delegate.protocol(),
            None => Protocol::Sftp,
        }
    }

    fn interrupt(&self) {
        self.interrupted.store(true, Ordering::SeqCst);
        if let Some(delegate) = &self.delegate {
            delegate.interrupt();
        }
    }

    fn is_connected(&self) -> bool {
        match &self.delegate {
            Some(delegate) => delegate.is_connected(),
            None => self.connected,
        }
    }

    async fn connect(&mut self, opt: &SessionOptions) -> Result<(), ClientError> {
        self.apply_latency().await;
        if let Some(msg) = &self.fail_connect {
            return Err(ClientError::OperationFailed(msg.clone()));
        }
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if let Some(delegate) = self.delegate.as_mut() {
            delegate.connect(opt).await?;
        } else if opt.host.is_empty() || opt.username.is_empty() {
            return Err(ClientError::OperationFailed(
                "Host and username are required".to_string(),
            ));
        }
        self.connected = true;
        self.last_host = Some(opt.host.clone());
        self.last_username = Some(opt.username.clone());
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
        self.apply_latency().await;
        if let Some(delegate) = self.delegate.as_mut() {
            let _ = delegate.disconnect().await;
        }
        self.connected = false;
        Ok(())
    }

    async fn list(&mut self, remote_path: &str) -> Result<Vec<FileInfo>, ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if let Some(delegate) = self.delegate.as_mut() {
            let res = delegate.list(remote_path).await;
            return self.after_op(res).await;
        }
        let res = self.standalone_list(remote_path);
        self.after_op(res).await
    }

    async fn get(
        &mut self,
        remote: &str,
        local: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if self.drop_mid_transfer {
            self.mark_disconnected().await;
            return Err(ClientError::OperationFailed(
                "Simulated mid-transfer disconnect".to_string(),
            ));
        }
        if let Some(delegate) = self.delegate.as_mut() {
            let res = delegate
                .get(remote, local, progress, should_cancel, resume)
                .await;
            return self.after_op(res).await;
        }
        let _ = (progress, should_cancel);
        let res = Err(ClientError::Unsupported("Mock no soporta GET".to_string()));
        self.after_op(res).await
    }

    async fn put(
        &mut self,
        local: &str,
        remote: &str,
        progress: Option<ProgressCb>,
        should_cancel: Option<CancelCb>,
        resume: bool,
    ) -> Result<(), ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if self.drop_mid_transfer {
            self.mark_disconnected().await;
            return Err(ClientError::OperationFailed(
                "Simulated mid-transfer disconnect".to_string(),
            ));
        }
        if let Some(delegate) = self.delegate.as_mut() {
            let res = delegate
                .put(local, remote, progress, should_cancel, resume)
                .await;
            return self.after_op(res).await;
        }
        let _ = (progress, should_cancel);
        let res = Err(ClientError::Unsupported("Mock no soporta PUT".to_string()));
        self.after_op(res).await
    }

    async fn exists(&mut self, remote_path: &str) -> Result<Option<bool>, ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if let Some(delegate) = self.delegate.as_mut() {
            let res = delegate.exists(remote_path).await;
            return self.after_op(res).await;
        }
        let res = Err(ClientError::Unsupported(
            "Mock no soporta exists".to_string(),
        ));
        self.after_op(res).await
    }

    async fn stat(&mut self, remote_path: &str) -> Result<FileInfo, ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if let Some(delegate) = self.delegate.as_mut() {
            let res = delegate.stat(remote_path).await;
            return self.after_op(res).await;
        }
        let res = Err(ClientError::Unsupported("Mock no soporta stat".to_string()));
        self.after_op(res).await
    }

    async fn chmod(&mut self, remote_path: &str, mode: u32) -> Result<(), ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if let Some(delegate) = self.delegate.as_mut() {
            let res = delegate.chmod(remote_path, mode).await;
            return self.after_op(res).await;
        }
        let res = Err(ClientError::Unsupported(
            "Mock no soporta chmod".to_string(),
        ));
        self.after_op(res).await
    }

    async fn chown(&mut self, remote_path: &str, uid: u32, gid: u32) -> Result<(), ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if let Some(delegate) = self.delegate.as_mut() {
            let res = delegate.chown(remote_path, uid, gid).await;
            return self.after_op(res).await;
        }
        let res = Err(ClientError::Unsupported(
            "Mock no soporta chown".to_string(),
        ));
        self.after_op(res).await
    }

    async fn set_times(
        &mut self,
        remote_path: &str,
        atime: u64,
        mtime: u64,
    ) -> Result<(), ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if let Some(delegate) = self.delegate.as_mut() {
            let res = delegate.set_times(remote_path, atime, mtime).await;
            return self.after_op(res).await;
        }
        // C++ mock: setTimes always succeeds, no connection check.
        self.after_op(Ok(())).await
    }

    async fn mkdir(&mut self, remote_dir: &str, mode: u32) -> Result<(), ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if let Some(delegate) = self.delegate.as_mut() {
            let res = delegate.mkdir(remote_dir, mode).await;
            return self.after_op(res).await;
        }
        let res = Err(ClientError::Unsupported(
            "Mock no soporta mkdir".to_string(),
        ));
        self.after_op(res).await
    }

    async fn remove_file(&mut self, remote_path: &str) -> Result<(), ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if let Some(delegate) = self.delegate.as_mut() {
            let res = delegate.remove_file(remote_path).await;
            return self.after_op(res).await;
        }
        let res = Err(ClientError::Unsupported(
            "Mock no soporta remove".to_string(),
        ));
        self.after_op(res).await
    }

    async fn remove_dir(&mut self, remote_dir: &str) -> Result<(), ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if let Some(delegate) = self.delegate.as_mut() {
            let res = delegate.remove_dir(remote_dir).await;
            return self.after_op(res).await;
        }
        let res = Err(ClientError::Unsupported(
            "Mock no soporta rmdir".to_string(),
        ));
        self.after_op(res).await
    }

    async fn rename(&mut self, from: &str, to: &str, overwrite: bool) -> Result<(), ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if let Some(delegate) = self.delegate.as_mut() {
            let res = delegate.rename(from, to, overwrite).await;
            return self.after_op(res).await;
        }
        let res = Err(ClientError::Unsupported(
            "Mock no soporta rename".to_string(),
        ));
        self.after_op(res).await
    }

    async fn new_connection_like(
        &self,
        opt: &SessionOptions,
    ) -> Result<Box<dyn SftpClient>, ClientError> {
        self.apply_latency().await;
        if let Some(err) = self.injected_error() {
            return Err(err);
        }
        if let Some(delegate) = &self.delegate {
            return delegate.new_connection_like(opt).await;
        }
        // C++ mock: build a fresh default client and connect it (validation
        // errors propagate).
        let mut client = MockSftpClient::new();
        client.connect(opt).await?;
        Ok(Box::new(client))
    }
}

fn default_fs() -> HashMap<String, Vec<FileInfo>> {
    fn entry(name: &str, is_dir: bool, size: u64, has_size: bool) -> FileInfo {
        FileInfo {
            name: name.to_string(),
            is_dir,
            size,
            has_size,
            ..Default::default()
        }
    }

    let mut fs = HashMap::new();
    fs.insert(
        "/".to_string(),
        vec![
            entry("home", true, 0, false),
            entry("var", true, 0, false),
            entry("readme.txt", false, 1280, true),
        ],
    );
    fs.insert(
        "/home".to_string(),
        vec![
            entry("luis", true, 0, false),
            entry("guest", true, 0, false),
            entry("notes.md", false, 2048, true),
        ],
    );
    fs.insert(
        "/home/luis".to_string(),
        vec![
            entry("proyectos", true, 0, false),
            entry("foto.jpg", false, 34567, true),
        ],
    );
    fs.insert("/var".to_string(), vec![entry("log", true, 0, false)]);
    fs
}
