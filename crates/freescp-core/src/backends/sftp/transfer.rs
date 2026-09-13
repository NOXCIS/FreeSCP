//! `get` / `put` transfer loops for the SFTP backend.
//!
//! Port of the transfer logic in `Libssh2SftpClient.cpp`:
//!
//! * streaming copy with a 64 KiB buffer (SFTP max-packet friendly),
//! * `resume`: `get` opens the local file in append mode and seeks the
//!   remote handle past the already-downloaded bytes; `put` opens the
//!   remote file without truncation and seeks past the already-uploaded
//!   bytes (in both cases only when the partial size is strictly smaller
//!   than the source, otherwise the transfer restarts from scratch),
//! * progress reporting throttled to ~10 Hz plus one final call with
//!   `done == total` (the C++ client throttled in `TransferManager`),
//! * cancellation polling per chunk (`should_cancel` callback; the backend
//!   also feeds its `interrupt()` flag into this callback in `sftp.rs`),
//! * transfer integrity via the shared `crate::integrity` module: remote
//!   size + SHA-256 are fetched over SFTP, the local file is hashed with
//!   `file_sha256_hex_async`, and the Optional/Required policy semantics of
//!   the C++ `verifyTransferIntegrity` are applied:
//!   - `Off`       → no verification,
//!   - `Optional`  → verify when possible; a *detected* mismatch (size or
//!     checksum) fails the transfer, but "cannot verify" (e.g. remote hash
//!     unavailable) only degrades to a warning (see `crate::integrity`),
//!   - `Required`  → verification is mandatory; any failure aborts with
//!     `OperationFailed`.
//!
//! # russh semantics differ from libssh2 here
//!
//! * russh-sftp `File` implements `AsyncRead`/`AsyncWrite`/`AsyncSeek`
//!   directly (no separate "read file" / "write file" split); `flush()`
//!   pushes buffered writes to the server and `sync_all()` issues the
//!   `fsync@openssh.com` extension when the server advertises it (best
//!   effort — libssh2 did not fsync at all).
//! * The remote hash is computed by streaming the file through an SFTP
//!   handle (`sess.open`) and hashing on the fly, equivalent to the C++
//!   `sha256_file_via_sftp`.

use std::io::SeekFrom;
use std::path::Path;
use std::time::{Duration, Instant};

use russh_sftp::client::fs::File as SftpFile;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tracing::{debug, info};

use crate::client::{CancelCb, ClientError, ProgressCb};
use crate::types::TransferIntegrityPolicy;

const BUF_SIZE: usize = 64 * 1024;
/// Progress callback throttle (the UI layer may throttle again).
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Throttled `(done, total)` reporter. Always emits the final `done == total`.
struct ProgressReporter {
    cb: Option<ProgressCb>,
    last: Option<Instant>,
}

impl ProgressReporter {
    fn new(cb: Option<ProgressCb>) -> Self {
        Self { cb, last: None }
    }

    fn report(&mut self, done: u64, total: u64) {
        let Some(cb) = self.cb.as_ref() else {
            return;
        };
        let now = Instant::now();
        let due = self
            .last
            .is_none_or(|t| now.duration_since(t) >= PROGRESS_INTERVAL);
        if due || done >= total {
            self.last = Some(now);
            cb(done, total);
        }
    }
}

fn check_cancel(should_cancel: &Option<CancelCb>) -> Result<(), ClientError> {
    if should_cancel.as_ref().is_some_and(|cb| cb()) {
        Err(ClientError::Cancelled)
    } else {
        Ok(())
    }
}

fn sftp_err(e: impl std::fmt::Display) -> ClientError {
    ClientError::OperationFailed(e.to_string())
}

/// Download `remote` to `local`.
pub(crate) async fn get(
    sess: &SftpSession,
    remote: &str,
    local: &str,
    progress: Option<ProgressCb>,
    should_cancel: Option<CancelCb>,
    resume: bool,
    policy: TransferIntegrityPolicy,
) -> Result<(), ClientError> {
    let mut rf = sess.open(remote).await.map_err(sftp_err)?;
    let remote_meta = rf.metadata().await.map_err(sftp_err)?;
    let remote_size = remote_meta.size;
    let remote_len = remote_size.unwrap_or(0);

    let mut done;
    let mut local_file;
    if resume {
        let local_size = tokio::fs::metadata(local)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        if local_size > 0 && local_size < remote_len {
            rf.seek(SeekFrom::Start(local_size))
                .await
                .map_err(sftp_err)?;
            local_file = tokio::fs::OpenOptions::new()
                .append(true)
                .open(local)
                .await
                .map_err(ClientError::Io)?;
            done = local_size;
            debug!(
                remote,
                local,
                skipped = done,
                total = remote_len,
                "resuming download"
            );
        } else {
            local_file = tokio::fs::File::create(local)
                .await
                .map_err(ClientError::Io)?;
            done = 0;
        }
    } else {
        local_file = tokio::fs::File::create(local)
            .await
            .map_err(ClientError::Io)?;
        done = 0;
    }

    let mut buf = vec![0u8; BUF_SIZE];
    let mut reporter = ProgressReporter::new(progress);
    reporter.report(done, remote_len);
    loop {
        check_cancel(&should_cancel)?;
        let n = rf.read(&mut buf).await.map_err(ClientError::Io)?;
        if n == 0 {
            break;
        }
        local_file
            .write_all(&buf[..n])
            .await
            .map_err(ClientError::Io)?;
        done += n as u64;
        reporter.report(done, remote_len);
    }
    local_file.flush().await.map_err(ClientError::Io)?;
    drop(local_file);
    drop(rf); // SFTP close

    verify_integrity(sess, remote, local, remote_size, policy).await
}

/// Upload `local` to `remote`.
pub(crate) async fn put(
    sess: &SftpSession,
    local: &str,
    remote: &str,
    progress: Option<ProgressCb>,
    should_cancel: Option<CancelCb>,
    resume: bool,
    policy: TransferIntegrityPolicy,
) -> Result<(), ClientError> {
    let local_len = tokio::fs::metadata(local)
        .await
        .map_err(ClientError::Io)?
        .len();
    let mut lf = tokio::fs::File::open(local)
        .await
        .map_err(ClientError::Io)?;

    let mut done;
    let mut rf: SftpFile;
    if resume {
        let remote_len = sess
            .metadata(remote)
            .await
            .map(|m| m.size.unwrap_or(0))
            .unwrap_or(0);
        if remote_len > 0 && remote_len < local_len {
            rf = sess
                .open_with_flags(remote, OpenFlags::WRITE | OpenFlags::CREATE)
                .await
                .map_err(sftp_err)?;
            rf.seek(SeekFrom::Start(remote_len))
                .await
                .map_err(sftp_err)?;
            done = remote_len;
            debug!(
                remote,
                local,
                skipped = done,
                total = local_len,
                "resuming upload"
            );
        } else {
            rf = open_truncate(sess, remote).await?;
            done = 0;
        }
    } else {
        rf = open_truncate(sess, remote).await?;
        done = 0;
    }

    let mut buf = vec![0u8; BUF_SIZE];
    let mut reporter = ProgressReporter::new(progress);
    reporter.report(done, local_len);
    while done < local_len {
        check_cancel(&should_cancel)?;
        let n = lf.read(&mut buf).await.map_err(ClientError::Io)?;
        if n == 0 {
            break;
        }
        rf.write_all(&buf[..n]).await.map_err(sftp_err)?;
        done += n as u64;
        reporter.report(done, local_len);
    }
    rf.flush().await.map_err(sftp_err)?;
    let _ = rf.sync_all().await; // best effort (fsync@openssh.com extension)
    let final_size = rf.metadata().await.map(|m| m.size).unwrap_or(None);
    drop(rf); // SFTP close

    verify_integrity(sess, remote, local, final_size.or(Some(local_len)), policy).await
}

/// Open/create `remote` for a fresh (non-resume) upload, mode 0644 — the
/// C++ client used `FXF_WRITE|FXF_CREAT|FXF_TRUNC` with mode `0644`.
async fn open_truncate(sess: &SftpSession, remote: &str) -> Result<SftpFile, ClientError> {
    let attrs = FileAttributes {
        permissions: Some(0o644),
        ..Default::default()
    };
    sess.open_with_flags_and_attributes(
        remote,
        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
        attrs,
    )
    .await
    .map_err(sftp_err)
}

/// Post-transfer integrity check with the C++ Optional/Required semantics.
async fn verify_integrity(
    sess: &SftpSession,
    remote: &str,
    local: &str,
    remote_size: Option<u64>,
    policy: TransferIntegrityPolicy,
) -> Result<(), ClientError> {
    if policy == TransferIntegrityPolicy::Off {
        return Ok(());
    }
    let remote_sha = remote_sha256_hex(sess, remote).await;
    match crate::integrity::verify_integrity_async(
        Path::new(local),
        remote_sha.as_deref(),
        remote_size,
        policy,
    )
    .await
    {
        Ok(_) => {
            info!(remote, local, "transfer integrity verified");
            Ok(())
        }
        // Per `crate::integrity`, `Err` always means "abort the transfer":
        // under Optional only *detected* mismatches (size/checksum) land
        // here, while "verification impossible" cases are reported as
        // `Ok(NotVerified)`.
        Err(e) => Err(ClientError::OperationFailed(format!(
            "integrity verification failed: {e}"
        ))),
    }
}

/// SHA-256 of the remote file, streamed through an SFTP handle.
///
/// `Ok(None)` when the remote file cannot be opened or read — the
/// `crate::integrity` policy layer then applies the Required/Optional
/// semantics (`RemoteHashUnavailable` vs `NotVerified`).
async fn remote_sha256_hex(sess: &SftpSession, remote: &str) -> Option<String> {
    let mut rf = match sess.open(remote).await {
        Ok(f) => f,
        Err(e) => {
            debug!(remote, error = %e, "remote hash unavailable (open failed)");
            return None;
        }
    };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        match rf.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) => {
                debug!(remote, error = %e, "remote hash unavailable (read failed)");
                return None;
            }
        }
    }
    Some(hex::encode(hasher.finalize()))
}
