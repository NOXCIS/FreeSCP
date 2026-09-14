//! Integration tests for the pure-Rust SMB2/3 backend (`SmbClient` in
//! `crates/freescp-core/src/backends/smb.rs`).
//!
//! The C++ suite exits with code 77 unless the required `FREESCP_IT_*`
//! environment variables exist. Rust has no per-test exit code, so each
//! env-gated test prints the same `[SKIP]` message and returns instead.
//!
//! Required:  FREESCP_IT_SMB_HOST, FREESCP_IT_SMB_SHARE
//! Optional:  FREESCP_IT_SMB_USER, FREESCP_IT_SMB_PASS,
//!            FREESCP_IT_SMB_DOMAIN (workgroup/domain for NTLM),
//!            FREESCP_IT_SMB_PORT (default 445)
//!
//! Run with e.g. (Docker Samba from `dperson/samba`):
//!   FREESCP_IT_SMB_HOST=127.0.0.1 FREESCP_IT_SMB_PORT=1445 \
//!   FREESCP_IT_SMB_SHARE=public FREESCP_IT_SMB_USER=test \
//!   FREESCP_IT_SMB_PASS=secret \
//!     cargo test -p freescp-core --test smb_integration -- --nocapture

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use freescp_core::client::{CancelCb, ProgressCb};
use freescp_core::client_factory::create_client;
use freescp_core::{ClientError, Protocol, SessionOptions, SftpClient};

const SKIP_MESSAGE: &str = "[SKIP] freescp_smb_integration_tests requires \
     FREESCP_IT_SMB_HOST and FREESCP_IT_SMB_SHARE";

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

fn env_value(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn parse_port(raw: Option<String>, fallback: u16) -> Result<u16, ()> {
    match raw {
        None => Ok(fallback),
        Some(v) => {
            let digits: String = v
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if digits.is_empty() {
                return Err(());
            }
            let n: i32 = digits.parse().map_err(|_| ())?;
            if (1..=65535).contains(&n) {
                Ok(n as u16)
            } else {
                Err(())
            }
        }
    }
}

fn unique_token() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the epoch")
        .as_nanos()
        .to_string()
}

fn join_remote_path(base: &str, name: &str) -> String {
    if base.is_empty() {
        format!("/{name}")
    } else if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

// ---------------------------------------------------------------------------
// Test configuration
// ---------------------------------------------------------------------------

struct TestConfig {
    host: String,
    user: String,
    pass: Option<String>,
    domain: Option<String>,
    share: String,
    /// Remote base path: `/` + share name.
    remote_base: String,
    port: u16,
}

fn read_test_config() -> Option<TestConfig> {
    let host = env_value("FREESCP_IT_SMB_HOST")?;
    let share = env_value("FREESCP_IT_SMB_SHARE")?;
    let user = env_value("FREESCP_IT_SMB_USER").unwrap_or_default();
    let pass = env_value("FREESCP_IT_SMB_PASS");
    let domain = env_value("FREESCP_IT_SMB_DOMAIN");
    let port = match parse_port(env_value("FREESCP_IT_SMB_PORT"), 445) {
        Ok(p) => p,
        Err(()) => panic!("[FAIL] FREESCP_IT_SMB_PORT is invalid"),
    };
    let remote_base = format!("/{share}");
    Some(TestConfig {
        host,
        user,
        pass,
        domain,
        share,
        remote_base,
        port,
    })
}

fn test_config_or_skip() -> Option<TestConfig> {
    match read_test_config() {
        Some(cfg) => Some(cfg),
        None => {
            println!("{SKIP_MESSAGE}");
            None
        }
    }
}

fn session_options(cfg: &TestConfig) -> SessionOptions {
    SessionOptions {
        protocol: Protocol::Smb,
        host: cfg.host.clone(),
        port: cfg.port,
        username: cfg.user.clone(),
        password: cfg.pass.clone(),
        smb_domain: cfg.domain.clone(),
        ..SessionOptions::default()
    }
}

async fn connect(cfg: &TestConfig) -> Box<dyn SftpClient> {
    let mut client =
        create_client(Protocol::Smb).expect("[FAIL] factory did not create SMB backend");
    client
        .connect(&session_options(cfg))
        .await
        .expect("[FAIL] SMB connect failed");
    client
}

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str, token: &str) -> Self {
        let path = std::env::temp_dir().join(format!("{tag}_{token}"));
        fs::create_dir_all(&path).expect("should create temp dir");
        TempDir(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn counting_progress(flag: &Arc<AtomicBool>) -> ProgressCb {
    let flag = Arc::clone(flag);
    Box::new(move |_done: u64, _total: u64| {
        flag.store(true, Ordering::SeqCst);
    })
}

/// Cancel callback that returns `true` after it has been polled `n` times
/// (one poll per transfer chunk).
fn cancel_after_n_polls(n: usize, counter: &Arc<AtomicUsize>) -> CancelCb {
    let counter = Arc::clone(counter);
    Box::new(move || counter.fetch_add(1, Ordering::SeqCst) + 1 > n)
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("temp path should be valid UTF-8")
}

// ---------------------------------------------------------------------------
// Metadata test (no server required)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smb_factory_metadata() {
    let client = create_client(Protocol::Smb).expect("factory did not create SMB backend");

    assert_eq!(
        client.protocol(),
        Protocol::Smb,
        "SMB client should report SMB protocol"
    );

    let caps = client.capabilities();
    assert!(caps.implemented, "SMB should be marked implemented");
    assert!(caps.supports_file_transfers, "SMB should support transfers");
    assert!(caps.supports_listing, "SMB should support remote listing");
    assert!(caps.supports_metadata, "SMB should support metadata");
    assert!(caps.supports_resume, "SMB should advertise resume");
    assert!(
        !caps.supports_permissions,
        "SMB has no POSIX permission model"
    );
    assert!(!caps.supports_ownership, "SMB has no ownership model");
    assert!(!caps.supports_timestamps, "smb2 has no set-times API");
    assert!(!caps.supports_proxy, "SMB has no proxy tunneling");
    assert!(!caps.supports_jump_host, "SMB has no jump-host support");

    // Direct backend construction path.
    let direct = freescp_core::backends::smb::SmbClient::new();
    assert_eq!(
        direct.protocol(),
        Protocol::Smb,
        "directly constructed backend should report SMB protocol"
    );
}

// ---------------------------------------------------------------------------
// Main flow: connect, upload/download roundtrip, listing, metadata, removal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smb_integration_flow() {
    let Some(cfg) = test_config_or_skip() else {
        return;
    };

    let mut client = connect(&cfg).await;
    assert!(
        client.is_connected(),
        "client should report connected after connect"
    );

    let token = unique_token();
    let temp = TempDir::new("freescp_smb", &token);
    let local_upload = temp.join("upload.txt");
    let local_download = temp.join("download.txt");

    let payload = format!("freescp smb integration payload {token}\nline two\n");
    fs::write(&local_upload, &payload).expect("should write local upload file");

    let remote_file_name = format!("freescp_smb_it_{token}.txt");
    let remote_path = join_remote_path(&cfg.remote_base, &remote_file_name);

    // The root listing enumerates shares; the configured share must appear.
    let shares = client
        .list("/")
        .await
        .expect("SMB root listing should succeed");
    assert!(
        shares.iter().all(|s| s.is_dir),
        "root listing entries are shares and must be directories"
    );
    assert!(
        shares
            .iter()
            .any(|s| s.name.eq_ignore_ascii_case(&cfg.share)),
        "root listing should include the configured share '{}' (got: {:?})",
        cfg.share,
        shares.iter().map(|s| s.name.as_str()).collect::<Vec<_>>()
    );

    // Upload with progress callback.
    let upload_progress_called = Arc::new(AtomicBool::new(false));
    client
        .put(
            path_str(&local_upload),
            &remote_path,
            Some(counting_progress(&upload_progress_called)),
            None,
            false,
        )
        .await
        .expect("SMB upload should succeed");
    assert!(
        upload_progress_called.load(Ordering::SeqCst),
        "upload progress callback should be called"
    );

    // Download with progress callback.
    let download_progress_called = Arc::new(AtomicBool::new(false));
    client
        .get(
            &remote_path,
            path_str(&local_download),
            Some(counting_progress(&download_progress_called)),
            None,
            false,
        )
        .await
        .expect("SMB download should succeed");
    assert!(
        download_progress_called.load(Ordering::SeqCst),
        "download progress callback should be called"
    );

    // Roundtrip content verification.
    let downloaded =
        fs::read_to_string(&local_download).expect("downloaded file should be readable");
    assert_eq!(
        downloaded, payload,
        "downloaded content should match uploaded"
    );

    // List the share root: file detection, size and mtime.
    let listing = client
        .list(&cfg.remote_base)
        .await
        .expect("SMB listing should succeed");
    assert!(
        listing.iter().all(|f| f.name != "." && f.name != ".."),
        "list() must filter SMB2's synthetic . and .. entries"
    );
    let listed = listing
        .iter()
        .find(|f| f.name == remote_file_name)
        .expect("SMB listing should include the uploaded file");
    assert!(
        !listed.is_dir,
        "listing should detect the uploaded entry as a file"
    );
    assert!(
        listed.has_size,
        "listing should report a known size for the uploaded file"
    );
    assert_eq!(
        listed.size,
        payload.len() as u64,
        "listing size should match the payload byte length"
    );
    assert!(
        listed.mtime > 0,
        "listing should report a nonzero mtime (SMB last-write time)"
    );

    // Stat on the uploaded file.
    let stat_info = client
        .stat(&remote_path)
        .await
        .expect("SMB stat should succeed");
    assert!(
        !stat_info.is_dir,
        "stat on uploaded file should report file"
    );
    assert!(
        stat_info.has_size,
        "stat on uploaded file should know its size"
    );
    assert_eq!(
        stat_info.size,
        payload.len() as u64,
        "stat size should match the payload byte length"
    );
    assert_eq!(
        stat_info.name, remote_file_name,
        "stat should report the file's base name"
    );

    // Exists on the uploaded file.
    let exists = client
        .exists(&remote_path)
        .await
        .expect("SMB exists should succeed");
    assert_eq!(
        exists,
        Some(false),
        "uploaded file should exist and not be a directory"
    );

    // Exists on a missing file reports None (not an error).
    let missing = join_remote_path(&cfg.remote_base, &format!("no_such_{token}.txt"));
    let missing_exists = client
        .exists(&missing)
        .await
        .expect("SMB exists on missing path should succeed");
    assert!(
        missing_exists.is_none(),
        "missing path should report does-not-exist"
    );

    // Unsupported operations match the capability matrix.
    let chmod_err = client.chmod(&remote_path, 0o644).await.unwrap_err();
    assert!(matches!(chmod_err, ClientError::Unsupported(_)));
    let chown_err = client.chown(&remote_path, 0, 0).await.unwrap_err();
    assert!(matches!(chown_err, ClientError::Unsupported(_)));
    let set_times_err = client.set_times(&remote_path, 0, 0).await.unwrap_err();
    assert!(matches!(set_times_err, ClientError::Unsupported(_)));

    // Delete the file, then confirm it is gone.
    client
        .remove_file(&remote_path)
        .await
        .expect("SMB remove file should succeed");
    let exists_after = client
        .exists(&remote_path)
        .await
        .expect("SMB exists should succeed");
    assert!(
        exists_after.is_none(),
        "removed file should not exist anymore"
    );

    // Disconnect.
    client
        .disconnect()
        .await
        .expect("SMB disconnect should succeed");
    assert!(
        !client.is_connected(),
        "client should report disconnected after disconnect"
    );

    println!("[OK] freescp_smb_integration_tests");
}

// ---------------------------------------------------------------------------
// Directory lifecycle: mkdir, detection, remove_dir (recursive)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smb_mkdir_stat_exists_remove_dir() {
    let Some(cfg) = test_config_or_skip() else {
        return;
    };

    let mut client = connect(&cfg).await;
    let token = unique_token();
    let temp = TempDir::new("freescp_smb_dir", &token);
    let dir_name = format!("freescp_smb_dir_{token}");
    let dir_path = join_remote_path(&cfg.remote_base, &dir_name);

    client
        .mkdir(&dir_path, 0o755)
        .await
        .expect("SMB mkdir should succeed");

    // Exists reports a directory.
    let exists = client
        .exists(&dir_path)
        .await
        .expect("SMB exists should succeed");
    assert_eq!(
        exists,
        Some(true),
        "newly created directory should exist as a directory"
    );

    // Stat reports a directory.
    let stat_info = client
        .stat(&dir_path)
        .await
        .expect("SMB stat on directory should succeed");
    assert!(
        stat_info.is_dir,
        "stat on the new directory should report a directory"
    );

    // Listing detects the directory vs plain files.
    let listing = client
        .list(&cfg.remote_base)
        .await
        .expect("SMB listing should succeed");
    let entry = listing
        .iter()
        .find(|f| f.name == dir_name)
        .expect("listing should include the created directory");
    assert!(
        entry.is_dir,
        "listing should detect the created directory as a directory"
    );

    // Recursive removal: seed a nested file, then remove_dir must clear it.
    let nested_file = join_remote_path(&dir_path, "nested.txt");
    let local = temp.join("nested.txt");
    fs::write(&local, "nested payload").expect("should write local nested file");
    client
        .put(path_str(&local), &nested_file, None, None, false)
        .await
        .expect("nested upload should succeed");

    client
        .remove_dir(&dir_path)
        .await
        .expect("SMB remove_dir should succeed");
    let gone = client
        .exists(&dir_path)
        .await
        .expect("SMB exists should succeed");
    assert!(gone.is_none(), "removed directory should not exist anymore");

    client
        .disconnect()
        .await
        .expect("disconnect should succeed");
}

// ---------------------------------------------------------------------------
// Rename / move, with and without overwrite
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smb_rename_move_and_overwrite() {
    let Some(cfg) = test_config_or_skip() else {
        return;
    };

    let mut client = connect(&cfg).await;
    let token = unique_token();
    let temp = TempDir::new("freescp_smb_rename", &token);

    let first_name = format!("freescp_smb_rename_{token}.txt");
    let second_name = format!("freescp_smb_renamed_{token}.txt");
    let from = join_remote_path(&cfg.remote_base, &first_name);
    let to = join_remote_path(&cfg.remote_base, &second_name);

    let payload = format!("rename payload {token}\n");
    let local = temp.join("rename_source.txt");
    fs::write(&local, &payload).expect("should write local rename source file");

    client
        .put(path_str(&local), &from, None, None, false)
        .await
        .expect("upload before rename should succeed");

    // Move without overwrite (target does not exist yet).
    client
        .rename(&from, &to, false)
        .await
        .expect("rename without overwrite should succeed");
    let old = client
        .exists(&from)
        .await
        .expect("exists on old name should succeed");
    assert!(old.is_none(), "old name should not exist after rename");
    let new = client
        .exists(&to)
        .await
        .expect("exists on new name should succeed");
    assert_eq!(
        new,
        Some(false),
        "new name should exist as a file after rename"
    );

    // Content survives the move.
    let download = temp.join("rename_download.txt");
    client
        .get(&to, path_str(&download), None, None, false)
        .await
        .expect("download after rename should succeed");
    let content = fs::read_to_string(&download).expect("downloaded file should be readable");
    assert_eq!(content, payload, "content should survive the rename");

    // Overwrite an existing target (SMB2 rename does not replace, so the
    // backend deletes the target first).
    let payload2 = format!("second rename payload {token}\n");
    let other = temp.join("rename_other.txt");
    fs::write(&other, &payload2).expect("should write second local file");
    client
        .put(path_str(&other), &from, None, None, false)
        .await
        .expect("second upload should succeed");
    client
        .rename(&from, &to, true)
        .await
        .expect("rename with overwrite should succeed");

    let download2 = temp.join("rename_download2.txt");
    client
        .get(&to, path_str(&download2), None, None, false)
        .await
        .expect("download after overwrite rename should succeed");
    let content2 = fs::read_to_string(&download2).expect("downloaded file should be readable");
    assert_eq!(
        content2, payload2,
        "overwritten target should contain the new content"
    );

    // Cross-share rename is rejected.
    let other_share = format!("/OtherShare_{token}/x.txt");
    let cross_err = client.rename(&to, &other_share, false).await.unwrap_err();
    assert!(
        matches!(cross_err, ClientError::Other(ref m) if m.contains("same share")),
        "cross-share rename should fail, got {cross_err:?}"
    );

    // Cleanup on the server.
    client
        .remove_file(&to)
        .await
        .expect("cleanup remove should succeed");
    client
        .disconnect()
        .await
        .expect("disconnect should succeed");
}

// ---------------------------------------------------------------------------
// Resume: partial local file continues the download; an interrupted upload
// continues from the server-side size.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smb_resume_transfers() {
    let Some(cfg) = test_config_or_skip() else {
        return;
    };

    let mut client = connect(&cfg).await;
    let token = unique_token();
    let temp = TempDir::new("freescp_smb_resume", &token);

    // 256 KiB gives the 64 KiB chunk loop four iterations.
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();

    // --- Download resume: seed a partial local file with the first half. ---
    let remote = join_remote_path(&cfg.remote_base, &format!("freescp_smb_resume_{token}.bin"));
    let local_full = temp.join("resume_full.bin");
    let local_partial = temp.join("resume_partial.bin");

    fs::write(&local_full, &payload).expect("should write local payload");
    client
        .put(path_str(&local_full), &remote, None, None, false)
        .await
        .expect("seed upload should succeed");

    let half = payload.len() / 2;
    fs::write(&local_partial, &payload[..half]).expect("should write partial local file");
    client
        .get(&remote, path_str(&local_partial), None, None, true)
        .await
        .expect("resume download should succeed");
    let resumed = fs::read(&local_partial).expect("resumed local file should be readable");
    assert_eq!(
        resumed, payload,
        "resume download should complete the partial local file"
    );

    // --- Upload resume: interrupt the upload partway, then resume it. ---
    let local_resume = temp.join("resume_upload.bin");
    fs::write(&local_resume, &payload).expect("should write local upload file");
    let remote_upload = join_remote_path(
        &cfg.remote_base,
        &format!("freescp_smb_resume_up_{token}.bin"),
    );

    let counter = Arc::new(AtomicUsize::new(0));
    let cancel = cancel_after_n_polls(2, &counter);
    let put_err = client
        .put(
            path_str(&local_resume),
            &remote_upload,
            None,
            Some(cancel),
            false,
        )
        .await
        .expect_err("interrupted upload should fail");
    assert!(
        matches!(put_err, ClientError::Cancelled),
        "interrupted upload should fail with Cancelled, got {put_err:?}"
    );

    let partial_stat = client
        .stat(&remote_upload)
        .await
        .expect("stat on partial upload should succeed");
    assert!(
        partial_stat.size > 0 && partial_stat.size < payload.len() as u64,
        "partial upload should have written some but not all bytes (got {})",
        partial_stat.size
    );

    client
        .put(path_str(&local_resume), &remote_upload, None, None, true)
        .await
        .expect("resume upload should succeed");
    let remote_download = temp.join("resume_verify.bin");
    client
        .get(
            &remote_upload,
            path_str(&remote_download),
            None,
            None,
            false,
        )
        .await
        .expect("verification download should succeed");
    let verified = fs::read(&remote_download).expect("verified file should be readable");
    assert_eq!(
        verified, payload,
        "resume upload should produce the complete payload"
    );

    client
        .remove_file(&remote)
        .await
        .expect("cleanup remove (download) should succeed");
    client
        .remove_file(&remote_upload)
        .await
        .expect("cleanup remove (upload) should succeed");
    client
        .disconnect()
        .await
        .expect("disconnect should succeed");
}

// ---------------------------------------------------------------------------
// Cancellation: the backend checks shouldCancel between chunks.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smb_cancel_transfers() {
    let Some(cfg) = test_config_or_skip() else {
        return;
    };

    let mut client = connect(&cfg).await;
    let token = unique_token();
    let temp = TempDir::new("freescp_smb_cancel", &token);

    // A 1 MiB payload gives the backend plenty of chunks to poll the cancel
    // callback during the transfer.
    let payload = vec![b'x'; 1024 * 1024];
    let local = temp.join("cancel_upload.txt");
    fs::write(&local, &payload).expect("should write local upload file");
    let remote = join_remote_path(&cfg.remote_base, &format!("freescp_smb_cancel_{token}.txt"));

    // Upload with an immediately-cancelling callback.
    let always_cancel: CancelCb = Box::new(|| true);
    let put_err = client
        .put(path_str(&local), &remote, None, Some(always_cancel), false)
        .await
        .expect_err("cancelled upload should fail");
    assert!(
        matches!(put_err, ClientError::Cancelled),
        "cancelled upload should fail with ClientError::Cancelled, got {put_err:?}"
    );

    // Seed the remote file for the download probe.
    client
        .put(path_str(&local), &remote, None, None, false)
        .await
        .expect("seeding upload should succeed");

    // Download with an immediately-cancelling callback.
    let dl = temp.join("cancel_download.txt");
    let always_cancel: CancelCb = Box::new(|| true);
    let get_err = client
        .get(&remote, path_str(&dl), None, Some(always_cancel), false)
        .await
        .expect_err("cancelled download should fail");
    assert!(
        matches!(get_err, ClientError::Cancelled),
        "cancelled download should fail with ClientError::Cancelled, got {get_err:?}"
    );

    client
        .remove_file(&remote)
        .await
        .expect("cleanup remove should succeed");
    client
        .disconnect()
        .await
        .expect("disconnect should succeed");
}
