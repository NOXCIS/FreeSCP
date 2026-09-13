//! Integration tests for the pure-Rust WebDAV backend (`WebDavClient` in
//! `crates/freescp-core/src/backends/webdav/`) — a port of
//! `tests/curl_webdav_integration_tests.cpp`.
//!
//! The C++ suite exits with code 77 unless the required `FREESCP_IT_WEBDAV_*`
//! environment variables exist. Rust has no per-test exit code, so each
//! env-gated test prints the same `[SKIP]` message and returns instead.
//!
//! Required:  FREESCP_IT_WEBDAV_HOST, FREESCP_IT_WEBDAV_REMOTE_BASE
//! Optional:  FREESCP_IT_WEBDAV_USER, FREESCP_IT_WEBDAV_PASS,
//!            FREESCP_IT_WEBDAV_PORT (default 443),
//!            FREESCP_IT_WEBDAV_SCHEME ("http"/"https"; default https, or
//!            http when the port is 80),
//!            FREESCP_IT_WEBDAV_VERIFY_PEER (default true; accepts
//!            1/true/TRUE/yes/YES, 0/false/FALSE/no/NO),
//!            FREESCP_IT_WEBDAV_CA_CERT
//!
//! Run with e.g.:
//!   FREESCP_IT_WEBDAV_HOST=... FREESCP_IT_WEBDAV_REMOTE_BASE=/dav \
//!     cargo test -p freescp-core --test webdav_integration -- --nocapture

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use freescp_core::client::{CancelCb, ProgressCb};
use freescp_core::client_factory::create_client;
use freescp_core::{ClientError, Protocol, SessionOptions, SftpClient, WebDavScheme};

const SKIP_MESSAGE: &str = "[SKIP] freescp_webdav_integration_tests requires \
     FREESCP_IT_WEBDAV_HOST and FREESCP_IT_WEBDAV_REMOTE_BASE";

// ---------------------------------------------------------------------------
// Environment helpers (mirrors of the C++ test file helpers)
// ---------------------------------------------------------------------------

fn env_value(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Mirrors the C++ `parsePort` (`std::stoi` prefix semantics + range check).
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

/// Mirrors the C++ `parseBool`.
fn parse_bool(raw: Option<String>, fallback: bool) -> bool {
    match raw.as_deref() {
        None => fallback,
        Some("1" | "true" | "TRUE" | "yes" | "YES") => true,
        Some("0" | "false" | "FALSE" | "no" | "NO") => false,
        _ => fallback,
    }
}

/// Mirrors the C++ `parseWebDavScheme`: unset falls back to Http only when
/// the port equals the Http default (80), otherwise Https.
fn parse_webdav_scheme(raw: Option<String>, port: u16) -> WebDavScheme {
    match raw {
        None => {
            if port == freescp_core::default_port_for_webdav_scheme(WebDavScheme::Http) {
                WebDavScheme::Http
            } else {
                WebDavScheme::Https
            }
        }
        Some(v) => freescp_core::webdav_scheme_from_storage_name(&v),
    }
}

/// Mirrors the C++ `uniqueToken`.
fn unique_token() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the epoch")
        .as_nanos()
        .to_string()
}

/// Mirrors the C++ `joinRemotePath`.
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
    remote_base: String,
    scheme: WebDavScheme,
    ca_cert: Option<String>,
    verify_peer: bool,
    port: u16,
}

fn read_test_config() -> Option<TestConfig> {
    let host = env_value("FREESCP_IT_WEBDAV_HOST")?;
    let remote_base = env_value("FREESCP_IT_WEBDAV_REMOTE_BASE")?;
    let user = env_value("FREESCP_IT_WEBDAV_USER").unwrap_or_default();
    let pass = env_value("FREESCP_IT_WEBDAV_PASS");
    let scheme_raw = env_value("FREESCP_IT_WEBDAV_SCHEME");
    let ca_cert = env_value("FREESCP_IT_WEBDAV_CA_CERT");
    let verify_peer = parse_bool(env_value("FREESCP_IT_WEBDAV_VERIFY_PEER"), true);
    let port = match parse_port(env_value("FREESCP_IT_WEBDAV_PORT"), 443) {
        Ok(p) => p,
        Err(()) => panic!("[FAIL] FREESCP_IT_WEBDAV_PORT is invalid"),
    };
    let scheme = parse_webdav_scheme(scheme_raw, port);
    Some(TestConfig {
        host,
        user,
        pass,
        remote_base,
        scheme,
        ca_cert,
        verify_peer,
        port,
    })
}

/// Reads env config, printing the C++-equivalent skip message when the
/// required variables are missing.
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
        protocol: Protocol::WebDav,
        host: cfg.host.clone(),
        port: cfg.port,
        username: cfg.user.clone(),
        password: cfg.pass.clone(),
        webdav_scheme: cfg.scheme,
        // Mirrors the C++ test: peer verification applies to https only.
        webdav_verify_peer: cfg.scheme == WebDavScheme::Https && cfg.verify_peer,
        webdav_ca_cert_path: cfg.ca_cert.clone(),
        ..SessionOptions::default()
    }
}

async fn connect(cfg: &TestConfig) -> Box<dyn SftpClient> {
    let mut client =
        create_client(Protocol::WebDav).expect("[FAIL] factory did not create WebDAV backend");
    client
        .connect(&session_options(cfg))
        .await
        .expect("[FAIL] WebDAV connect failed");
    client
}

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

/// Temp directory that removes itself (best effort) on drop, so panicking
/// tests do not leave local clutter behind.
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

/// Progress callback that records whether it was invoked.
fn counting_progress(flag: &Arc<AtomicBool>) -> ProgressCb {
    let flag = Arc::clone(flag);
    Box::new(move |_done: u64, _total: u64| {
        flag.store(true, Ordering::SeqCst);
    })
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("temp path should be valid UTF-8")
}

// ---------------------------------------------------------------------------
// Metadata test (no server required)
// ---------------------------------------------------------------------------

/// Factory/metadata checks ported from the top of the C++ `main()`; these do
/// not touch the network so they always run.
#[tokio::test]
async fn webdav_factory_metadata() {
    let client = create_client(Protocol::WebDav).expect("factory did not create WebDAV backend");

    assert_eq!(
        client.protocol(),
        Protocol::WebDav,
        "WebDAV client should report WebDAV protocol"
    );

    let caps = client.capabilities();
    assert!(caps.implemented, "WebDAV should be marked implemented");
    assert!(
        caps.supports_file_transfers,
        "WebDAV should support transfers"
    );
    assert!(
        caps.supports_listing,
        "WebDAV should support remote listing"
    );
    assert!(caps.supports_metadata, "WebDAV should support metadata");
    assert!(!caps.supports_resume, "WebDAV should not advertise resume");

    // Direct backend construction path.
    let direct = freescp_core::backends::webdav::WebDavClient::new();
    assert_eq!(
        direct.protocol(),
        Protocol::WebDav,
        "directly constructed backend should report WebDAV protocol"
    );

    // `new_connection_like` yields the same backend type, disconnected.
    let opt = SessionOptions {
        protocol: Protocol::WebDav,
        ..SessionOptions::default()
    };
    let like = client
        .new_connection_like(&opt)
        .await
        .expect("new_connection_like should succeed");
    assert_eq!(like.protocol(), Protocol::WebDav);
    assert!(
        !like.is_connected(),
        "new_connection_like result should start disconnected"
    );
}

// ---------------------------------------------------------------------------
// Main flow: exact port of the C++ main() scenario sequence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webdav_integration_flow() {
    let Some(cfg) = test_config_or_skip() else {
        return;
    };

    let mut client = connect(&cfg).await;
    assert!(
        client.is_connected(),
        "client should report connected after connect"
    );

    let token = unique_token();
    let temp = TempDir::new("freescp_webdav", &token);
    let local_upload = temp.join("upload.txt");
    let local_download = temp.join("download.txt");

    let payload = format!("freescp webdav integration payload {token}\nline two\n");
    fs::write(&local_upload, &payload).expect("should write local upload file");

    let remote_file_name = format!("freescp_webdav_it_{token}.txt");
    let remote_path = join_remote_path(&cfg.remote_base, &remote_file_name);

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
        .expect("WebDAV upload should succeed");
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
        .expect("WebDAV download should succeed");
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

    // List the remote base: file detection, size and mtime.
    let listing = client
        .list(&cfg.remote_base)
        .await
        .expect("WebDAV listing should succeed");
    let listed = listing
        .iter()
        .find(|f| f.name == remote_file_name)
        .expect("WebDAV listing should include the uploaded file");
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
        "listing should report a nonzero mtime (server getlastmodified)"
    );

    // Stat on the uploaded file.
    let stat_info = client
        .stat(&remote_path)
        .await
        .expect("WebDAV stat should succeed");
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

    // Exists on the uploaded file.
    let exists = client
        .exists(&remote_path)
        .await
        .expect("WebDAV exists should succeed");
    assert_eq!(
        exists,
        Some(false),
        "uploaded file should exist and not be a directory"
    );

    // Delete the file, then confirm it is gone.
    client
        .remove_file(&remote_path)
        .await
        .expect("WebDAV remove file should succeed");
    let exists_after = client
        .exists(&remote_path)
        .await
        .expect("WebDAV exists should succeed");
    assert!(
        exists_after.is_none(),
        "removed file should not exist anymore"
    );

    // Disconnect.
    client
        .disconnect()
        .await
        .expect("WebDAV disconnect should succeed");
    assert!(
        !client.is_connected(),
        "client should report disconnected after disconnect"
    );

    println!("[OK] freescp_webdav_integration_tests");
}

// ---------------------------------------------------------------------------
// Directory lifecycle: mkdir, collection detection, remove_dir
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webdav_mkdir_stat_exists_remove_dir() {
    let Some(cfg) = test_config_or_skip() else {
        return;
    };

    let mut client = connect(&cfg).await;
    let token = unique_token();
    let dir_name = format!("freescp_webdav_dir_{token}");
    let dir_path = join_remote_path(&cfg.remote_base, &dir_name);

    client
        .mkdir(&dir_path, 0o755)
        .await
        .expect("WebDAV mkdir should succeed");

    // Exists reports a collection.
    let exists = client
        .exists(&dir_path)
        .await
        .expect("WebDAV exists should succeed");
    assert_eq!(
        exists,
        Some(true),
        "newly created collection should exist as a directory"
    );

    // Stat reports a collection.
    let stat_info = client
        .stat(&dir_path)
        .await
        .expect("WebDAV stat on collection should succeed");
    assert!(
        stat_info.is_dir,
        "stat on the new collection should report a directory"
    );

    // Listing detects the collection vs plain files.
    let listing = client
        .list(&cfg.remote_base)
        .await
        .expect("WebDAV listing should succeed");
    let entry = listing
        .iter()
        .find(|f| f.name == dir_name)
        .expect("listing should include the created collection");
    assert!(
        entry.is_dir,
        "listing should detect the created collection as a directory"
    );

    // Remove the (empty) directory and confirm it is gone.
    client
        .remove_dir(&dir_path)
        .await
        .expect("WebDAV remove_dir should succeed");
    let gone = client
        .exists(&dir_path)
        .await
        .expect("WebDAV exists should succeed");
    assert!(
        gone.is_none(),
        "removed collection should not exist anymore"
    );

    client
        .disconnect()
        .await
        .expect("disconnect should succeed");
}

// ---------------------------------------------------------------------------
// Rename / move, with and without overwrite
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webdav_rename_move_and_overwrite() {
    let Some(cfg) = test_config_or_skip() else {
        return;
    };

    let mut client = connect(&cfg).await;
    let token = unique_token();
    let temp = TempDir::new("freescp_webdav_rename", &token);

    let first_name = format!("freescp_webdav_rename_{token}.txt");
    let second_name = format!("freescp_webdav_renamed_{token}.txt");
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

    // Overwrite an existing target.
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
// Resume: the C++ client rejects resume=true ("WebDAV backend does not
// support resume"); not exercised by the C++ integration file, added here
// because the capability matrix advertises supports_resume=false.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webdav_resume_is_unsupported() {
    let Some(cfg) = test_config_or_skip() else {
        return;
    };

    let mut client = connect(&cfg).await;
    let token = unique_token();
    let temp = TempDir::new("freescp_webdav_resume", &token);
    let local = temp.join("resume_probe.txt");
    fs::write(&local, "resume probe").expect("should write local probe file");
    let remote = join_remote_path(
        &cfg.remote_base,
        &format!("freescp_webdav_resume_{token}.txt"),
    );

    // Upload with resume=true must be rejected.
    let put_err = client
        .put(path_str(&local), &remote, None, None, true)
        .await
        .expect_err("resume upload should be rejected");
    assert!(
        matches!(put_err, ClientError::Unsupported(_)),
        "resume upload should fail with Unsupported, got {put_err:?}"
    );

    // Create the file normally so the download-side probe has a target.
    client
        .put(path_str(&local), &remote, None, None, false)
        .await
        .expect("plain upload should succeed");

    // Download with resume=true must be rejected as well.
    let dl = temp.join("resume_download.txt");
    let get_err = client
        .get(&remote, path_str(&dl), None, None, true)
        .await
        .expect_err("resume download should be rejected");
    assert!(
        matches!(get_err, ClientError::Unsupported(_)),
        "resume download should fail with Unsupported, got {get_err:?}"
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

// ---------------------------------------------------------------------------
// Cancellation: the C++ client checks shouldCancel during transfers and
// fails with "Canceled by user"; not exercised by the C++ integration file.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webdav_cancel_transfers() {
    let Some(cfg) = test_config_or_skip() else {
        return;
    };

    let mut client = connect(&cfg).await;
    let token = unique_token();
    let temp = TempDir::new("freescp_webdav_cancel", &token);

    // A 1 MiB payload gives the backend plenty of chunks to poll the cancel
    // callback during the transfer.
    let payload = vec![b'x'; 1024 * 1024];
    let local = temp.join("cancel_upload.txt");
    fs::write(&local, &payload).expect("should write local upload file");
    let remote = join_remote_path(
        &cfg.remote_base,
        &format!("freescp_webdav_cancel_{token}.txt"),
    );

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
