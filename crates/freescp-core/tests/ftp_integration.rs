//! Integration tests for the pure-Rust FTP backend, ported from
//! `tests/curl_ftp_integration_tests.cpp` (runs against a real FTP server).
//!
//! Skip semantics mirror the C++ exit code 77: when the required
//! `FREESCP_IT_FTP_HOST` / `FREESCP_IT_FTP_REMOTE_BASE` variables are unset a
//! `[SKIP]` line is printed and the test returns without executing.

use freescp_core::client::{ProgressCb, SftpClient};
use freescp_core::client_factory::create_client;
use freescp_core::types::{FileInfo, Protocol, SessionOptions};

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Environment-gated configuration for the FTP integration suite.
struct FtpTestConfig {
    host: String,
    port: u16,
    username: String,
    password: Option<String>,
    remote_base: String,
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

/// Ports the C++ `parsePort`: unset -> fallback, invalid -> hard failure.
fn parse_port(raw: Option<String>, fallback: u16) -> u16 {
    match raw {
        None => fallback,
        Some(value) => {
            let parsed: i32 = value
                .parse()
                .unwrap_or_else(|_| panic!("[FAIL] FTP port env value is invalid: {value}"));
            assert!(
                (1..=65535).contains(&parsed),
                "[FAIL] FTP port env value out of range: {parsed}"
            );
            parsed as u16
        }
    }
}

/// Ports the C++ `uniqueToken` (steady-clock counter); the process id keeps
/// tokens unique across concurrent test binaries.
fn unique_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    format!("{}_{}", std::process::id(), nanos)
}

/// Ports the C++ `joinRemotePath`.
fn join_remote_path(base: &str, name: &str) -> String {
    if base.is_empty() {
        format!("/{name}")
    } else if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Local scratch directory under the system temp dir, unique per test.
fn make_temp_dir(prefix: &str, token: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}_{token}"));
    fs::create_dir_all(&dir).expect("[FAIL] should create local temp dir");
    dir
}

fn ftp_test_config() -> Option<FtpTestConfig> {
    let host = env_value("FREESCP_IT_FTP_HOST");
    let remote_base = env_value("FREESCP_IT_FTP_REMOTE_BASE");
    if host.is_none() || remote_base.is_none() {
        println!(
            "[SKIP] freescp_ftp_integration_tests requires \
             FREESCP_IT_FTP_HOST and FREESCP_IT_FTP_REMOTE_BASE"
        );
        return None;
    }
    Some(FtpTestConfig {
        host: host.unwrap(),
        port: parse_port(env_value("FREESCP_IT_FTP_PORT"), 21),
        username: env_value("FREESCP_IT_FTP_USER").unwrap_or_else(|| "anonymous".to_string()),
        password: env_value("FREESCP_IT_FTP_PASS"),
        remote_base: remote_base.unwrap(),
    })
}

/// Ports the C++ option assembly: protocol, host/port/credentials.
fn ftp_session_options(cfg: &FtpTestConfig) -> SessionOptions {
    SessionOptions {
        protocol: Protocol::Ftp,
        host: cfg.host.clone(),
        port: cfg.port,
        username: cfg.username.clone(),
        password: cfg.password.clone(),
        ..SessionOptions::default()
    }
}

async fn connect_ftp(cfg: &FtpTestConfig) -> Box<dyn SftpClient> {
    let mut client =
        create_client(Protocol::Ftp).expect("[FAIL] factory did not create FTP backend");
    client
        .connect(&ftp_session_options(cfg))
        .await
        .unwrap_or_else(|err| panic!("[FAIL] FTP connect failed: {err}"));
    client
}

fn progress_flag_cb(flag: Arc<AtomicBool>) -> ProgressCb {
    Box::new(move |_done, _total| {
        flag.store(true, Ordering::SeqCst);
    })
}

/// C++ scenario: factory + connect + protocol/capabilities + disconnect.
#[tokio::test]
async fn ftp_connect_disconnect_and_capabilities() {
    let Some(cfg) = ftp_test_config() else {
        return;
    };

    let mut client = connect_ftp(&cfg).await;
    assert!(
        client.is_connected(),
        "[FAIL] FTP client should report connected after connect()"
    );
    assert_eq!(
        client.protocol(),
        Protocol::Ftp,
        "[FAIL] FTP client should report FTP protocol"
    );
    let caps = client.capabilities();
    assert!(caps.implemented, "[FAIL] FTP should be marked implemented");
    assert!(
        caps.supports_file_transfers,
        "[FAIL] FTP should support transfers"
    );
    assert!(
        caps.supports_listing,
        "[FAIL] FTP should support remote listing"
    );

    client
        .disconnect()
        .await
        .expect("[FAIL] FTP disconnect should succeed");
    assert!(
        !client.is_connected(),
        "[FAIL] FTP client should report disconnected after disconnect()"
    );
}

/// C++ scenario: upload (progress cb) -> download (progress cb) -> content
/// roundtrip verification.
#[tokio::test]
async fn ftp_upload_download_roundtrip() {
    let Some(cfg) = ftp_test_config() else {
        return;
    };

    let mut client = connect_ftp(&cfg).await;

    let token = unique_token();
    let temp_dir = make_temp_dir("freescp_ftp", &token);
    let local_upload = temp_dir.join("upload.txt");
    let local_download = temp_dir.join("download.txt");

    let payload = format!("freescp ftp integration payload {token}\nline two\n");
    fs::write(&local_upload, &payload).expect("[FAIL] should write local upload file");

    let remote_path = join_remote_path(&cfg.remote_base, &format!("freescp_ftp_it_{token}.txt"));

    let upload_progress = Arc::new(AtomicBool::new(false));
    client
        .put(
            &local_upload.to_string_lossy(),
            &remote_path,
            Some(progress_flag_cb(Arc::clone(&upload_progress))),
            None,
            false,
        )
        .await
        .unwrap_or_else(|err| panic!("[FAIL] FTP upload should succeed: {err}"));
    assert!(
        upload_progress.load(Ordering::SeqCst),
        "[FAIL] upload progress callback should be called"
    );

    let download_progress = Arc::new(AtomicBool::new(false));
    client
        .get(
            &remote_path,
            &local_download.to_string_lossy(),
            Some(progress_flag_cb(Arc::clone(&download_progress))),
            None,
            false,
        )
        .await
        .unwrap_or_else(|err| panic!("[FAIL] FTP download should succeed: {err}"));
    assert!(
        download_progress.load(Ordering::SeqCst),
        "[FAIL] download progress callback should be called"
    );

    let downloaded = fs::read(&local_download).expect("[FAIL] downloaded file should be readable");
    assert_eq!(
        downloaded,
        payload.as_bytes(),
        "[FAIL] downloaded content should match uploaded"
    );

    // The C++ original leaves the remote file behind; remove it best-effort
    // so repeated runs do not accumulate files on the test server.
    let _ = client.remove_file(&remote_path).await;

    client
        .disconnect()
        .await
        .expect("[FAIL] FTP disconnect should succeed");
    let _ = fs::remove_dir_all(&temp_dir);
}

/// C++ scenario: listing includes the uploaded file; extended with a file-vs-
/// directory detection check on the listed entry (`is_dir == false`).
#[tokio::test]
async fn ftp_listing_detects_uploaded_file() {
    let Some(cfg) = ftp_test_config() else {
        return;
    };

    let mut client = connect_ftp(&cfg).await;

    let token = unique_token();
    let temp_dir = make_temp_dir("freescp_ftp_list", &token);
    let local_upload = temp_dir.join("upload.txt");
    fs::write(
        &local_upload,
        format!("freescp ftp listing payload {token}\n"),
    )
    .expect("[FAIL] should write local upload file");

    let remote_file_name = format!("freescp_ftp_it_{token}.txt");
    let remote_path = join_remote_path(&cfg.remote_base, &remote_file_name);
    client
        .put(
            &local_upload.to_string_lossy(),
            &remote_path,
            None,
            None,
            false,
        )
        .await
        .unwrap_or_else(|err| panic!("[FAIL] FTP upload should succeed: {err}"));

    let listing: Vec<FileInfo> = client
        .list(&cfg.remote_base)
        .await
        .unwrap_or_else(|err| panic!("[FAIL] FTP listing should succeed: {err}"));
    let entry = listing
        .iter()
        .find(|f| f.name == remote_file_name)
        .unwrap_or_else(|| {
            panic!("[FAIL] FTP listing should include the uploaded file ({remote_file_name})")
        });
    assert!(
        !entry.is_dir,
        "[FAIL] uploaded file should be listed as a regular file"
    );

    let _ = client.remove_file(&remote_path).await;

    client
        .disconnect()
        .await
        .expect("[FAIL] FTP disconnect should succeed");
    let _ = fs::remove_dir_all(&temp_dir);
}
