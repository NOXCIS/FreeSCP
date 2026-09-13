//! Integration tests for the russh-based SFTP backend.
//!
//! Rust port of `tests/libssh2_integration_tests.cpp`, extended with the
//! scenarios requested by the rewrite plan: successful resume paths, TOFU
//! accept/reject via `hostkey_confirm_cb`, keyboard-interactive,
//! mid-transfer cancellation, an integrity policy matrix and
//! `new_connection_like`.
//!
//! Gating mirrors the C++ suite: tests read the `FREESCP_IT_*` environment
//! variables and skip (pass trivially, with a `SKIP:` notice) when the
//! required variables are absent. Present-but-invalid configuration fails
//! loudly, mirroring the C++ `EXIT_FAILURE` paths.
//!
//! Note: `anyhow` is not listed in freescp-core's dev-dependencies, so these
//! tests stick to `expect`/`assert!` instead of `Result` propagation. The
//! only external crates used here are `tokio` (dev-dependency) and the
//! crate's own public API.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use freescp_core::backends::sftp::RusshSftpClient;
use freescp_core::client_factory::create_client;
use freescp_core::{
    ClientError, KbdIntPromptResult, KnownHostsPolicy, Protocol, ProxyType, SessionOptions,
    SftpClient, TransferIntegrityPolicy,
};

/// The payload used by the roundtrip tests (kept identical to the C++ suite).
const PAYLOAD: &str = "FreeSCP integration payload\nline-2\n";
/// A deliberately wrong payload for integrity-mismatch regressions.
const BAD_PAYLOAD: &str = "CORRUPTED prefix\nline-x\n";

// ---------------------------------------------------------------------------
// Test context (port of the C++ TestContext / env plumbing)
// ---------------------------------------------------------------------------

/// Environment-derived test configuration shared by every test.
struct TestCtx {
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
    key_path: Option<String>,
    key_passphrase: Option<String>,
    remote_base: String,
    proxy_type: ProxyType,
    proxy_host: Option<String>,
    proxy_port: u16,
    proxy_user: Option<String>,
    proxy_pass: Option<String>,
    jump_host: Option<String>,
    jump_port: u16,
    jump_user: Option<String>,
    jump_key: Option<String>,
    token: String,
    local_tmp: PathBuf,
}

fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

fn unique_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos();
    nanos.to_string()
}

fn join_remote(base: &str, name: &str) -> String {
    if base.is_empty() {
        format!("/{name}")
    } else if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// known_hosts host token, matching the C++ helper (bracketed for non-22
/// ports).
fn known_hosts_host_token(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Port of the C++ `parsePort`: 1..=65535, `None` when absent/invalid.
fn parse_port(raw: Option<String>) -> Option<u16> {
    let port = raw?.parse::<u16>().ok()?;
    (port >= 1).then_some(port)
}

/// Port of the C++ `parseProxyType` (case-insensitive aliases).
fn parse_proxy_type(raw: Option<String>) -> Option<ProxyType> {
    let raw = raw?;
    match raw.to_ascii_lowercase().as_str() {
        "none" | "direct" | "off" => Some(ProxyType::None),
        "socks5" | "socks" => Some(ProxyType::Socks5),
        "http" | "http_connect" | "http-connect" | "connect" => Some(ProxyType::HttpConnect),
        _ => None,
    }
}

/// Reads the `FREESCP_IT_*` environment and builds the test context.
///
/// Returns `None` (after printing the skip notice) when the suite is not
/// configured, mirroring the C++ exit-code-77 skip. Present-but-invalid
/// configuration panics, mirroring the C++ `EXIT_FAILURE` paths.
fn test_ctx() -> Option<TestCtx> {
    const SKIP_MSG: &str = "SKIP: freescp_sftp_integration_tests requires env vars: \
        FREESCP_IT_SFTP_HOST, FREESCP_IT_SFTP_USER and one auth method \
        (FREESCP_IT_SFTP_PASS or FREESCP_IT_SFTP_KEY)";

    let host = env_str("FREESCP_IT_SFTP_HOST");
    let user = env_str("FREESCP_IT_SFTP_USER");
    let password = env_str("FREESCP_IT_SFTP_PASS");
    let key_path = env_str("FREESCP_IT_SFTP_KEY");
    if host.is_none() || user.is_none() || (password.is_none() && key_path.is_none()) {
        eprintln!("{SKIP_MSG}");
        return None;
    }
    let host = host.unwrap();
    let user = user.unwrap();

    let key_passphrase = env_str("FREESCP_IT_SFTP_KEY_PASSPHRASE");
    if let Some(key) = &key_path {
        assert!(
            Path::new(key).exists(),
            "FREESCP_IT_SFTP_KEY does not exist: {key}"
        );
    }
    let jump_key = env_str("FREESCP_IT_JUMP_KEY");
    if let Some(key) = &jump_key {
        assert!(
            Path::new(key).exists(),
            "FREESCP_IT_JUMP_KEY does not exist: {key}"
        );
    }

    let port = env_str("FREESCP_IT_SFTP_PORT")
        .map(|raw| parse_port(Some(raw)).expect("FREESCP_IT_SFTP_PORT is invalid"))
        .unwrap_or(22);

    let proxy_type = env_str("FREESCP_IT_PROXY_TYPE")
        .map(|raw| parse_proxy_type(Some(raw)).expect("FREESCP_IT_PROXY_TYPE is invalid"))
        .unwrap_or(ProxyType::None);

    let proxy_host = env_str("FREESCP_IT_PROXY_HOST");
    let mut proxy_port = 0;
    if proxy_type != ProxyType::None {
        assert!(
            proxy_host.is_some(),
            "FREESCP_IT_PROXY_HOST is required when FREESCP_IT_PROXY_TYPE is set"
        );
        let default_port = if proxy_type == ProxyType::Socks5 {
            1080
        } else {
            8080
        };
        proxy_port = env_str("FREESCP_IT_PROXY_PORT")
            .map(|raw| parse_port(Some(raw)).expect("FREESCP_IT_PROXY_PORT is invalid"))
            .unwrap_or(default_port);
    }
    let proxy_user = env_str("FREESCP_IT_PROXY_USER");
    let proxy_pass = env_str("FREESCP_IT_PROXY_PASS");

    let jump_host = env_str("FREESCP_IT_JUMP_HOST");
    let jump_port = if jump_host.is_some() {
        env_str("FREESCP_IT_JUMP_PORT")
            .map(|raw| parse_port(Some(raw)).expect("FREESCP_IT_JUMP_PORT is invalid"))
            .unwrap_or(22)
    } else {
        22
    };
    let jump_user = env_str("FREESCP_IT_JUMP_USER");

    assert!(
        !(proxy_type != ProxyType::None && jump_host.is_some()),
        "FREESCP_IT_PROXY_TYPE and FREESCP_IT_JUMP_HOST cannot be used together in the same run"
    );

    let token = unique_token();
    let local_tmp = std::env::temp_dir().join(format!("freescp-it-{token}"));
    fs::create_dir_all(&local_tmp).expect("could not create temp dir");

    Some(TestCtx {
        host,
        port,
        user,
        password,
        key_path,
        key_passphrase,
        remote_base: env_str("FREESCP_IT_REMOTE_BASE").unwrap_or_else(|| "/tmp".to_string()),
        proxy_type,
        proxy_host,
        proxy_port,
        proxy_user,
        proxy_pass,
        jump_host,
        jump_port,
        jump_user,
        jump_key,
        token,
        local_tmp,
    })
}

impl TestCtx {
    /// Base options mirroring the C++ suite: auth from env, known_hosts Off,
    /// transfer integrity Required, proxy/jump from env.
    fn options(&self) -> SessionOptions {
        SessionOptions {
            host: self.host.clone(),
            port: self.port,
            username: self.user.clone(),
            password: self.password.clone(),
            private_key_path: self.key_path.clone(),
            private_key_passphrase: self.key_passphrase.clone(),
            known_hosts_policy: KnownHostsPolicy::Off,
            transfer_integrity_policy: TransferIntegrityPolicy::Required,
            proxy_type: self.proxy_type,
            proxy_host: self.proxy_host.clone().unwrap_or_default(),
            proxy_port: self.proxy_port,
            proxy_username: self.proxy_user.clone(),
            proxy_password: self.proxy_pass.clone(),
            jump_host: self.jump_host.clone(),
            jump_port: self.jump_port,
            jump_username: self.jump_user.clone(),
            jump_private_key_path: self.jump_key.clone(),
            ..SessionOptions::default()
        }
    }

    /// Remote scratch directory unique to this test run:
    /// `{remote_base}/freescp-it-{token}`.
    fn suite_dir(&self) -> String {
        join_remote(&self.remote_base, &format!("freescp-it-{}", self.token))
    }

    /// Remote path inside the scratch directory.
    fn remote_path(&self, name: &str) -> String {
        join_remote(&self.suite_dir(), name)
    }

    fn remove_local_tmp(&self) {
        let _ = fs::remove_dir_all(&self.local_tmp);
    }
}

// ---------------------------------------------------------------------------
// File helpers (std only)
// ---------------------------------------------------------------------------

fn read_file(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()))
}

fn write_file(path: &Path, content: &str) {
    fs::write(path, content).unwrap_or_else(|e| panic!("could not write {}: {e}", path.display()));
}

// ---------------------------------------------------------------------------
// Remote helpers (async)
// ---------------------------------------------------------------------------

/// Create and connect a fresh SFTP client for `ctx`.
async fn connect(ctx: &TestCtx) -> Box<dyn SftpClient> {
    let mut client = create_client(Protocol::Sftp).expect("create_client(Protocol::Sftp) failed");
    client
        .connect(&ctx.options())
        .await
        .unwrap_or_else(|e| panic!("connect should succeed: {e}"));
    assert!(client.is_connected(), "client should report connected");
    client
}

/// Strict removal of a remote file that tolerates a missing path (port of the
/// C++ `removeRemoteFileIfExists`).
async fn remove_remote_file_if_exists(client: &mut Box<dyn SftpClient>, remote: &str) {
    match client.exists(remote).await {
        Ok(Some(false)) => client
            .remove_file(remote)
            .await
            .unwrap_or_else(|e| panic!("remove_file({remote}) should succeed: {e}")),
        Ok(Some(true)) => panic!("remove_remote_file_if_exists({remote}): path is a directory"),
        Ok(None) => {}
        Err(e) => panic!("exists({remote}) should succeed: {e}"),
    }
}

/// Best-effort cleanup for files and directories (errors are ignored,
/// mirroring the C++ `(void)` cleanup calls).
async fn best_effort_remove(client: &mut Box<dyn SftpClient>, remote: &str) {
    match client.exists(remote).await {
        Ok(Some(false)) => {
            let _ = client.remove_file(remote).await;
        }
        Ok(Some(true)) => {
            let _ = client.remove_dir(remote).await;
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Regression (C++): TOFU must reject known_hosts mismatches (changed keys)
/// before the confirmation callback is ever invoked.
#[tokio::test]
async fn tofu_hostkey_mismatch_fails_before_callback() {
    let Some(ctx) = test_ctx() else { return };

    const FAKE_ED25519: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAILZlz+tnMZZGpyX4/qwU9iIfMHkUqPnwGwGZRuQQ3v1d";
    let known_hosts = ctx.local_tmp.join("known_hosts_tofu_mismatch");
    write_file(
        &known_hosts,
        &format!(
            "{} ssh-ed25519 {FAKE_ED25519}\n",
            known_hosts_host_token(&ctx.host, ctx.port)
        ),
    );

    let confirm_called = Arc::new(AtomicBool::new(false));
    let opt = {
        let mut opt = ctx.options();
        opt.known_hosts_policy = KnownHostsPolicy::AcceptNew;
        opt.known_hosts_path = Some(known_hosts.to_string_lossy().into_owned());
        let called = Arc::clone(&confirm_called);
        opt.hostkey_confirm_cb = Some(Arc::new(
            move |_host: &str, _port: u16, _algo: &str, _fp: &str, _can_save: bool| {
                called.store(true, Ordering::SeqCst);
                true
            },
        ));
        opt
    };

    let mut client = create_client(Protocol::Sftp).expect("create_client failed");
    let result = client.connect(&opt).await;
    assert!(
        result.is_err(),
        "TOFU connect should fail when known_hosts entry mismatches"
    );
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("does not match known_hosts"),
        "TOFU mismatch should report host-key mismatch: {message}"
    );
    assert!(
        !confirm_called.load(Ordering::SeqCst),
        "TOFU mismatch should fail before invoking confirmation callback"
    );
    let _ = client.disconnect().await;

    ctx.remove_local_tmp();
}

/// Password authentication exercised through the concrete
/// `RusshSftpClient::new()` constructor (pins the documented backend path).
#[tokio::test]
async fn connect_with_password() {
    let Some(ctx) = test_ctx() else { return };
    if ctx.password.is_none() {
        eprintln!("SKIP: FREESCP_IT_SFTP_PASS is not set");
        ctx.remove_local_tmp();
        return;
    }

    let mut opt = ctx.options();
    opt.private_key_path = None; // force the password auth path
    opt.private_key_passphrase = None;

    let mut client: Box<dyn SftpClient> = Box::new(RusshSftpClient::new());
    client
        .connect(&opt)
        .await
        .unwrap_or_else(|e| panic!("connect should succeed: {e}"));
    assert!(client.is_connected());
    client
        .disconnect()
        .await
        .unwrap_or_else(|e| panic!("disconnect should succeed: {e}"));
    assert!(!client.is_connected());

    ctx.remove_local_tmp();
}

/// Public-key authentication (with optional passphrase from env).
#[tokio::test]
async fn connect_with_key() {
    let Some(ctx) = test_ctx() else { return };
    if ctx.key_path.is_none() {
        eprintln!("SKIP: FREESCP_IT_SFTP_KEY is not set");
        ctx.remove_local_tmp();
        return;
    }

    let mut opt = ctx.options();
    opt.password = None; // force the key auth path

    let mut client = create_client(Protocol::Sftp).expect("create_client failed");
    client
        .connect(&opt)
        .await
        .unwrap_or_else(|e| panic!("connect should succeed: {e}"));
    assert!(client.is_connected());
    let _ = client.disconnect().await;

    ctx.remove_local_tmp();
}

/// `new_connection_like` must produce a fresh, disconnected client that can
/// be connected and used independently of the original session.
#[tokio::test]
async fn new_connection_like_creates_fresh_client() {
    let Some(ctx) = test_ctx() else { return };

    let suite = ctx.suite_dir();
    let mut client = connect(&ctx).await;
    let opt = ctx.options();

    let fresh = client
        .new_connection_like(&opt)
        .await
        .unwrap_or_else(|e| panic!("new_connection_like should succeed: {e}"));
    assert!(
        !fresh.is_connected(),
        "new_connection_like must return a disconnected client"
    );

    let mut fresh = fresh;
    fresh
        .connect(&opt)
        .await
        .unwrap_or_else(|e| panic!("fresh client connect should succeed: {e}"));
    assert!(fresh.is_connected());
    fresh
        .mkdir(&suite, 0o755)
        .await
        .unwrap_or_else(|e| panic!("fresh client mkdir should succeed: {e}"));
    let entries = fresh
        .list(&suite)
        .await
        .unwrap_or_else(|e| panic!("fresh client list should succeed: {e}"));
    assert!(entries.is_empty(), "fresh suite dir should be empty");
    let _ = fresh.disconnect().await;

    best_effort_remove(&mut client, &suite).await;
    let _ = client.disconnect().await;

    ctx.remove_local_tmp();
}

/// mkdir / list / exists / remove_file / remove_dir lifecycle.
#[tokio::test]
async fn mkdir_list_exists_rmdir() {
    let Some(ctx) = test_ctx() else { return };

    let suite = ctx.suite_dir();
    let payload_remote = ctx.remote_path("payload.txt");
    let local_payload = ctx.local_tmp.join("payload.txt");
    write_file(&local_payload, PAYLOAD);

    let mut client = connect(&ctx).await;

    client
        .mkdir(&suite, 0o755)
        .await
        .unwrap_or_else(|e| panic!("mkdir({suite}) should succeed: {e}"));
    assert_eq!(
        client
            .exists(&suite)
            .await
            .unwrap_or_else(|e| panic!("exists({suite}) failed: {e}")),
        Some(true),
        "suite dir should exist and be reported as a directory"
    );
    assert_eq!(
        client
            .exists(&ctx.remote_path("missing.txt"))
            .await
            .unwrap_or_else(|e| panic!("exists(missing) failed: {e}")),
        None,
        "missing path should report None"
    );

    client
        .put(
            &local_payload.to_string_lossy(),
            &payload_remote,
            None,
            None,
            false,
        )
        .await
        .unwrap_or_else(|e| panic!("put should succeed: {e}"));

    let entries = client
        .list(&suite)
        .await
        .unwrap_or_else(|e| panic!("list({suite}) should succeed: {e}"));
    assert!(
        entries.iter().any(|entry| entry.name == "payload.txt"),
        "list should include payload.txt (got {entries:?})"
    );

    remove_remote_file_if_exists(&mut client, &payload_remote).await;
    client
        .remove_dir(&suite)
        .await
        .unwrap_or_else(|e| panic!("remove_dir({suite}) should succeed: {e}"));
    assert_eq!(
        client.exists(&suite).await.expect("exists failed"),
        None,
        "suite dir should be gone after remove_dir"
    );

    let _ = client.disconnect().await;
    ctx.remove_local_tmp();
}

/// Upload/download roundtrip with content verification, exists and stat.
#[tokio::test]
async fn upload_download_roundtrip_with_stat() {
    let Some(ctx) = test_ctx() else { return };

    let suite = ctx.suite_dir();
    let remote_src = ctx.remote_path("payload.txt");
    let local_src = ctx.local_tmp.join("payload.txt");
    let local_dst = ctx.local_tmp.join("payload-downloaded.txt");
    write_file(&local_src, PAYLOAD);

    let mut client = connect(&ctx).await;
    client
        .mkdir(&suite, 0o755)
        .await
        .expect("mkdir should succeed");

    client
        .put(&local_src.to_string_lossy(), &remote_src, None, None, false)
        .await
        .unwrap_or_else(|e| panic!("put should succeed: {e}"));

    assert_eq!(
        client.exists(&remote_src).await.expect("exists failed"),
        Some(false),
        "exists(remoteSrc) should report a file"
    );

    let info = client
        .stat(&remote_src)
        .await
        .unwrap_or_else(|e| panic!("stat should succeed: {e}"));
    assert!(info.has_size, "stat should report size");
    assert_eq!(
        info.size,
        PAYLOAD.len() as u64,
        "remote file size should match payload size"
    );

    client
        .get(&remote_src, &local_dst.to_string_lossy(), None, None, false)
        .await
        .unwrap_or_else(|e| panic!("get should succeed: {e}"));
    assert_eq!(
        read_file(&local_dst),
        PAYLOAD,
        "downloaded content should match uploaded payload"
    );

    best_effort_remove(&mut client, &suite).await;
    let _ = client.disconnect().await;
    ctx.remove_local_tmp();
}

/// Download resume (required integrity): a `.part` file matching the payload
/// prefix is completed successfully.
#[tokio::test]
async fn download_resume_completes() {
    let Some(ctx) = test_ctx() else { return };

    let suite = ctx.suite_dir();
    let remote = ctx.remote_path("resume-download.txt");
    let local_src = ctx.local_tmp.join("resume-src.txt");
    let local_dst = ctx.local_tmp.join("payload-resume-downloaded.txt");
    let local_part = ctx.local_tmp.join("payload-resume-downloaded.txt.part");
    write_file(&local_src, PAYLOAD);

    let mut client = connect(&ctx).await;
    client
        .mkdir(&suite, 0o755)
        .await
        .expect("mkdir should succeed");
    client
        .put(&local_src.to_string_lossy(), &remote, None, None, false)
        .await
        .expect("put should succeed");

    let split = PAYLOAD.len() / 2;
    write_file(&local_part, &PAYLOAD[..split]);
    client
        .get(&remote, &local_dst.to_string_lossy(), None, None, true)
        .await
        .unwrap_or_else(|e| panic!("get resume should succeed: {e}"));
    assert_eq!(
        read_file(&local_dst),
        PAYLOAD,
        "resumed download content should match payload"
    );

    best_effort_remove(&mut client, &suite).await;
    let _ = client.disconnect().await;
    ctx.remove_local_tmp();
}

/// Upload resume (required integrity): a remote `.part` matching the local
/// payload prefix is completed successfully.
#[tokio::test]
async fn upload_resume_completes() {
    let Some(ctx) = test_ctx() else { return };

    let suite = ctx.suite_dir();
    let remote = ctx.remote_path("resume-upload.txt");
    let local_src = ctx.local_tmp.join("resume-src.txt");
    let local_seed = ctx.local_tmp.join("resume-seed.txt");
    let local_check = ctx.local_tmp.join("resume-check.txt");
    write_file(&local_src, PAYLOAD);

    let mut client = connect(&ctx).await;
    client
        .mkdir(&suite, 0o755)
        .await
        .expect("mkdir should succeed");

    let split = PAYLOAD.len() / 2;
    write_file(&local_seed, &PAYLOAD[..split]);
    client
        .put(
            &local_seed.to_string_lossy(),
            &format!("{remote}.part"),
            None,
            None,
            false,
        )
        .await
        .expect("put seed should succeed");
    client
        .put(&local_src.to_string_lossy(), &remote, None, None, true)
        .await
        .unwrap_or_else(|e| panic!("put resume should succeed: {e}"));

    client
        .get(&remote, &local_check.to_string_lossy(), None, None, false)
        .await
        .expect("get should succeed");
    assert_eq!(
        read_file(&local_check),
        PAYLOAD,
        "resumed upload content should match payload"
    );

    best_effort_remove(&mut client, &suite).await;
    let _ = client.disconnect().await;
    ctx.remove_local_tmp();
}

/// Regression (C++): required integrity must fail on resume mismatch
/// (download).
#[tokio::test]
async fn download_resume_integrity_mismatch_fails() {
    let Some(ctx) = test_ctx() else { return };

    let suite = ctx.suite_dir();
    let remote = ctx.remote_path("resume-download.txt");
    let local_src = ctx.local_tmp.join("resume-src.txt");
    let local_dst = ctx.local_tmp.join("payload-resume-downloaded.txt");
    let local_part = ctx.local_tmp.join("payload-resume-downloaded.txt.part");
    write_file(&local_src, PAYLOAD);

    let mut client = connect(&ctx).await;
    client
        .mkdir(&suite, 0o755)
        .await
        .expect("mkdir should succeed");
    client
        .put(&local_src.to_string_lossy(), &remote, None, None, false)
        .await
        .expect("put should succeed");

    write_file(&local_part, BAD_PAYLOAD);
    let result = client
        .get(&remote, &local_dst.to_string_lossy(), None, None, true)
        .await;
    assert!(
        result.is_err(),
        "get resume with required integrity should fail on mismatch"
    );
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("Integrity check failed in resume (download)"),
        "download mismatch should report integrity error: {message}"
    );

    best_effort_remove(&mut client, &suite).await;
    let _ = client.disconnect().await;
    ctx.remove_local_tmp();
}

/// Regression (C++): required integrity must fail on resume mismatch
/// (upload).
#[tokio::test]
async fn upload_resume_integrity_mismatch_fails() {
    let Some(ctx) = test_ctx() else { return };

    let suite = ctx.suite_dir();
    let remote = ctx.remote_path("resume-upload.txt");
    let local_src = ctx.local_tmp.join("resume-src.txt");
    let local_bad = ctx.local_tmp.join("payload-bad.txt");
    write_file(&local_src, PAYLOAD);
    write_file(&local_bad, BAD_PAYLOAD);

    let mut client = connect(&ctx).await;
    client
        .mkdir(&suite, 0o755)
        .await
        .expect("mkdir should succeed");

    client
        .put(
            &local_bad.to_string_lossy(),
            &ctx.remote_path("resume-upload-seed.txt"),
            None,
            None,
            false,
        )
        .await
        .expect("put(seed) should succeed");
    client
        .rename(
            &ctx.remote_path("resume-upload-seed.txt"),
            &format!("{remote}.part"),
            false,
        )
        .await
        .expect("rename(seed -> .part) should succeed");

    let result = client
        .put(&local_src.to_string_lossy(), &remote, None, None, true)
        .await;
    assert!(
        result.is_err(),
        "put resume with required integrity should fail on mismatch"
    );
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("Integrity check failed in resume (upload)"),
        "upload mismatch should report integrity error: {message}"
    );

    best_effort_remove(&mut client, &suite).await;
    let _ = client.disconnect().await;
    ctx.remove_local_tmp();
}

/// Integrity policy matrix: Optional and Off both complete a plain roundtrip.
#[tokio::test]
async fn integrity_policies_optional_and_off_roundtrip() {
    let Some(ctx) = test_ctx() else { return };

    for policy in [
        TransferIntegrityPolicy::Optional,
        TransferIntegrityPolicy::Off,
    ] {
        let mut opt = ctx.options();
        opt.transfer_integrity_policy = policy;

        let mut client = create_client(Protocol::Sftp).expect("create_client failed");
        client
            .connect(&opt)
            .await
            .unwrap_or_else(|e| panic!("connect ({policy:?}) should succeed: {e}"));

        let suite = join_remote(&ctx.suite_dir(), &format!("policy-{policy:?}"));
        let remote = join_remote(&suite, "payload.txt");
        let local_src = ctx.local_tmp.join(format!("policy-{policy:?}-src.txt"));
        let local_dst = ctx.local_tmp.join(format!("policy-{policy:?}-dst.txt"));
        write_file(&local_src, PAYLOAD);

        client
            .mkdir(&suite, 0o755)
            .await
            .expect("mkdir should succeed");
        client
            .put(&local_src.to_string_lossy(), &remote, None, None, false)
            .await
            .unwrap_or_else(|e| panic!("put ({policy:?}) should succeed: {e}"));
        client
            .get(&remote, &local_dst.to_string_lossy(), None, None, false)
            .await
            .unwrap_or_else(|e| panic!("get ({policy:?}) should succeed: {e}"));
        assert_eq!(read_file(&local_dst), PAYLOAD);

        best_effort_remove(&mut client, &suite).await;
        let _ = client.disconnect().await;
    }

    ctx.remove_local_tmp();
}

/// chmod must be reflected in the remote mode reported by stat.
#[tokio::test]
async fn chmod_updates_remote_mode() {
    let Some(ctx) = test_ctx() else { return };

    let suite = ctx.suite_dir();
    let remote = ctx.remote_path("payload.txt");
    let local_src = ctx.local_tmp.join("payload.txt");
    write_file(&local_src, PAYLOAD);

    let mut client = connect(&ctx).await;
    client
        .mkdir(&suite, 0o755)
        .await
        .expect("mkdir should succeed");
    client
        .put(&local_src.to_string_lossy(), &remote, None, None, false)
        .await
        .expect("put should succeed");

    client
        .chmod(&remote, 0o600)
        .await
        .unwrap_or_else(|e| panic!("chmod should succeed: {e}"));
    let info = client
        .stat(&remote)
        .await
        .unwrap_or_else(|e| panic!("stat should succeed: {e}"));
    assert_eq!(
        info.mode & 0o777,
        0o600,
        "chmod 0600 should be reflected in stat mode"
    );

    best_effort_remove(&mut client, &suite).await;
    let _ = client.disconnect().await;
    ctx.remove_local_tmp();
}

/// rename moves a path; `overwrite = false` must refuse to clobber an
/// existing target.
#[tokio::test]
async fn rename_moves_path_and_rejects_overwrite_when_denied() {
    let Some(ctx) = test_ctx() else { return };

    let suite = ctx.suite_dir();
    let remote_src = ctx.remote_path("payload.txt");
    let remote_dst = ctx.remote_path("payload-existing.txt");
    let remote_moved = ctx.remote_path("payload-moved.txt");
    let local_src = ctx.local_tmp.join("payload.txt");
    let local_dst = ctx.local_tmp.join("payload-existing.txt");
    let local_check = ctx.local_tmp.join("payload-check.txt");
    write_file(&local_src, PAYLOAD);
    write_file(&local_dst, BAD_PAYLOAD);

    let mut client = connect(&ctx).await;
    client
        .mkdir(&suite, 0o755)
        .await
        .expect("mkdir should succeed");
    client
        .put(&local_src.to_string_lossy(), &remote_src, None, None, false)
        .await
        .expect("put(src) should succeed");
    client
        .put(&local_dst.to_string_lossy(), &remote_dst, None, None, false)
        .await
        .expect("put(dst) should succeed");

    let result = client.rename(&remote_src, &remote_dst, false).await;
    assert!(
        result.is_err(),
        "rename with overwrite=false onto an existing target should fail"
    );
    client
        .get(
            &remote_dst,
            &local_check.to_string_lossy(),
            None,
            None,
            false,
        )
        .await
        .expect("get(dst) should succeed");
    assert_eq!(
        read_file(&local_check),
        BAD_PAYLOAD,
        "existing target must be untouched"
    );

    client
        .rename(&remote_src, &remote_moved, false)
        .await
        .unwrap_or_else(|e| panic!("rename should succeed: {e}"));
    assert_eq!(
        client.exists(&remote_src).await.expect("exists failed"),
        None,
        "old path should not exist after rename"
    );
    assert_eq!(
        client.exists(&remote_moved).await.expect("exists failed"),
        Some(false),
        "new path should exist after rename"
    );

    best_effort_remove(&mut client, &suite).await;
    let _ = client.disconnect().await;
    ctx.remove_local_tmp();
}

/// TOFU accept: an unknown host key plus a confirmation callback returning
/// `true` must connect and persist the key for the next connection.
#[tokio::test]
async fn tofu_accept_confirms_and_persists_key() {
    let Some(ctx) = test_ctx() else { return };

    let known_hosts = ctx.local_tmp.join("known_hosts_tofu_accept");
    let calls: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
    let opt = {
        let mut opt = ctx.options();
        opt.known_hosts_policy = KnownHostsPolicy::AcceptNew;
        opt.known_hosts_path = Some(known_hosts.to_string_lossy().into_owned());
        let calls = Arc::clone(&calls);
        opt.hostkey_confirm_cb = Some(Arc::new(
            move |host: &str, port: u16, _algo: &str, _fp: &str, _can_save: bool| {
                calls.lock().unwrap().push((host.to_string(), port));
                true
            },
        ));
        opt
    };

    let mut client = create_client(Protocol::Sftp).expect("create_client failed");
    client
        .connect(&opt)
        .await
        .unwrap_or_else(|e| panic!("TOFU accept connect should succeed: {e}"));
    {
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "confirmation callback should fire once");
        assert_eq!(calls[0], (ctx.host.clone(), ctx.port));
    }
    let saved = fs::metadata(&known_hosts).expect("known_hosts should be saved");
    assert!(
        saved.len() > 0,
        "known_hosts should contain the accepted key"
    );
    let _ = client.disconnect().await;

    // Second connect with the persisted key: no confirmation needed.
    let mut client = create_client(Protocol::Sftp).expect("create_client failed");
    client
        .connect(&opt)
        .await
        .unwrap_or_else(|e| panic!("second TOFU connect should succeed: {e}"));
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "callback must not fire for a known key"
    );
    let _ = client.disconnect().await;

    ctx.remove_local_tmp();
}

/// TOFU reject: a confirmation callback returning `false` must abort the
/// connection with `ClientError::HostKeyRejected`.
#[tokio::test]
async fn tofu_reject_returns_host_key_rejected() {
    let Some(ctx) = test_ctx() else { return };

    let known_hosts = ctx.local_tmp.join("known_hosts_tofu_reject");
    let opt = {
        let mut opt = ctx.options();
        opt.known_hosts_policy = KnownHostsPolicy::AcceptNew;
        opt.known_hosts_path = Some(known_hosts.to_string_lossy().into_owned());
        opt.hostkey_confirm_cb = Some(Arc::new(
            |_host: &str, _port: u16, _algo: &str, _fp: &str, _can_save: bool| false,
        ));
        opt
    };

    let mut client = create_client(Protocol::Sftp).expect("create_client failed");
    let result = client.connect(&opt).await;
    assert!(result.is_err(), "TOFU reject connect should fail");
    assert!(
        matches!(result.unwrap_err(), ClientError::HostKeyRejected(_)),
        "TOFU reject should surface HostKeyRejected"
    );
    assert!(
        !client.is_connected(),
        "client must not report connected after rejection"
    );

    ctx.remove_local_tmp();
}

/// Keyboard-interactive flow: the callback answers prompts with the
/// configured password. Some servers accept the password directly, so the
/// assertion is only that the connection succeeds.
#[tokio::test]
async fn keyboard_interactive_flow_connects() {
    let Some(ctx) = test_ctx() else { return };
    let Some(password) = ctx.password.clone() else {
        eprintln!("SKIP: FREESCP_IT_SFTP_PASS is not set");
        ctx.remove_local_tmp();
        return;
    };

    let opt = {
        let mut opt = ctx.options();
        opt.keyboard_interactive_cb = Some(Arc::new(
            move |_name: &str,
                  _instruction: &str,
                  prompts: &[String],
                  responses: &mut Vec<String>| {
                for _ in prompts {
                    responses.push(password.clone());
                }
                KbdIntPromptResult::Handled
            },
        ));
        opt
    };

    let mut client = create_client(Protocol::Sftp).expect("create_client failed");
    client
        .connect(&opt)
        .await
        .unwrap_or_else(|e| panic!("keyboard-interactive connect should succeed: {e}"));
    assert!(client.is_connected());
    let _ = client.disconnect().await;

    ctx.remove_local_tmp();
}

/// Cancelling mid-transfer through the `CancelCb` must abort the upload with
/// `ClientError::Cancelled`.
#[tokio::test]
async fn cancel_mid_transfer_aborts_upload() {
    let Some(ctx) = test_ctx() else { return };

    const SIZE: usize = 1024 * 1024; // 1 MiB
    let payload: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
    let local_src = ctx.local_tmp.join("cancel-src.bin");
    fs::write(&local_src, &payload).expect("could not write cancel source file");

    let suite = ctx.suite_dir();
    let remote = ctx.remote_path("cancel.bin");

    let last_done = Arc::new(AtomicU64::new(0));
    let cancel_requested = Arc::new(AtomicBool::new(false));
    let progress = {
        let last_done = Arc::clone(&last_done);
        Box::new(move |done: u64, _total: u64| {
            last_done.store(done, Ordering::SeqCst);
        })
    };
    let should_cancel = {
        let last_done = Arc::clone(&last_done);
        let cancel_requested = Arc::clone(&cancel_requested);
        Box::new(move || {
            if last_done.load(Ordering::SeqCst) > 65536 {
                cancel_requested.store(true, Ordering::SeqCst);
                true
            } else {
                false
            }
        })
    };

    let mut client = connect(&ctx).await;
    client
        .mkdir(&suite, 0o755)
        .await
        .expect("mkdir should succeed");

    let result = client
        .put(
            &local_src.to_string_lossy(),
            &remote,
            Some(progress),
            Some(should_cancel),
            false,
        )
        .await;

    assert!(
        cancel_requested.load(Ordering::SeqCst),
        "cancel callback should have requested cancellation mid-transfer"
    );
    assert!(
        matches!(result, Err(ClientError::Cancelled)),
        "cancelled transfer must fail with ClientError::Cancelled"
    );

    best_effort_remove(&mut client, &suite).await;
    let _ = client.disconnect().await;
    ctx.remove_local_tmp();
}

/// Jump-host lifecycle (unix): a roundtrip through the bastion must work and
/// reconnecting after disconnect must be clean.
///
/// The C++ suite additionally asserted that no helper `ssh -W` process leaks
/// after disconnect; the Rust backend uses a russh direct-tcpip channel
/// instead of a helper process, so the process-count check is replaced by a
/// post-disconnect reconnect roundtrip.
#[cfg(unix)]
#[tokio::test]
async fn jump_host_roundtrip_and_reconnect() {
    let Some(ctx) = test_ctx() else { return };
    if ctx.jump_host.is_none() {
        eprintln!("SKIP: FREESCP_IT_JUMP_HOST is not set");
        ctx.remove_local_tmp();
        return;
    }

    let suite = ctx.suite_dir();
    let remote = ctx.remote_path("payload.txt");
    let local_src = ctx.local_tmp.join("payload.txt");
    let local_dst = ctx.local_tmp.join("payload-check.txt");
    write_file(&local_src, PAYLOAD);

    let mut client = connect(&ctx).await;
    client
        .mkdir(&suite, 0o755)
        .await
        .expect("mkdir should succeed");
    client
        .put(&local_src.to_string_lossy(), &remote, None, None, false)
        .await
        .unwrap_or_else(|e| panic!("put through jump host should succeed: {e}"));
    client
        .get(&remote, &local_dst.to_string_lossy(), None, None, false)
        .await
        .unwrap_or_else(|e| panic!("get through jump host should succeed: {e}"));
    assert_eq!(
        read_file(&local_dst),
        PAYLOAD,
        "jump-host roundtrip content should match"
    );

    let _ = client.disconnect().await;
    assert!(
        !client.is_connected(),
        "disconnect should tear the session down"
    );

    // Lifecycle: a fresh session over the same bastion must work cleanly.
    let mut client = connect(&ctx).await;
    client
        .list(&suite)
        .await
        .unwrap_or_else(|e| panic!("reconnect list through jump host should succeed: {e}"));
    best_effort_remove(&mut client, &suite).await;
    let _ = client.disconnect().await;

    ctx.remove_local_tmp();
}
