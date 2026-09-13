//! Integration tests for the pure-Rust SCP backend against a real SSH server
//! with SCP support.
//!
//! Rust port of `tests/libssh2_scp_integration_tests.cpp`. The test is skipped
//! (mirroring the C++ exit-code-77 skip) unless the required `FREESCP_IT_*`
//! env vars exist.
//!
//! Required: `FREESCP_IT_SCP_HOST`, `FREESCP_IT_SCP_USER` and one auth method
//! (`FREESCP_IT_SCP_PASS` or `FREESCP_IT_SCP_KEY`). Optional:
//! `FREESCP_IT_SCP_PORT`, `FREESCP_IT_SCP_KEY_PASSPHRASE`,
//! `FREESCP_IT_SCP_REMOTE_BASE`. Every `FREESCP_IT_SCP_*` variable also falls
//! back to the corresponding `FREESCP_IT_SFTP_*` variable, and the remote base
//! additionally falls back to `FREESCP_IT_REMOTE_BASE` (default `/tmp`).

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use freescp_core::client_factory::create_client;
use freescp_core::{KnownHostsPolicy, Protocol, SessionOptions};

/// Accumulates check failures, mirroring the C++ `TestContext`.
#[derive(Default)]
struct CheckCtx {
    failures: usize,
}

impl CheckCtx {
    fn check(&mut self, cond: bool, msg: &str) {
        if !cond {
            self.failures += 1;
            eprintln!("[FAIL] {msg}");
        }
    }
}

/// Returns a non-empty env var value, mirroring the C++ `envValue`.
fn env_value(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Primary env var with a fallback env var, mirroring the C++
/// `envValueWithFallback`.
fn env_value_with_fallback(primary: &str, fallback: &str) -> Option<String> {
    env_value(primary).or_else(|| env_value(fallback))
}

/// Parses a TCP port, mirroring the C++ `parsePort`: unset means the
/// fallback, and anything outside 1..=65535 (or unparsable) is invalid.
fn parse_port(raw: &Option<String>, fallback: u16) -> Option<u16> {
    match raw {
        None => Some(fallback),
        Some(s) => s
            .parse::<i64>()
            .ok()
            .filter(|n| (1..=65535).contains(n))
            .map(|n| n as u16),
    }
}

/// Unique per-process token for temp paths, mirroring the C++
/// `uniqueToken()` (steady-clock count) with an added per-process counter so
/// two calls in the same nanosecond still differ.
fn unique_token() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{nanos}_{n}")
}

/// Joins a remote base directory with a file name, mirroring the C++
/// `joinRemotePath`.
fn join_remote_path(base: &str, name: &str) -> String {
    if base.is_empty() {
        return format!("/{name}");
    }
    if base.ends_with('/') {
        return format!("{base}{name}");
    }
    format!("{base}/{name}")
}

#[tokio::test]
async fn scp_integration_flow() {
    let host = env_value_with_fallback("FREESCP_IT_SCP_HOST", "FREESCP_IT_SFTP_HOST");
    let user = env_value_with_fallback("FREESCP_IT_SCP_USER", "FREESCP_IT_SFTP_USER");
    let pass = env_value_with_fallback("FREESCP_IT_SCP_PASS", "FREESCP_IT_SFTP_PASS");
    let key_path = env_value_with_fallback("FREESCP_IT_SCP_KEY", "FREESCP_IT_SFTP_KEY");
    let key_passphrase = env_value_with_fallback(
        "FREESCP_IT_SCP_KEY_PASSPHRASE",
        "FREESCP_IT_SFTP_KEY_PASSPHRASE",
    );
    let remote_base = env_value("FREESCP_IT_SCP_REMOTE_BASE")
        .or_else(|| env_value("FREESCP_IT_REMOTE_BASE"))
        .unwrap_or_else(|| "/tmp".to_string());

    if host.is_none() || user.is_none() || (pass.is_none() && key_path.is_none()) {
        println!(
            "[SKIP] freescp_scp_integration_tests requires env vars: \
             FREESCP_IT_SCP_HOST, FREESCP_IT_SCP_USER and one auth method \
             (FREESCP_IT_SCP_PASS or FREESCP_IT_SCP_KEY). It also accepts \
             FREESCP_IT_SFTP_* fallbacks."
        );
        return;
    }

    if let Some(key) = &key_path {
        if !Path::new(key).exists() {
            eprintln!("[FAIL] SCP private key does not exist: {key}");
            panic!("SCP private key does not exist: {key}");
        }
    }

    let port_raw = env_value_with_fallback("FREESCP_IT_SCP_PORT", "FREESCP_IT_SFTP_PORT");
    let port = match parse_port(&port_raw, 22) {
        Some(p) => p,
        None => {
            eprintln!("[FAIL] SCP port is invalid");
            panic!("SCP port is invalid");
        }
    };

    let opt = SessionOptions {
        protocol: Protocol::Scp,
        host: host.expect("host checked above"),
        port,
        username: user.expect("user checked above"),
        known_hosts_policy: KnownHostsPolicy::Off,
        password: pass,
        private_key_path: key_path,
        private_key_passphrase: key_passphrase,
        ..SessionOptions::default()
    };

    let mut client = match create_client(Protocol::Scp) {
        Ok(c) => c,
        Err(e) => panic!("[FAIL] SCP client creation failed: {e}"),
    };
    if let Err(e) = client.connect(&opt).await {
        eprintln!("[FAIL] SCP connect failed: {e}");
        panic!("SCP connect failed: {e}");
    }

    let mut t = CheckCtx::default();

    t.check(
        client.protocol() == Protocol::Scp,
        "client should report SCP protocol",
    );
    let caps = client.capabilities();
    t.check(caps.implemented, "SCP should be marked implemented");
    t.check(
        caps.supports_file_transfers,
        "SCP should support file transfers",
    );
    t.check(!caps.supports_listing, "SCP should not support listing");
    t.check(!caps.supports_resume, "SCP should not support resume");

    let token = unique_token();
    let temp_dir = std::env::temp_dir().join(format!("freescp_scp_{token}"));
    let local_upload = temp_dir.join("upload.txt");
    let local_download = temp_dir.join("download.txt");
    std::fs::create_dir_all(&temp_dir).expect("temp dir should be creatable");

    let payload = format!("freescp scp integration payload {token}\nline two\n");
    t.check(
        std::fs::write(&local_upload, payload.as_bytes()).is_ok(),
        "should write local upload file",
    );

    let remote_path = join_remote_path(&remote_base, &format!("freescp_scp_it_{token}.txt"));

    let upload_progress_called = Arc::new(AtomicBool::new(false));
    let upload_flag = upload_progress_called.clone();
    let upload_progress = Box::new(move |_done: u64, _total: u64| {
        upload_flag.store(true, Ordering::SeqCst);
    });
    if let Err(e) = client
        .put(
            local_upload.to_str().expect("temp path is UTF-8"),
            &remote_path,
            Some(upload_progress),
            None,
            false,
        )
        .await
    {
        t.check(false, &format!("SCP upload should succeed: {e}"));
    }
    t.check(
        upload_progress_called.load(Ordering::SeqCst),
        "upload progress callback should be called",
    );

    let download_progress_called = Arc::new(AtomicBool::new(false));
    let download_flag = download_progress_called.clone();
    let download_progress = Box::new(move |_done: u64, _total: u64| {
        download_flag.store(true, Ordering::SeqCst);
    });
    if let Err(e) = client
        .get(
            &remote_path,
            local_download.to_str().expect("temp path is UTF-8"),
            Some(download_progress),
            None,
            false,
        )
        .await
    {
        t.check(false, &format!("SCP download should succeed: {e}"));
    }
    t.check(
        download_progress_called.load(Ordering::SeqCst),
        "download progress callback should be called",
    );

    match std::fs::read_to_string(&local_download) {
        Ok(downloaded) => t.check(
            downloaded == payload,
            "downloaded content should match uploaded",
        ),
        Err(_) => t.check(false, "downloaded file should be readable"),
    }

    match client.list(&remote_base).await {
        Ok(_) => t.check(false, "SCP listing should report unsupported"),
        Err(e) => t.check(
            !e.to_string().is_empty(),
            "SCP listing unsupported should set error message",
        ),
    }

    match client
        .put(
            local_upload.to_str().expect("temp path is UTF-8"),
            &remote_path,
            None,
            None,
            true,
        )
        .await
    {
        Ok(_) => t.check(false, "SCP upload resume should be rejected"),
        Err(e) => t.check(
            e.to_string().contains("resume"),
            "SCP upload resume error should mention resume",
        ),
    }

    match client
        .get(
            &remote_path,
            local_download.to_str().expect("temp path is UTF-8"),
            None,
            None,
            true,
        )
        .await
    {
        Ok(_) => t.check(false, "SCP download resume should be rejected"),
        Err(e) => t.check(
            e.to_string().contains("resume"),
            "SCP download resume error should mention resume",
        ),
    }

    let _ = client.disconnect().await;
    let _ = std::fs::remove_dir_all(&temp_dir);

    if t.failures != 0 {
        eprintln!(
            "[FAIL] freescp_scp_integration_tests failures={}",
            t.failures
        );
        panic!("freescp_scp_integration_tests failures={}", t.failures);
    }
    println!("[OK] freescp_scp_integration_tests");
}
