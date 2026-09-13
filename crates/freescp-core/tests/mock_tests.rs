//! Port of `tests/core_mock_tests.cpp` (mock and shared-type scenarios) as
//! offline Rust unit tests.
//!
//! Scenarios owned by sibling workstreams are intentionally not ported here:
//! - `test_client_factory` -> core-api (`client_factory.rs`)
//! - `test_curlftp_rejects_unsupported_proxy_type` -> FTP backend
//! - `test_libssh2_rejects_conflicting_proxy_and_jump` -> SFTP backend
//! - `test_libssh2_rejects_jump_on_windows` -> SFTP backend (Windows-only)
//! - `test_remove_known_hosts_entry_plain_and_hashed` -> known_hosts helper
//! - `test_remove_known_hosts_entry_non_default_port` -> known_hosts helper

use freescp_core as _;
use freescp_core::backends::mock::MockSftpClient;
use freescp_core::client::{ClientError, SftpClient};
use freescp_core::types::{
    capabilities_for_protocol, default_port_for_protocol, default_port_for_proxy_type,
    default_port_for_webdav_scheme, protocol_display_name, protocol_from_storage_name,
    protocol_storage_name, proxy_type_from_storage_value, scp_transfer_mode_from_storage_name,
    scp_transfer_mode_storage_name, webdav_scheme_from_storage_name, webdav_scheme_storage_name,
    FileInfo, KnownHostsPolicy, Protocol, ProxyType, ScpTransferMode, SessionOptions,
    TransferIntegrityPolicy, WebDavScheme,
};
use std::time::Duration;

fn valid_options() -> SessionOptions {
    SessionOptions {
        host: "example.test".to_string(),
        username: "alice".to_string(),
        ..Default::default()
    }
}

fn expect_operation_failed<T>(res: Result<T, ClientError>, expected: &str) {
    match res {
        Err(ClientError::OperationFailed(msg)) => assert_eq!(msg, expected),
        Err(other) => panic!("expected OperationFailed({:?}), got {:?}", expected, other),
        Ok(_) => panic!("expected OperationFailed({:?}), got Ok", expected),
    }
}

fn expect_mock_unsupported<T>(res: Result<T, ClientError>, op: &str) {
    let expected = format!("Mock no soporta {}", op);
    match res {
        Err(ClientError::Unsupported(msg)) => assert_eq!(msg, expected),
        Err(other) => panic!("expected Unsupported({:?}), got {:?}", expected, other),
        Ok(_) => panic!("expected Unsupported({:?}), got Ok", expected),
    }
}

fn assert_entry(entry: &FileInfo, name: &str, is_dir: bool, size: u64, has_size: bool) {
    assert_eq!(entry.name, name, "entry name");
    assert_eq!(entry.is_dir, is_dir, "entry is_dir for {}", name);
    assert_eq!(entry.size, size, "entry size for {}", name);
    assert_eq!(entry.has_size, has_size, "entry has_size for {}", name);
}

// --- Port of test_session_defaults ---

#[test]
fn session_defaults() {
    let o = SessionOptions::default();
    assert_eq!(
        o.protocol,
        Protocol::Sftp,
        "default protocol should be SFTP"
    );
    assert_eq!(
        o.scp_transfer_mode,
        ScpTransferMode::Auto,
        "default SCP transfer mode should be Auto"
    );
    assert_eq!(
        o.port,
        default_port_for_protocol(Protocol::Sftp),
        "default port should match the SFTP default"
    );
    assert_eq!(
        o.known_hosts_policy,
        KnownHostsPolicy::Strict,
        "default known_hosts_policy should be Strict"
    );
    assert!(
        o.known_hosts_hash_names,
        "known_hosts_hash_names should default to true"
    );
    assert!(!o.show_fp_hex, "show_fp_hex should default to false");
    assert_eq!(
        o.transfer_integrity_policy,
        TransferIntegrityPolicy::Optional,
        "transfer_integrity_policy should default to Optional"
    );
    assert!(o.password.is_none(), "password should be empty by default");
    assert!(
        o.private_key_path.is_none(),
        "private_key_path should be empty by default"
    );
    assert_eq!(
        o.webdav_scheme,
        WebDavScheme::Https,
        "default WebDAV scheme should be HTTPS"
    );
    assert!(
        o.webdav_verify_peer,
        "WebDAV TLS verification should default to enabled"
    );
}

// --- Port of test_protocol_helpers ---
//
// The C++ test guards FTP/FTPS/WebDAV capability assertions behind
// FREESCP_HAS_CURL_FTP / FREESCP_HAS_CURL_WEBDAV; the Rust rewrite builds
// every backend, so those branches are covered by the backend workstreams.

#[test]
fn protocol_helpers() {
    assert_eq!(
        protocol_from_storage_name("sftp"),
        Protocol::Sftp,
        "protocolFromStorageName should parse sftp"
    );
    assert_eq!(
        protocol_from_storage_name("SCP"),
        Protocol::Scp,
        "protocolFromStorageName should parse scp case-insensitively"
    );
    assert_eq!(
        protocol_from_storage_name("FTPS"),
        Protocol::Ftps,
        "protocolFromStorageName should parse ftps case-insensitively"
    );
    assert_eq!(
        protocol_from_storage_name("unknown"),
        Protocol::Sftp,
        "protocolFromStorageName should fallback to sftp"
    );
    assert_eq!(
        protocol_storage_name(Protocol::Scp),
        "scp",
        "protocolStorageName should serialize SCP"
    );
    assert_eq!(
        protocol_display_name(Protocol::Scp),
        "SCP",
        "protocolDisplayName should expose SCP label"
    );
    assert_eq!(
        scp_transfer_mode_from_storage_name("auto"),
        ScpTransferMode::Auto,
        "scpTransferModeFromStorageName should parse auto"
    );
    assert_eq!(
        scp_transfer_mode_from_storage_name("SCP-ONLY"),
        ScpTransferMode::ScpOnly,
        "scpTransferModeFromStorageName should parse scp-only"
    );
    assert_eq!(
        scp_transfer_mode_storage_name(ScpTransferMode::ScpOnly),
        "scp-only",
        "scpTransferModeStorageName should serialize scp-only"
    );
    // 1 == C++ static_cast<int>(ProxyType::Socks5), 2 == HttpConnect.
    assert_eq!(
        proxy_type_from_storage_value(1),
        ProxyType::Socks5,
        "proxyTypeFromStorageValue should parse SOCKS5"
    );
    assert_eq!(
        proxy_type_from_storage_value(2),
        ProxyType::HttpConnect,
        "proxyTypeFromStorageValue should parse HTTP CONNECT"
    );
    assert_eq!(
        proxy_type_from_storage_value(999),
        ProxyType::None,
        "proxyTypeFromStorageValue should fallback invalid values to None"
    );
    assert_eq!(
        default_port_for_proxy_type(ProxyType::Socks5),
        1080,
        "default SOCKS5 proxy port should be 1080"
    );
    assert_eq!(
        default_port_for_proxy_type(ProxyType::HttpConnect),
        8080,
        "default HTTP CONNECT proxy port should be 8080"
    );
    assert_eq!(
        webdav_scheme_from_storage_name("http"),
        WebDavScheme::Http,
        "webDavSchemeFromStorageName should parse http"
    );
    assert_eq!(
        webdav_scheme_from_storage_name("HTTPS"),
        WebDavScheme::Https,
        "webDavSchemeFromStorageName should parse https case-insensitively"
    );
    assert_eq!(
        webdav_scheme_storage_name(WebDavScheme::Http),
        "http",
        "webDavSchemeStorageName should serialize http"
    );
    assert_eq!(
        default_port_for_webdav_scheme(WebDavScheme::Http),
        80,
        "default HTTP WebDAV port should be 80"
    );
    assert_eq!(
        default_port_for_webdav_scheme(WebDavScheme::Https),
        443,
        "default HTTPS WebDAV port should be 443"
    );

    let sftp_caps = capabilities_for_protocol(Protocol::Sftp);
    assert!(
        sftp_caps.implemented,
        "SFTP capabilities should be implemented"
    );
    assert!(
        sftp_caps.supports_listing,
        "SFTP capabilities should include listing"
    );

    let scp_caps = capabilities_for_protocol(Protocol::Scp);
    assert!(
        scp_caps.implemented,
        "SCP capabilities should be implemented"
    );
    assert!(
        scp_caps.supports_file_transfers,
        "SCP capabilities should include file transfers"
    );
    assert!(
        !scp_caps.supports_listing,
        "SCP capabilities should not include listing"
    );
    assert!(
        !scp_caps.supports_resume,
        "SCP capabilities should not include resume"
    );
    assert!(
        !scp_caps.supports_permissions,
        "SCP capabilities should not include chmod/chown metadata edits"
    );
    assert!(
        scp_caps.supports_known_hosts,
        "SCP capabilities should include known_hosts verification"
    );
}

// --- Port of test_connect_validation ---

#[tokio::test]
async fn mock_connect_validation() {
    let mut c = MockSftpClient::new();

    let mut opt = SessionOptions {
        host: String::new(),
        username: "user".to_string(),
        ..Default::default()
    };
    expect_operation_failed(c.connect(&opt).await, "Host and username are required");
    assert!(!c.is_connected(), "connect should fail when host is empty");

    opt.host = "example.test".to_string();
    opt.username = String::new();
    expect_operation_failed(c.connect(&opt).await, "Host and username are required");
    assert!(
        !c.is_connected(),
        "connect should fail when username is empty"
    );

    opt.username = "alice".to_string();
    assert!(
        c.connect(&opt).await.is_ok(),
        "connect should succeed with host+username"
    );
    assert!(
        c.is_connected(),
        "client should report connected after successful connect"
    );
    assert_eq!(c.last_host(), Some("example.test"));
    assert_eq!(c.last_username(), Some("alice"));
}

// --- Port of test_disconnect_changes_state ---

#[tokio::test]
async fn mock_disconnect_changes_state() {
    let mut c = MockSftpClient::new();
    c.connect(&valid_options())
        .await
        .expect("connect should succeed before disconnect test");
    c.disconnect().await.expect("disconnect should succeed");
    assert!(
        !c.is_connected(),
        "disconnect should flip isConnected to false"
    );

    expect_operation_failed(c.list("/").await, "Not connected");
}

// --- Port of test_list_requires_connection ---

#[tokio::test]
async fn mock_list_requires_connection() {
    let mut c = MockSftpClient::new();
    expect_operation_failed(c.list("/").await, "Not connected");
}

// --- Port of test_list_sorting_and_known_path ---

#[tokio::test]
async fn mock_list_sorting_and_known_path() {
    let mut c = MockSftpClient::new();
    c.connect(&valid_options())
        .await
        .expect("connect should succeed before list test");

    let out = c
        .list("/home")
        .await
        .expect("list('/home') should succeed in mock FS");
    assert_eq!(out.len(), 3, "list('/home') should return 3 entries");
    assert_entry(out.first().expect("first entry"), "guest", true, 0, false);
    assert_entry(out.get(1).expect("second entry"), "luis", true, 0, false);
    assert_entry(
        out.get(2).expect("third entry"),
        "notes.md",
        false,
        2048,
        true,
    );
}

// --- Port of test_list_root_and_empty_path ---

#[tokio::test]
async fn mock_list_root_and_empty_path() {
    let mut c = MockSftpClient::new();
    c.connect(&valid_options())
        .await
        .expect("connect should succeed before root listing test");

    let root = c.list("/").await.expect("list('/') should succeed");
    assert_eq!(
        root.len(),
        3,
        "list('/') should return expected mock entries"
    );
    assert_entry(root.first().expect("root[0]"), "home", true, 0, false);
    assert_entry(root.get(1).expect("root[1]"), "var", true, 0, false);
    assert_entry(
        root.get(2).expect("root[2]"),
        "readme.txt",
        false,
        1280,
        true,
    );

    let empty_path = c.list("").await.expect("list('') should be treated as '/'");
    assert_eq!(
        empty_path.len(),
        root.len(),
        "list('') should match root entry count"
    );
}

// --- Port of test_missing_path_error ---

#[tokio::test]
async fn mock_missing_path_error() {
    let mut c = MockSftpClient::new();
    c.connect(&valid_options())
        .await
        .expect("connect should succeed before missing path test");

    match c.list("/does-not-exist").await {
        Err(ClientError::OperationFailed(msg)) => {
            assert!(
                msg.contains("Mock remote path not found"),
                "missing path should report non-empty error"
            );
        }
        other => panic!(
            "expected OperationFailed for missing path, got {:?}",
            other.map(|_| ())
        ),
    }
}

// --- Port of test_unsupported_methods_report_error ---

#[tokio::test]
async fn mock_unsupported_methods_report_error() {
    let mut c = MockSftpClient::new();

    expect_mock_unsupported(c.exists("/x").await, "exists");
    expect_mock_unsupported(c.stat("/x").await, "stat");
    expect_mock_unsupported(c.mkdir("/x", 0o755).await, "mkdir");
    expect_mock_unsupported(c.remove_file("/x").await, "remove");
    expect_mock_unsupported(c.remove_dir("/x").await, "rmdir");
    expect_mock_unsupported(c.rename("/a", "/b", true).await, "rename");
    expect_mock_unsupported(c.chmod("/x", 0o644).await, "chmod");
    expect_mock_unsupported(c.chown("/x", 1000, 1000).await, "chown");
    expect_mock_unsupported(c.get("/remote", "/local", None, None, false).await, "GET");
    expect_mock_unsupported(c.put("/local", "/remote", None, None, false).await, "PUT");
}

// --- Port of test_new_connection_like ---

#[tokio::test]
async fn mock_new_connection_like() {
    let c = MockSftpClient::new();
    let conn = c
        .new_connection_like(&valid_options())
        .await
        .expect("new_connection_like should return a client");
    assert!(
        conn.is_connected(),
        "new_connection_like client should be connected"
    );
}

// --- Port of test_new_connection_like_validation ---

#[tokio::test]
async fn mock_new_connection_like_validation() {
    let c = MockSftpClient::new();
    let bad = SessionOptions {
        host: String::new(),
        username: "alice".to_string(),
        ..Default::default()
    };
    expect_operation_failed(
        c.new_connection_like(&bad).await,
        "Host and username are required",
    );
}

// --- Port of test_set_times ---

#[tokio::test]
async fn mock_set_times() {
    let mut c = MockSftpClient::new();
    c.set_times("/home/luis/foto.jpg", 10, 20)
        .await
        .expect("set_times should be supported by mock client");
}

// --- Failure-injection knobs (additive over the C++ mock) ---

#[tokio::test]
async fn mock_decorator_forwards_to_delegate() {
    let inner = MockSftpClient::new();
    let mut outer = MockSftpClient::with_delegate(Box::new(inner));
    let opt = valid_options();

    outer
        .connect(&opt)
        .await
        .expect("decorated connect should succeed");
    assert!(
        outer.is_connected(),
        "decorated client should report connected"
    );
    assert_eq!(
        outer.protocol(),
        Protocol::Sftp,
        "decorated protocol forwards"
    );

    let out = outer
        .list("/home")
        .await
        .expect("decorated list should forward to delegate");
    assert_eq!(
        out.len(),
        3,
        "decorated list('/home') should return 3 entries"
    );

    let conn = outer
        .new_connection_like(&opt)
        .await
        .expect("decorated new_connection_like should forward");
    assert!(
        conn.is_connected(),
        "forwarded new connection should be connected"
    );

    outer
        .disconnect()
        .await
        .expect("decorated disconnect should succeed");
    assert!(
        !outer.is_connected(),
        "decorated client should report disconnected"
    );
}

#[tokio::test]
async fn mock_fail_connect_knob() {
    let mut c = MockSftpClient::new().with_failing_connect("injected connect failure");
    expect_operation_failed(
        c.connect(&valid_options()).await,
        "injected connect failure",
    );
    assert!(
        !c.is_connected(),
        "failed connect must not leave the mock connected"
    );

    c.fail_connect = None;
    assert!(
        c.connect(&valid_options()).await.is_ok(),
        "clearing fail_connect should restore normal connects"
    );
}

#[tokio::test]
async fn mock_forced_error_knob() {
    let mut c = MockSftpClient::new().with_forced_error("kaput");
    expect_operation_failed(c.connect(&valid_options()).await, "kaput");
    expect_operation_failed(c.list("/").await, "kaput");

    c.forced_error = None;
    c.connect(&valid_options())
        .await
        .expect("clearing forced_error should restore normal operations");
    assert!(c.list("/").await.is_ok());
}

#[tokio::test]
async fn mock_latency_knob_delays_operations() {
    let mut c = MockSftpClient::new().with_latency_ms(50);
    let start = tokio::time::Instant::now();
    c.connect(&valid_options())
        .await
        .expect("connect should succeed");
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(50),
        "latency knob should delay connect by ~50ms (took {:?})",
        elapsed
    );
    assert!(c.is_connected());
}

#[tokio::test]
async fn mock_mid_transfer_drop_knob() {
    let mut c =
        MockSftpClient::with_delegate(Box::new(MockSftpClient::new())).with_mid_transfer_drop();
    c.connect(&valid_options())
        .await
        .expect("connect should succeed");
    assert!(c.is_connected());

    match c.get("/remote.txt", "/local.txt", None, None, false).await {
        Err(ClientError::OperationFailed(msg)) => {
            assert!(
                msg.contains("mid-transfer"),
                "unexpected drop message: {}",
                msg
            );
        }
        other => panic!("expected simulated drop error, got {:?}", other.map(|_| ())),
    }
    assert!(
        !c.is_connected(),
        "drop_mid_transfer should leave the client disconnected"
    );

    c.connect(&valid_options())
        .await
        .expect("reconnect after simulated drop should succeed");
    assert!(c.is_connected());
    assert!(
        c.put("/local.txt", "/remote.txt", None, None, false)
            .await
            .is_err(),
        "put should also honor drop_mid_transfer"
    );
    assert!(!c.is_connected());
}

#[tokio::test]
async fn mock_force_disconnect_knob() {
    let mut c = MockSftpClient::new().with_forced_disconnect();
    c.connect(&valid_options())
        .await
        .expect("connect should succeed");
    assert!(
        c.is_connected(),
        "connecting with force_disconnect should not fail immediately"
    );

    assert!(c.list("/").await.is_ok(), "first operation should succeed");
    assert!(
        !c.is_connected(),
        "force_disconnect should disconnect after the first successful op"
    );

    expect_operation_failed(c.list("/").await, "Not connected");
}

#[tokio::test]
async fn mock_interrupt_sets_flag() {
    let c = MockSftpClient::new();
    assert!(!c.was_interrupted());
    c.interrupt();
    assert!(
        c.was_interrupted(),
        "interrupt should set the interrupted flag"
    );
}
