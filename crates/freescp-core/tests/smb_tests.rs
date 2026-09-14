//! Unit tests for the SMB backend's pure helpers (path handling, FILETIME
//! conversion, error mapping) and the factory/metadata wiring. These do not
//! touch the network, so they always run. Lifecycle/transfer behavior is
//! covered by the env-gated `smb_integration.rs` suite.

use std::io;

use freescp_core::backends::smb::{
    filetime_to_epoch, is_dot_entry, map_smb_error, normalize_remote_path, plan_resume,
    split_share, ResumePlan,
};
use freescp_core::client_factory::create_client;
use freescp_core::{ClientError, Protocol};
use smb2::pack::FileTime;

// ---------------------------------------------------------------------------
// Path handling
// ---------------------------------------------------------------------------

#[test]
fn normalize_remote_path_basic() {
    assert_eq!(normalize_remote_path(""), "/");
    assert_eq!(normalize_remote_path("/"), "/");
    assert_eq!(normalize_remote_path("/Share"), "/Share");
    assert_eq!(normalize_remote_path("/Share/sub"), "/Share/sub");
    assert_eq!(normalize_remote_path("Share"), "/Share");
    assert_eq!(
        normalize_remote_path("Share/sub/file.txt"),
        "/Share/sub/file.txt"
    );
    assert_eq!(normalize_remote_path("/Share/"), "/Share/");
}

#[test]
fn split_share_splits_first_component() {
    assert_eq!(
        split_share("/Share/sub/dir").unwrap(),
        ("Share".to_string(), "sub/dir".to_string())
    );
    assert_eq!(
        split_share("/Share").unwrap(),
        ("Share".to_string(), "".to_string())
    );
    // Empty components are ignored, so a trailing slash still resolves to
    // the share root.
    assert_eq!(
        split_share("/Share/").unwrap(),
        ("Share".to_string(), "".to_string())
    );
    assert_eq!(
        split_share("/Share///").unwrap(),
        ("Share".to_string(), "".to_string())
    );
    assert_eq!(
        split_share("Share/relative").unwrap(),
        ("Share".to_string(), "relative".to_string())
    );
    assert_eq!(
        split_share("/Share/sub/file name.txt").unwrap(),
        ("Share".to_string(), "sub/file name.txt".to_string())
    );
}

#[test]
fn split_share_rejects_root_and_empty() {
    assert!(split_share("/").is_err());
    assert!(split_share("").is_err());
    assert!(split_share("///").is_err());
}

#[test]
fn dot_entries_are_recognized() {
    // SMB2 directory listings include these; recursive delete/overwrite must
    // skip them or it loops into the directory's own parent.
    assert!(is_dot_entry("."));
    assert!(is_dot_entry(".."));
    assert!(!is_dot_entry("..."));
    assert!(!is_dot_entry(".hidden"));
    assert!(!is_dot_entry("file.txt"));
    assert!(!is_dot_entry(""));
}

#[test]
fn split_share_preserves_subpath_slashes() {
    assert_eq!(
        split_share("/S/a//b///c").unwrap(),
        ("S".to_string(), "a/b/c".to_string())
    );
}

// ---------------------------------------------------------------------------
// Resume upload decisions
// ---------------------------------------------------------------------------

#[test]
fn resume_smaller_remote_starts_at_remote_size() {
    assert_eq!(plan_resume(10, 100).unwrap(), ResumePlan::FromOffset(10));
}

#[test]
fn resume_equal_remote_is_already_complete() {
    assert_eq!(plan_resume(100, 100).unwrap(), ResumePlan::Complete);
}

#[test]
fn resume_larger_remote_is_refused() {
    // Falling through would truncate a larger remote file, so this must be an
    // error rather than an offset.
    let err = plan_resume(101, 100).expect_err("larger remote must be refused");
    assert!(
        err.contains("larger"),
        "error should explain the size mismatch: {err}"
    );
}

#[test]
fn resume_empty_remote_starts_from_zero() {
    assert_eq!(plan_resume(0, 100).unwrap(), ResumePlan::FromOffset(0));
}

// ---------------------------------------------------------------------------
// FILETIME conversion
// ---------------------------------------------------------------------------

/// Windows epoch offset: 116_444_736_000_000_000 ticks of 100 ns between
/// 1601-01-01 and 1970-01-01.
const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;

#[test]
fn filetime_zero_is_epoch_zero() {
    assert_eq!(filetime_to_epoch(FileTime::ZERO), 0);
}

#[test]
fn filetime_pre_unix_epoch_clamps_to_zero() {
    assert_eq!(filetime_to_epoch(FileTime(EPOCH_DIFF_100NS - 1)), 0);
}

#[test]
fn filetime_unix_epoch_maps_to_zero_seconds() {
    assert_eq!(filetime_to_epoch(FileTime(EPOCH_DIFF_100NS)), 0);
}

#[test]
fn filetime_known_instant() {
    // 2024-01-01 00:00:00 UTC == Unix 1_704_067_200 (same constant the smb2
    // crate's own tests use).
    let raw = 1_704_067_200u64 * 10_000_000 + EPOCH_DIFF_100NS;
    assert_eq!(filetime_to_epoch(FileTime(raw)), 1_704_067_200);
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn protocol_error(status: smb2::types::status::NtStatus) -> smb2::Error {
    smb2::Error::Protocol {
        status,
        command: smb2::types::Command::Create,
    }
}

#[test]
fn map_io_error_passes_io_through() {
    let io = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
    match map_smb_error(smb2::Error::Io(io)) {
        ClientError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused),
        other => panic!("expected ClientError::Io, got {other:?}"),
    }
}

#[test]
fn map_auth_error_is_auth_failed() {
    match map_smb_error(smb2::Error::Auth {
        message: "logon failed".into(),
    }) {
        ClientError::AuthFailed(msg) => assert!(msg.contains("logon failed")),
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    // ACCESS_DENIED classifies as access-denied → AuthFailed as well.
    match map_smb_error(protocol_error(smb2::types::status::NtStatus::ACCESS_DENIED)) {
        ClientError::AuthFailed(_) => {}
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

#[test]
fn map_timeout_is_io_timeout() {
    match map_smb_error(smb2::Error::Timeout) {
        ClientError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
        other => panic!("expected Io(TimedOut), got {other:?}"),
    }
}

#[test]
fn map_disconnect_is_io_reset() {
    match map_smb_error(smb2::Error::Disconnected) {
        ClientError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
        other => panic!("expected Io(ConnectionReset), got {other:?}"),
    }
}

#[test]
fn map_not_found_is_operation_failed() {
    // The backend intercepts NotFound for `exists()`; a NotFound surfacing
    // anywhere else must still be a regular OperationFailed, not an Io error.
    match map_smb_error(protocol_error(
        smb2::types::status::NtStatus::OBJECT_NAME_NOT_FOUND,
    )) {
        ClientError::OperationFailed(_) => {}
        other => panic!("expected OperationFailed, got {other:?}"),
    }
}

#[test]
fn map_server_error_is_operation_failed() {
    match map_smb_error(protocol_error(smb2::types::status::NtStatus::DISK_FULL)) {
        ClientError::OperationFailed(msg) => assert!(msg.to_lowercase().contains("disk")),
        other => panic!("expected OperationFailed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Factory / metadata wiring
// ---------------------------------------------------------------------------

#[test]
fn factory_creates_smb_backend() {
    let client = create_client(Protocol::Smb).expect("factory did not create SMB backend");
    assert_eq!(client.protocol(), Protocol::Smb);
    assert!(!client.is_connected());
}

#[tokio::test]
async fn smb_client_rejects_connect_without_host() {
    let mut client = create_client(Protocol::Smb).expect("factory did not create SMB backend");
    let opt = freescp_core::SessionOptions {
        protocol: Protocol::Smb,
        host: String::new(),
        ..Default::default()
    };
    let err = client.connect(&opt).await.unwrap_err();
    assert!(
        matches!(err, ClientError::Other(ref m) if m.contains("Host is required")),
        "unexpected error: {err:?}"
    );
    assert!(!client.is_connected());
}

#[tokio::test]
async fn smb_client_rejects_jump_host_and_proxy() {
    let mut client = create_client(Protocol::Smb).expect("factory did not create SMB backend");
    let base = freescp_core::SessionOptions {
        protocol: Protocol::Smb,
        host: "smb.example.com".to_string(),
        ..Default::default()
    };
    let mut with_jump = base.clone();
    with_jump.jump_host = Some("bastion.example.com".to_string());
    assert!(matches!(
        client.connect(&with_jump).await,
        Err(ClientError::Unsupported(_))
    ));
    let mut with_proxy = base;
    with_proxy.proxy_type = freescp_core::ProxyType::Socks5;
    with_proxy.proxy_host = "proxy.example.com".to_string();
    with_proxy.proxy_port = 1080;
    assert!(matches!(
        client.connect(&with_proxy).await,
        Err(ClientError::Unsupported(_))
    ));
    assert!(!client.is_connected());
}

#[tokio::test]
async fn disconnected_client_errors_on_operations() {
    let mut client = create_client(Protocol::Smb).expect("factory did not create SMB backend");
    let err = client.list("/").await.unwrap_err();
    assert!(
        matches!(err, ClientError::Other(ref m) if m == "Not connected."),
        "unexpected error: {err:?}"
    );
}
