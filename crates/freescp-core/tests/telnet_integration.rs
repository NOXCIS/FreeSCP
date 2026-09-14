//! Integration tests for the telnet console transport, following the
//! `FREESCP_IT_*` contract (skip with `[SKIP]` when the environment does not
//! provide a server).
//!
//! Environment:
//! * `FREESCP_IT_TELNET_HOST` — server host (required);
//! * `FREESCP_IT_TELNET_PORT` — server port (default 23);
//! * `FREESCP_IT_TELNET_USER` / `FREESCP_IT_TELNET_PASS` — credentials for
//!   the auto-login test (both required for that test, which prints `[SKIP]`
//!   otherwise);
//! * `FREESCP_IT_TELNET_TLS` — `1` for telnet-over-TLS (default 0);
//! * `FREESCP_IT_TELNET_VERIFY_PEER` — `0` to disable TLS peer verification
//!   (default 1);
//! * `FREESCP_IT_TELNET_CA_CERT` — CA bundle for TLS verification;
//! * `FREESCP_IT_TELNET_EXPECT_LOGIN` — `1` when the server confirms a
//!   successful auto-login with a `welcome` message (default 0).
//!
//! The CI workflow provisions a tiny inline Python telnet server that
//! answers `login:`/`Password:` prompts and echoes input back.

use std::time::Duration;

use freescp_core::telnet::{connect, TelnetEvent};
use freescp_core::types::{Protocol, SessionOptions};

use tokio::sync::mpsc;

const IO_TIMEOUT: Duration = Duration::from_secs(30);

fn env_value(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

fn parse_bool(raw: Option<String>, fallback: bool) -> bool {
    match raw.as_deref() {
        None => fallback,
        Some("1" | "true" | "TRUE" | "yes" | "YES") => true,
        Some("0" | "false" | "FALSE" | "no" | "NO") => false,
        Some(_) => fallback,
    }
}

fn parse_port(raw: Option<String>, fallback: u16) -> u16 {
    match raw {
        None => fallback,
        Some(value) => {
            let parsed: i32 = value
                .parse()
                .unwrap_or_else(|_| panic!("[FAIL] telnet port env value is invalid: {value}"));
            assert!(
                (1..=65535).contains(&parsed),
                "[FAIL] telnet port env value out of range: {parsed}"
            );
            parsed as u16
        }
    }
}

struct TelnetTestConfig {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    tls: bool,
    verify_peer: bool,
    ca_cert: Option<String>,
    expect_login: bool,
}

fn telnet_test_config() -> Option<TelnetTestConfig> {
    let Some(host) = env_value("FREESCP_IT_TELNET_HOST") else {
        println!("[SKIP] freescp_telnet_integration requires FREESCP_IT_TELNET_HOST");
        return None;
    };
    let tls = parse_bool(env_value("FREESCP_IT_TELNET_TLS"), false);
    Some(TelnetTestConfig {
        host,
        port: parse_port(
            env_value("FREESCP_IT_TELNET_PORT"),
            if tls { 992 } else { 23 },
        ),
        username: env_value("FREESCP_IT_TELNET_USER"),
        password: env_value("FREESCP_IT_TELNET_PASS"),
        tls,
        verify_peer: parse_bool(env_value("FREESCP_IT_TELNET_VERIFY_PEER"), true),
        ca_cert: env_value("FREESCP_IT_TELNET_CA_CERT"),
        expect_login: parse_bool(env_value("FREESCP_IT_TELNET_EXPECT_LOGIN"), false),
    })
}

fn session_options(cfg: &TelnetTestConfig) -> SessionOptions {
    SessionOptions {
        protocol: Protocol::Telnet,
        host: cfg.host.clone(),
        port: cfg.port,
        username: cfg.username.clone().unwrap_or_default(),
        password: cfg.password.clone(),
        telnet_tls: cfg.tls,
        telnet_verify_peer: cfg.verify_peer,
        telnet_ca_cert_path: cfg.ca_cert.clone(),
        telnet_auto_login: cfg.username.is_some() && cfg.password.is_some(),
        telnet_terminal_type: "xterm-256color".to_string(),
        ..SessionOptions::default()
    }
}

/// Collects data events until `expected` is contained; returns everything
/// received. Fails on timeout or an `Error` event.
async fn collect_until(rx: &mut mpsc::UnboundedReceiver<TelnetEvent>, expected: &[u8]) -> Vec<u8> {
    let mut acc = Vec::new();
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    while !acc.windows(expected.len()).any(|w| w == expected) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            panic!("[FAIL] timed out waiting for {expected:?}; got {acc:?}");
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(TelnetEvent::Data(data))) => acc.extend_from_slice(&data),
            Ok(Some(TelnetEvent::Error(message))) => {
                panic!("[FAIL] telnet session error: {message}")
            }
            Ok(Some(TelnetEvent::Closed)) => panic!("[FAIL] telnet session closed early"),
            Ok(None) => panic!("[FAIL] telnet event channel closed"),
            Err(_) => panic!("[FAIL] timed out waiting for {expected:?}; got {acc:?}"),
        }
    }
    acc
}

/// Smoke test: connect (plain or TLS), receive the banner, send input and
/// resize without errors.
#[tokio::test]
async fn telnet_session_smoke() {
    let Some(cfg) = telnet_test_config() else {
        return;
    };
    let (session, mut events) = connect(&session_options(&cfg)).await.unwrap_or_else(|e| {
        panic!(
            "[FAIL] telnet connect to {}:{} failed: {e}",
            cfg.host, cfg.port
        )
    });
    // The banner arrives as data; a data event within the timeout proves the
    // transport works. `Closed` before any data means the banner path (or the
    // negotiation) never worked, so only a Data event passes.
    match tokio::time::timeout(IO_TIMEOUT, events.recv()).await {
        Ok(Some(TelnetEvent::Data(_))) => {}
        Ok(Some(TelnetEvent::Closed)) => {
            panic!("[FAIL] telnet session closed before sending any data")
        }
        Ok(Some(TelnetEvent::Error(message))) => {
            panic!("[FAIL] telnet session error: {message}")
        }
        Ok(None) => panic!("[FAIL] telnet event channel closed"),
        Err(_) => panic!("[FAIL] no banner received within {IO_TIMEOUT:?}"),
    }
    session.send(b"\r");
    session.resize(100, 30);
    session.close();
}

/// Auto-login: requires `FREESCP_IT_TELNET_USER` + `FREESCP_IT_TELNET_PASS`;
/// with `FREESCP_IT_TELNET_EXPECT_LOGIN=1` the server must answer the
/// password with a `welcome` message.
#[tokio::test]
async fn telnet_auto_login() {
    let Some(cfg) = telnet_test_config() else {
        return;
    };
    if cfg.username.is_none() || cfg.password.is_none() {
        println!(
            "[SKIP] telnet_auto_login requires FREESCP_IT_TELNET_USER and \
             FREESCP_IT_TELNET_PASS"
        );
        return;
    }
    let (session, mut events) = connect(&session_options(&cfg)).await.unwrap_or_else(|e| {
        panic!(
            "[FAIL] telnet connect to {}:{} failed: {e}",
            cfg.host, cfg.port
        )
    });
    let data = collect_until(&mut events, b"Password:").await;
    assert!(
        !data.is_empty(),
        "[FAIL] no data received before the password prompt"
    );
    if cfg.expect_login {
        let data = collect_until(&mut events, b"elcome").await;
        let lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
        assert!(
            lower.windows(7).any(|w| w == b"welcome"),
            "[FAIL] auto-login did not complete; received {data:?}"
        );
    }
    session.close();
}
