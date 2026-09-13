//! russh client `Handler` for the SFTP backend.
//!
//! Ports the host-key verification block of `Libssh2SftpClient.cpp`
//! (`sshHandshakeAuth`): known_hosts `Strict` / `AcceptNew` (TOFU) / `Off`
//! policies, fingerprint presentation, `hostkey_confirm_cb` and
//! `hostkey_status_cb`.
//!
//! The actual known_hosts file parsing, matching and saving is delegated to
//! the shared `crate::known_hosts` module (workstream "sftp-helper"); this
//! handler only wires the user-interaction flow around it.
//!
//! # Type-identity requirement (cross-workstream)
//!
//! `crate::known_hosts` must use the *same* `PublicKey` type as this
//! handler: `russh::keys::PublicKey` (russh 0.63 re-exports `ssh-key`
//! `0.7.0-rc.11`; the workspace declares no separate `russh-keys` crate).
//! If it imports the standalone `russh_keys` crate instead, the key types
//! are nominally different and calls to `verify_host` / `save_host` /
//! `fingerprint_sha256` / `hostkey_bits` will not type-check.
//!
//! # russh semantics differ from libssh2 here
//!
//! * `Handler::check_server_key` receives `&PublicKeyOrCertificate` (russh
//!   0.63, which supports OpenSSH host certificates). The C++ client only
//!   dealt with plain keys, so we extract `PublicKeyOrCertificate::public_key()`
//!   and verify that (certificate keys are compared by their embedded
//!   public key).
//! * Returning `Ok(true)` accepts the key; `Ok(false)` rejects it with a
//!   generic message; `Err(SftpHandlerError::HostKeyRejected(msg))` rejects
//!   it with *our* message, which `connect_stream` propagates verbatim and
//!   `sftp.rs` maps to `ClientError::HostKeyRejected`.
//! * The handler runs during key exchange, i.e. before authentication —
//!   matching libssh2's ordering.
//! * Keyboard-interactive is NOT handler-driven in russh 0.63: the
//!   `authenticate_keyboard_interactive_start` / `_respond` methods on
//!   `Handle` expose the prompt/response loop directly (see `sftp.rs`).

use std::path::PathBuf;

use russh::keys::{Algorithm, EcdsaCurve, PublicKey, PublicKeyOrCertificate};
use tracing::{debug, info};

use crate::known_hosts::{
    default_known_hosts_path, fingerprint_sha256, hostkey_bits, load_known_hosts,
    load_known_hosts_strict, save_host, verify_host, KnownHostVerdict,
};
use crate::types::{KnownHostsPolicy, SessionOptions};

/// Error type of [`SftpHandler`]. `russh::client::Handler::Error` must
/// implement `From<russh::Error>`; the `HostKeyRejected` variant carries the
/// reason shown to the user.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SftpHandlerError {
    /// Host key was not accepted under the configured known_hosts policy.
    #[error("{0}")]
    HostKeyRejected(String),
    /// Transparent wrapper so russh transport errors can flow through the
    /// handler error type.
    #[error(transparent)]
    Russh(#[from] russh::Error),
}

/// Client handler for the target SSH connection. Host-key policy and TOFU
/// callbacks come from the [`SessionOptions`] clone the client hands over in
/// `connect`.
pub(crate) struct SftpHandler {
    pub(crate) opts: SessionOptions,
}

impl SftpHandler {
    pub(crate) fn new(opts: SessionOptions) -> Self {
        Self { opts }
    }

    fn status_cb(&self, message: &str) {
        if let Some(cb) = &self.opts.hostkey_status_cb {
            cb(message);
        }
    }

    fn confirm(&self, alg: &str, fp: &str, can_save: bool) -> bool {
        match &self.opts.hostkey_confirm_cb {
            Some(cb) => cb(&self.opts.host, self.opts.port, alg, fp, can_save),
            None => false,
        }
    }
}

/// Resolve the known_hosts file path from options: explicit path if set,
/// otherwise `~/.ssh/known_hosts` (`default_known_hosts_path`).
fn resolved_known_hosts_path(opts: &SessionOptions) -> Option<PathBuf> {
    match opts.known_hosts_path.as_deref() {
        Some(p) if !p.is_empty() => Some(PathBuf::from(p)),
        _ => default_known_hosts_path(),
    }
}

/// SSH algorithm display name for the TOFU prompt. Matches the `algDisplay`
/// values of the C++ client: ssh-ed25519 / ssh-rsa / ecdsa-sha2-nistp{256,384,521}.
fn algorithm_name(key: &PublicKey) -> &'static str {
    match key.algorithm() {
        Algorithm::Ed25519 => "ssh-ed25519",
        Algorithm::Ecdsa { curve } => match curve {
            EcdsaCurve::NistP256 => "ecdsa-sha2-nistp256",
            EcdsaCurve::NistP384 => "ecdsa-sha2-nistp384",
            EcdsaCurve::NistP521 => "ecdsa-sha2-nistp521",
        },
        Algorithm::Rsa { .. } => "ssh-rsa",
        _ => "unknown",
    }
}

impl russh::client::Handler for SftpHandler {
    type Error = SftpHandlerError;

    /// Host-key verification: ports the known_hosts policy block of
    /// `sshHandshakeAuth`.
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = server_public_key.public_key();
        let opts = &self.opts;
        let policy = opts.known_hosts_policy;

        if policy == KnownHostsPolicy::Off {
            debug!(host = %opts.host, "known_hosts policy Off: accepting any host key");
            return Ok(true);
        }

        let kh_path = resolved_known_hosts_path(opts);

        // Strict requires a usable known_hosts file (C++: "known_hosts
        // unavailable or unreadable (strict policy)").
        let entries = match kh_path.as_deref() {
            None => {
                let msg = "known_hosts unavailable or unreadable (strict policy)".to_string();
                return Err(SftpHandlerError::HostKeyRejected(msg));
            }
            Some(path) if policy == KnownHostsPolicy::Strict => {
                if !path.exists() {
                    let msg = "known_hosts unavailable or unreadable (strict policy)".to_string();
                    return Err(SftpHandlerError::HostKeyRejected(msg));
                }
                match load_known_hosts_strict(path) {
                    Ok(e) => e,
                    Err(e) => {
                        let msg =
                            format!("known_hosts unavailable or unreadable (strict policy): {e}");
                        return Err(SftpHandlerError::HostKeyRejected(msg));
                    }
                }
            }
            Some(path) => match load_known_hosts(path) {
                Ok(e) => e,
                Err(e) => {
                    // AcceptNew with an unreadable file degrades to TOFU (the
                    // file is empty for all practical purposes).
                    self.status_cb(&format!("Could not read known_hosts: {e}"));
                    Vec::new()
                }
            },
        };

        let fingerprint = fingerprint_sha256(&key, opts.show_fp_hex)
            .unwrap_or_else(|_| "SHA256:<unavailable>".to_string());
        let alg_display = format!("{} ({}-bit)", algorithm_name(&key), hostkey_bits(&key));

        match verify_host(&entries, policy, &opts.host, opts.port, &key) {
            KnownHostVerdict::Accepted { line_no } => {
                debug!(host = %opts.host, port = opts.port, line_no, "known_hosts MATCH");
                Ok(true)
            }
            KnownHostVerdict::Mismatch => {
                let msg = match policy {
                    KnownHostsPolicy::Strict => "Host key does not match known_hosts".to_string(),
                    _ => "Host key does not match known_hosts (TOFU rejects changed keys)"
                        .to_string(),
                };
                self.status_cb(&msg);
                info!(host = %opts.host, "host key mismatch rejected");
                Err(SftpHandlerError::HostKeyRejected(msg))
            }
            KnownHostVerdict::Missing => {
                if policy == KnownHostsPolicy::Strict {
                    let msg = "Unknown host in known_hosts".to_string();
                    return Err(SftpHandlerError::HostKeyRejected(msg));
                }

                // AcceptNew / TOFU: confirm with the user, then persist.
                let can_save = kh_path.is_some();
                debug!(
                    host = %opts.host, port = opts.port, alg = %alg_display, fp = %fingerprint,
                    can_save, "TOFU: asking user to confirm unknown host key"
                );
                if !self.confirm(&alg_display, &fingerprint, can_save) {
                    let msg = "Unknown host: fingerprint not confirmed by user".to_string();
                    info!(host = %opts.host, "TOFU: user rejected unknown host key");
                    return Err(SftpHandlerError::HostKeyRejected(msg));
                }

                let Some(path) = kh_path.as_deref() else {
                    // One-time connection, like C++ when !can_save.
                    self.status_cb("Fingerprint cannot be saved: known_hosts path is not set");
                    return Ok(true);
                };

                if let Err(e) = save_host(
                    path,
                    &opts.host,
                    opts.port,
                    &key,
                    opts.known_hosts_hash_names,
                ) {
                    // Persist failed: ask again with can_save=false; reject
                    // unless the user explicitly accepts one-time.
                    self.status_cb(&format!("Could not save known_hosts: {e}"));
                    if !self.confirm(&alg_display, &fingerprint, false) {
                        let msg = "Could not save fingerprint in known_hosts".to_string();
                        return Err(SftpHandlerError::HostKeyRejected(msg));
                    }
                } else {
                    info!(host = %opts.host, port = opts.port, "TOFU: saved new host key");
                }
                Ok(true)
            }
        }
    }
}
