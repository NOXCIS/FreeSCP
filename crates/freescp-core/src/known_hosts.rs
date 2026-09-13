//! OpenSSH `known_hosts` file handling for FreeSCP.
//!
//! Rust port of the known_hosts logic in `core/src/libssh2/Libssh2SftpClient.cpp`
//! (host key verification, hashed-host lookup, atomic save/update) and of
//! `core/include/freescp/KnownHostsUtils.hpp` (`RemoveKnownHostEntry`).
//!
//! Files produced by this module interoperate with OpenSSH (`ssh`, `ssh-keygen`):
//!
//! * plain entries — `host[,host...] keytype base64(key)`
//! * hashed entries — `|1|base64(salt)|base64(HMAC_SHA1(salt, host)) keytype base64(key)`
//!   (OpenSSH hashed-host format; 20-byte salt, same as the C++ port)
//! * optional markers — `@cert-authority` / `@revoked`
//! * `#` comments and blank lines are preserved verbatim when the file is
//!   rewritten by [`save_host`] / [`remove_host`].
//!
//! Public host keys are parsed/serialized via `russh::keys` (bundled
//! `ssh-key` 0.7, OpenSSH key formats: RSA, ECDSA, Ed25519). Hashed-host
//! tokens are matched with a hand-rolled HMAC-SHA1 over `sha1::Sha1` —
//! identical output to OpenSSH.
//!
//! # Policy semantics
//!
//! Mirrors the C++ verification flow for
//! [`KnownHostsPolicy`](crate::types::KnownHostsPolicy):
//!
//! | Policy | key found & matches | key differs | host absent | file unreadable |
//! |---|---|---|---|---|
//! | `Strict`    | proceed | abort | abort | abort |
//! | `AcceptNew` | proceed | abort (TOFU rejects changed keys) | show fingerprint to user, then [`save_host`] | proceed (no file yet is fine) |
//! | `Off`       | proceed, file not consulted | proceed | proceed | proceed |
//!
//! # Suggested call sequence for the SFTP/SCP backend
//!
//! ```no_run
//! use freescp_core::known_hosts::{self, KnownHostVerdict};
//! use freescp_core::types::KnownHostsPolicy;
//!
//! # fn demo(server_key: &russh::keys::PublicKey) -> Result<(), known_hosts::KhError> {
//! let path = known_hosts::default_known_hosts_path().unwrap();
//!
//! // 1. Load. Ok(vec![]) means "file does not exist". Any other I/O error is
//! //    an Err; under Strict the connection must be aborted in both cases
//! //    ("known_hosts unavailable or unreadable (strict policy)").
//! let entries = known_hosts::load_known_hosts(&path)?;
//!
//! // 2. Verify the server key.
//! let verdict = known_hosts::verify_host(
//!     &entries, KnownHostsPolicy::AcceptNew, "example.com", 22, server_key,
//! );
//! match verdict {
//!     KnownHostVerdict::Accepted { .. } => { /* proceed */ }
//!     KnownHostVerdict::Mismatch => { /* abort: changed key (Strict and AcceptNew) */ }
//!     KnownHostVerdict::Missing => {
//!         // Strict: abort. AcceptNew: ask the user to confirm
//!         // known_hosts::fingerprint_sha256(server_key, false)? then:
//!         // known_hosts::save_host(&path, "example.com", 22, server_key, true)?;
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Backend notes
//!
//! * Strict policy additionally requires the file to exist: callers should
//!   check `!path.exists()` (or use [`load_known_hosts_strict`]) and abort
//!   with the same error message as the C++ code.
//! * `verify_host`/`check_host` ignore entries whose recorded key cannot be
//!   parsed as a public key (e.g. `@cert-authority` lines, which this module
//!   does not verify); such entries are treated as if the host was absent and
//!   are preserved byte-for-byte on rewrite.
//! * Saving a changed key is intentionally not provided: `AcceptNew` rejects
//!   changed keys; the user deletes the stale entry via the UI, which should
//!   call [`remove_host`].

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::RngCore;
use russh::keys::ssh_key::{Algorithm, EcdsaCurve};
use russh::keys::PublicKey;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::types::KnownHostsPolicy;

/// Errors produced while loading, verifying against, or rewriting a
/// `known_hosts` file.
#[derive(Debug, thiserror::Error)]
pub enum KhError {
    /// The `known_hosts` path was empty.
    #[error("known_hosts path is empty")]
    EmptyPath,

    /// The hostname to look up / save / remove was empty.
    #[error("host name is empty")]
    EmptyHost,

    /// The file could not be read (path + underlying I/O error).
    ///
    /// Never produced for a missing file by [`load_known_hosts`] /
    /// [`save_host`] / [`remove_host`]; use [`load_known_hosts_strict`] if
    /// absence must be an error (Strict policy).
    #[error("could not read known_hosts file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The temporary file could not be created/written/flushed.
    #[error("could not write known_hosts file {path}: {source}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The temporary file could not be renamed over the destination.
    #[error("could not finalize known_hosts file {path}: {source}")]
    Finalize {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A host key could not be serialized (e.g. unsupported key algorithm).
    #[error("could not serialize host key: {0}")]
    KeyEncode(String),
}

/// One parsed, non-comment, non-empty line of a `known_hosts` file.
///
/// `raw_line` always holds the original line text (line endings stripped) so
/// that rewrites can preserve the file byte-for-byte apart from the changed
/// lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    /// 1-based line number in the file this entry came from.
    pub line_no: usize,

    /// Optional leading marker: `@cert-authority` or `@revoked`.
    pub marker: Option<String>,

    /// Host field tokens (split on `,`). Tokens are either plain hostnames /
    /// `[host]:port` strings or hashed-host tokens (`|1|salt|hash`).
    pub host_tokens: Vec<String>,

    /// SSH key algorithm name, e.g. `ssh-ed25519` or `ecdsa-sha2-nistp256`.
    pub key_type: String,

    /// Base64-encoded public key blob (the third field of the line).
    pub key_base64: String,

    /// The parsed public key, or `None` when the base64 blob could not be
    /// parsed (certificates, unknown algorithms, malformed lines). Entries
    /// with `key == None` are ignored by [`check_host`] / [`verify_host`].
    pub key: Option<PublicKey>,

    /// The complete original line (without line endings).
    pub raw_line: String,
}

impl HostEntry {
    /// True when this entry's host field matches `host:port`.
    ///
    /// Plain tokens are compared literally; hashed tokens (`|1|...`) are
    /// compared by recomputing HMAC-SHA1(salt, candidate) — see
    /// [`hash_hostname`]. For `port == 22` both `host` and `[host]:22` are
    /// accepted (parity with the C++ `RemoveKnownHostEntry`); for other ports
    /// only `[host]:port` is accepted.
    pub fn matches_host(&self, host: &str, port: u16) -> bool {
        let candidates = host_tokens_for(host, port);
        self.host_tokens.iter().any(|token| {
            candidates
                .iter()
                .any(|candidate| token == candidate || hashed_token_matches(token, candidate))
        })
    }
}

/// Result of comparing a server host key against the loaded entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownHostMatch {
    /// A matching host entry exists and the key material is identical.
    Match,

    /// At least one entry names this host, but its key differs from the
    /// server key. Always abort under `Strict` and `AcceptNew`.
    Mismatch,

    /// No entry names this host (unparseable-key entries do not count).
    Missing,
}

/// Policy-aware host key verification result, ready for backend flow control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownHostVerdict {
    /// Proceed. `line_no` is the 1-based line of the matching entry
    /// (`0` when the policy was `Off`).
    Accepted { line_no: usize },

    /// No entry for this host.
    /// * `Strict`: abort ("Unknown host in known_hosts").
    /// * `AcceptNew`: TOFU — show the user [`fingerprint_sha256`], and on
    ///   confirmation call [`save_host`] before proceeding.
    Missing,

    /// An entry exists but the server key changed. Abort under both `Strict`
    /// and `AcceptNew` ("Host key does not match known_hosts" /
    /// "TOFU rejects changed keys").
    Mismatch,
}

/// Load and parse a `known_hosts` file.
///
/// * File does not exist → `Ok(vec![])` (mirrors the C++ behavior where
///   `AcceptNew` proceeds with an empty file; under `Strict` the caller must
///   treat a non-existent file as fatal — see [`load_known_hosts_strict`]).
/// * Unreadable for any other reason → `Err(KhError::ReadFile)`.
/// * Malformed lines are skipped silently; lines whose key cannot be parsed
///   are returned with `HostEntry::key == None`.
pub fn load_known_hosts(path: &Path) -> Result<Vec<HostEntry>, KhError> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(KhError::ReadFile {
                path: path.to_path_buf(),
                source: e,
            })
        }
    };
    Ok(parse_known_hosts(&content))
}

/// Like [`load_known_hosts`], but a missing file is an error
/// (`KhError::ReadFile` with `ErrorKind::NotFound`).
///
/// This implements the `Strict` policy requirement "known_hosts unavailable
/// or unreadable (strict policy)": call it when the policy is `Strict`, or
/// call [`load_known_hosts`] and check for file existence yourself.
pub fn load_known_hosts_strict(path: &Path) -> Result<Vec<HostEntry>, KhError> {
    let content = std::fs::read_to_string(path).map_err(|e| KhError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(parse_known_hosts(&content))
}

/// Compare the server host key against pre-loaded entries.
///
/// Hosts match via [`HostEntry::matches_host`]; key comparison is performed
/// on the decoded key data (algorithm-insensitive to key comments). Entries
/// whose recorded key cannot be parsed are ignored entirely.
pub fn check_host(
    entries: &[HostEntry],
    host: &str,
    port: u16,
    server_key: &PublicKey,
) -> KnownHostMatch {
    check_host_inner(entries, host, port, server_key).0
}

/// Policy-aware host key verification.
///
/// * `Off` → always `KnownHostVerdict::Accepted { line_no: 0 }`.
/// * Otherwise: [`KnownHostMatch::Match`] → `Accepted` (with the line
///   number); `Mismatch` → `KnownHostVerdict::Mismatch`; `Missing` →
///   `KnownHostVerdict::Missing`.
///
/// The policy is *not* enforced here beyond `Off` — the backend decides what
/// to do with `Missing`/`Mismatch` (see the module-level table). This keeps
/// the user-interaction flow (TOFU dialog, save) in backend/UI control.
pub fn verify_host(
    entries: &[HostEntry],
    policy: KnownHostsPolicy,
    host: &str,
    port: u16,
    server_key: &PublicKey,
) -> KnownHostVerdict {
    if policy == KnownHostsPolicy::Off {
        return KnownHostVerdict::Accepted { line_no: 0 };
    }
    let (found, line_no) = check_host_inner(entries, host, port, server_key);
    match found {
        KnownHostMatch::Match => KnownHostVerdict::Accepted {
            line_no: line_no.unwrap_or(0),
        },
        KnownHostMatch::Mismatch => KnownHostVerdict::Mismatch,
        KnownHostMatch::Missing => KnownHostVerdict::Missing,
    }
}

/// Save or update the host key of `host:port` in `path`, preserving the rest
/// of the file.
///
/// # Behavior
///
/// * The stored host token is `host` for port 22, `[host]:port` otherwise.
/// * `hash_hostnames == true` → the token is stored as an OpenSSH hashed-host
///   token (`|1|...`, fresh random 20-byte salt per call); such entries can
///   never be deduplicated, so a new line is always appended.
/// * `hash_hostnames == false` → the first existing entry whose host field
///   contains the identical plain token is replaced in place (any key type);
///   otherwise a new line is appended.
/// * All other lines — comments, blanks, markers — are preserved verbatim.
/// * The file is written atomically (temp file + rename, fsync) with mode
///   `0600` on Unix; the parent directory is created if needed (mode `0700`
///   best effort on Unix).
pub fn save_host(
    path: &Path,
    host: &str,
    port: u16,
    server_key: &PublicKey,
    hash_hostnames: bool,
) -> Result<(), KhError> {
    if path.as_os_str().is_empty() {
        return Err(KhError::EmptyPath);
    }
    if host.is_empty() {
        return Err(KhError::EmptyHost);
    }

    let plain_token = host_token_for(host, port);
    let stored_token = if hash_hostnames {
        random_hashed_host(&plain_token)
    } else {
        plain_token.clone()
    };
    let new_line = format!("{} {}", stored_token, key_line(server_key)?);

    let mut lines: Vec<String> = match std::fs::read_to_string(path) {
        Ok(content) => content.lines().map(str::to_string).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            return Err(KhError::ReadFile {
                path: path.to_path_buf(),
                source: e,
            })
        }
    };

    if hash_hostnames {
        // A new random salt is used on every call, so there is nothing to
        // deduplicate against (same note as the C++ fallback writer).
        lines.push(new_line);
    } else {
        let mut replaced = false;
        for (idx, line) in lines.iter().enumerate() {
            if let Some(entry) = parse_line(idx + 1, line) {
                if entry.host_tokens.iter().any(|t| t == &plain_token) {
                    lines[idx] = new_line.clone();
                    replaced = true;
                    break;
                }
            }
        }
        if !replaced {
            lines.push(new_line);
        }
    }

    tracing::debug!(?path, ?host, port, "saving known_hosts entry");
    write_atomic(path, &join_lines(&lines))
}

/// Remove every entry for `host:port` from `path` and rewrite the file
/// atomically.
///
/// Port of `RemoveKnownHostEntry` from `KnownHostsUtils.hpp` / the C++
/// implementation:
///
/// * Plain tokens and hashed tokens (`|1|...`) are both matched
///   (HMAC-SHA1 recomputed against every candidate host token).
/// * `port == 22` also removes `[host]:22` entries; other ports remove
///   `[host]:port` entries.
/// * Returns `Ok(())` without touching the file when nothing matched or the
///   file does not exist.
/// * All remaining lines are preserved; the rewritten file ends with `\n`.
pub fn remove_host(path: &Path, host: &str, port: u16) -> Result<(), KhError> {
    if path.as_os_str().is_empty() {
        return Err(KhError::EmptyPath);
    }
    if host.is_empty() {
        return Err(KhError::EmptyHost);
    }

    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(KhError::ReadFile {
                path: path.to_path_buf(),
                source: e,
            })
        }
    };

    let candidates = host_tokens_for(host, port);
    let mut kept: Vec<String> = Vec::new();
    let mut removed_any = false;
    for (idx, line) in content.lines().enumerate() {
        let matched = parse_line(idx + 1, line)
            .map(|entry| {
                entry.host_tokens.iter().any(|token| {
                    candidates
                        .iter()
                        .any(|c| token == c || hashed_token_matches(token, c))
                })
            })
            .unwrap_or(false);
        if matched {
            removed_any = true;
        } else {
            kept.push(line.to_string());
        }
    }

    if !removed_any {
        return Ok(());
    }
    tracing::debug!(?path, ?host, port, "removing known_hosts entry");
    write_atomic(path, &join_lines(&kept))
}

/// Format the SHA-256 fingerprint of a host key in the OpenSSH presentation.
///
/// * `hex_colons == false` → `SHA256:<base64, '=' padding stripped>`
///   (the default `ssh` / `ssh-keygen -l -E sha256` format; also what the
///   C++ TOFU dialog showed by default).
/// * `hex_colons == true` → `SHA256:AA:BB:CC:...` (uppercase hex bytes,
///   colon-separated; matches the C++ `FREESCP_FP_HEX_ONLY` / `show_fp_hex`
///   presentation).
///
/// The digest is computed over the SSH wire encoding of the public key
/// (the same bytes OpenSSH hashes).
pub fn fingerprint_sha256(key: &PublicKey, hex_colons: bool) -> Result<String, KhError> {
    let blob = key
        .to_bytes()
        .map_err(|e| KhError::KeyEncode(e.to_string()))?;
    let digest = Sha256::digest(&blob);
    if hex_colons {
        let mut out = String::from("SHA256:");
        for (i, byte) in digest.iter().enumerate() {
            if i > 0 {
                out.push(':');
            }
            let _ = write!(out, "{byte:02X}");
        }
        Ok(out)
    } else {
        Ok(format!(
            "SHA256:{}",
            STANDARD.encode(digest).trim_end_matches('=')
        ))
    }
}

/// Approximate key size in bits, for display purposes only.
///
/// Mirrors the C++ TOFU dialog calculation: Ed25519 → 256, ECDSA → the curve
/// size (256/384/521), everything else (RSA, DSA, unknown) → the length of
/// the SSH key blob in bytes × 8.
pub fn hostkey_bits(key: &PublicKey) -> usize {
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::SkEd25519 => 256,
        Algorithm::SkEcdsaSha2NistP256 => 256,
        Algorithm::Ecdsa { curve } => match curve {
            EcdsaCurve::NistP256 => 256,
            EcdsaCurve::NistP384 => 384,
            EcdsaCurve::NistP521 => 521,
        },
        _ => key.to_bytes().map(|b| b.len() * 8).unwrap_or(0),
    }
}

/// Compute an OpenSSH hashed-host token for `host` using the given `salt`
/// (any length; OpenSSH and the C++ port use 20 bytes).
///
/// Output format: `|1|base64(salt)|base64(HMAC_SHA1(salt, host))` — standard
/// base64 with `=` padding, exactly what OpenSSH writes to `known_hosts`.
///
/// Deterministic for a fixed salt; use [`random_hashed_host`] when saving.
pub fn hash_hostname(host: &str, salt: &[u8]) -> String {
    let mac = hmac_sha1(salt, host.as_bytes());
    format!("|1|{}|{}", STANDARD.encode(salt), STANDARD.encode(mac))
}

/// Compute a hashed-host token for `host` with a fresh cryptographically
/// random 20-byte salt (OpenSSH convention).
pub fn random_hashed_host(host: &str) -> String {
    let mut salt = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut salt);
    hash_hostname(host, &salt)
}

/// Resolve the default `known_hosts` location from the environment:
/// `$HOME/.ssh/known_hosts` on Unix, `%USERPROFILE%\ssh\known_hosts` on
/// Windows. Returns `None` when the home directory cannot be determined.
pub fn default_known_hosts_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME");
    home.map(|home| {
        let mut path = PathBuf::from(home);
        if cfg!(windows) {
            path.push("ssh");
        } else {
            path.push(".ssh");
        }
        path.push("known_hosts");
        path
    })
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Candidate host tokens for (host, port), mirroring the C++ code: port 22
/// matches both `host` and the uncommon `[host]:22` notation; other ports
/// match only `[host]:port`.
fn host_tokens_for(host: &str, port: u16) -> Vec<String> {
    if port == 22 {
        vec![host.to_string(), format!("[{host}]:22")]
    } else {
        vec![format!("[{host}]:{port}")]
    }
}

fn host_token_for(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

fn check_host_inner(
    entries: &[HostEntry],
    host: &str,
    port: u16,
    server_key: &PublicKey,
) -> (KnownHostMatch, Option<usize>) {
    let mut saw_host = false;
    for entry in entries {
        if !entry.matches_host(host, port) {
            continue;
        }
        match &entry.key {
            Some(recorded) => {
                saw_host = true;
                if recorded.key_data() == server_key.key_data() {
                    return (KnownHostMatch::Match, Some(entry.line_no));
                }
            }
            // Unparseable recorded key (certificate, unknown algorithm):
            // invisible for matching purposes, like libssh2 skipping
            // unsupported lines.
            None => continue,
        }
    }
    if saw_host {
        (KnownHostMatch::Mismatch, None)
    } else {
        (KnownHostMatch::Missing, None)
    }
}

/// Parse every non-comment, non-blank line. Malformed lines (fewer than
/// host/keytype/key fields) are skipped.
fn parse_known_hosts(content: &str) -> Vec<HostEntry> {
    content
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| parse_line(idx + 1, line))
        .collect()
}

/// Parse a single line. Returns `None` for blank lines and comments.
fn parse_line(line_no: usize, raw: &str) -> Option<HostEntry> {
    let trimmed = raw.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let mut fields = raw.split_whitespace();
    let mut first = fields.next()?;
    let mut marker = None;
    if first.starts_with('@') {
        marker = Some(first.to_string());
        first = fields.next()?;
    }
    let key_type = fields.next()?.to_string();
    let key_base64 = fields.next()?.to_string();
    let key = russh::keys::parse_public_key_base64(&key_base64).ok();
    Some(HostEntry {
        line_no,
        marker,
        host_tokens: first.split(',').map(str::to_string).collect(),
        key_type,
        key_base64,
        key,
        raw_line: raw.to_string(),
    })
}

/// True when `token` is a hashed-host token (`|1|b64(salt)|b64(mac)`) whose
/// HMAC-SHA1 over `candidate` matches. Plain tokens always return `false`
/// (they are compared literally by the caller).
fn hashed_token_matches(token: &str, candidate: &str) -> bool {
    if !token.starts_with("|1|") {
        return false;
    }
    let rest = &token[3..];
    let Some(sep) = rest.find('|') else {
        return false;
    };
    let (salt_b64, mac_b64) = (&rest[..sep], &rest[sep + 1..]);
    if salt_b64.is_empty() || mac_b64.is_empty() {
        return false;
    }
    let Ok(salt) = STANDARD.decode(salt_b64) else {
        return false;
    };
    let Ok(expected) = STANDARD.decode(mac_b64) else {
        return false;
    };
    let actual = hmac_sha1(&salt, candidate.as_bytes());
    expected.len() == actual.len() && ct_eq(&expected, &actual)
}

/// Constant-time comparison (XOR accumulator).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// HMAC-SHA1 (RFC 2104) hand-rolled over `sha1::Sha1`; byte-identical output
/// to OpenSSL `HMAC(EVP_sha1(), ...)` / OpenSSH's hashed-host computation.
fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    let mut block_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        block_key[..20].copy_from_slice(&Sha1::digest(key));
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }

    let mut inner = Sha1::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(opad);
    outer.update(inner_digest);
    let mut out = [0u8; 20];
    out.copy_from_slice(&outer.finalize());
    out
}

/// Serialize a public key as the known_hosts `keytype base64(key)` pair.
fn key_line(key: &PublicKey) -> Result<String, KhError> {
    let openssh = key
        .to_openssh()
        .map_err(|e| KhError::KeyEncode(e.to_string()))?;
    let mut fields = openssh.split_whitespace();
    let algorithm = fields
        .next()
        .ok_or_else(|| KhError::KeyEncode("empty OpenSSH key encoding".into()))?;
    let base64 = fields
        .next()
        .ok_or_else(|| KhError::KeyEncode("missing key data in OpenSSH encoding".into()))?;
    Ok(format!("{algorithm} {base64}"))
}

fn join_lines(lines: &[String]) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Atomic file write: temp file in the same directory (mode `0600` on Unix),
/// fsync, rename over the destination, best-effort parent-dir fsync.
/// Creates the parent directory (`0700` best effort on Unix) when missing.
fn write_atomic(path: &Path, content: &str) -> Result<(), KhError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(parent).map_err(|e| KhError::WriteFile {
        path: parent.to_path_buf(),
        source: e,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    let base = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("known_hosts");
    let tmp_path = parent.join(format!(".{base}.tmp{:08x}", rand::random::<u32>()));

    let result = (|| -> Result<(), KhError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp_path).map_err(|e| KhError::WriteFile {
            path: tmp_path.clone(),
            source: e,
        })?;
        file.write_all(content.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| KhError::WriteFile {
                path: tmp_path.clone(),
                source: e,
            })?;
        drop(file);
        std::fs::rename(&tmp_path, path).map_err(|e| KhError::Finalize {
            path: path.to_path_buf(),
            source: e,
        })
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    #[cfg(unix)]
    if result.is_ok() {
        if let Ok(parent_dir) = std::fs::File::open(parent) {
            let _ = parent_dir.sync_all();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_BLOB: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
    const OTHER_ED25519_BLOB: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X";

    fn test_key() -> PublicKey {
        russh::keys::parse_public_key_base64(ED25519_BLOB).unwrap()
    }

    fn temp_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("freescp_kh_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn hmac_sha1_matches_rfc2202_vector() {
        // RFC 2202 test case 2: key = "key", data = "The quick brown fox..."
        let key = b"key";
        let data = b"The quick brown fox jumps over the lazy dog";
        let mac = hmac_sha1(key, data);
        assert_eq!(hex::encode(mac), "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
    }

    #[test]
    fn hashed_host_roundtrip() {
        let salt = [7u8; 20];
        let token = hash_hostname("example.com", &salt);
        assert!(token.starts_with("|1|"));
        assert!(hashed_token_matches(&token, "example.com"));
        assert!(!hashed_token_matches(&token, "other.example"));
        assert!(!hashed_token_matches("example.com", "example.com"));
    }

    #[test]
    fn parse_and_match_plain_and_hashed() {
        let path = temp_file("parse.kh");
        std::fs::write(
            &path,
            format!(
                "# comment\n\n\
                 example.com ssh-ed25519 {ED25519_BLOB}\n\
                 [example.com]:2222 ssh-ed25519 {OTHER_ED25519_BLOB}\n\
                 {} ssh-ed25519 {OTHER_ED25519_BLOB}\n",
                hash_hostname("hashed.example", &[9u8; 20]),
            ),
        )
        .unwrap();

        let entries = load_known_hosts(&path).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].line_no, 3);
        assert!(entries[0].marker.is_none());

        let key = test_key();
        let other = russh::keys::parse_public_key_base64(OTHER_ED25519_BLOB).unwrap();

        // Plain match on port 22.
        assert_eq!(
            check_host(&entries, "example.com", 22, &key),
            KnownHostMatch::Match
        );
        // Plain entry exists with a different key -> mismatch.
        assert_eq!(
            check_host(&entries, "example.com", 22, &other),
            KnownHostMatch::Mismatch
        );
        // Hashed entry matches through the HMAC.
        assert_eq!(
            check_host(&entries, "hashed.example", 22, &other),
            KnownHostMatch::Match
        );
        assert_eq!(
            check_host(&entries, "hashed.example", 22, &key),
            KnownHostMatch::Mismatch
        );
        // Non-default port: only [host]:port matches.
        assert_eq!(
            check_host(&entries, "example.com", 2222, &other),
            KnownHostMatch::Match
        );
        assert_eq!(
            check_host(&entries, "example.com", 2223, &other),
            KnownHostMatch::Missing
        );
    }

    #[test]
    fn save_and_remove_roundtrip() {
        let path = temp_file("roundtrip.kh");
        let key = test_key();
        let other = russh::keys::parse_public_key_base64(OTHER_ED25519_BLOB).unwrap();

        // Missing file + plain save.
        save_host(&path, "example.com", 22, &key, false).unwrap();
        let entries = load_known_hosts(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            check_host(&entries, "example.com", 22, &key),
            KnownHostMatch::Match
        );
        assert_eq!(
            check_host(&entries, "example.com", 22, &other),
            KnownHostMatch::Mismatch
        );

        // Plain save replaces the existing line instead of appending.
        save_host(&path, "example.com", 22, &other, false).unwrap();
        let entries = load_known_hosts(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            check_host(&entries, "example.com", 22, &other),
            KnownHostMatch::Match
        );

        // Hashed save always appends.
        save_host(&path, "example.com", 22, &key, true).unwrap();
        let entries = load_known_hosts(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[1].host_tokens[0].starts_with("|1|"));
        assert_eq!(
            check_host(&entries, "example.com", 22, &key),
            KnownHostMatch::Match
        );

        // Remove drops both plain and hashed entries for the host.
        remove_host(&path, "example.com", 22).unwrap();
        let entries = load_known_hosts(&path).unwrap();
        assert!(entries.is_empty());

        // Removing a non-present host leaves the file untouched.
        remove_host(&path, "example.com", 22).unwrap();
        assert!(load_known_hosts(&path).unwrap().is_empty());
    }

    #[test]
    fn non_default_port_uses_bracket_notation() {
        let path = temp_file("port.kh");
        let key = test_key();
        save_host(&path, "example.com", 2222, &key, false).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("[example.com]:2222 ssh-ed25519"));
        let entries = load_known_hosts(&path).unwrap();
        assert_eq!(
            check_host(&entries, "example.com", 2222, &key),
            KnownHostMatch::Match
        );
        remove_host(&path, "example.com", 2222).unwrap();
        assert!(load_known_hosts(&path).unwrap().is_empty());
    }

    #[test]
    fn fingerprint_formats() {
        let key = test_key();
        let b64 = fingerprint_sha256(&key, false).unwrap();
        assert!(b64.starts_with("SHA256:"));
        assert!(!b64.ends_with('='));
        let hex = fingerprint_sha256(&key, true).unwrap();
        assert!(hex.starts_with("SHA256:"));
        let body = hex.trim_start_matches("SHA256:");
        assert_eq!(body.len(), 32 * 3 - 1);
        assert!(body.split(':').all(|p| p.len() == 2));
        assert_eq!(hostkey_bits(&key), 256);
    }
}
