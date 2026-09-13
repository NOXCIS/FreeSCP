//! Transfer-integrity hashing (SHA-256) for FreeSCP.
//!
//! Rust port of the post-transfer verification inside
//! `core/src/libssh2/Libssh2SftpClient.cpp` (`get` / `put` final checksum and
//! resume-prefix checks). The C++ code hashed both sides of a transfer with
//! EVP-SHA256 and compared digests; here the remote digest is supplied by the
//! backend (which computes it over the remote file with the same streaming
//! 64 KiB algorithm), and this module verifies the local file against it.
//!
//! # Policy semantics
//!
//! Port of
//! [`TransferIntegrityPolicy`](crate::types::TransferIntegrityPolicy)
//! (`Off` / `Optional` / `Required`, from `SftpTypes.hpp`):
//!
//! | Policy | remote hash known | hash/size mismatch | verification impossible (no remote hash, malformed hash, unreadable local file) |
//! |---|---|---|---|
//! | `Off`      | ignored | ignored | ignored |
//! | `Optional` | verify | **fail** with `Err` | proceed with `Ok(NotVerified)` |
//! | `Required` | verify | **fail** with `Err` | **fail** with `Err` |
//!
//! `Ok(_)` always means "safe to proceed": either verified, skipped, or
//! unverifiable-but-allowed. `Err(_)` always means "abort the transfer" (or,
//! for the resume window checks in the backend, "restart from scratch" under
//! `Optional`).
//!
//! # Remote hash formats accepted by [`verify_integrity`]
//!
//! The `remote_sha256` parameter accepts the raw SHA-256 digest in any of the
//! following textual forms (case-insensitive where applicable):
//!
//! * 64 hex chars, e.g. `e3b0c44298fc...` (what [`file_sha256_hex`] returns)
//! * hex with `:` separators, e.g. `e3:b0:c4:...`
//! * OpenSSH presentation `SHA256:<base64>` with or without `=` padding,
//!   e.g. `SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU`
//!
//! An empty string is treated as "no hash available".
//!
//! # Blocking note
//!
//! [`file_sha256_hex`] and [`verify_integrity`] perform blocking file I/O and
//! are intended for blocking contexts (e.g. `tokio::task::spawn_blocking`) or
//! non-tokio code. [`file_sha256_hex_async`] / [`verify_integrity_async`] use
//! `tokio::fs` and do not block the executor, but they do hold the SHA-256
//! computation on the async task; use `spawn_blocking` for very large files
//! if executor latency matters.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::types::TransferIntegrityPolicy;

/// Streaming buffer size used by the hashing functions (same 64 KiB chunk as
/// the C++ implementation).
pub const SHA256_CHUNK_SIZE: usize = 64 * 1024;

/// Compute the SHA-256 digest of a local file, streaming with a 64 KiB
/// buffer. Returns lowercase hex (64 characters).
///
/// Blocking: intended for blocking contexts; see the module-level blocking
/// note.
pub fn file_sha256_hex(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    sha256_hex_from_reader(&mut file)
}

/// Stream `reader` through SHA-256 (64 KiB chunks) and return lowercase hex.
///
/// Useful for the resume-window checks ported from the C++
/// `hash_local_range` / `hash_remote_range` helpers: pass a local `File`
/// positioned at the window start (limited to the window length) or a
/// `Read` adapter over a remote (SFTP) file handle.
pub fn sha256_hex_from_reader(reader: &mut impl std::io::Read) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; SHA256_CHUNK_SIZE];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Async variant of [`file_sha256_hex`] using `tokio::fs`; identical output.
pub async fn file_sha256_hex_async(path: &Path) -> std::io::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    sha256_hex_from_async_reader(&mut file).await
}

/// Async variant of [`sha256_hex_from_reader`] for `tokio::io::AsyncRead`
/// sources (e.g. a `tokio::io::BufReader` over a russh-sftp file handle).
pub async fn sha256_hex_from_async_reader<R>(reader: &mut R) -> std::io::Result<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; SHA256_CHUNK_SIZE];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Outcome of a verification that is safe to continue with.
///
/// All `Err` results from [`verify_integrity`] / [`verify_integrity_async`]
/// mean "abort"; all `Ok` results mean "safe to proceed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityOutcome {
    /// Policy was `Off`: nothing was checked or hashed.
    Skipped,

    /// Local SHA-256 matched the remote hash (and the size matched when a
    /// remote size was supplied). `sha256_hex` is the verified digest
    /// (lowercase hex).
    Verified { sha256_hex: String },

    /// Verification could not be completed but the policy allows proceeding
    /// (`Optional`). `reason` explains why (e.g. remote hash not available,
    /// malformed remote hash, unreadable local file).
    NotVerified { reason: String },
}

/// Errors from transfer-integrity verification. Every variant means the
/// transfer must be aborted (`Required`/`Optional` fail on detected
/// mismatches; `Required` also fails when verification is impossible).
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    /// The local file could not be read (or stat'ed) while a `Required`
    /// policy demanded verification.
    #[error("could not read local file {path}: {source}")]
    LocalIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// `Required` policy but no remote SHA-256 hash was provided.
    #[error("integrity verification is required but no remote SHA-256 hash is available")]
    RemoteHashUnavailable,

    /// The supplied remote hash is not a recognizable SHA-256 representation
    /// (see the module docs for accepted formats).
    #[error("remote SHA-256 hash is malformed: {0:?}")]
    InvalidRemoteHash(String),

    /// Local and remote sizes differ (checked only when `remote_size` is
    /// `Some`). Treated as a detected mismatch under `Optional` and
    /// `Required` alike.
    #[error("size mismatch: local is {local} bytes, remote is {remote} bytes")]
    SizeMismatch { local: u64, remote: u64 },

    /// The SHA-256 digests differ (both lowercase hex).
    #[error("checksum mismatch: local={local}, remote={remote}")]
    ChecksumMismatch { local: String, remote: String },
}

/// Verify a local file against a remote SHA-256 hash and/or size.
///
/// # Parameters
///
/// * `local_path` — the fully downloaded / uploaded local file (the backend
///   should pass the final file, not a `.part`).
/// * `remote_sha256` — SHA-256 of the remote file as text; see the module
///   docs for accepted formats. `None` / empty = hash unavailable.
/// * `remote_size` — expected size in bytes; `None` disables the size check.
/// * `policy` — [`TransferIntegrityPolicy`]: `Off` skips everything.
///
/// # Semantics (exact port of the C++ Optional/Required behavior)
///
/// * `Off` → `Ok(Skipped)`, nothing is hashed.
/// * `remote_size = Some(s)` and the local size differs → `Err(SizeMismatch)`
///   under `Optional` and `Required`.
/// * Remote hash present and malformed → `Err(InvalidRemoteHash)` under
///   `Required`, `Ok(NotVerified)` under `Optional`.
/// * Remote hash absent → `Err(RemoteHashUnavailable)` under `Required`,
///   `Ok(NotVerified)` under `Optional`.
/// * Local file unreadable → `Err(LocalIo)` under `Required`,
///   `Ok(NotVerified)` under `Optional`.
/// * Digests differ → always `Err(ChecksumMismatch)` (C++: "Final integrity
///   check failed ... checksum mismatch").
/// * Digests equal → `Ok(Verified)`.
///
/// Blocking: see the module-level blocking note; prefer
/// [`verify_integrity_async`] on a tokio runtime.
pub fn verify_integrity(
    local_path: &Path,
    remote_sha256: Option<&str>,
    remote_size: Option<u64>,
    policy: TransferIntegrityPolicy,
) -> Result<IntegrityOutcome, IntegrityError> {
    if policy == TransferIntegrityPolicy::Off {
        return Ok(IntegrityOutcome::Skipped);
    }
    let local_size = std::fs::metadata(local_path).map(|metadata| metadata.len());
    let local_hex = file_sha256_hex(local_path);
    evaluate(
        local_path,
        local_size,
        local_hex,
        remote_sha256,
        remote_size,
        policy,
    )
}

/// Async variant of [`verify_integrity`] (uses [`file_sha256_hex_async`] and
/// `tokio::fs::metadata`); identical semantics.
pub async fn verify_integrity_async(
    local_path: &Path,
    remote_sha256: Option<&str>,
    remote_size: Option<u64>,
    policy: TransferIntegrityPolicy,
) -> Result<IntegrityOutcome, IntegrityError> {
    if policy == TransferIntegrityPolicy::Off {
        return Ok(IntegrityOutcome::Skipped);
    }
    let local_size = tokio::fs::metadata(local_path)
        .await
        .map(|metadata| metadata.len());
    let local_hex = file_sha256_hex_async(local_path).await;
    evaluate(
        local_path,
        local_size,
        local_hex,
        remote_sha256,
        remote_size,
        policy,
    )
}

/// Shared decision logic for the sync/async entry points. `local_size` /
/// `local_hex` are already-computed results so that policy-dependent error
/// handling stays in one place.
fn evaluate(
    local_path: &Path,
    local_size: std::io::Result<u64>,
    local_hex: std::io::Result<String>,
    remote_sha256: Option<&str>,
    remote_size: Option<u64>,
    policy: TransferIntegrityPolicy,
) -> Result<IntegrityOutcome, IntegrityError> {
    debug_assert_ne!(policy, TransferIntegrityPolicy::Off);

    let local_size = match local_size {
        Ok(size) => size,
        Err(e) => {
            return match policy {
                TransferIntegrityPolicy::Required => Err(IntegrityError::LocalIo {
                    path: local_path.to_path_buf(),
                    source: e,
                }),
                TransferIntegrityPolicy::Optional | TransferIntegrityPolicy::Off => {
                    Ok(IntegrityOutcome::NotVerified {
                        reason: format!("local file unreadable: {e}"),
                    })
                }
            }
        }
    };

    if let Some(remote) = remote_size {
        if remote != local_size {
            return Err(IntegrityError::SizeMismatch {
                local: local_size,
                remote,
            });
        }
    }

    let remote_hex = match remote_sha256 {
        None => None,
        Some(raw) if raw.trim().is_empty() => None,
        Some(raw) => match normalize_remote_sha256(raw) {
            Some(normalized) => Some(normalized),
            None => {
                return match policy {
                    TransferIntegrityPolicy::Required => {
                        Err(IntegrityError::InvalidRemoteHash(raw.to_string()))
                    }
                    TransferIntegrityPolicy::Optional | TransferIntegrityPolicy::Off => {
                        Ok(IntegrityOutcome::NotVerified {
                            reason: format!("remote SHA-256 hash is malformed: {raw:?}"),
                        })
                    }
                }
            }
        },
    };

    match remote_hex {
        Some(remote) => {
            let local = match local_hex {
                Ok(hex) => hex,
                Err(e) => {
                    return match policy {
                        TransferIntegrityPolicy::Required => Err(IntegrityError::LocalIo {
                            path: local_path.to_path_buf(),
                            source: e,
                        }),
                        TransferIntegrityPolicy::Optional | TransferIntegrityPolicy::Off => {
                            Ok(IntegrityOutcome::NotVerified {
                                reason: format!("local hash failed: {e}"),
                            })
                        }
                    }
                }
            };
            if local == remote {
                Ok(IntegrityOutcome::Verified { sha256_hex: local })
            } else {
                Err(IntegrityError::ChecksumMismatch { local, remote })
            }
        }
        None => match policy {
            TransferIntegrityPolicy::Required => Err(IntegrityError::RemoteHashUnavailable),
            TransferIntegrityPolicy::Optional | TransferIntegrityPolicy::Off => {
                Ok(IntegrityOutcome::NotVerified {
                    reason: "remote SHA-256 hash is not available".to_string(),
                })
            }
        },
    }
}

/// Normalize any accepted remote-hash representation to lowercase hex
/// (64 chars). Returns `None` for unrecognized input.
fn normalize_remote_sha256(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let without_prefix = trimmed
        .strip_prefix("SHA256:")
        .or_else(|| trimmed.strip_prefix("sha256:"))
        .unwrap_or(trimmed);

    // Hex, optionally with ':' separators.
    let compact: String = without_prefix
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect();
    if compact.len() == 64 && compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(compact.to_ascii_lowercase());
    }

    // Base64 (standard alphabet), with or without padding.
    for engine in [&STANDARD, &STANDARD_NO_PAD] {
        if let Ok(bytes) = engine.decode(without_prefix.as_bytes()) {
            if bytes.len() == 32 {
                return Some(hex::encode(bytes));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("freescp_integrity_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn sha256_known_vectors() {
        let empty = temp_file("empty.bin");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(
            file_sha256_hex(&empty).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let abc = temp_file("abc.bin");
        std::fs::write(&abc, b"abc").unwrap();
        assert_eq!(
            file_sha256_hex(&abc).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn normalize_accepts_all_documented_formats() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(normalize_remote_sha256(hex).as_deref(), Some(hex));

        let colon = "e3:b0:c4:42:98:fc:1c:14:9a:fb:f4:c8:99:6f:b9:24:27:ae:41:e4:64:9b:93:4c:a4:95:99:1b:78:52:b8:55";
        assert_eq!(normalize_remote_sha256(colon).as_deref(), Some(hex));

        let b64 = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
        assert_eq!(normalize_remote_sha256(b64).as_deref(), Some(hex));

        assert_eq!(normalize_remote_sha256("not-a-hash"), None);
    }

    #[test]
    fn verify_off_skips() {
        let path = temp_file("missing.bin");
        let outcome = verify_integrity(&path, None, None, TransferIntegrityPolicy::Off).unwrap();
        assert_eq!(outcome, IntegrityOutcome::Skipped);
    }

    #[test]
    fn verify_matching_hash() {
        let path = temp_file("data.bin");
        std::fs::write(&path, b"abc").unwrap();
        let remote = file_sha256_hex(&path).unwrap();

        let outcome = verify_integrity(
            &path,
            Some(&remote),
            Some(3),
            TransferIntegrityPolicy::Optional,
        )
        .unwrap();
        assert_eq!(
            outcome,
            IntegrityOutcome::Verified {
                sha256_hex: remote.clone()
            }
        );

        let outcome = verify_integrity(
            &path,
            Some(&remote),
            None,
            TransferIntegrityPolicy::Required,
        )
        .unwrap();
        assert_eq!(outcome, IntegrityOutcome::Verified { sha256_hex: remote });
    }

    #[test]
    fn verify_mismatches_fail() {
        let path = temp_file("data2.bin");
        std::fs::write(&path, b"abc").unwrap();
        let wrong = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ae";

        // Checksum mismatch fails under Optional and Required.
        assert!(matches!(
            verify_integrity(&path, Some(wrong), None, TransferIntegrityPolicy::Optional),
            Err(IntegrityError::ChecksumMismatch { .. })
        ));
        assert!(matches!(
            verify_integrity(&path, Some(wrong), None, TransferIntegrityPolicy::Required),
            Err(IntegrityError::ChecksumMismatch { .. })
        ));

        // Size mismatch fails under Optional and Required.
        assert!(matches!(
            verify_integrity(&path, None, Some(4), TransferIntegrityPolicy::Optional),
            Err(IntegrityError::SizeMismatch {
                local: 3,
                remote: 4
            })
        ));
        assert!(matches!(
            verify_integrity(&path, None, Some(4), TransferIntegrityPolicy::Required),
            Err(IntegrityError::SizeMismatch {
                local: 3,
                remote: 4
            })
        ));
    }

    #[test]
    fn verify_unavailable_semantics() {
        let path = temp_file("data3.bin");
        std::fs::write(&path, b"abc").unwrap();

        // No remote hash: Optional proceeds unverified, Required fails.
        assert!(matches!(
            verify_integrity(&path, None, None, TransferIntegrityPolicy::Optional),
            Ok(IntegrityOutcome::NotVerified { .. })
        ));
        assert!(matches!(
            verify_integrity(&path, None, None, TransferIntegrityPolicy::Required),
            Err(IntegrityError::RemoteHashUnavailable)
        ));

        // Malformed remote hash: same split.
        assert!(matches!(
            verify_integrity(&path, Some("junk"), None, TransferIntegrityPolicy::Optional),
            Ok(IntegrityOutcome::NotVerified { .. })
        ));
        assert!(matches!(
            verify_integrity(&path, Some("junk"), None, TransferIntegrityPolicy::Required),
            Err(IntegrityError::InvalidRemoteHash(_))
        ));

        // Missing local file: Optional proceeds unverified, Required fails.
        let missing = temp_file("does-not-exist.bin");
        let remote = file_sha256_hex(&path).unwrap();
        assert!(matches!(
            verify_integrity(
                &missing,
                Some(&remote),
                None,
                TransferIntegrityPolicy::Optional
            ),
            Ok(IntegrityOutcome::NotVerified { .. })
        ));
        assert!(matches!(
            verify_integrity(
                &missing,
                Some(&remote),
                None,
                TransferIntegrityPolicy::Required
            ),
            Err(IntegrityError::LocalIo { .. })
        ));
    }

    #[tokio::test]
    async fn async_matches_sync() {
        let path = temp_file("async.bin");
        std::fs::write(&path, b"async-data").unwrap();
        let sync = file_sha256_hex(&path).unwrap();
        let async_hex = file_sha256_hex_async(&path).await.unwrap();
        assert_eq!(sync, async_hex);

        let outcome = verify_integrity_async(
            &path,
            Some(&sync),
            Some(10),
            TransferIntegrityPolicy::Required,
        )
        .await
        .unwrap();
        assert_eq!(outcome, IntegrityOutcome::Verified { sha256_hex: sync });
    }
}
