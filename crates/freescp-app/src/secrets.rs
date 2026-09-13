//! Secret storage for credentials: pure-Rust port of `ui/SecretStore.cpp`.
//!
//! - macOS: Keychain via `security-framework`, service "FreeSCP", with the
//!   accessibility attribute from `Security/macKeychainRestrictive` applied
//!   on both the update and the add path (the `keyring` macOS backend cannot
//!   set `kSecAttrAccessible`).
//! - Linux: Secret Service via `keyring` (sync-secret-service).
//! - Fallback: when the secure backend is unavailable at runtime, secrets may
//!   be stored *insecurely* in `config_dir()/freescp/secrets.toml` only if the
//!   user opted in — either with the `FREESCP_ENABLE_INSECURE_FALLBACK=1`
//!   environment variable or the `Security/enableInsecureSecretFallback`
//!   preference (the exact same opt-in as `SecretStore.cpp`).
//!
//! [`SecretError`] mirrors the C++ `SecretStore::PersistStatus` + detail
//! semantics: "stored" is `Ok(())`, "unavailable", "permission denied" and
//! "backend error (detail)" are the error variants with the same wording.

#[cfg(not(target_os = "macos"))]
use serde::{Deserialize, Serialize};
#[cfg(not(target_os = "macos"))]
use std::collections::BTreeMap;
use std::fmt;
#[cfg(not(target_os = "macos"))]
use std::path::PathBuf;

/// Keychain service / Secret Service application name (matches
/// `kServiceNameCF()` in SecretStore.cpp).
const KEYRING_SERVICE: &str = "FreeSCP";

/// Keychain service used by the OpenSCP-era builds. Entries found there are
/// migrated lazily on read (see [`migrate_legacy_secret`]); the legacy items
/// are left in place so reverting to OpenSCP keeps working.
const LEGACY_KEYRING_SERVICE: &str = "OpenSCP";

/// Env var enabling the insecure fallback. `SecretStore.cpp` reads the same
/// variable name; a value of exactly "1" enables it.
#[cfg(not(target_os = "macos"))]
const INSECURE_FALLBACK_ENV: &str = "FREESCP_ENABLE_INSECURE_FALLBACK";

/// Fallback storage file inside the FreeSCP config directory.
#[cfg(not(target_os = "macos"))]
const FALLBACK_FILE: &str = "secrets.toml";

/// Result of persisting/reading a secret, mirroring the C++
/// `SecretStore::PersistStatus` semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    /// The secure backend is not available on this platform/session
    /// (C++ "unavailable").
    Unavailable,
    /// The user or OS denied access to the secure backend
    /// (C++ "permission denied"). Note: `keyring` v3 rarely surfaces this
    /// directly; kept for parity with the C++ mapping.
    #[allow(dead_code)] // parity variant; keyring v3 reports such failures via BackendError
    PermissionDenied,
    /// Any other backend failure with a detail message
    /// (C++ "backend error (detail)").
    BackendError(String),
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::Unavailable => f.write_str("unavailable"),
            SecretError::PermissionDenied => f.write_str("permission denied"),
            SecretError::BackendError(detail) => {
                if detail.is_empty() {
                    f.write_str("backend error")
                } else {
                    write!(f, "backend error ({detail})")
                }
            }
        }
    }
}

impl std::error::Error for SecretError {}

/// Whether the insecure fallback is active. Always `false` on macOS (the
/// Keychain is always available), mirroring `SecretStore.cpp`.
pub fn insecure_fallback_active() -> bool {
    fallback_allowed()
}

#[cfg(target_os = "macos")]
fn fallback_allowed() -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
fn fallback_allowed() -> bool {
    if std::env::var(INSECURE_FALLBACK_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return true;
    }
    crate::settings::Preferences::load().enable_insecure_secret_fallback
}

/// Stores a secret under a logical key (e.g. "site-id:<uuid>:password").
/// Returns [`SecretError::Unavailable`] when the secure backend is missing
/// and the insecure fallback is disabled, mirroring the C++ "unavailable /
/// insecure fallback disabled by configuration" behavior.
pub fn set_secret(key: &str, value: &str) -> Result<(), SecretError> {
    if key.is_empty() {
        return Err(SecretError::BackendError("Secret key is empty".into()));
    }
    #[cfg(target_os = "macos")]
    {
        macos_keychain::set_secret(key, value)
    }
    #[cfg(not(target_os = "macos"))]
    {
        match keyring::Entry::new(KEYRING_SERVICE, key) {
            Ok(entry) => match entry.set_password(value) {
                Ok(()) => {
                    remove_fallback_entry(key);
                    Ok(())
                }
                Err(keyring::Error::NoStorageAccess(_)) => fallback_or_err(key, value),
                Err(e) => Err(SecretError::BackendError(e.to_string())),
            },
            Err(keyring::Error::NoStorageAccess(_)) => fallback_or_err(key, value),
            Err(e) => Err(SecretError::BackendError(e.to_string())),
        }
    }
}

/// Retrieves a secret if present. A missing entry yields `Ok(None)`; a
/// failing backend also yields `Ok(None)` (with a warning), mirroring
/// `SecretStore::getSecret` which returns `std::nullopt` on any failure.
///
/// When the key is absent from the current service but exists under the
/// legacy OpenSCP one, it is copied over (lazy migration) and returned.
pub fn get_secret(key: &str) -> Result<Option<String>, SecretError> {
    if key.is_empty() {
        return Ok(None);
    }
    match get_secret_primary(key)? {
        Some(value) => Ok(Some(value)),
        None => migrate_legacy_secret(key),
    }
}

fn get_secret_primary(key: &str) -> Result<Option<String>, SecretError> {
    #[cfg(target_os = "macos")]
    return macos_keychain::get_secret(key);
    #[cfg(not(target_os = "macos"))]
    match keyring::Entry::new(KEYRING_SERVICE, key) {
        Ok(entry) => match entry.get_password() {
            Ok(password) => {
                // C++ returns nullopt for empty values as well.
                Ok(if password.is_empty() {
                    None
                } else {
                    Some(password)
                })
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => {
                tracing::warn!("Secure backend lookup failed for {key}: {e}");
                if fallback_allowed() {
                    fallback_get(key)
                } else {
                    Ok(None)
                }
            }
        },
        Err(e) => {
            tracing::warn!("Secure backend unavailable for {key}: {e}");
            if fallback_allowed() {
                fallback_get(key)
            } else {
                Ok(None)
            }
        }
    }
}

/// Reads `key` from the legacy OpenSCP service and, when found, writes it
/// through to the current storage before returning it (lazy migration).
fn migrate_legacy_secret(key: &str) -> Result<Option<String>, SecretError> {
    let Some(value) = legacy_get_secret(key)?.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    match set_secret(key, &value) {
        Ok(()) => {
            tracing::info!("Migrated secret {key} from the legacy OpenSCP keychain service")
        }
        Err(err) => tracing::warn!(
            "Copied secret {key} from the legacy OpenSCP service but could not re-store it: {err}"
        ),
    }
    Ok(Some(value))
}

/// Best-effort lookup in the legacy OpenSCP service; backend failures are
/// demoted to "missing" so a broken legacy backend never blocks connects.
fn legacy_get_secret(key: &str) -> Result<Option<String>, SecretError> {
    #[cfg(target_os = "macos")]
    return macos_keychain::get_secret_for_service(LEGACY_KEYRING_SERVICE, key);
    #[cfg(not(target_os = "macos"))]
    match keyring::Entry::new(LEGACY_KEYRING_SERVICE, key) {
        Ok(entry) => match entry.get_password() {
            Ok(password) if !password.is_empty() => Ok(Some(password)),
            Ok(_) => Ok(None),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => {
                tracing::warn!("Legacy OpenSCP keychain lookup failed for {key}: {e}");
                Ok(None)
            }
        },
        Err(e) => {
            tracing::warn!("Legacy OpenSCP keychain unavailable for {key}: {e}");
            Ok(None)
        }
    }
}

/// Removes a secret. Failures are logged but ignored, mirroring
/// `SecretStore::removeSecret` (which ignores backend errors).
pub fn remove_secret(key: &str) -> Result<(), SecretError> {
    if key.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        macos_keychain::remove_secret(key);
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        match keyring::Entry::new(KEYRING_SERVICE, key) {
            Ok(entry) => {
                if let Err(e) = entry.delete_credential() {
                    match e {
                        keyring::Error::NoEntry => {}
                        other => tracing::warn!("Could not delete secret {key}: {other}"),
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Secure backend unavailable while deleting {key}: {e}");
            }
        }
        remove_fallback_entry(key);
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
fn fallback_or_err(key: &str, value: &str) -> Result<(), SecretError> {
    if fallback_allowed() {
        tracing::warn!(
            "Secure backend unavailable; storing secret {key} in the insecure \
             fallback file (enabled via {INSECURE_FALLBACK_ENV}=1 or \
             Security/enableInsecureSecretFallback)"
        );
        fallback_store(key, value)
    } else {
        Err(SecretError::Unavailable)
    }
}

// ---------------------------------------------------------------------------
// Insecure fallback storage: config_dir()/freescp/secrets.toml
//
// Non-macOS only: `SecretStore.cpp` has no fallback branch on Apple platforms
// because the Keychain is always present.
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct FallbackFile {
    secrets: BTreeMap<String, String>,
}

#[cfg(not(target_os = "macos"))]
fn fallback_path() -> PathBuf {
    crate::settings::config_dir().join(FALLBACK_FILE)
}

#[cfg(not(target_os = "macos"))]
fn fallback_load() -> FallbackFile {
    match std::fs::read_to_string(fallback_path()) {
        Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
            tracing::warn!("Could not parse insecure secrets file: {e}; starting empty");
            FallbackFile::default()
        }),
        Err(_) => FallbackFile::default(),
    }
}

#[cfg(not(target_os = "macos"))]
fn fallback_store(key: &str, value: &str) -> Result<(), SecretError> {
    let mut file = fallback_load();
    file.secrets.insert(key.to_string(), value.to_string());
    fallback_save(&file)
}

#[cfg(not(target_os = "macos"))]
fn fallback_get(key: &str) -> Result<Option<String>, SecretError> {
    let file = fallback_load();
    Ok(file.secrets.get(key).filter(|v| !v.is_empty()).cloned())
}

#[cfg(not(target_os = "macos"))]
fn remove_fallback_entry(key: &str) {
    let mut file = fallback_load();
    if file.secrets.remove(key).is_none() {
        return;
    }
    if let Err(e) = fallback_save(&file) {
        tracing::warn!("Could not update insecure secrets file: {e}");
    }
}

#[cfg(not(target_os = "macos"))]
fn fallback_save(file: &FallbackFile) -> Result<(), SecretError> {
    let dir = crate::settings::config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| {
        SecretError::BackendError(format!(
            "Could not create config directory {}: {e}",
            dir.display()
        ))
    })?;
    let text = toml::to_string(file)
        .map_err(|e| SecretError::BackendError(format!("Could not serialize secrets: {e}")))?;
    let path = fallback_path();
    std::fs::write(&path, text).map_err(|e| {
        SecretError::BackendError(format!(
            "Could not persist insecure secret fallback {}: {e}",
            path.display()
        ))
    })?;
    // Defense in depth: the file holds plaintext secrets, so keep it private
    // like QSettings would (best-effort; not all platforms support modes).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// macOS Keychain (port of the Apple branch of SecretStore.cpp)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos_keychain {
    //! Raw Security.framework/CoreFoundation calls for the write path.
    //!
    //! `security-framework` 3.7 cannot express what `SecretStore.cpp` does:
    //! `PasswordOptions` only exposes `kSecAttrAccessControl` (not
    //! `kSecAttrAccessible`), and its set path adds first and only then updates
    //! with the password, so it can never rewrite the accessibility attribute
    //! of an existing item (`passwords.rs::set_password_internal`). The C++
    //! code updates first and creates on `errSecItemNotFound`, passing
    //! `kSecAttrAccessible` on both paths, so the write path is ported with the
    //! same raw calls. Reads/deletes use the safe crate API because they only
    //! need the class/service/account query shape.

    use super::{SecretError, KEYRING_SERVICE};
    use std::ffi::c_void;
    use std::ptr;

    type CFIndex = isize;
    type CFHashCode = usize;
    type Boolean = u8;
    type OSStatus = i32;
    type CFAllocatorRef = *const c_void;
    type CFTypeRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFMutableDictionaryRef = *mut c_void;
    type CFDictionaryRef = *const c_void;

    /// `kCFStringEncodingUTF8` (CFString.h).
    const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    // OSStatus values from SecBase.h (not all are defined in
    // security-framework-sys).
    const ERR_SEC_SUCCESS: OSStatus = 0;
    const ERR_SEC_USER_CANCELED: OSStatus = -128;
    const ERR_SEC_NOT_AVAILABLE: OSStatus = -25291;
    const ERR_SEC_AUTH_FAILED: OSStatus = -25293;
    const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: OSStatus = -25308;

    type CFDictionaryRetainCallBack =
        extern "C" fn(allocator: CFAllocatorRef, value: *const c_void) -> *const c_void;
    type CFDictionaryReleaseCallBack =
        extern "C" fn(allocator: CFAllocatorRef, value: *const c_void);
    type CFDictionaryCopyDescriptionCallBack = extern "C" fn(value: *const c_void) -> CFStringRef;
    type CFDictionaryEqualCallBack =
        extern "C" fn(value1: *const c_void, value2: *const c_void) -> Boolean;
    type CFDictionaryHashCallBack = extern "C" fn(value: *const c_void) -> CFHashCode;

    /// Layout of the framework's `kCFTypeDictionaryKeyCallBacks` static; the
    /// struct is never constructed here, only pointed at.
    #[allow(dead_code)] // fields exist for layout; the framework fills them in
    #[repr(C)]
    struct CFDictionaryKeyCallBacks {
        version: CFIndex,
        retain: Option<CFDictionaryRetainCallBack>,
        release: Option<CFDictionaryReleaseCallBack>,
        copy_description: Option<CFDictionaryCopyDescriptionCallBack>,
        equal: Option<CFDictionaryEqualCallBack>,
        hash: Option<CFDictionaryHashCallBack>,
    }

    #[allow(dead_code)] // see CFDictionaryKeyCallBacks
    #[repr(C)]
    struct CFDictionaryValueCallBacks {
        version: CFIndex,
        retain: Option<CFDictionaryRetainCallBack>,
        release: Option<CFDictionaryReleaseCallBack>,
        copy_description: Option<CFDictionaryCopyDescriptionCallBack>,
        equal: Option<CFDictionaryEqualCallBack>,
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFAllocatorDefault: CFAllocatorRef;
        static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
        static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;

        fn CFDictionaryCreateMutable(
            allocator: CFAllocatorRef,
            capacity: CFIndex,
            key_callbacks: *const CFDictionaryKeyCallBacks,
            value_callbacks: *const CFDictionaryValueCallBacks,
        ) -> CFMutableDictionaryRef;
        fn CFDictionarySetValue(
            dict: CFMutableDictionaryRef,
            key: *const c_void,
            value: *const c_void,
        );
        fn CFStringCreateWithBytes(
            allocator: CFAllocatorRef,
            bytes: *const u8,
            num_bytes: CFIndex,
            encoding: u32,
            is_external_representation: Boolean,
        ) -> CFStringRef;
        fn CFDataCreate(
            allocator: CFAllocatorRef,
            bytes: *const u8,
            length: CFIndex,
        ) -> *mut c_void;
        fn CFRelease(cf: CFTypeRef);
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecClass: CFStringRef;
        static kSecClassGenericPassword: CFStringRef;
        static kSecAttrService: CFStringRef;
        static kSecAttrAccount: CFStringRef;
        static kSecValueData: CFStringRef;
        static kSecAttrAccessible: CFStringRef;
        static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
        static kSecAttrAccessibleAfterFirstUnlock: CFStringRef;

        fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemUpdate(query: CFDictionaryRef, attributes_to_update: CFDictionaryRef)
            -> OSStatus;
    }

    /// Port of `mapApplePersistStatus` (SecretStore.cpp:29-45).
    pub(super) fn map_status(status: OSStatus) -> Result<(), SecretError> {
        match status {
            ERR_SEC_SUCCESS => Ok(()),
            ERR_SEC_NOT_AVAILABLE => Err(SecretError::Unavailable),
            ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_USER_CANCELED => {
                Err(SecretError::PermissionDenied)
            }
            other => Err(SecretError::BackendError(format!(
                "Keychain OSStatus={other}"
            ))),
        }
    }

    /// Owning CoreFoundation reference, released on drop so the early error
    /// returns above cannot leak.
    struct CfRef(*mut c_void);

    impl CfRef {
        fn new(ptr: *mut c_void) -> Self {
            Self(ptr)
        }

        fn is_null(&self) -> bool {
            self.0.is_null()
        }

        fn raw(&self) -> CFTypeRef {
            self.0 as CFTypeRef
        }

        fn as_mut(&self) -> CFMutableDictionaryRef {
            self.0
        }
    }

    impl Drop for CfRef {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer comes from a CF*Create call (owned
                // reference) and is released exactly once.
                unsafe { CFRelease(self.0) }
            }
        }
    }

    fn cf_string(text: &str) -> CfRef {
        // SAFETY: `text` is readable for the call and the framework copies it.
        unsafe {
            CfRef::new(CFStringCreateWithBytes(
                kCFAllocatorDefault,
                text.as_ptr(),
                text.len() as CFIndex,
                CF_STRING_ENCODING_UTF8,
                0,
            ) as *mut c_void)
        }
    }

    fn cf_data(bytes: &[u8]) -> CfRef {
        // SAFETY: `bytes` is readable for the call and the framework copies it.
        unsafe {
            CfRef::new(CFDataCreate(
                kCFAllocatorDefault,
                bytes.as_ptr(),
                bytes.len() as CFIndex,
            ))
        }
    }

    fn new_dict() -> CfRef {
        // SAFETY: the callbacks statics are the framework's own type callbacks.
        unsafe {
            CfRef::new(CFDictionaryCreateMutable(
                kCFAllocatorDefault,
                0,
                ptr::addr_of!(kCFTypeDictionaryKeyCallBacks),
                ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
            ))
        }
    }

    pub(super) fn set_secret(key: &str, value: &str) -> Result<(), SecretError> {
        // Accessibility policy from `Security/macKeychainRestrictive`
        // (default: the less restrictive attribute, like the C++ code).
        let restrictive = crate::settings::Preferences::load().mac_keychain_restrictive;
        // SAFETY: every CoreFoundation object is created and released by the
        // `CfRef` guards below; the dictionaries retain their contents, so the
        // pointers handed to Security.framework stay valid for the calls.
        unsafe {
            let service = cf_string(KEYRING_SERVICE);
            let account = cf_string(key);
            let data = cf_data(value.as_bytes());
            if service.is_null() || account.is_null() || data.is_null() {
                return Err(SecretError::BackendError(
                    "Could not build Keychain entry".into(),
                ));
            }
            let accessible: CFTypeRef = if restrictive {
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            } else {
                kSecAttrAccessibleAfterFirstUnlock
            };

            let query = new_dict();
            if query.is_null() {
                return Err(SecretError::BackendError(
                    "Could not build Keychain entry".into(),
                ));
            }
            CFDictionarySetValue(query.as_mut(), kSecClass, kSecClassGenericPassword);
            CFDictionarySetValue(query.as_mut(), kSecAttrService, service.raw());
            CFDictionarySetValue(query.as_mut(), kSecAttrAccount, account.raw());

            let attrs = new_dict();
            if attrs.is_null() {
                return Err(SecretError::BackendError(
                    "Could not build Keychain entry".into(),
                ));
            }
            CFDictionarySetValue(attrs.as_mut(), kSecValueData, data.raw());
            CFDictionarySetValue(attrs.as_mut(), kSecAttrAccessible, accessible);

            // Update first, create on miss (same order as the C++ code).
            // Passing kSecAttrAccessible on both paths rewrites the
            // accessibility of existing items when the preference is flipped.
            let mut status = SecItemUpdate(query.raw(), attrs.raw());
            if status == ERR_SEC_ITEM_NOT_FOUND {
                CFDictionarySetValue(query.as_mut(), kSecValueData, data.raw());
                CFDictionarySetValue(query.as_mut(), kSecAttrAccessible, accessible);
                status = SecItemAdd(query.raw(), ptr::null_mut());
            }
            map_status(status)
        }
    }

    pub(super) fn get_secret(key: &str) -> Result<Option<String>, SecretError> {
        get_secret_for_service(KEYRING_SERVICE, key)
    }

    pub(super) fn get_secret_for_service(
        service: &str,
        key: &str,
    ) -> Result<Option<String>, SecretError> {
        use security_framework::passwords::{generic_password, PasswordOptions};
        match generic_password(PasswordOptions::new_generic_password(service, key)) {
            Ok(bytes) => {
                // C++ returns nullopt for empty values as well.
                if bytes.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
                }
            }
            Err(err) if err.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(err) => {
                // C++ returns nullopt on any failure, so the caller only sees
                // "no secret"; surface the reason in the log.
                tracing::warn!("Secure backend lookup failed for {key}: {err}");
                Ok(None)
            }
        }
    }

    pub(super) fn remove_secret(key: &str) {
        use security_framework::passwords::delete_generic_password;
        if let Err(err) = delete_generic_password(KEYRING_SERVICE, key) {
            if err.code() != ERR_SEC_ITEM_NOT_FOUND {
                tracing::warn!("Could not delete secret {key}: {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_mirrors_cpp_wording() {
        assert_eq!(SecretError::Unavailable.to_string(), "unavailable");
        assert_eq!(
            SecretError::PermissionDenied.to_string(),
            "permission denied"
        );
        assert_eq!(
            SecretError::BackendError(String::new()).to_string(),
            "backend error"
        );
        assert_eq!(
            SecretError::BackendError("Secret key is empty".into()).to_string(),
            "backend error (Secret key is empty)"
        );
    }

    #[test]
    fn empty_key_is_rejected() {
        assert_eq!(
            set_secret("", "value"),
            Err(SecretError::BackendError("Secret key is empty".into()))
        );
        assert_eq!(get_secret("").unwrap(), None);
        assert!(remove_secret("").is_ok());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn fallback_file_roundtrip() {
        let mut file = FallbackFile::default();
        file.secrets.insert("a".into(), "1".into());
        let text = toml::to_string(&file).unwrap();
        let parsed: FallbackFile = toml::from_str(&text).unwrap();
        assert_eq!(parsed.secrets.get("a").map(String::as_str), Some("1"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_status_mapping_mirrors_cpp() {
        use super::macos_keychain::map_status;
        assert_eq!(map_status(0), Ok(()));
        assert_eq!(map_status(-25291), Err(SecretError::Unavailable));
        assert_eq!(map_status(-25293), Err(SecretError::PermissionDenied));
        assert_eq!(map_status(-25308), Err(SecretError::PermissionDenied));
        assert_eq!(map_status(-128), Err(SecretError::PermissionDenied));
        assert_eq!(
            map_status(-25300),
            Err(SecretError::BackendError("Keychain OSStatus=-25300".into()))
        );
    }

    /// Manual smoke test against the real login keychain (writes an item and
    /// removes it again); ignored so unit-test runs never touch user secrets.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "touches the real login keychain"]
    fn macos_keychain_roundtrip_live() {
        let key = "freescp-selftest-roundtrip";
        set_secret(key, "s3cret").expect("store secret");
        assert_eq!(get_secret(key).unwrap().as_deref(), Some("s3cret"));
        remove_secret(key).expect("remove secret");
        assert_eq!(get_secret(key).unwrap(), None);
    }
}
