//! macOS Keychain status contract and the Touch ID passphrase item layout
//! (SESSION-003, the part that needs no biometric prompt).
//!
//! Go stores the biometric-gated passphrase as a generic-password item whose
//! service is `symvault-biometric:<vault dir>` and whose account is
//! `passphrase`; the value is the passphrase bytes themselves. It reports
//! failures as a macOS `OSStatus` mapped to a sentinel plus a diagnosis. This
//! module is the portable, pure half of that contract so every OS can verify it
//! against the Go-generated fixture `testdata/port/session/biometric.json`;
//! the Security-framework adapter lives in `symvault-platform`.

use std::fmt;

pub use zeroize::Zeroizing;

use crate::session::{Keyring, SessionError};

/// Service-name prefix of the Touch ID passphrase item (Go
/// `currentBiometricServicePrefix`).
pub const BIOMETRIC_SERVICE_PREFIX: &str = "symvault-biometric:";
/// Account of the Touch ID passphrase item (Go `biometricAccount`).
pub const BIOMETRIC_ACCOUNT: &str = "passphrase";

/// Go `biometricServiceName(vaultDir)`.
#[must_use]
pub fn biometric_service_name(vault: &str) -> String {
    format!("{BIOMETRIC_SERVICE_PREFIX}{vault}")
}

/// Go hands the passphrase to Keychain Services as a NUL-terminated C string
/// (`C.CString` on save, `C.GoString` on load), so anything after the first NUL
/// byte never reaches or leaves the keychain.
#[must_use]
pub fn truncate_at_nul(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .map_or(bytes, |end| &bytes[..end])
}

/// Value prefixes of the go-keyring wrapper that earlier Rust builds put around
/// the Touch ID passphrase (they routed it through the provider-wrapped keyring
/// codec; `go-keyring-base64:` is what they wrote, `go-keyring-encoded:` is the
/// codec's other form). Go never wrote either: its item holds the raw bytes.
const LEGACY_RUST_WRAPPER_PREFIXES: [&[u8]; 2] = [b"go-keyring-base64:", b"go-keyring-encoded:"];

/// Whether a stored Touch ID value is a wrapper item from an earlier Rust build
/// rather than a raw passphrase. Such a value is not decoded and not rewritten:
/// the caller reports it and leaves replacing it to the user (approved Rust-only
/// migration behavior, `docs/rust-port/contract-matrix.md` SESSION-003).
#[must_use]
pub fn is_legacy_rust_wrapped_value(stored: &[u8]) -> bool {
    LEGACY_RUST_WRAPPER_PREFIXES
        .iter()
        .any(|prefix| stored.starts_with(prefix))
}

pub const ERR_SEC_SUCCESS: i32 = 0;
pub const ERR_SEC_UNIMPLEMENTED: i32 = -4;
pub const ERR_SEC_PARAM: i32 = -50;
pub const ERR_SEC_ALLOCATE: i32 = -108;
pub const ERR_SEC_USER_CANCELED: i32 = -128;
pub const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
pub const ERR_SEC_READ_ONLY: i32 = -25292;
pub const ERR_SEC_AUTH_FAILED: i32 = -25293;
pub const ERR_SEC_NO_SUCH_KEYCHAIN: i32 = -25294;
pub const ERR_SEC_INVALID_KEYCHAIN: i32 = -25295;
pub const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
pub const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
pub const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
pub const ERR_SEC_DECODE: i32 = -26275;
pub const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

/// Go's sentinel errors that a keychain status can wrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeychainErrorKind {
    /// `ErrBiometricFailed`: the only kind that really is a biometric fault.
    BiometricFailed,
    DuplicateItem,
    ItemNotFound,
    NoSuchKeychain,
    Invalid,
    Locked,
    ReadOnly,
    InteractionNotAllowed,
    MissingEntitlement,
    Internal,
    UnexpectedStatus,
}

impl KeychainErrorKind {
    /// The Go identifier of the wrapped sentinel.
    #[must_use]
    pub const fn go_name(self) -> &'static str {
        match self {
            Self::BiometricFailed => "ErrBiometricFailed",
            Self::DuplicateItem => "ErrKeychainDuplicateItem",
            Self::ItemNotFound => "ErrKeychainItemNotFound",
            Self::NoSuchKeychain => "ErrKeychainNoSuchKeychain",
            Self::Invalid => "ErrKeychainInvalid",
            Self::Locked => "ErrKeychainLocked",
            Self::ReadOnly => "ErrKeychainReadOnly",
            Self::InteractionNotAllowed => "ErrKeychainInteractionNotAllowed",
            Self::MissingEntitlement => "ErrKeychainMissingEntitlement",
            Self::Internal => "ErrKeychainInternal",
            Self::UnexpectedStatus => "ErrKeychainUnexpectedStatus",
        }
    }

    /// The sentinel's own message (Go `Err*.Error()`).
    #[must_use]
    pub const fn sentinel_message(self) -> &'static str {
        match self {
            Self::BiometricFailed => "biometric authentication failed",
            Self::DuplicateItem => "keychain item already exists",
            Self::ItemNotFound => "keychain item not found",
            Self::NoSuchKeychain => "keychain not found",
            Self::Invalid => "keychain is invalid or corrupted",
            Self::Locked => "keychain is locked or unavailable",
            Self::ReadOnly => "keychain is read-only",
            Self::InteractionNotAllowed => "keychain access requires user interaction",
            Self::MissingEntitlement => "keychain access denied for this binary",
            Self::Internal => "keychain call failed",
            Self::UnexpectedStatus => "unexpected keychain error",
        }
    }
}

const DOCTOR_HINT: &str =
    "run `symvault doctor` and check the \"Session keyring roundtrip\" result";
const SEARCH_LIST_HINT: &str = "the login keychain may be missing from the keychain search list (`security list-keychains -d user`), so writes and lookups target different keychains — run `symvault doctor` and check the \"Session keyring roundtrip\" result";
const UNLOCK_HINT: &str = "unlock the login keychain with `security unlock-keychain` and re-run the command from a logged-in session";

struct Mapping {
    kind: KeychainErrorKind,
    detail: &'static str,
    hint: &'static str,
}

fn mapping(status: i32) -> Mapping {
    let (kind, detail, hint) = match status {
        ERR_SEC_DUPLICATE_ITEM => (
            KeychainErrorKind::DuplicateItem,
            "the existing item could not be replaced",
            SEARCH_LIST_HINT,
        ),
        ERR_SEC_ITEM_NOT_FOUND => (
            KeychainErrorKind::ItemNotFound,
            "no matching item is visible to this process",
            SEARCH_LIST_HINT,
        ),
        ERR_SEC_NO_SUCH_KEYCHAIN => (
            KeychainErrorKind::NoSuchKeychain,
            "the target keychain does not exist",
            SEARCH_LIST_HINT,
        ),
        ERR_SEC_INVALID_KEYCHAIN => (
            KeychainErrorKind::Invalid,
            "the target keychain could not be read",
            DOCTOR_HINT,
        ),
        ERR_SEC_NOT_AVAILABLE => (
            KeychainErrorKind::Locked,
            "no keychain is available to this process",
            UNLOCK_HINT,
        ),
        ERR_SEC_READ_ONLY => (
            KeychainErrorKind::ReadOnly,
            "the keychain does not accept writes",
            "unlock the login keychain with `security unlock-keychain` and check its permissions in Keychain Access",
        ),
        ERR_SEC_INTERACTION_NOT_ALLOWED => (
            KeychainErrorKind::InteractionNotAllowed,
            "the keychain is locked and this process cannot prompt",
            "unlock the login keychain with `security unlock-keychain` and re-run the command from a logged-in GUI session",
        ),
        ERR_SEC_MISSING_ENTITLEMENT => (
            KeychainErrorKind::MissingEntitlement,
            "the running binary lacks the entitlement or signature the keychain item requires",
            "use an official signed `symvault` build, or re-create the item with the binary you are running",
        ),
        ERR_SEC_AUTH_FAILED => (
            KeychainErrorKind::BiometricFailed,
            "the system rejected the authentication",
            "retry, or fall back to `symvault unlock` with your passphrase",
        ),
        ERR_SEC_USER_CANCELED => (
            KeychainErrorKind::BiometricFailed,
            "the authentication prompt was canceled",
            "retry and complete the Touch ID prompt",
        ),
        ERR_SEC_DECODE => (
            KeychainErrorKind::Invalid,
            "the stored item could not be decoded",
            "re-run `symvault auth set touchid` to store the passphrase again",
        ),
        ERR_SEC_PARAM => (
            KeychainErrorKind::Internal,
            "the keychain rejected the request parameters",
            "",
        ),
        ERR_SEC_ALLOCATE => (
            KeychainErrorKind::Internal,
            "the keychain could not allocate memory",
            "",
        ),
        ERR_SEC_UNIMPLEMENTED => (
            KeychainErrorKind::Internal,
            "the keychain operation is not implemented on this system",
            "",
        ),
        _ => (KeychainErrorKind::UnexpectedStatus, "", DOCTOR_HINT),
    };
    Mapping { kind, detail, hint }
}

/// A macOS Keychain failure, rendered exactly as Go's `keychainStatusError`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeychainStatusError {
    kind: KeychainErrorKind,
    status: i32,
    message: String,
}

impl KeychainStatusError {
    #[must_use]
    pub const fn kind(&self) -> KeychainErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn status(&self) -> i32 {
        self.status
    }
}

impl fmt::Display for KeychainStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for KeychainStatusError {}

/// Go `keychainStatusError`: `None` for `errSecSuccess`. Only statuses that
/// describe a failed biometric factor wrap `BiometricFailed`; everything else
/// names the real keychain cause.
#[must_use]
pub fn keychain_status_error(status: i32) -> Option<KeychainStatusError> {
    if status == ERR_SEC_SUCCESS {
        return None;
    }
    let Mapping { kind, detail, hint } = mapping(status);
    let mut message = kind.sentinel_message().to_owned();
    if !detail.is_empty() {
        message.push_str(": ");
        message.push_str(detail);
    }
    message.push_str(&format!(" (keychain status {status})"));
    if !hint.is_empty() {
        message.push_str("; ");
        message.push_str(hint);
    }
    Some(KeychainStatusError {
        kind,
        status,
        message,
    })
}

/// Storage of the Touch ID passphrase item. Go's operations, minus the
/// biometric prompt, which stays with [`crate::platform::TouchId`].
pub trait BiometricItemStore: Send + Sync {
    /// Whether the item exists, learned without returning its data (Go's
    /// pre-prompt `SecItemCopyMatching` probe). `Ok(false)` is `errSecItemNotFound`.
    ///
    /// # Errors
    /// Any other keychain status.
    fn exists(&self, vault: &str) -> Result<bool, KeychainStatusError>;

    /// Replaces the item with the raw passphrase bytes (cut at the first NUL).
    ///
    /// # Errors
    /// The keychain status of the failed call.
    fn save(&self, vault: &str, passphrase: &[u8]) -> Result<(), KeychainStatusError>;

    /// Reads the raw passphrase bytes. A missing item is `ItemNotFound`.
    ///
    /// # Errors
    /// The keychain status of the failed call.
    fn load(&self, vault: &str) -> Result<Zeroizing<Vec<u8>>, KeychainStatusError>;

    /// Removes the item; an absent item is success.
    ///
    /// # Errors
    /// The keychain status of the failed call.
    fn delete(&self, vault: &str) -> Result<(), KeychainStatusError>;
}

fn status_error(status: i32) -> KeychainStatusError {
    keychain_status_error(status).expect("non-zero status always maps to an error")
}

/// Adapts any [`Keyring`] (the in-memory fallback, test doubles) to the item
/// store, using the same `service|account` address as the native item and
/// storing the value verbatim.
pub struct KeyringBiometricItems<'a>(pub &'a dyn Keyring);

impl KeyringBiometricItems<'_> {
    fn key(vault: &str) -> String {
        format!("{}|{BIOMETRIC_ACCOUNT}", biometric_service_name(vault))
    }
}

impl BiometricItemStore for KeyringBiometricItems<'_> {
    fn exists(&self, vault: &str) -> Result<bool, KeychainStatusError> {
        match self.0.get(&Self::key(vault)) {
            Ok(_) => Ok(true),
            Err(SessionError::NotFound) => Ok(false),
            Err(_) => Err(status_error(ERR_SEC_NOT_AVAILABLE)),
        }
    }

    fn save(&self, vault: &str, passphrase: &[u8]) -> Result<(), KeychainStatusError> {
        self.0
            .set(&Self::key(vault), truncate_at_nul(passphrase))
            .map_err(|_| status_error(ERR_SEC_NOT_AVAILABLE))
    }

    fn load(&self, vault: &str) -> Result<Zeroizing<Vec<u8>>, KeychainStatusError> {
        match self.0.get(&Self::key(vault)) {
            Ok(value) => Ok(Zeroizing::new(truncate_at_nul(&value).to_vec())),
            Err(SessionError::NotFound) => Err(status_error(ERR_SEC_ITEM_NOT_FOUND)),
            Err(_) => Err(status_error(ERR_SEC_NOT_AVAILABLE)),
        }
    }

    fn delete(&self, vault: &str) -> Result<(), KeychainStatusError> {
        self.0
            .delete(&Self::key(vault))
            .map_err(|_| status_error(ERR_SEC_NOT_AVAILABLE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::MemoryKeyring;

    #[test]
    fn success_is_not_an_error() {
        assert!(keychain_status_error(ERR_SEC_SUCCESS).is_none());
    }

    #[test]
    fn only_authentication_statuses_are_biometric_failures() {
        for status in [ERR_SEC_AUTH_FAILED, ERR_SEC_USER_CANCELED] {
            assert_eq!(
                keychain_status_error(status).unwrap().kind(),
                KeychainErrorKind::BiometricFailed
            );
        }
        assert_eq!(
            keychain_status_error(ERR_SEC_ITEM_NOT_FOUND)
                .unwrap()
                .kind(),
            KeychainErrorKind::ItemNotFound
        );
    }

    #[test]
    fn legacy_wrapper_prefixes_are_recognised_exactly() {
        assert!(is_legacy_rust_wrapped_value(b"go-keyring-base64:c2VjcmV0"));
        assert!(is_legacy_rust_wrapped_value(b"go-keyring-encoded:7061"));
        assert!(is_legacy_rust_wrapped_value(b"go-keyring-base64:"));
        for raw in [
            b"".as_slice(),
            b"secret".as_slice(),
            b"go-keyring-base64".as_slice(),
            b" go-keyring-base64:c2VjcmV0".as_slice(),
            b"Go-Keyring-Base64:c2VjcmV0".as_slice(),
            b"x go-keyring-encoded:7061".as_slice(),
        ] {
            assert!(!is_legacy_rust_wrapped_value(raw), "{raw:?}");
        }
    }

    #[test]
    fn nul_truncation_matches_c_strings() {
        assert_eq!(truncate_at_nul(b"abc\0def"), b"abc");
        assert_eq!(truncate_at_nul(b"abc"), b"abc");
        assert_eq!(truncate_at_nul(b"\0abc"), b"");
    }

    #[test]
    fn keyring_adapter_stores_raw_bytes_at_the_go_address() {
        let keyring = MemoryKeyring::new();
        let items = KeyringBiometricItems(&keyring);
        assert!(!items.exists("/v").unwrap());
        assert_eq!(
            items.load("/v").unwrap_err().kind(),
            KeychainErrorKind::ItemNotFound
        );
        items.save("/v", b" go-keyring-base64:eA== \0tail").unwrap();
        assert_eq!(
            keyring.get("symvault-biometric:/v|passphrase").unwrap(),
            b" go-keyring-base64:eA== "
        );
        assert_eq!(&**items.load("/v").unwrap(), b" go-keyring-base64:eA== ");
        items.delete("/v").unwrap();
        items.delete("/v").unwrap();
        assert!(!items.exists("/v").unwrap());
    }
}
