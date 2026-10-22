//! Pure session command operations for the CLI dispatcher.
//!
//! The dispatcher owns vault resolution, initialization checks, and native
//! keyring construction. This module only consumes those resolved values so
//! it can be tested without a real keychain. Interactive unlock remains at
//! that boundary until the platform keyring and secure input are wired into
//! the Rust CLI.

use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};
use symvault_core::{config::AuthMethod, session::SessionManager};
#[cfg(any(target_os = "macos", test))]
use symvault_core::{
    keychain_status::{BiometricItemStore, KeychainErrorKind},
    platform::TouchId,
};
#[cfg(any(target_os = "macos", test))]
use zeroize::Zeroizing;

#[cfg(any(target_os = "macos", test))]
const BIOMETRIC_REASON: &str = "Unlock Symaira Vault vault";
#[cfg(any(target_os = "macos", test))]
const BIOMETRIC_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheStatus {
    pub backend: String,
    pub persistent: bool,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthStatus {
    pub cache: CacheStatus,
    #[serde(rename = "keyringHealth")]
    pub keyring_health: String,
    pub method: String,
    #[serde(rename = "touchIDAvailable")]
    pub touch_id_available: bool,
    pub vault: String,
}

/// Builds the status document used by `auth status`.
pub fn auth_status(
    vault: &Path,
    method: AuthMethod,
    cache: CacheStatus,
    touch_id_available: bool,
) -> Result<AuthStatus, String> {
    let vault = vault
        .to_str()
        .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
    let keyring_health = if cache.persistent {
        "available"
    } else {
        "unavailable"
    };
    Ok(AuthStatus {
        cache,
        keyring_health: keyring_health.to_owned(),
        method: method.as_str().to_owned(),
        touch_id_available,
        vault: vault.to_owned(),
    })
}

/// Renders the Go auth-status contract. The Go command treats every format
/// other than JSON as its human-readable status view.
pub fn render_status(
    status: &AuthStatus,
    output_format: &str,
    json_flag: bool,
    quiet: bool,
) -> Result<String, String> {
    if quiet {
        return Ok(String::new());
    }
    if json_flag || output_format == "json" {
        // Go's auth-status printer deliberately calls SetEscapeHTML(false),
        // so this command must preserve literal <, >, and & bytes.
        let mut rendered = serde_json::to_string(status)
            .map_err(|e| e.to_string())?
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029");
        rendered.push('\n');
        return Ok(rendered);
    }
    Ok(format!(
        "Vault: {}\nAuth method: {}\nTouch ID available: {}\nSession cache: {} (persistent: {})\nKeyring health: {}\n",
        status.vault,
        status.method,
        status.touch_id_available,
        status.cache.backend,
        status.cache.persistent,
        status.keyring_health,
    ))
}

/// Clears passphrase, identity, and wrapping-key cache entries for a vault.
/// The caller is responsible for clearing any in-memory search index.
pub fn lock(manager: &SessionManager, vault: &Path, quiet: bool) -> Result<String, String> {
    let vault = vault
        .to_str()
        .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
    manager
        .revoke(vault)
        .map_err(|error| format!("cannot clear session: {error}"))?;
    if quiet {
        Ok(String::new())
    } else {
        Ok("Vault locked\n".to_owned())
    }
}

/// Reports whether either cached credential accepted by the Go CLI is active.
#[must_use]
pub fn session_active(manager: &SessionManager, vault: &Path) -> bool {
    let Some(vault) = vault.to_str() else {
        return false;
    };
    !manager.is_session_expired(vault) || !manager.is_identity_expired(vault)
}

/// Implements `unlock --check` without reading or printing credentials.
pub fn check(manager: &SessionManager, vault: &Path) -> Result<(), String> {
    if session_active(manager, vault) {
        Ok(())
    } else {
        Err("no active session".to_owned())
    }
}

/// Loads the passphrase stored by Go's macOS Touch ID provider.
///
/// Go keeps this credential apart from the normal session entry, as a
/// generic-password item `symvault-biometric:<vault>` / `passphrase` holding the
/// raw passphrase bytes. The order is Go's: learn whether the item exists
/// without reading it (so an unconfigured vault never raises a prompt), then
/// authenticate, then read. The item store and the authenticator are injected so
/// the decision and error paths are testable without a developer keychain or
/// Touch ID.
#[cfg(any(target_os = "macos", test))]
pub fn load_touch_id_passphrase(
    vault: &Path,
    items: &dyn BiometricItemStore,
    touch_id: &dyn TouchId,
) -> Result<Zeroizing<Vec<u8>>, String> {
    const NOT_CONFIGURED: &str = "Touch ID unlock is not configured for this vault";
    let vault = vault
        .to_str()
        .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
    if !touch_id.is_available() {
        return Err("Touch ID unlock is unavailable on this system".to_owned());
    }
    match items.exists(vault) {
        Ok(true) => {}
        Ok(false) => return Err(NOT_CONFIGURED.to_owned()),
        Err(error) => return Err(error.to_string()),
    }
    touch_id
        .authenticate(BIOMETRIC_REASON, BIOMETRIC_TIMEOUT)
        .map_err(|error| format!("Touch ID authentication failed: {error}"))?;
    let value = items.load(vault).map_err(|error| {
        if error.kind() == KeychainErrorKind::ItemNotFound {
            NOT_CONFIGURED.to_owned()
        } else {
            error.to_string()
        }
    })?;
    if value.is_empty() {
        return Err(NOT_CONFIGURED.to_owned());
    }
    Ok(value)
}

/// Stores a passphrase as Go's Touch ID item so a later unlock or biometric
/// setup change can retrieve it. Mirrors Go's `session.SaveBiometricPassphrase`
/// (the store has no separate authentication step; only `Load` is
/// biometric-gated in both ports).
#[cfg(any(target_os = "macos", test))]
pub fn save_touch_id_passphrase(
    vault: &Path,
    items: &dyn BiometricItemStore,
    passphrase: &[u8],
) -> Result<(), String> {
    let vault = vault
        .to_str()
        .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
    items
        .save(vault, passphrase)
        .map_err(|error| format!("save Touch ID unlock item: {error}"))
}

/// Removes the Touch ID unlock item for a vault, mirroring Go's
/// `session.ClearBiometricPassphrase`. An absent item is success in both ports;
/// callers still treat a failure as a warning, as the Go CLI's
/// `auth set passphrase` only logs it.
#[cfg(any(target_os = "macos", test))]
pub fn clear_touch_id_passphrase(
    vault: &Path,
    items: &dyn BiometricItemStore,
) -> Result<(), String> {
    let vault = vault
        .to_str()
        .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
    items
        .delete(vault)
        .map_err(|error| format!("could not remove Touch ID unlock item: {error}"))
}

/// Returns whether a macOS process is attached to an Aqua GUI session.
/// Touch ID prompts cannot be shown from SSH, daemon, or CI contexts.
#[allow(dead_code)]
pub fn gui_session_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/bin/launchctl")
            .arg("managername")
            .output()
            .map(|output| {
                output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "Aqua"
            })
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Parses the duration syntax accepted by Go's `time.ParseDuration` for CLI
/// session TTLs. Fractions are preserved without floating point rounding.
pub fn parse_ttl_override(value: &str) -> Result<Option<Duration>, String> {
    let nanos = symvault_core::config::parse_duration_nanos(value)
        .ok_or_else(|| format!("invalid ttl {value:?}"))?;
    if nanos <= 0 {
        return Ok(None);
    }
    Ok(Some(Duration::from_nanos(nanos as u64)))
}

/// Compatibility wrapper for the pre-dispatch CLI call site. New dispatchers
/// should use [`parse_ttl_override`] so Go's non-positive override semantics
/// remain visible as `None`.
#[allow(dead_code)]
pub fn parse_duration(value: &str) -> Result<Duration, String> {
    parse_ttl_override(value)?.ok_or_else(|| "ttl must be greater than zero".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeTouchId {
        available: bool,
        authenticated: Mutex<Vec<(String, Duration)>>,
        error: Option<String>,
    }

    impl TouchId for FakeTouchId {
        fn is_available(&self) -> bool {
            self.available
        }

        fn authenticate(
            &self,
            reason: &str,
            timeout: Duration,
        ) -> Result<(), symvault_core::platform::PlatformError> {
            self.authenticated
                .lock()
                .expect("fake lock")
                .push((reason.to_owned(), timeout));
            match &self.error {
                Some(message) => Err(symvault_core::platform::PlatformError {
                    kind: symvault_core::platform::PlatformErrorKind::Canceled,
                    message: message.clone(),
                }),
                None => Ok(()),
            }
        }
    }

    use symvault_core::keychain_status::KeyringBiometricItems;
    use symvault_core::session::{Keyring, MemoryKeyring};

    const ADDRESS: &str = "symvault-biometric:/fixture/vault|passphrase";

    #[test]
    fn touch_id_load_matches_go_service_and_account() {
        let keyring = MemoryKeyring::new();
        keyring.set(ADDRESS, b"secret").expect("store fixture");
        let touch = FakeTouchId {
            available: true,
            ..Default::default()
        };
        let got = load_touch_id_passphrase(
            Path::new("/fixture/vault"),
            &KeyringBiometricItems(&keyring),
            &touch,
        )
        .expect("load biometric passphrase");
        assert_eq!(&*got, b"secret");
        let calls = touch.authenticated.lock().expect("fake lock");
        assert_eq!(&*calls, &[(BIOMETRIC_REASON.to_owned(), BIOMETRIC_TIMEOUT)]);
    }

    #[test]
    fn touch_id_does_not_read_items_when_unavailable() {
        let touch = FakeTouchId::default();
        let keyring = MemoryKeyring::new();
        let error = load_touch_id_passphrase(
            Path::new("/fixture/vault"),
            &KeyringBiometricItems(&keyring),
            &touch,
        )
        .expect_err("unavailable touch id");
        assert_eq!(error, "Touch ID unlock is unavailable on this system");
    }

    /// Go learns the item is missing before it shows the prompt.
    #[test]
    fn touch_id_unconfigured_vault_never_prompts() {
        let keyring = MemoryKeyring::new();
        let touch = FakeTouchId {
            available: true,
            ..Default::default()
        };
        let error = load_touch_id_passphrase(
            Path::new("/fixture/vault"),
            &KeyringBiometricItems(&keyring),
            &touch,
        )
        .expect_err("nothing stored");
        assert_eq!(error, "Touch ID unlock is not configured for this vault");
        assert!(touch.authenticated.lock().expect("fake lock").is_empty());
    }

    /// The value is the raw passphrase: nothing a go-keyring wrapper would
    /// have trimmed or decoded may change on the way through.
    #[test]
    fn touch_id_passphrase_is_raw_bytes_both_ways() {
        let keyring = MemoryKeyring::new();
        let items = KeyringBiometricItems(&keyring);
        let touch = FakeTouchId {
            available: true,
            ..Default::default()
        };
        for secret in [
            b" padded \n".as_slice(),
            b"go-keyring-base64:c2VjcmV0".as_slice(),
        ] {
            save_touch_id_passphrase(Path::new("/fixture/vault"), &items, secret)
                .expect("save biometric passphrase");
            assert_eq!(keyring.get(ADDRESS).expect("stored"), secret);
            let got = load_touch_id_passphrase(Path::new("/fixture/vault"), &items, &touch)
                .expect("load biometric passphrase");
            assert_eq!(&*got, secret);
        }
    }

    #[test]
    fn clear_touch_id_passphrase_removes_saved_item_and_is_idempotent() {
        let keyring = MemoryKeyring::new();
        let items = KeyringBiometricItems(&keyring);
        save_touch_id_passphrase(Path::new("/fixture/vault"), &items, b"secret")
            .expect("save biometric passphrase");
        clear_touch_id_passphrase(Path::new("/fixture/vault"), &items)
            .expect("clear biometric passphrase");
        assert!(matches!(
            keyring.get(ADDRESS).expect_err("item removed"),
            symvault_core::session::SessionError::NotFound
        ));
        clear_touch_id_passphrase(Path::new("/fixture/vault"), &items)
            .expect("clearing an absent item succeeds, as in Go");
    }

    #[test]
    fn duration_parser_matches_go_common_forms() {
        assert_eq!(
            parse_ttl_override("30m").unwrap(),
            Some(Duration::from_secs(30 * 60))
        );
        assert_eq!(
            parse_ttl_override("1h30m").unwrap(),
            Some(Duration::from_secs(90 * 60))
        );
        assert_eq!(
            parse_ttl_override("1.5s").unwrap(),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(
            parse_ttl_override(".5s").unwrap(),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            parse_ttl_override("1.s").unwrap(),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            parse_ttl_override("1μs").unwrap(),
            Some(Duration::from_micros(1))
        );
        assert_eq!(parse_ttl_override("0s").unwrap(), None);
        assert_eq!(parse_ttl_override("-1m").unwrap(), None);
        assert!(parse_ttl_override("15").is_err());
        assert!(parse_ttl_override(" 30m").is_err());
    }
}
