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
    platform::TouchId,
    session::{Keyring, SessionError},
};
#[cfg(any(target_os = "macos", test))]
use zeroize::Zeroizing;

#[cfg(any(target_os = "macos", test))]
const BIOMETRIC_SERVICE_PREFIX: &str = "symvault-biometric:";
#[cfg(any(target_os = "macos", test))]
const BIOMETRIC_ACCOUNT: &str = "passphrase";
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
/// Go stores this credential separately from the normal session entry under
/// `symvault-biometric:<vault>|passphrase`. Authentication is performed before
/// reading the item so the OS keychain remains the authorization boundary.
/// The keyring and authenticator are injected to make the decision and error
/// paths testable without touching a developer keychain or invoking Touch ID.
#[cfg(any(target_os = "macos", test))]
pub fn load_touch_id_passphrase(
    vault: &Path,
    keyring: &dyn Keyring,
    touch_id: &dyn TouchId,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let vault = vault
        .to_str()
        .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
    if !touch_id.is_available() {
        return Err("Touch ID unlock is unavailable on this system".to_owned());
    }
    touch_id
        .authenticate(BIOMETRIC_REASON, BIOMETRIC_TIMEOUT)
        .map_err(|error| format!("Touch ID authentication failed: {error}"))?;
    let key = format!("{BIOMETRIC_SERVICE_PREFIX}{vault}|{BIOMETRIC_ACCOUNT}");
    let value = keyring.get(&key).map_err(|error| match error {
        SessionError::NotFound => "Touch ID unlock is not configured for this vault".to_owned(),
        _ => "Touch ID passphrase could not be loaded from the native keychain".to_owned(),
    })?;
    if value.is_empty() {
        return Err("Touch ID unlock is not configured for this vault".to_owned());
    }
    Ok(Zeroizing::new(value))
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

    #[test]
    fn touch_id_load_matches_go_service_and_account() {
        let keyring = symvault_core::session::MemoryKeyring::new();
        keyring
            .set("symvault-biometric:/fixture/vault|passphrase", b"secret")
            .expect("store fixture");
        let touch = FakeTouchId {
            available: true,
            ..Default::default()
        };
        let got = load_touch_id_passphrase(Path::new("/fixture/vault"), &keyring, &touch)
            .expect("load biometric passphrase");
        assert_eq!(&*got, b"secret");
        let calls = touch.authenticated.lock().expect("fake lock");
        assert_eq!(&*calls, &[(BIOMETRIC_REASON.to_owned(), BIOMETRIC_TIMEOUT)]);
    }

    #[test]
    fn touch_id_does_not_read_keyring_when_unavailable() {
        let touch = FakeTouchId::default();
        let keyring = symvault_core::session::MemoryKeyring::new();
        let error = load_touch_id_passphrase(Path::new("/fixture/vault"), &keyring, &touch)
            .expect_err("unavailable touch id");
        assert_eq!(error, "Touch ID unlock is unavailable on this system");
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
