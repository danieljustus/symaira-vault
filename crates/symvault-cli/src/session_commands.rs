//! Pure session command operations for the CLI dispatcher.
//!
//! The dispatcher owns vault resolution, initialization checks, and native
//! keyring construction. This module only consumes those resolved values so
//! it can be tested without a real keychain. Interactive unlock remains at
//! that boundary until the platform keyring and secure input are wired into
//! the Rust CLI.

use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};
use symvault_core::{
    config::AuthMethod,
    platform::TouchId,
    session::{Keyring, SessionError, SessionManager},
};
use zeroize::Zeroizing;

const BIOMETRIC_SERVICE_PREFIX: &str = "symvault-biometric:";
const BIOMETRIC_ACCOUNT: &str = "passphrase";
const BIOMETRIC_REASON: &str = "Unlock Symaira Vault vault";
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
        let mut rendered = serde_json::to_string(status).map_err(|e| e.to_string())?;
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
            .map(|output| output.status.success() && output.stdout.as_slice() == b"Aqua\n")
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Parses the duration syntax accepted by Go's `time.ParseDuration` for CLI
/// session TTLs. Fractions are preserved without floating point rounding.
pub fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("ttl must be a duration such as 30m or 1h".to_owned());
    }
    if value == "0" {
        return Err("ttl must be greater than zero".to_owned());
    }
    let mut rest = value;
    let negative = rest.starts_with('-');
    if negative || rest.starts_with('+') {
        rest = &rest[1..];
    }
    if negative || rest.is_empty() {
        return Err("ttl must be greater than zero".to_owned());
    }
    let mut total_nanos = 0u128;
    while !rest.is_empty() {
        let number_end = rest
            .find(|ch: char| !ch.is_ascii_digit() && ch != '.')
            .ok_or_else(|| "ttl is missing a unit".to_owned())?;
        let number = &rest[..number_end];
        if number.is_empty() || number.matches('.').count() > 1 {
            return Err(format!("invalid ttl {value:?}"));
        }
        let unit_start = number_end;
        let unit_end = rest[unit_start..]
            .find(|ch: char| ch.is_ascii_digit() || ch == '.')
            .map_or(rest.len(), |offset| unit_start + offset);
        let unit = &rest[unit_start..unit_end];
        let multiplier = match unit {
            "ns" => 1u128,
            "us" | "µs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err(format!("invalid ttl unit {unit:?}")),
        };
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if number.contains('.') && fraction.is_empty() {
            return Err(format!("invalid ttl {value:?}"));
        }
        let whole = whole
            .parse::<u128>()
            .map_err(|_| format!("invalid ttl {value:?}"))?;
        let whole_nanos = whole
            .checked_mul(multiplier)
            .ok_or_else(|| "ttl is too large".to_owned())?;
        let fraction_nanos = if fraction.is_empty() {
            0
        } else if fraction.len() > 18 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("invalid ttl {value:?}"));
        } else {
            let digits = fraction
                .parse::<u128>()
                .map_err(|_| format!("invalid ttl {value:?}"))?;
            let scale = 10u128.pow(fraction.len() as u32);
            digits
                .checked_mul(multiplier)
                .and_then(|nanos| nanos.checked_div(scale))
                .ok_or_else(|| "ttl is too large".to_owned())?
        };
        total_nanos = total_nanos
            .checked_add(whole_nanos)
            .and_then(|nanos| nanos.checked_add(fraction_nanos))
            .ok_or_else(|| "ttl is too large".to_owned())?;
        rest = &rest[unit_end..];
    }
    if total_nanos == 0 {
        return Err("ttl must be greater than zero".to_owned());
    }
    let nanos = u64::try_from(total_nanos).map_err(|_| "ttl is too large".to_owned())?;
    Ok(Duration::from_nanos(nanos))
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
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(30 * 60));
        assert_eq!(
            parse_duration("1h30m").unwrap(),
            Duration::from_secs(90 * 60)
        );
        assert_eq!(parse_duration("1.5s").unwrap(), Duration::from_millis(1500));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("-1m").is_err());
        assert!(parse_duration("1.s").is_err());
        assert!(parse_duration("15").is_err());
    }
}
