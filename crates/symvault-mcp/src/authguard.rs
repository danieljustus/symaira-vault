//! Port of Go `internal/authguard/challenge.go`: the biometric challenger used
//! before critical configuration changes and by the MCP `require_biometry`
//! policy action.
//!
//! The challenger never touches the OS itself. It delegates to an injected
//! [`TouchId`] so production wires the platform adapter (behind the CLI's
//! availability gate) and tests inject a fake: no test ever raises a real Touch
//! ID prompt. A challenger built without an adapter is "not initialized" exactly
//! like Go's nil `*Challenger`.
//!
//! Error texts are the Go texts byte for byte, including the darwin
//! authenticator's `errTouchID*` wording (`internal/session/touchid_darwin.go`).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use symvault_core::platform::{PlatformErrorKind, TouchId, UnavailablePlatform};
use zeroize::Zeroizing;

/// Upper bound for one interactive prompt. Go's darwin authenticator has no
/// timeout of its own (it follows the caller's context); the platform adapter
/// needs a finite value, so this is deliberately generous.
const CHALLENGE_TIMEOUT: Duration = Duration::from_secs(120);

/// Go `session.ErrBiometricNotAvailable`.
const ERR_BIOMETRIC_NOT_AVAILABLE: &str = "biometric authentication not available";
/// Go `errTouchIDNotAvailable` (`touchid_darwin.go`).
const ERR_TOUCH_ID_NOT_AVAILABLE: &str = "touch id not available";
/// Go `errTouchIDFailed` (`touchid_darwin.go`): every rejection, cancel and
/// timeout of the system dialog collapses into this one text.
const ERR_TOUCH_ID_FAILED: &str = "touch id authentication failed";

/// Go `authguard.OperationType`: a short machine label whose
/// [`label`](Self::label) is the user-visible text in challenge errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationType<'a>(&'a str);

impl OperationType<'static> {
    /// Go `OpTierUpgrade`.
    pub const TIER_UPGRADE: Self = OperationType("agent_tier_upgrade");
    /// Go `OpAuthMethodSet`.
    pub const AUTH_METHOD_SET: Self = OperationType("set_auth_method");
}

impl<'a> OperationType<'a> {
    /// Go `authguard.OperationType(toolName)`: an arbitrary tool name is a
    /// valid operation and renders as itself.
    #[must_use]
    pub const fn tool(name: &'a str) -> Self {
        Self(name)
    }

    /// Go `OperationType.String`.
    #[must_use]
    pub fn label(&self) -> &str {
        match self.0 {
            "agent_tier_upgrade" => "agent tier upgrade",
            "set_auth_method" => "auth method change",
            other => other,
        }
    }
}

/// Go `authguard.Challenger` over an injected [`TouchId`].
#[derive(Clone)]
pub struct Challenger {
    touch_id: Option<Arc<dyn TouchId>>,
}

impl Challenger {
    /// Wires a platform (or fake) authenticator.
    #[must_use]
    pub fn new(touch_id: Arc<dyn TouchId>) -> Self {
        Self {
            touch_id: Some(touch_id),
        }
    }

    /// Go's noop authenticator (every non-Touch-ID platform): never available.
    #[must_use]
    pub fn unavailable() -> Self {
        Self::new(Arc::new(UnavailablePlatform))
    }

    /// A challenger with no authenticator, Go's nil `*Challenger`.
    #[must_use]
    pub const fn uninitialized() -> Self {
        Self { touch_id: None }
    }

    /// Go `Challenger.Available`.
    #[must_use]
    pub fn available(&self) -> bool {
        self.touch_id
            .as_ref()
            .is_some_and(|touch_id| touch_id.is_available())
    }

    /// Go `Challenger.Challenge`: blocks until the user succeeds, fails or
    /// cancels. `Err` carries the Go error text.
    ///
    /// # Errors
    /// `biometric challenger not initialized`, the not-available text, or
    /// `biometric verification for <op> failed: <touch id error>`.
    pub fn challenge(&self, op: &OperationType<'_>, reason: &str) -> Result<(), String> {
        let Some(touch_id) = &self.touch_id else {
            return Err("biometric challenger not initialized".to_owned());
        };
        if !touch_id.is_available() {
            return Err(format!(
                "{ERR_BIOMETRIC_NOT_AVAILABLE}: biometric authentication is not available on this platform"
            ));
        }
        touch_id
            .authenticate(reason, CHALLENGE_TIMEOUT)
            .map_err(|error| {
                let cause = match error.kind {
                    PlatformErrorKind::Unavailable => ERR_TOUCH_ID_NOT_AVAILABLE,
                    _ => ERR_TOUCH_ID_FAILED,
                };
                format!("biometric verification for {} failed: {cause}", op.label())
            })
    }
}

impl Default for Challenger {
    fn default() -> Self {
        Self::unavailable()
    }
}

/// The session/keychain side of `set_auth_method`: Go's package-level
/// `session.BiometricAvailable`, `LoadPassphrase`, `SaveBiometricPassphrase`
/// and `ClearBiometricPassphrase`. Injected so the MCP crate never opens a
/// keychain; the default is Go's noop store.
pub trait AuthMethodBackend: Send + Sync {
    /// `session.BiometricAvailable()`: the Touch ID passphrase store works.
    fn biometric_available(&self) -> bool;
    /// `session.LoadPassphrase(vaultDir)`; `None` is any error or an empty
    /// passphrase (Go treats both as "no active session").
    fn load_session_passphrase(&self, vault_dir: &str) -> Option<Zeroizing<Vec<u8>>>;
    /// `session.SaveBiometricPassphrase`; `Err` carries the cause text.
    ///
    /// # Errors
    /// The backing store's failure text.
    fn save_biometric_passphrase(&self, vault_dir: &Path, passphrase: &[u8]) -> Result<(), String>;
    /// `session.ClearBiometricPassphrase`; an absent item is success.
    ///
    /// # Errors
    /// The backing store's failure text.
    fn clear_biometric_passphrase(&self, vault_dir: &Path) -> Result<(), String>;
}

/// Go's `noopBiometricPassphraseStore` plus an empty session cache.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableAuthMethodBackend;

impl AuthMethodBackend for UnavailableAuthMethodBackend {
    fn biometric_available(&self) -> bool {
        false
    }
    fn load_session_passphrase(&self, _vault_dir: &str) -> Option<Zeroizing<Vec<u8>>> {
        None
    }
    fn save_biometric_passphrase(
        &self,
        _vault_dir: &Path,
        _passphrase: &[u8],
    ) -> Result<(), String> {
        Err(ERR_BIOMETRIC_NOT_AVAILABLE.to_owned())
    }
    fn clear_biometric_passphrase(&self, _vault_dir: &Path) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use symvault_core::platform::PlatformError;

    struct Fake {
        available: bool,
        outcome: Result<(), PlatformErrorKind>,
        prompts: AtomicUsize,
    }

    impl TouchId for Fake {
        fn is_available(&self) -> bool {
            self.available
        }
        fn authenticate(&self, _reason: &str, _timeout: Duration) -> Result<(), PlatformError> {
            self.prompts.fetch_add(1, Ordering::SeqCst);
            self.outcome.map_err(|kind| PlatformError {
                kind,
                message: "platform detail must not leak".into(),
            })
        }
    }

    fn challenger(
        available: bool,
        outcome: Result<(), PlatformErrorKind>,
    ) -> (Challenger, Arc<Fake>) {
        let fake = Arc::new(Fake {
            available,
            outcome,
            prompts: AtomicUsize::new(0),
        });
        (Challenger::new(fake.clone()), fake)
    }

    #[test]
    fn operation_labels_match_go_string() {
        assert_eq!(OperationType::TIER_UPGRADE.label(), "agent tier upgrade");
        assert_eq!(OperationType::AUTH_METHOD_SET.label(), "auth method change");
        assert_eq!(OperationType::tool("get_entry").label(), "get_entry");
    }

    #[test]
    fn approve_returns_ok_after_one_prompt() {
        let (challenger, fake) = challenger(true, Ok(()));
        assert!(challenger.available());
        challenger
            .challenge(&OperationType::TIER_UPGRADE, "reason")
            .unwrap();
        assert_eq!(fake.prompts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reject_uses_go_touch_id_failed_text() {
        for kind in [
            PlatformErrorKind::Canceled,
            PlatformErrorKind::TimedOut,
            PlatformErrorKind::Failed,
        ] {
            let (challenger, _) = challenger(true, Err(kind));
            assert_eq!(
                challenger
                    .challenge(&OperationType::TIER_UPGRADE, "reason")
                    .unwrap_err(),
                "biometric verification for agent tier upgrade failed: touch id authentication failed"
            );
        }
    }

    #[test]
    fn unavailable_at_prompt_time_uses_go_not_available_text() {
        let (challenger, _) = challenger(true, Err(PlatformErrorKind::Unavailable));
        assert_eq!(
            challenger
                .challenge(&OperationType::AUTH_METHOD_SET, "reason")
                .unwrap_err(),
            "biometric verification for auth method change failed: touch id not available"
        );
    }

    #[test]
    fn unavailable_never_prompts() {
        let (challenger, fake) = challenger(false, Ok(()));
        assert!(!challenger.available());
        assert_eq!(
            challenger
                .challenge(&OperationType::tool("get_entry"), "reason")
                .unwrap_err(),
            "biometric authentication not available: biometric authentication is not available on this platform"
        );
        assert_eq!(fake.prompts.load(Ordering::SeqCst), 0);
        assert!(!Challenger::unavailable().available());
    }

    #[test]
    fn uninitialized_matches_go_nil_challenger() {
        let challenger = Challenger::uninitialized();
        assert!(!challenger.available());
        assert_eq!(
            challenger
                .challenge(&OperationType::TIER_UPGRADE, "reason")
                .unwrap_err(),
            "biometric challenger not initialized"
        );
    }
}
