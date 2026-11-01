//! CLI wiring for Go's `internal/authguard` biometric challenger.
//!
//! The challenger itself, its Go error texts and the `set_auth_method` session
//! seam live in `symvault_mcp::authguard`; this module only decides what the
//! production process injects:
//!
//! * a real [`MacOsTouchId`](symvault_platform::MacOsTouchId) when the same
//!   gate the unlock path uses is open (macOS, an Aqua GUI session, not a test
//!   or CI run), otherwise [`UnavailablePlatform`];
//! * on macOS, a session/keychain backend for `set_auth_method` built from the
//!   runtime's keyring.
//!
//! Nothing here prompts by itself; a prompt only happens when a caller invokes
//! `Challenger::challenge` on an available authenticator.

use std::sync::Arc;

use symvault_core::platform::{TouchId, UnavailablePlatform};
use symvault_mcp::authguard::{Challenger, UnavailableAuthMethodBackend};

use crate::mcp_commands::AuthGuardSeams;

/// The shared availability gate (see `unlock_passphrase_with_mode`): a Touch ID
/// dialog can only be shown from a GUI session, and never from tests or CI.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const fn gate_open(test_or_ci: bool, gui_session: bool) -> bool {
    !test_or_ci && gui_session
}

/// The production authenticator behind the gate.
pub(crate) fn default_touch_id() -> Arc<dyn TouchId> {
    #[cfg(target_os = "macos")]
    if gate_open(
        crate::is_test_or_ci(),
        crate::session_commands::gui_session_available(),
    ) {
        return Arc::new(symvault_platform::MacOsTouchId);
    }
    Arc::new(UnavailablePlatform)
}

/// Go `authguard.DefaultChallenger()`.
pub(crate) fn default_challenger() -> Challenger {
    Challenger::new(default_touch_id())
}

/// Seams for `symvault mcp`: the gated authenticator plus the session backend.
pub(crate) fn mcp_seams(
    keyring: Option<Arc<symvault_platform::FallbackKeyring>>,
) -> AuthGuardSeams {
    let touch_id = default_touch_id();
    #[cfg(target_os = "macos")]
    if let Some(keyring) = keyring {
        return AuthGuardSeams {
            backend: Arc::new(macos::SessionAuthBackend::new(touch_id.clone(), keyring)),
            touch_id,
        };
    }
    #[cfg(not(target_os = "macos"))]
    let _ = keyring;
    AuthGuardSeams {
        touch_id,
        backend: Arc::new(UnavailableAuthMethodBackend),
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::path::Path;
    use std::sync::Arc;

    use symvault_core::{
        keychain_status::{BiometricItemStore, KeyringBiometricItems},
        platform::TouchId,
        session::SessionManager,
    };
    use symvault_mcp::authguard::AuthMethodBackend;
    use symvault_platform::{FallbackKeyring, SecurityBiometricItems};
    use zeroize::Zeroizing;

    /// Go's package-level `session.*` helpers for `set_auth_method`. The item
    /// follows the session cache like `touch_id_items` in `main.rs`: the
    /// in-memory fallback in tests/CI, Go's native Keychain item otherwise.
    pub(super) struct SessionAuthBackend {
        touch_id: Arc<dyn TouchId>,
        manager: SessionManager,
        keyring: Arc<FallbackKeyring>,
    }

    impl SessionAuthBackend {
        pub(super) fn new(touch_id: Arc<dyn TouchId>, keyring: Arc<FallbackKeyring>) -> Self {
            Self {
                touch_id,
                manager: SessionManager::with_system_clock(keyring.clone()),
                keyring,
            }
        }

        fn with_items<R>(&self, action: impl FnOnce(&dyn BiometricItemStore) -> R) -> R {
            if self.keyring.is_fallback_active() {
                action(&KeyringBiometricItems(&*self.keyring))
            } else {
                action(&SecurityBiometricItems::system())
            }
        }
    }

    fn vault_str(vault_dir: &Path) -> Result<&str, String> {
        vault_dir
            .to_str()
            .ok_or_else(|| "vault path is not valid UTF-8".to_owned())
    }

    impl AuthMethodBackend for SessionAuthBackend {
        fn biometric_available(&self) -> bool {
            self.touch_id.is_available()
        }

        fn load_session_passphrase(&self, vault_dir: &str) -> Option<Zeroizing<Vec<u8>>> {
            self.manager
                .load_passphrase(vault_dir)
                .ok()
                .filter(|passphrase| !passphrase.is_empty())
                .map(Zeroizing::new)
        }

        fn save_biometric_passphrase(
            &self,
            vault_dir: &Path,
            passphrase: &[u8],
        ) -> Result<(), String> {
            let vault = vault_str(vault_dir)?;
            self.with_items(|items| items.save(vault, passphrase))
                .map_err(|error| error.to_string())
        }

        fn clear_biometric_passphrase(&self, vault_dir: &Path) -> Result<(), String> {
            let vault = vault_str(vault_dir)?;
            self.with_items(|items| items.delete(vault))
                .map_err(|error| error.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_requires_gui_and_no_test_or_ci() {
        assert!(gate_open(false, true));
        assert!(!gate_open(true, true));
        assert!(!gate_open(false, false));
        assert!(!gate_open(true, false));
    }

    #[test]
    fn unavailable_platform_challenger_never_prompts() {
        let challenger = Challenger::new(Arc::new(UnavailablePlatform));
        assert!(!challenger.available());
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_backend_tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use symvault_core::{
        keychain_status::{BiometricItemStore, KeyringBiometricItems},
        platform::{PlatformError, TouchId},
        session::{MemoryKeyring, SessionManager},
    };
    use symvault_mcp::authguard::AuthMethodBackend;
    use symvault_platform::FallbackKeyring;

    struct Available(bool);

    impl TouchId for Available {
        fn is_available(&self) -> bool {
            self.0
        }
        fn authenticate(&self, _: &str, _: Duration) -> Result<(), PlatformError> {
            unreachable!("the backend never prompts")
        }
    }

    /// Runs against the in-memory fallback only: never the real Keychain.
    #[test]
    fn session_backend_round_trips_through_the_fallback_keyring() {
        let keyring = FallbackKeyring::new(Arc::new(MemoryKeyring::new()), true);
        let backend =
            super::macos::SessionAuthBackend::new(Arc::new(Available(true)), keyring.clone());
        assert!(backend.biometric_available());
        assert!(backend.load_session_passphrase("/vault").is_none());

        SessionManager::with_system_clock(keyring.clone())
            .save_passphrase(
                "/vault",
                b"hunter2",
                Duration::from_secs(900),
                Duration::from_secs(3600),
            )
            .expect("seed session");
        assert_eq!(
            &**backend
                .load_session_passphrase("/vault")
                .expect("session passphrase"),
            b"hunter2"
        );

        let items = KeyringBiometricItems(&*keyring);
        backend
            .save_biometric_passphrase(Path::new("/vault"), b"hunter2")
            .expect("save item");
        assert!(items.exists("/vault").unwrap());
        backend
            .clear_biometric_passphrase(Path::new("/vault"))
            .expect("clear item");
        assert!(!items.exists("/vault").unwrap());
        backend
            .clear_biometric_passphrase(Path::new("/vault"))
            .expect("an absent item is success");
        let closed = super::macos::SessionAuthBackend::new(
            Arc::new(Available(false)),
            FallbackKeyring::new(Arc::new(MemoryKeyring::new()), true),
        );
        assert!(!closed.biometric_available());
    }
}
