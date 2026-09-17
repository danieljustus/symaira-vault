//! Platform seam crate. Native implementations belong here, not in core.
#![deny(unsafe_code)]

#[cfg(any(target_os = "macos", test))]
mod focus;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
mod os_keyring;
#[cfg(target_os = "macos")]
pub use macos::{MacOsDaemon, MacOsKeyring, MacOsPlatform, MacOsTouchId};
#[cfg(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub use os_keyring::OsKeyring;

pub use symvault_core::persistent_quota::{
    NativeQuotaPlatform, QUOTA_FILE_NAME, QuotaCounter, QuotaError, QuotaPlatform,
};
pub use symvault_core::platform::*;
pub use symvault_core::quota::AgentRateLimiter;
pub use symvault_core::session::{
    Clock, Keyring, MemoryKeyring, NativeKeyring, SessionError, SessionManager, SystemClock,
};

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// OS-keyring wrapper with the same process-lifetime memory fallback as Go.
/// A missing credential is an ordinary cache miss; provider failures activate
/// the fallback and all later operations stay in memory.
pub struct FallbackKeyring {
    primary: Arc<dyn Keyring>,
    fallback: Arc<MemoryKeyring>,
    active: AtomicBool,
}

impl FallbackKeyring {
    #[must_use]
    pub fn new(primary: Arc<dyn Keyring>, start_in_fallback: bool) -> Arc<Self> {
        Arc::new(Self {
            primary,
            fallback: Arc::new(MemoryKeyring::new()),
            active: AtomicBool::new(start_in_fallback),
        })
    }

    #[must_use]
    pub fn is_fallback_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    fn activate(&self) {
        self.active.store(true, Ordering::Release);
    }
}

impl Keyring for FallbackKeyring {
    fn get(&self, key: &str) -> Result<Vec<u8>, SessionError> {
        if self.is_fallback_active() {
            return self.fallback.get(key);
        }
        match self.primary.get(key) {
            Ok(value) => Ok(value),
            Err(SessionError::NotFound) => Err(SessionError::NotFound),
            Err(_) => {
                self.activate();
                self.fallback.get(key)
            }
        }
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), SessionError> {
        if self.is_fallback_active() {
            return self.fallback.set(key, value);
        }
        match self.primary.set(key, value) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.activate();
                self.fallback.set(key, value)
            }
        }
    }

    fn delete(&self, key: &str) -> Result<(), SessionError> {
        if self.is_fallback_active() {
            return self.fallback.delete(key);
        }
        match self.primary.delete(key) {
            Ok(()) | Err(SessionError::NotFound) => Ok(()),
            Err(_) => {
                self.activate();
                self.fallback.delete(key)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Default)]
    struct Fake {
        typed: Mutex<Vec<String>>,
        notices: Mutex<Vec<(String, String)>>,
    }
    impl Autotype for Fake {
        fn type_text(&self, text: &str) -> Result<(), PlatformError> {
            self.typed.lock().unwrap().push(text.to_owned());
            Ok(())
        }
    }
    impl Notifier for Fake {
        fn notify(&self, title: &str, message: &str) -> Result<(), PlatformError> {
            self.notices
                .lock()
                .unwrap()
                .push((title.into(), message.into()));
            Ok(())
        }
    }

    struct FailingKeyring;
    impl Keyring for FailingKeyring {
        fn get(&self, _: &str) -> Result<Vec<u8>, SessionError> {
            Err(SessionError::NotFound)
        }
        fn set(&self, _: &str, _: &[u8]) -> Result<(), SessionError> {
            Err(SessionError::Keyring("unavailable".into()))
        }
        fn delete(&self, _: &str) -> Result<(), SessionError> {
            Err(SessionError::Keyring("unavailable".into()))
        }
    }

    #[test]
    fn injected_adapters_receive_exact_bytes_and_arguments() {
        let fake = Fake::default();
        fake.type_text("a\0b").unwrap();
        fake.notify("title", "message").unwrap();
        assert_eq!(fake.typed.lock().unwrap().as_slice(), ["a\0b"]);
        assert_eq!(
            fake.notices.lock().unwrap().as_slice(),
            [("title".into(), "message".into())]
        );
    }

    #[test]
    fn unavailable_native_is_not_reported_as_success() {
        let native = UnavailablePlatform;
        let error = native.type_text("secret").unwrap_err();
        assert_eq!(error.kind, PlatformErrorKind::Unavailable);
        assert!(
            native
                .prompt("unlock", true, Duration::from_secs(1))
                .is_err()
        );
    }

    #[test]
    fn quota_wrapper_uses_platform_lock_and_persists() {
        let dir =
            std::env::temp_dir().join(format!("symvault-platform-quota-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let q = QuotaCounter::new(&dir).unwrap();
        assert_eq!(q.increment("read_entry").unwrap(), 1);
        assert_eq!(q.check("read_entry", 2).unwrap(), (true, 1));
        drop(q);
        let q = QuotaCounter::new(&dir).unwrap();
        assert_eq!(q.check("read_entry", 2).unwrap(), (true, 1));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn session_keyring_is_injected_and_native_is_explicit() {
        let keyring: Arc<MemoryKeyring> = Arc::new(MemoryKeyring::new());
        let session = SessionManager::with_system_clock(keyring);
        session
            .save_passphrase(
                "/isolated/vault",
                b"bytes",
                Duration::from_secs(60),
                Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(
            session.load_passphrase("/isolated/vault").unwrap(),
            b"bytes"
        );
        assert!(NativeKeyring.get("anything").is_err());
    }

    #[test]
    fn fallback_keyring_switches_on_provider_failure_but_not_cache_miss() {
        let fallback = FallbackKeyring::new(Arc::new(FailingKeyring), false);
        assert!(!fallback.is_fallback_active());
        assert!(matches!(
            fallback.get("svc|missing"),
            Err(SessionError::NotFound)
        ));
        assert!(!fallback.is_fallback_active());

        fallback.set("svc|value", b"cached").unwrap();
        assert!(fallback.is_fallback_active());
        assert_eq!(fallback.get("svc|value").unwrap(), b"cached");
        fallback.delete("svc|value").unwrap();
        assert!(matches!(
            fallback.get("svc|value"),
            Err(SessionError::NotFound)
        ));
    }
}
