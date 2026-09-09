//! Platform seam crate. Native implementations belong here, not in core.
#![deny(unsafe_code)]

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{MacOsDaemon, MacOsKeyring, MacOsPlatform, MacOsTouchId};

pub use symvault_core::persistent_quota::{
    NativeQuotaPlatform, QUOTA_FILE_NAME, QuotaCounter, QuotaError, QuotaPlatform,
};
pub use symvault_core::platform::*;
pub use symvault_core::quota::AgentRateLimiter;
pub use symvault_core::session::{
    Clock, Keyring, MemoryKeyring, NativeKeyring, SessionError, SessionManager, SystemClock,
};

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
}
