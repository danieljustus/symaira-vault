#![deny(unsafe_code)]

#[cfg(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
mod supported {
    use symvault_core::session::{Keyring, SessionError};
    use symvault_platform::OsKeyring;

    #[test]
    fn malformed_key_is_rejected_before_provider_access() {
        let keyring = OsKeyring;
        for key in ["missing-separator", "", "service-only"] {
            assert!(matches!(
                keyring.get(key),
                Err(SessionError::Keyring(message)) if message == "invalid keyring key"
            ));
            assert!(matches!(
                keyring.set(key, b"fixture"),
                Err(SessionError::Keyring(message)) if message == "invalid keyring key"
            ));
            assert!(matches!(
                keyring.delete(key),
                Err(SessionError::Keyring(message)) if message == "invalid keyring key"
            ));
        }
    }
}
