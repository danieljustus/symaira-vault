#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

//! Explicit native smoke, never run by the ordinary suite. Uses only a newly
//! generated service/account namespace, never an existing vault/keychain entry.
use std::time::{SystemTime, UNIX_EPOCH};
use symvault_core::session::{Keyring, SessionError};
use symvault_platform::MacOsKeyring;

struct TestEntry {
    key: String,
    written: bool,
}
impl Drop for TestEntry {
    fn drop(&mut self) {
        if self.written && MacOsKeyring.delete(&self.key).is_err() {
            eprintln!("native test-entry cleanup failed: {}", self.key);
        }
    }
}

#[test]
#[ignore = "writes one generated test-only macOS Keychain item; run explicitly"]
fn native_keyring_binary_roundtrip_and_delete() {
    let namespace = format!(
        "symvault:rust-port-native-test-{}-{}|binary-payload",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut entry = TestEntry {
        key: namespace,
        written: false,
    };
    let keyring = MacOsKeyring;
    match keyring.get(&entry.key) {
        Err(SessionError::NotFound) => {}
        Err(error) => panic!("native keychain unavailable before test write: {error}"),
        Ok(_) => panic!("test namespace already exists; refusing to change it"),
    }
    let payload = [0, 255, 1, 128, b'\n', b'\r', b'|', 0];
    keyring
        .set(&entry.key, &payload)
        .expect("native keychain set");
    entry.written = true;
    assert_eq!(
        keyring.get(&entry.key).expect("native keychain get"),
        payload
    );
    keyring
        .set(&entry.key, b"replacement-test-bytes")
        .expect("native keychain update");
    assert_eq!(keyring.get(&entry.key).unwrap(), b"replacement-test-bytes");
    keyring.delete(&entry.key).expect("native keychain delete");
    assert!(matches!(
        keyring.get(&entry.key),
        Err(SessionError::NotFound)
    ));
    keyring
        .delete(&entry.key)
        .expect("native delete is idempotent");
    entry.written = false;
}
