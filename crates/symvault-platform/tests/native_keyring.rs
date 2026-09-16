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

/// Decodes the hex the exchange uses to carry a payload across a process
/// boundary. The payload is deliberately not valid UTF-8, so it cannot travel
/// as an argv string.
fn from_hex(text: &str) -> Vec<u8> {
    assert!(
        text.len().is_multiple_of(2),
        "hex payload must have even length"
    );
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn required(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is required for the cross-parity exchange"))
}

/// The Rust half of the cross-implementation exchange.
///
/// Go writes a value, this reads it back and asserts byte equality, then writes
/// its own value for Go to verify. Before this existed each side round-tripped
/// only its own entry and the probe reported `rust_parity: false` — two
/// independent smokes that would both stay green even if the two adapters
/// disagreed about encoding, because neither ever read the other's bytes.
///
/// Go's backend stores a `string` and Rust's takes a `&[u8]`, which is exactly
/// where a silent encoding difference would hide, so the payload is chosen to
/// be invalid UTF-8.
#[test]
#[ignore = "reads and writes one generated test-only Keychain item; run explicitly on a disposable runner"]
fn native_keyring_cross_parity() {
    assert_eq!(
        std::env::var("GITHUB_ACTIONS").ok().as_deref(),
        Some("true"),
        "the cross-parity exchange runs only on CI"
    );
    assert_eq!(
        std::env::var("SYMVAULT_DISPOSABLE_NATIVE_RUNNER")
            .ok()
            .as_deref(),
        Some("1"),
        "the cross-parity exchange requires explicit disposable-runner authorization"
    );

    let key = required("SYMVAULT_PARITY_KEY");
    let expect = from_hex(&required("SYMVAULT_PARITY_EXPECT_HEX"));
    let write = from_hex(&required("SYMVAULT_PARITY_WRITE_HEX"));

    let keyring = MacOsKeyring;
    let got = keyring
        .get(&key)
        .expect("reading the value Go wrote must succeed");
    assert_eq!(
        to_hex(&got),
        to_hex(&expect),
        "Rust read different bytes than Go wrote"
    );

    keyring
        .set(&key, &write)
        .expect("writing the value Go will verify must succeed");
}
