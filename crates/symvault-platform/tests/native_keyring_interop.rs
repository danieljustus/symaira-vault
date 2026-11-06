#![cfg(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
#![deny(unsafe_code)]

//! Cross-language native keyring stage. The Go `write` and `verify` stages
//! surround this test; all three stages share the disposable runner's native
//! keyring environment.

use serde::Deserialize;
use std::{env, fs, path::Path};
use symvault_core::session::Keyring;
use symvault_platform::OsKeyring;

const REPORT_ENV: &str = "SYMVAULT_NATIVE_KEYRING_INTEROP_REPORT";
const AUTH_ENV: &str = "SYMVAULT_DISPOSABLE_NATIVE_RUNNER";
const GO_PAYLOAD: &[u8] = b"go-written\0binary\xff\n|fixture";
const RUST_PAYLOAD: &[u8] = b"rust-updated\0binary\xfe\r|fixture";

#[derive(Debug, Deserialize)]
struct Report {
    schema_version: u8,
    key: String,
    go_payload: Vec<u8>,
    rust_payload: Vec<u8>,
}

#[test]
#[ignore = "requires explicit disposable hosted runner and Go write/verify stages"]
fn native_keyring_go_write_rust_update_go_read_delete() {
    assert_eq!(
        env::var("GITHUB_ACTIONS").as_deref(),
        Ok("true"),
        "cross-language keyring test is hosted-runner only"
    );
    assert_eq!(
        env::var(AUTH_ENV).as_deref(),
        Ok("1"),
        "cross-language keyring test requires disposable-runner authorization"
    );
    let path = env::var(REPORT_ENV).expect("interop report path");
    assert!(
        Path::new(&path).is_absolute(),
        "interop report must be absolute"
    );
    let report: Report = serde_json::from_slice(&fs::read(&path).expect("read Go interop report"))
        .expect("decode Go interop report");
    assert_eq!(report.schema_version, 1);
    assert!(report.key.contains('|'));
    assert_eq!(report.go_payload, GO_PAYLOAD);
    assert_eq!(report.rust_payload, RUST_PAYLOAD);

    let keyring = OsKeyring;
    assert_eq!(
        keyring.get(&report.key).expect("Rust read Go-written item"),
        GO_PAYLOAD
    );
    keyring
        .set(&report.key, RUST_PAYLOAD)
        .expect("Rust update native item");
    assert_eq!(
        keyring.get(&report.key).expect("Rust update read-back"),
        RUST_PAYLOAD
    );
}

/// The Rust half of the same boundary, runnable without Go. The Go `write` and `verify` stages are
/// recorded as an attestation (`docs/rust-port/evidence/go-removal-attestations/native-keyring-interop.<os>.json`)
/// of a live run of the test above; here Rust stores the very bytes Go stored (the attested payload),
/// updates the item, reads it back and deletes it, in a disposable native keyring.
#[test]
#[ignore = "requires explicit disposable hosted runner"]
fn native_keyring_rust_half_set_update_read_delete() {
    assert_eq!(
        env::var("GITHUB_ACTIONS").as_deref(),
        Ok("true"),
        "native keyring test is disposable-runner only"
    );
    assert_eq!(
        env::var(AUTH_ENV).as_deref(),
        Ok("1"),
        "native keyring test requires disposable-runner authorization"
    );
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let key = format!(
        "symvault:rust-cross-language-{}-{nanos}|cross-language-binary",
        std::process::id()
    );
    let keyring = OsKeyring;
    assert!(
        keyring.get(&key).is_err(),
        "native namespace preflight must be missing"
    );
    keyring
        .set(&key, GO_PAYLOAD)
        .expect("Rust store Go payload");
    assert_eq!(keyring.get(&key).expect("Rust read-back"), GO_PAYLOAD);
    keyring
        .set(&key, RUST_PAYLOAD)
        .expect("Rust update native item");
    assert_eq!(
        keyring.get(&key).expect("Rust update read-back"),
        RUST_PAYLOAD
    );
    keyring.delete(&key).expect("Rust delete native item");
    assert!(
        keyring.get(&key).is_err(),
        "native item remained after delete"
    );
}
