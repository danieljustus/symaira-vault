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
