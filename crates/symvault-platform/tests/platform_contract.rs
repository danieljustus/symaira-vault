#![deny(unsafe_code)]

use serde::Deserialize;
use std::time::Duration;
use symvault_platform::{
    Autotype, Clipboard, Daemon, Notifier, PlatformErrorKind, SecureUi, TouchId,
    UnavailablePlatform,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    oracle: Oracle,
    cases: Option<Vec<serde_json::Value>>,
    platform_cases: Vec<PlatformCase>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
}

#[derive(Debug, Deserialize)]
struct PlatformCase {
    name: String,
    expected: String,
    native_evidence: String,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/platform/contract.json");
    serde_json::from_slice(CONTENT).expect("decode Go-generated platform fixture")
}

#[test]
fn platform_fixture_has_provenance_and_explicit_native_blocker() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "caadd5e");
    assert_eq!(fixture.oracle.release, "v0.22.1");
    assert_eq!(fixture.oracle.source_files.len(), 9);
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert!(fixture.cases.is_none());
    assert_eq!(fixture.platform_cases.len(), 4);
    assert!(
        fixture
            .platform_cases
            .iter()
            .all(|case| case.native_evidence.starts_with("injected-only;"))
    );
    assert!(
        fixture
            .platform_cases
            .iter()
            .any(|case| case.name == "clipboard_verify_unchanged" && case.expected == "error")
    );
}

#[test]
fn unavailable_native_boundaries_fail_closed() {
    let native = UnavailablePlatform;
    assert_eq!(
        native.type_text("fixture").unwrap_err().kind,
        PlatformErrorKind::Unavailable
    );
    assert_eq!(
        native.set(b"fixture").unwrap_err().kind,
        PlatformErrorKind::Unavailable
    );
    assert_eq!(
        native.notify("title", "message").unwrap_err().kind,
        PlatformErrorKind::Unavailable
    );
    assert_eq!(
        native
            .prompt("unlock", true, Duration::from_secs(1))
            .unwrap_err()
            .kind,
        PlatformErrorKind::Unavailable
    );
    assert_eq!(
        native
            .approve("delete", Duration::from_secs(1))
            .unwrap_err()
            .kind,
        PlatformErrorKind::Unavailable
    );
    assert!(!native.is_available());
    assert_eq!(
        native
            .authenticate("unlock", Duration::from_secs(1))
            .unwrap_err()
            .kind,
        PlatformErrorKind::Unavailable
    );
    assert_eq!(
        native.install().unwrap_err().kind,
        PlatformErrorKind::Unavailable
    );
    assert_eq!(
        native.uninstall().unwrap_err().kind,
        PlatformErrorKind::Unavailable
    );
    assert_eq!(
        native.status().unwrap_err().kind,
        PlatformErrorKind::Unavailable
    );
    // Clearing is safe and idempotent even when no native clipboard is linked.
    assert!(native.clear().is_ok());
}
