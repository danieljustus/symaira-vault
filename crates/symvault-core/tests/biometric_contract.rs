#![deny(unsafe_code)]
//! SESSION-003 (non-interactive half): replay of the Go-generated macOS
//! Keychain status contract, the no-op biometric manager and the Touch ID
//! passphrase item layout from `testdata/port/session/biometric.json`.
//!
//! Touch ID authentication itself, and the real Security-framework call
//! sequence, are out of reach without biometric hardware and an operator
//! keychain; see `docs/rust-port/contract-matrix.md` (SESSION-003).

use serde::Deserialize;
use symvault_core::{
    keychain_status::{
        BIOMETRIC_ACCOUNT, BIOMETRIC_SERVICE_PREFIX, BiometricItemStore, KeychainErrorKind,
        KeyringBiometricItems, biometric_service_name, keychain_status_error, truncate_at_nul,
    },
    platform::{PlatformErrorKind, TouchId, UnavailablePlatform},
    session::{Keyring, MemoryKeyring},
};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    oracle: Oracle,
    driver: Driver,
    layout: Layout,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
}

#[derive(Debug, Deserialize)]
struct Driver {
    sentinels: Vec<Sentinel>,
    statuses: Vec<StatusCase>,
    noop_manager: Vec<NoopOp>,
}

#[derive(Debug, Deserialize)]
struct Sentinel {
    name: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct StatusCase {
    status: i32,
    ok: bool,
    #[serde(default)]
    message: String,
    sentinels: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct NoopOp {
    op: String,
    ok: bool,
    #[serde(default)]
    message: String,
    sentinels: Vec<String>,
    #[serde(default)]
    bool: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct Layout {
    account: String,
    service_prefix: String,
    service_names: Vec<ServiceName>,
    load_reason: String,
    source_assertions: Vec<Assertion>,
}

#[derive(Debug, Deserialize)]
struct ServiceName {
    vault: String,
    service: String,
}

#[derive(Debug, Deserialize)]
struct Assertion {
    name: String,
    matched: bool,
}

const CONTENT: &[u8] = include_bytes!("../../../testdata/port/session/biometric.json");

fn fixture() -> Fixture {
    serde_json::from_slice(CONTENT).expect("decode Go-generated biometric fixture")
}

const ALL_KINDS: [KeychainErrorKind; 11] = [
    KeychainErrorKind::BiometricFailed,
    KeychainErrorKind::DuplicateItem,
    KeychainErrorKind::ItemNotFound,
    KeychainErrorKind::NoSuchKeychain,
    KeychainErrorKind::Invalid,
    KeychainErrorKind::Locked,
    KeychainErrorKind::ReadOnly,
    KeychainErrorKind::InteractionNotAllowed,
    KeychainErrorKind::MissingEntitlement,
    KeychainErrorKind::Internal,
    KeychainErrorKind::UnexpectedStatus,
];

/// Rejection function shared by the positive check and the negative control.
fn check_status_case(case: &StatusCase) -> Result<(), String> {
    match keychain_status_error(case.status) {
        None => {
            if case.ok {
                Ok(())
            } else {
                Err(format!(
                    "status {}: Go reports an error, port reports success",
                    case.status
                ))
            }
        }
        Some(error) => {
            if case.ok {
                return Err(format!(
                    "status {}: Go reports success, port reports an error",
                    case.status
                ));
            }
            if error.to_string() != case.message {
                return Err(format!(
                    "status {}: message differs\n go:   {}\n port: {error}",
                    case.status, case.message
                ));
            }
            if error.status() != case.status {
                return Err(format!(
                    "status {}: port keeps status {}",
                    case.status,
                    error.status()
                ));
            }
            let wrapped: Vec<&str> = ALL_KINDS
                .iter()
                .filter(|kind| **kind == error.kind())
                .map(|kind| kind.go_name())
                .collect();
            let expected: Vec<&str> = case.sentinels.iter().map(String::as_str).collect();
            if wrapped != expected {
                return Err(format!(
                    "status {}: sentinels differ: go {expected:?} port {wrapped:?}",
                    case.status
                ));
            }
            Ok(())
        }
    }
}

#[test]
fn fixture_has_pinned_provenance_and_shape() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "d13e5d0b");
    assert_eq!(fixture.oracle.release, "unreleased");
    assert_eq!(fixture.oracle.commit_sha.len(), 40);
    assert!(
        fixture
            .oracle
            .commit_sha
            .starts_with(&fixture.oracle.commit)
    );
    assert_eq!(
        fixture.oracle.source_files,
        [
            "internal/session/biometric.go",
            "internal/session/keychain_status.go",
            "internal/session/touchid_darwin.go"
        ]
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert!(
        fixture.driver.statuses.len() >= 20,
        "fixture lost status cases"
    );
    assert!(fixture.layout.source_assertions.len() >= 15);
}

#[test]
fn sentinel_messages_match_go() {
    let sentinels = fixture().driver.sentinels;
    for kind in ALL_KINDS {
        let go = sentinels
            .iter()
            .find(|s| s.name == kind.go_name())
            .unwrap_or_else(|| panic!("fixture lacks {}", kind.go_name()));
        assert_eq!(go.message, kind.sentinel_message(), "{}", kind.go_name());
    }
    // Every Go sentinel is either a port kind or one of the two biometric
    // sentinels owned by the platform layer.
    for sentinel in &sentinels {
        assert!(
            ALL_KINDS.iter().any(|k| k.go_name() == sentinel.name)
                || matches!(
                    sentinel.name.as_str(),
                    "ErrBiometricNotAvailable" | "ErrBiometricNotConfigured"
                ),
            "unmapped Go sentinel {}",
            sentinel.name
        );
    }
}

#[test]
fn every_status_maps_to_go_text_and_sentinel() {
    for case in &fixture().driver.statuses {
        check_status_case(case).unwrap_or_else(|reason| panic!("{reason}"));
    }
}

/// The fixture covers all 14 statuses Go names, success, and unknown values on
/// both signs and at the i32 extremes, so a table that only handles the named
/// ones (or only negatives) cannot pass.
#[test]
fn status_corpus_covers_named_unknown_and_extreme_values() {
    let statuses: Vec<i32> = fixture().driver.statuses.iter().map(|c| c.status).collect();
    for named in [
        0, -4, -50, -108, -128, -25291, -25292, -25293, -25294, -25295, -25299, -25300, -25308,
        -26275, -34018,
    ] {
        assert!(statuses.contains(&named), "fixture lost status {named}");
    }
    assert!(
        statuses.iter().any(|s| *s > 0),
        "no positive unknown status"
    );
    assert!(statuses.contains(&i32::MAX) && statuses.contains(&i32::MIN));
}

/// Negative control: feed a fixture entry with one field mutated through the
/// real rejection function. A comparison that merely computes a different
/// value would pass vacuously.
#[test]
fn negative_control_mutated_fixture_is_rejected() {
    let fixture = fixture();
    let original = fixture
        .driver
        .statuses
        .iter()
        .find(|c| c.status == -25300)
        .unwrap();
    let mutated_message = StatusCase {
        status: original.status,
        ok: false,
        message: original.message.replace("item not found", "item missing"),
        sentinels: original.sentinels.clone(),
    };
    let error = check_status_case(&mutated_message).expect_err("mutated message accepted");
    assert!(error.contains("message differs"), "{error}");

    let mutated_sentinel = StatusCase {
        status: original.status,
        ok: false,
        message: original.message.clone(),
        sentinels: vec!["ErrBiometricFailed".to_owned()],
    };
    let error = check_status_case(&mutated_sentinel).expect_err("mutated sentinel accepted");
    assert!(error.contains("sentinels differ"), "{error}");

    let mutated_ok = StatusCase {
        status: original.status,
        ok: true,
        message: String::new(),
        sentinels: Vec::new(),
    };
    assert!(check_status_case(&mutated_ok).is_err());
}

#[test]
fn item_address_matches_go_layout() {
    let layout = fixture().layout;
    assert_eq!(layout.account, BIOMETRIC_ACCOUNT);
    assert_eq!(layout.service_prefix, BIOMETRIC_SERVICE_PREFIX);
    assert_eq!(layout.load_reason, "Unlock Symaira Vault vault");
    for name in &layout.service_names {
        assert_eq!(
            biometric_service_name(&name.vault),
            name.service,
            "{:?}",
            name.vault
        );
    }
    assert!(layout.service_names.len() >= 5);
}

#[test]
fn pinned_source_assertions_all_hold() {
    let layout = fixture().layout;
    // All 15 assertions the generator records. A fixture that silently drops
    // one (e.g. the accessibility attribute) must fail here, not pass on a
    // subset.
    let mut required = vec![
        "item_class_generic_password",
        "item_attributes_service_account_only",
        "value_is_raw_passphrase_bytes",
        "store_accessible_when_unlocked_this_device_only",
        "store_deletes_before_add",
        "store_duplicate_updates_in_place",
        "update_replaces_value_data_only",
        "update_scoped_to_default_keychain",
        "load_checks_item_before_prompt",
        "load_missing_item_is_not_configured",
        "load_prompt_timeout_30s",
        "load_prompt_failure_is_auth_failed",
        "delete_missing_item_is_success",
        "passphrase_is_c_string",
        "save_requires_availability",
    ];
    assert_eq!(required.len(), 15);
    assert_eq!(
        layout.source_assertions.len(),
        required.len(),
        "fixture assertion set changed: {:?}",
        layout
            .source_assertions
            .iter()
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>()
    );
    required.sort_unstable();
    required.dedup();
    assert_eq!(required.len(), 15, "duplicate required name");
    for required in required {
        let assertion = layout
            .source_assertions
            .iter()
            .find(|a| a.name == required)
            .unwrap_or_else(|| panic!("fixture lost assertion {required}"));
        assert!(assertion.matched, "{required}");
    }
    assert!(layout.source_assertions.iter().all(|a| a.matched));
}

/// Go's item holds the passphrase bytes verbatim. Values that the go-keyring
/// wrapper would have rewritten (a prefix, surrounding whitespace, binary) must
/// round-trip exactly, and an embedded NUL ends the value like a C string.
#[test]
fn item_value_is_the_raw_passphrase() {
    let keyring = MemoryKeyring::new();
    let items = KeyringBiometricItems(&keyring);
    for passphrase in [
        b"plain".as_slice(),
        b" leading and trailing \n".as_slice(),
        b"go-keyring-base64:cGFzcw==".as_slice(),
        b"go-keyring-encoded:7061".as_slice(),
        "pässwörd-üñí".as_bytes(),
        b"\xff\xfe".as_slice(),
    ] {
        items.save("/fixture/vault", passphrase).unwrap();
        let key = format!(
            "{}|{}",
            biometric_service_name("/fixture/vault"),
            BIOMETRIC_ACCOUNT
        );
        assert_eq!(keyring.get(&key).unwrap(), passphrase);
        assert_eq!(&**items.load("/fixture/vault").unwrap(), passphrase);
    }
    items.save("/fixture/vault", b"ab\0cd").unwrap();
    // What was stored, read without the store's own load-side truncation: the
    // bytes after the first NUL must never reach the keychain (Go: C.CString).
    let key = format!(
        "{}|{}",
        biometric_service_name("/fixture/vault"),
        BIOMETRIC_ACCOUNT
    );
    assert_eq!(
        keyring.get(&key).unwrap(),
        b"ab",
        "save kept bytes after NUL"
    );
    assert_eq!(&**items.load("/fixture/vault").unwrap(), b"ab");
    assert_eq!(truncate_at_nul(b"ab\0cd"), b"ab");
}

#[test]
fn load_of_missing_item_is_item_not_found_and_delete_is_idempotent() {
    let keyring = MemoryKeyring::new();
    let items = KeyringBiometricItems(&keyring);
    let error = items.load("/absent").unwrap_err();
    assert_eq!(error.kind(), KeychainErrorKind::ItemNotFound);
    let go = fixture()
        .driver
        .statuses
        .into_iter()
        .find(|c| c.status == error.status())
        .unwrap();
    assert_eq!(error.to_string(), go.message);
    items.delete("/absent").unwrap();
    items.delete("/absent").unwrap();
}

/// Go's default manager is the no-op fallback until a platform claims the slot.
/// The port's equivalent is `UnavailablePlatform`; its decisions must agree
/// with the fixture's classes (availability false, authenticate fails closed).
#[test]
fn unavailable_biometrics_fail_closed_like_the_go_noop_manager() {
    let ops = fixture().driver.noop_manager;
    let platform = UnavailablePlatform;
    for op in &ops {
        match op.op.as_str() {
            "authenticator.is_available" | "after_nil_reset.authenticator.is_available" => {
                assert_eq!(op.bool, Some(platform.is_available()), "{}", op.op);
            }
            "authenticator.authenticate" => {
                assert!(!op.ok && op.sentinels == ["ErrBiometricNotAvailable"]);
                assert_eq!(op.message, "biometric authentication not available");
                let error = platform
                    .authenticate("reason", std::time::Duration::from_secs(1))
                    .unwrap_err();
                assert_eq!(error.kind, PlatformErrorKind::Unavailable);
            }
            "store.is_available" | "after_nil_reset.store.is_available" => {
                assert_eq!(op.bool, Some(false), "{}", op.op);
            }
            "store.save" | "store.load" => {
                assert!(
                    !op.ok && op.sentinels == ["ErrBiometricNotAvailable"],
                    "{}",
                    op.op
                );
            }
            "store.delete" => assert!(op.ok, "Go's no-op delete succeeds"),
            other => panic!("unmodelled no-op op {other}"),
        }
    }
    assert!(ops.len() >= 8);
}
