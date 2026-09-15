#![deny(unsafe_code)]
//! SESSION-002's portable half: how a composite keyring key is split, which
//! keys can name a native keychain item, and the in-memory backend's
//! observable semantics.
//!
//! The native keychain round-trip stays a macOS-gated diagnostic. These rules
//! are platform-independent, so they are verifiable on every OS -- which is
//! the part of this row that had no cross-implementation evidence at all.

use serde::Deserialize;
use symvault_core::session::{Keyring, MemoryKeyring, SessionError, split_keyring_key};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    oracle: Oracle,
    split_cases: Vec<SplitCase>,
    backend_cases: Vec<BackendCase>,
    divergent_cases: Vec<DivergentCase>,
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
struct SplitCase {
    name: String,
    key: String,
    service: String,
    account: String,
    natively_addressable: bool,
}

#[derive(Debug, Deserialize)]
struct BackendStep {
    op: String,
    key: String,
    #[serde(default)]
    value: String,
    outcome: String,
    #[serde(default)]
    got: String,
}

#[derive(Debug, Deserialize)]
struct BackendCase {
    name: String,
    steps: Vec<BackendStep>,
}

#[derive(Debug, Deserialize)]
struct DivergentCase {
    name: String,
    steps: Vec<BackendStep>,
    rust_outcomes: Vec<String>,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/session/keyring-keys.json");
    serde_json::from_slice(CONTENT).expect("decode Go-generated keyring-key fixture")
}

#[test]
fn fixture_has_pinned_provenance_and_schema() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "7743fd21");
    assert_eq!(fixture.oracle.release, "unreleased");
    assert_eq!(fixture.oracle.commit_sha.len(), 40);
    assert!(
        fixture
            .oracle
            .commit_sha
            .starts_with(&fixture.oracle.commit)
    );
    assert_eq!(fixture.oracle.source_files.len(), 2);
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert!(fixture.split_cases.len() >= 12, "fixture lost split cases");
    assert!(
        fixture.backend_cases.len() >= 7,
        "fixture lost backend cases"
    );
}

/// Scripts where the Go in-memory backend is knowingly NOT opaque storage.
///
/// Its session-account `Get` parses the stored value as a session document and
/// deletes the entry when the parse fails, so a value `Set` just accepted is
/// destroyed on the first read. This side is a plain key-value store, which is
/// what `KeyringBackend`'s own documentation describes, so it returns the
/// value.
///
/// Pinned exactly -- both the Go outcome and this side's -- so the divergence
/// can neither grow nor shrink unnoticed while it is adjudicated. See
/// `docs/rust-port/session-002-memory-backend-adjudication.md`.
const KNOWN_DIVERGENCES: [&str; 2] = [
    "session_account_discards_an_opaque_value",
    "session_account_second_read_confirms_the_delete",
];

#[test]
fn the_divergence_set_is_exactly_what_is_adjudicated() {
    let mut names: Vec<String> = fixture()
        .divergent_cases
        .iter()
        .map(|case| case.name.clone())
        .collect();
    names.sort();
    let mut expected: Vec<String> = KNOWN_DIVERGENCES.iter().map(|s| (*s).to_owned()).collect();
    expected.sort();
    assert_eq!(names, expected, "the pinned divergence set changed");
}

/// The divergence must stay real: each pinned case must still differ, and this
/// side must still produce exactly the plain-store outcome the fixture records.
/// If Go is aligned later, this test fails and the row is re-adjudicated rather
/// than quietly passing.
#[test]
fn pinned_divergences_still_diverge_and_match_the_recorded_shape() {
    for case in &fixture().divergent_cases {
        let go_outcomes: Vec<&str> = case.steps.iter().map(|s| s.outcome.as_str()).collect();
        assert_ne!(
            go_outcomes, case.rust_outcomes,
            "{}: the recorded divergence no longer differs; re-adjudicate the row",
            case.name
        );
        let keyring = MemoryKeyring::new();
        let mut observed: Vec<String> = Vec::new();
        for step in &case.steps {
            observed.push(match step.op.as_str() {
                "set" => match keyring.set(&step.key, step.value.as_bytes()) {
                    Ok(()) => "ok".to_owned(),
                    Err(_) => "error".to_owned(),
                },
                "delete" => match keyring.delete(&step.key) {
                    Ok(()) => "ok".to_owned(),
                    Err(_) => "error".to_owned(),
                },
                "get" => match keyring.get(&step.key) {
                    Ok(_) => "found".to_owned(),
                    Err(SessionError::NotFound) => "not_found".to_owned(),
                    Err(_) => "error".to_owned(),
                },
                other => panic!("{}: unsupported operation {other}", case.name),
            });
        }
        assert_eq!(
            observed, case.rust_outcomes,
            "{}: this side no longer behaves as the fixture records",
            case.name
        );
    }
}

#[test]
fn key_split_matches_go_oracle() {
    for case in &fixture().split_cases {
        match split_keyring_key(&case.key) {
            Some((service, account)) => {
                assert!(
                    case.natively_addressable,
                    "{}: Go says {:?} cannot name a native item, this side split it",
                    case.name, case.key
                );
                assert_eq!(service, case.service, "service for {}", case.name);
                assert_eq!(account, case.account, "account for {}", case.name);
            }
            None => {
                assert!(
                    !case.natively_addressable,
                    "{}: Go split {:?} into ({:?}, {:?}), this side refused it",
                    case.name, case.key, case.service, case.account
                );
            }
        }
    }
}

/// The counter-example that keeps the rule honest: splitting at the FIRST
/// separator would pass every production case and silently corrupt a vault
/// path that contains one.
#[test]
fn the_fixture_distinguishes_first_from_last_separator() {
    let cases = fixture().split_cases;
    let multi: Vec<&SplitCase> = cases
        .iter()
        .filter(|case| case.key.matches('|').count() > 1)
        .collect();
    assert!(
        !multi.is_empty(),
        "fixture no longer carries a key with more than one separator"
    );
    for case in multi {
        assert!(
            case.service.contains('|'),
            "{}: the extra separator must land in the service half",
            case.name
        );
        assert!(!case.account.contains('|'), "{}: account half", case.name);
    }
}

/// And that at least one input is refused, or the check above would pass
/// vacuously for an implementation that accepts everything.
#[test]
fn the_fixture_carries_a_non_addressable_key() {
    let cases = fixture().split_cases;
    assert!(
        cases.iter().any(|case| !case.natively_addressable),
        "fixture no longer exercises a key that cannot name a native item"
    );
}

#[test]
fn memory_backend_steps_match_go_oracle() {
    for case in &fixture().backend_cases {
        let keyring = MemoryKeyring::new();
        for (index, step) in case.steps.iter().enumerate() {
            let label = format!("{} step {} ({})", case.name, index, step.op);
            match step.op.as_str() {
                "set" => {
                    let result = keyring.set(&step.key, step.value.as_bytes());
                    assert_eq!(outcome_of_unit(&result), step.outcome, "{label}");
                }
                "delete" => {
                    let result = keyring.delete(&step.key);
                    assert_eq!(outcome_of_unit(&result), step.outcome, "{label}");
                }
                "get" => {
                    let result = keyring.get(&step.key);
                    match &result {
                        Ok(value) => {
                            assert_eq!(step.outcome, "found", "{label}");
                            assert_eq!(String::from_utf8_lossy(value), step.got, "{label}: value");
                        }
                        Err(SessionError::NotFound) => {
                            assert_eq!(step.outcome, "not_found", "{label}");
                        }
                        Err(_) => assert_eq!(step.outcome, "error", "{label}"),
                    }
                }
                other => panic!("{label}: unsupported operation {other}"),
            }
        }
    }
}

fn outcome_of_unit(result: &Result<(), SessionError>) -> &'static str {
    match result {
        Ok(()) => "ok",
        Err(_) => "error",
    }
}
