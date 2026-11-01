//! Replays `testdata/port/ffi/mobilebind.json` — recorded from the real Go
//! `pkg/mobilebind` functions — through the exported C ABI.

mod common;

use common::{FUNCTIONS, load_fixture, replay};

#[test]
fn replays_every_recorded_case_through_the_c_abi() {
    let fixture = load_fixture();
    let (counts, failures) = replay(&fixture);

    for function in FUNCTIONS {
        let replayed = counts.get(function).copied().unwrap_or(0);
        let recorded = fixture["step_counts"][function].as_u64().unwrap_or(0) as usize;
        eprintln!("FFI-001 {function:<26} {replayed:>4} steps");
        assert!(replayed > 0, "{function} was not exercised");
        assert_eq!(
            replayed, recorded,
            "{function}: replayed step count differs from the fixture"
        );
    }
    let total: usize = counts.values().sum();
    eprintln!(
        "FFI-001 replayed {total} steps over {} cases",
        fixture["cases"].as_array().map_or(0, Vec::len)
    );

    for failure in failures.iter().take(60) {
        eprintln!("MISMATCH {failure}");
    }
    assert!(
        failures.is_empty(),
        "{} of {total} steps differ from the Go oracle",
        failures.len()
    );
}

#[test]
fn fixture_provenance_is_complete() {
    let fixture = load_fixture();
    let oracle = &fixture["oracle"];
    assert_eq!(oracle["commit"].as_str().map(str::len), Some(40));
    assert_eq!(oracle["commit_sha"], oracle["commit"]);
    for key in ["source_digest", "generator_digest"] {
        let digest = oracle[key].as_str().expect(key);
        assert_eq!(digest.len(), 64, "{key}");
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()), "{key}");
    }
    assert_eq!(oracle["go_version"], "go1.26.6");
    assert!(oracle["dependencies"]["filippo.io/age"].is_string());
    assert_eq!(fixture["functions"].as_array().map(Vec::len), Some(13));
}
