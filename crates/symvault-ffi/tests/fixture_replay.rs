//! Replays `testdata/port/ffi/mobilebind.json` — recorded from the real Go
//! `pkg/mobilebind` functions — through the exported C ABI.

mod common;

use common::{FUNCTIONS, load_fixture, replay, replay_matching};

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

/// Stack, in bytes, the deep-document replay runs on. iOS gives secondary
/// threads 512 KiB; half of that must be enough for any input.
const SMALL_STACK: usize = 256 * 1024;

/// A document nested thousands of levels deep used to abort the process (stack
/// overflow, which `catch_unwind` cannot contain). Every deep case of the
/// fixture, up to and beyond `encoding/json`'s 10 000-level limit, must give
/// Go's answer on a thread with a stack far smaller than the default.
#[test]
fn deeply_nested_documents_fit_a_small_stack() {
    fn is_deep_case(id: &str) -> bool {
        id.starts_with("WriteEntryJSON/json-deep-") || id.starts_with("WriteEntryJSON/json-limit-")
    }
    let fixture = load_fixture();
    let expected = fixture["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter(|case| is_deep_case(case["id"].as_str().expect("id")))
        .count();
    assert!(
        fixture["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .any(|case| case["id"] == "WriteEntryJSON/json-deep-object-10001"),
        "the 10 001-level case is missing from the fixture"
    );
    let handle = std::thread::Builder::new()
        .name("small-stack".to_owned())
        .stack_size(SMALL_STACK)
        .spawn(move || replay_matching(&fixture, is_deep_case))
        .expect("spawn the small-stack thread");
    let (counts, failures) = handle.join().expect("the replay must not panic");
    // Every deep case writes once.
    assert_eq!(
        counts.get("WriteEntryJSON").copied().unwrap_or(0),
        expected,
        "{counts:?}"
    );
    assert!(expected >= 28, "only {expected} deep cases");
    assert!(failures.is_empty(), "{failures:#?}");
}
