#![deny(unsafe_code)]

use serde::Deserialize;
use std::collections::BTreeMap;
use symvault_core::config::{Config, Profile};

#[derive(Debug, Deserialize)]
struct OracleCase {
    name: String,
    input: String,
    result: Option<OracleResult>,
    error: Option<String>,
    panic: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OracleResult {
    default_profile: String,
    profiles: Option<BTreeMap<String, Profile>>,
    saved: String,
}

#[derive(Debug, Deserialize)]
struct OracleFixture {
    oracle: serde_json::Value,
    cases: Vec<OracleCase>,
}

fn fixture() -> OracleFixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/config_profiles_contract.json");
    let fixture: OracleFixture =
        serde_json::from_slice(CONTENT).expect("decode pinned Go profile oracle");
    assert_eq!(
        fixture.oracle["commit"],
        "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
    );
    assert_eq!(fixture.oracle["release"], "v0.22.1");
    assert_eq!(fixture.oracle["source_digest"].as_str().unwrap().len(), 64);
    assert_eq!(
        fixture.oracle["generator_digest"].as_str().unwrap().len(),
        64
    );
    fixture
}

fn cases() -> Vec<OracleCase> {
    fixture().cases
}

#[test]
fn pinned_go_profile_cases_match_load_and_save() {
    let cases = cases();
    assert_eq!(cases.len(), 58);
    for case in cases {
        let loaded = Config::load_from_bytes(case.input.as_bytes());
        match (loaded, case.result, case.error, case.panic) {
            (Ok(config), Some(expected), None, None) => {
                assert_eq!(
                    config.default_profile, expected.default_profile,
                    "{}",
                    case.name
                );
                assert_eq!(config.profiles, expected.profiles, "{}", case.name);
                let actual = String::from_utf8(config.to_yaml_bytes().unwrap()).unwrap();
                let expected_yaml = expected
                    .saved
                    .replace("/fixture/root/data/symaira-vault", &config.vault_dir);
                assert_eq!(actual, expected_yaml, "{} writer", case.name);
                let round_tripped = Config::load_from_bytes(actual.as_bytes()).unwrap();
                assert_eq!(
                    round_tripped.default_profile, config.default_profile,
                    "{} round trip",
                    case.name
                );
                assert_eq!(
                    round_tripped.profiles, config.profiles,
                    "{} round trip",
                    case.name
                );
            }
            (Err(error), None, None, Some(expected)) if case.name == "null_profile" => {
                assert!(
                    error.to_string().contains("mapping") || error.to_string().contains("parse")
                );
                // Go panics here; Rust rejects the malformed ordinary input safely.
                assert!(expected.contains("nil pointer dereference"));
            }
            (Err(error), None, Some(expected), None) => {
                assert!(!expected.is_empty(), "{} error oracle", case.name);
                assert!(
                    error.to_string().contains("mapping") || error.to_string().contains("parse"),
                    "{}: {error}",
                    case.name
                );
            }
            (actual, expected, error, panic) => panic!(
                "oracle shape mismatch for {}: result={actual:?}, expected={expected:?}, error={error:?}, panic={panic:?}",
                case.name
            ),
        }
    }
}

#[test]
fn profile_null_and_scalar_fields_follow_go_observations() {
    let cases = cases();
    let null_profiles = cases
        .iter()
        .find(|case| case.name == "null_profiles")
        .unwrap();
    let config = Config::load_from_bytes(null_profiles.input.as_bytes()).unwrap();
    assert_eq!(config.profiles, None);
    assert_eq!(config.default_profile, "");

    let null_path = cases.iter().find(|case| case.name == "null_path").unwrap();
    let config = Config::load_from_bytes(null_path.input.as_bytes()).unwrap();
    assert_eq!(config.profiles.as_ref().unwrap()["empty"].vault_path, "");

    let numeric_name = cases
        .iter()
        .find(|case| case.name == "numeric_name")
        .unwrap();
    let config = Config::load_from_bytes(numeric_name.input.as_bytes()).unwrap();
    assert_eq!(
        config.profiles.as_ref().unwrap()["1"].vault_path,
        "/tmp/vault"
    );

    let numeric_path = cases
        .iter()
        .find(|case| case.name == "numeric_path")
        .unwrap();
    let config = Config::load_from_bytes(numeric_path.input.as_bytes()).unwrap();
    assert_eq!(config.profiles.as_ref().unwrap()["bad"].vault_path, "1");
}

#[test]
fn profile_lookup_with_no_profiles_matches_go() {
    let config = Config::load_from_bytes(b"defaultProfile: null\n").unwrap();
    assert!(config.profile_for_name("work").is_none());
}
