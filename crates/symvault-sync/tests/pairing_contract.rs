//! PAIRING-001 differential: every case in `testdata/port/pairing/contract.json`
//! is replayed against the Rust handshake implementation.
//!
//! The fixture is frozen by `scripts/rust-port/cmd/pairinggen` from the pinned
//! Go oracle and re-verified by `make pairing-differential`, so a drift on
//! either side fails: the generator's `--check` catches a Go-side change, and
//! this test catches a Rust-side one.

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use symvault_sync::pairing::{
    self, GoTime, JoinResponse, PairingFile, TokenStore, display_token, marshal_join_response,
    marshal_pairing_file, parse_join_response, parse_pairing_file, response_filenames,
    validate_pairing_token,
};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/port/pairing/contract.json"
);

fn fixture() -> Value {
    serde_json::from_slice(&fs::read(FIXTURE).expect("read pairing fixture"))
        .expect("parse pairing fixture")
}

fn decode(value: &Value, key: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value[key].as_str().expect("base64 field"))
        .expect("decode base64 field")
}

fn text(value: &Value, key: &str) -> String {
    String::from_utf8(decode(value, key)).expect("utf-8 field")
}

fn str_field(value: &Value, key: &str) -> String {
    value[key].as_str().expect("string field").to_owned()
}

/// Every case is exercised exactly once; a new oracle case that this test does
/// not know how to replay fails instead of being silently skipped.
#[test]
fn every_pairing_case_is_replayed() {
    let fixture = fixture();
    assert_eq!(fixture["schema_version"], 1);
    assert_eq!(fixture["oracle"]["commit"], "caadd5e");
    assert_eq!(fixture["oracle"]["release"], "v0.22.1");

    let cases = fixture["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty(), "fixture holds no cases");

    let mut replayed = 0usize;
    for case in cases {
        let id = case["id"].as_str().expect("case id");
        assert_eq!(case["seam"], "PAIRING-001", "case {id} has a foreign seam");
        let input = &case["input"];
        let expected = &case["expected"];
        let (group, _) = id.split_once('/').unwrap_or((id, ""));
        match group {
            "marshal" => replay_marshal(id, input, expected),
            "parse" => replay_parse(id, input, expected),
            "filenames" => replay_filenames(id, input, expected),
            "validate" => replay_validate(id, input, expected),
            "display" => replay_display(id, input, expected),
            "store" => replay_store(id, input, expected),
            other => panic!("case {id} has unhandled group {other}"),
        }
        replayed += 1;
    }
    assert_eq!(replayed, cases.len());
}

fn replay_marshal(id: &str, input: &Value, expected: &Value) {
    let created_at = GoTime::parse_rfc3339(input["created_at"].as_str().expect("created_at"))
        .unwrap_or_else(|error| panic!("case {id}: {error}"));
    let produced = match input["kind"].as_str().expect("kind") {
        "pairing_file" => marshal_pairing_file(&PairingFile {
            token: str_field(input, "token"),
            public_key: str_field(input, "public_key"),
            created_at,
        }),
        "join_response" => marshal_join_response(&JoinResponse {
            token: str_field(input, "token"),
            name: str_field(input, "name"),
            public_key: str_field(input, "public_key"),
            created_at,
        }),
        other => panic!("case {id}: unknown artifact kind {other}"),
    }
    .unwrap_or_else(|error| panic!("case {id}: {error}"));

    let want = decode(expected, "bytes_b64");
    assert_eq!(
        String::from_utf8_lossy(&produced),
        String::from_utf8_lossy(&want),
        "case {id}: artifact bytes diverged from the Go oracle"
    );
    assert_eq!(
        hex(&produced),
        expected["sha256"].as_str().expect("sha256"),
        "case {id}: artifact digest diverged"
    );
}

fn hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn replay_parse(id: &str, input: &Value, expected: &Value) {
    let data = decode(input, "data_b64");
    let want_ok = expected["ok"].as_bool().expect("ok flag");
    match input["kind"].as_str().expect("kind") {
        "pairing_file" => match parse_pairing_file(&data) {
            Ok(parsed) => {
                assert!(want_ok, "case {id}: Rust accepted what Go rejected");
                let want = &expected["parsed"];
                assert_eq!(parsed.token, want["token"], "case {id}: token");
                assert_eq!(
                    parsed.public_key, want["public_key"],
                    "case {id}: public_key"
                );
                assert_created_at(id, parsed.created_at, want);
            }
            Err(error) => assert!(
                !want_ok,
                "case {id}: Rust rejected what Go accepted: {error}"
            ),
        },
        "join_response" => match parse_join_response(&data) {
            Ok(parsed) => {
                assert!(want_ok, "case {id}: Rust accepted what Go rejected");
                let want = &expected["parsed"];
                assert_eq!(parsed.token, want["token"], "case {id}: token");
                assert_eq!(parsed.name, want["name"], "case {id}: name");
                assert_eq!(
                    parsed.public_key, want["public_key"],
                    "case {id}: public_key"
                );
                assert_created_at(id, parsed.created_at, want);
            }
            Err(error) => assert!(
                !want_ok,
                "case {id}: Rust rejected what Go accepted: {error}"
            ),
        },
        other => panic!("case {id}: unknown artifact kind {other}"),
    }
}

/// The oracle records `created_at` as Go's own `MarshalJSON` result, so the
/// comparison covers the parsed instant, the re-serialized shape (including a
/// zero offset collapsing to `Z` and `+01:60` folding to `+02:00`), and the
/// cases Go parses but refuses to marshal back.
fn assert_created_at(id: &str, parsed: GoTime, want: &Value) {
    match (
        want.get("created_at_json"),
        want.get("created_at_marshal_error"),
    ) {
        (Some(expected), None) => assert_eq!(
            parsed.to_go_json().unwrap_or_else(|error| panic!(
                "case {id}: Rust refused to marshal a time Go marshalled: {error}"
            )),
            expected.as_str().expect("created_at_json"),
            "case {id}: created_at"
        ),
        (None, Some(_)) => assert!(
            parsed.to_go_json().is_err(),
            "case {id}: Rust marshalled a time Go refused to marshal"
        ),
        _ => panic!("case {id}: oracle recorded neither one created_at outcome nor the other"),
    }
}

fn replay_filenames(id: &str, input: &Value, expected: &Value) {
    let names = response_filenames(&text(input, "token_b64"));
    let want = expected["names"].as_array().expect("names array");
    assert_eq!(names.len(), want.len(), "case {id}: filename count");
    for (produced, wanted) in names.iter().zip(want) {
        assert_eq!(produced.as_str(), wanted, "case {id}: filename");
    }
}

fn replay_validate(id: &str, input: &Value, expected: &Value) {
    let accepted = validate_pairing_token(&text(input, "token_b64")).is_ok();
    assert_eq!(
        accepted,
        expected["ok"].as_bool().expect("ok flag"),
        "case {id}: token acceptance diverged from the Go oracle"
    );
}

fn replay_display(id: &str, input: &Value, expected: &Value) {
    let token = text(input, "token_b64");
    assert_eq!(
        display_token(&token).unwrap_or_else(|error| panic!("case {id}: {error}")),
        expected["display"].as_str().expect("display"),
        "case {id}: display"
    );
    assert_eq!(
        token,
        expected["string"].as_str().expect("string"),
        "case {id}: string"
    );
}

/// Replays an operation script against the Rust store on a virtual clock.
/// Wall-clock time never enters: the oracle expresses expiry through the TTL,
/// so the same fixed `NOW` reproduces it here.
fn replay_store(id: &str, input: &Value, expected: &Value) {
    const NOW: i64 = 1_789_000_000_000;

    let ops = input["ops"].as_array().expect("ops array");
    let want = expected["results"].as_array().expect("results array");
    assert_eq!(ops.len(), want.len(), "case {id}: result cardinality");

    let mut store = TokenStore::new(pairing::DEFAULT_TOKEN_TTL_MS);
    for (index, op) in ops.iter().enumerate() {
        let want = &want[index];
        let kind = op["op"].as_str().expect("op kind");
        assert_eq!(want["op"], kind, "case {id}: op {index} kind");
        match kind {
            "set_ttl_ms" => store.set_ttl_ms(op["ttl_ms"].as_i64().expect("ttl_ms")),
            "store" => {
                store.store(
                    op["token"].as_str().expect("token"),
                    op["public_key"].as_str().expect("public_key"),
                    NOW,
                );
                assert!(
                    want["ok"].as_bool().expect("store ok"),
                    "case {id}: op {index} Go store failed but Rust store cannot"
                );
            }
            "validate" => {
                let produced = store.validate(op["token"].as_str().expect("token"), NOW);
                assert_eq!(
                    produced.is_some(),
                    want["ok"].as_bool().expect("validate ok"),
                    "case {id}: op {index} validation outcome"
                );
                assert_eq!(
                    produced.unwrap_or_default(),
                    want["public_key"].as_str().expect("public_key"),
                    "case {id}: op {index} public key"
                );
            }
            "cleanup" => store.cleanup_expired(NOW),
            other => panic!("case {id}: unknown op {other}"),
        }
    }
}

/// The fixture is the only place the register points at; a missing or
/// truncated file must fail loudly rather than quietly replay nothing.
#[test]
fn fixture_covers_every_contract_surface() {
    let fixture = fixture();
    let ids: Vec<&str> = fixture["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| case["id"].as_str().expect("id"))
        .collect();
    for group in [
        "marshal/",
        "parse/",
        "filenames/",
        "validate/",
        "display/",
        "store/",
    ] {
        assert!(
            ids.iter().any(|id| id.starts_with(group)),
            "fixture has no {group} cases"
        );
    }
}
