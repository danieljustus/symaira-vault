//! Replays `testdata/port/template/gotemplate-corpus.json` (generated from the
//! real Go `text/template` by `scripts/rust-port/cmd/gotemplategen`) against
//! the Rust interpreter. Output and error text must be byte-identical; no case
//! may be skipped.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf};
use symvault_sync::gotemplate::{PlainData, render};

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/port/template/gotemplate-corpus.json")
}

fn bytes(v: &Value) -> Vec<u8> {
    if let Some(s) = v.get("s").and_then(Value::as_str) {
        return s.as_bytes().to_vec();
    }
    if let Some(b) = v.get("b64").and_then(Value::as_str) {
        return STANDARD.decode(b).expect("valid base64");
    }
    Vec::new()
}

fn map(v: &Value) -> BTreeMap<Vec<u8>, Vec<u8>> {
    v.as_array()
        .map(|pairs| {
            pairs
                .iter()
                .map(|p| (bytes(&p["k"]), bytes(&p["v"])))
                .collect()
        })
        .unwrap_or_default()
}

/// Returns `Err(diff)` when Rust disagrees with Go for this case.
fn check_case(case: &Value) -> Result<(), String> {
    let id = case["id"].as_str().unwrap_or("?");
    let name = bytes(&case["name"]);
    let src = bytes(&case["src"]);
    let data = PlainData {
        name: bytes(&case["data"]["name"]),
        refs: map(&case["data"]["refs"]),
        values: map(&case["data"]["values"]),
    };
    let kind = case["kind"].as_str().unwrap_or("");
    let got = render(&name, &src, data);
    match (kind, got) {
        ("ok", Ok(out)) => {
            let want = bytes(&case["output"]);
            if out == want {
                Ok(())
            } else {
                Err(format!(
                    "{id}: output differs\n  go:   {:?}\n  rust: {:?}",
                    String::from_utf8_lossy(&want),
                    String::from_utf8_lossy(&out)
                ))
            }
        }
        ("parse_error" | "exec_error", Err(err)) => {
            let want = bytes(&case["error"]);
            if err == want {
                Ok(())
            } else {
                Err(format!(
                    "{id}: error differs\n  src:  {:?}\n  go:   {:?}\n  rust: {:?}",
                    String::from_utf8_lossy(&src),
                    String::from_utf8_lossy(&want),
                    String::from_utf8_lossy(&err)
                ))
            }
        }
        (kind, Ok(out)) => Err(format!(
            "{id}: Go {kind} but Rust rendered {:?}",
            String::from_utf8_lossy(&out)
        )),
        (kind, Err(err)) => Err(format!(
            "{id}: Go {kind} but Rust failed with {:?}",
            String::from_utf8_lossy(&err)
        )),
    }
}

fn load() -> Value {
    let raw = std::fs::read(corpus_path()).expect("corpus present");
    serde_json::from_slice(&raw).expect("corpus is JSON")
}

#[test]
fn rust_replays_every_go_case_byte_identically() {
    let corpus = load();
    let cases = corpus["cases"].as_array().expect("cases");
    assert!(cases.len() >= 300, "corpus too small: {}", cases.len());
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut executed = 0usize;
    for case in cases {
        *kinds
            .entry(case["kind"].as_str().unwrap_or("?").to_owned())
            .or_default() += 1;
        executed += 1;
        if let Err(diff) = check_case(case) {
            failures.push(diff);
        }
    }
    assert_eq!(executed, cases.len(), "every case must execute");
    for kind in ["ok", "parse_error", "exec_error"] {
        assert!(
            kinds.get(kind).copied().unwrap_or(0) >= 50,
            "too few {kind} cases: {kinds:?}"
        );
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ from Go:\n{}",
        failures.len(),
        cases.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn mutated_expectation_is_detected() {
    let corpus = load();
    let cases = corpus["cases"].as_array().expect("cases");
    // One successful and one failing case, each with a single expected byte flipped.
    let mut checked = 0;
    for want_kind in ["ok", "exec_error", "parse_error"] {
        let case = cases
            .iter()
            .find(|c| {
                c["kind"] == want_kind
                    && !bytes(if want_kind == "ok" {
                        &c["output"]
                    } else {
                        &c["error"]
                    })
                    .is_empty()
                    && c["output"].get("b64").is_none()
                    && c["error"].get("b64").is_none()
            })
            .expect("case of kind");
        assert!(
            check_case(case).is_ok(),
            "unmutated case must pass: {}",
            case["id"]
        );
        let mut mutated = case.clone();
        let field = if want_kind == "ok" { "output" } else { "error" };
        let mut text = mutated[field]["s"].as_str().unwrap().as_bytes().to_vec();
        let last = text.len() - 1;
        text[last] ^= 0x01;
        mutated[field]["s"] =
            Value::String(String::from_utf8(text).expect("ascii flip stays utf-8"));
        assert!(
            check_case(&mutated).is_err(),
            "mutation of {want_kind} case went unnoticed"
        );
        checked += 1;
    }
    assert_eq!(checked, 3);
}

/// Optional wider differential: `GOTEMPLATE_EXTRA_CORPUS=<file>` points at a
/// corpus written by `gotemplategen --fuzz N --seed S --out <file>`.
#[test]
fn extra_corpus_from_environment() {
    let Some(path) = std::env::var_os("GOTEMPLATE_EXTRA_CORPUS") else {
        return;
    };
    let raw = std::fs::read(path).expect("extra corpus readable");
    let corpus: Value = serde_json::from_slice(&raw).expect("extra corpus is JSON");
    let cases = corpus["cases"].as_array().expect("cases");
    let failures: Vec<String> = cases.iter().filter_map(|c| check_case(c).err()).collect();
    assert!(
        failures.is_empty(),
        "{} of {} extra cases differ from Go:\n{}",
        failures.len(),
        cases.len(),
        failures
            .iter()
            .take(30)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn json_field_formatting_matches_go_sprintf_v() {
    let corpus = load();
    let cases = corpus["value_cases"].as_array().expect("value_cases");
    assert!(cases.len() >= 40, "too few value cases: {}", cases.len());
    for case in cases {
        let text = case["json"].as_str().unwrap();
        let value: Value = serde_json::from_str(text).unwrap();
        let got = symvault_sync::gotemplate::sprint_json_value(&value);
        let want = bytes(&case["output"]);
        assert_eq!(
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&want),
            "%v of {text}"
        );
    }
}
