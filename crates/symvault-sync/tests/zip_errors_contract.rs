//! IO-001: every Go `archive/zip` / `compress/flate` failure of the 1PUX and
//! CXF importers, not only `zip: not a valid zip file`.
//!
//! `testdata/port/import/zip-errors.json` is produced by
//! `scripts/rust-port/cmd/zipgen`: hand-assembled and systematically damaged
//! zip archives run through the REAL Go importers, recording Go's complete
//! error text or its entries.

use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use std::collections::BTreeSet;
use symvault_sync::importer::{ImportedEntry, parse_1pux, parse_cxf};

#[derive(Debug, Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    importer: String,
    input_b64: String,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    #[serde(default)]
    entries: Option<Vec<ImportedEntry>>,
    error: Option<String>,
}

const CASES: usize = 4150;

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../testdata/port/import/zip-errors.json"
    ))
    .expect("valid generated zip-errors fixture")
}

/// Compares one case with Go's recorded outcome; `None` means it matches.
fn difference(
    case: &Case,
    rust_error: Option<&str>,
    rust_entries: Option<&[ImportedEntry]>,
) -> Option<String> {
    let id = &case.id;
    match (&case.expected.error, &case.expected.entries) {
        (Some(go), _) => match (rust_error, rust_entries) {
            (Some(text), _) if text == go => None,
            (Some(text), _) => Some(format!("{id}: error differs\n  go:   {go}\n  rust: {text}")),
            (None, got) => Some(format!(
                "{id}: rust accepted {} entries, go: {go}",
                got.map_or(0, <[ImportedEntry]>::len)
            )),
        },
        (None, expected) => {
            let expected = expected.clone().unwrap_or_default();
            match (rust_error, rust_entries) {
                (Some(text), _) => Some(format!("{id}: rust error {text}")),
                (None, Some(got)) if got == expected.as_slice() => None,
                (None, got) => Some(format!(
                    "{id}: entries differ\n  go:   {expected:?}\n  rust: {got:?}"
                )),
            }
        }
    }
}

fn run(case: &Case) -> (Option<String>, Option<Vec<ImportedEntry>>) {
    let input = general_purpose::STANDARD
        .decode(&case.input_b64)
        .expect("fixture input base64");
    let result = match case.importer.as_str() {
        "1pux" => parse_1pux(&input),
        "cxf" => parse_cxf(&input),
        other => panic!("{}: unknown importer {other}", case.id),
    };
    match result {
        Ok(entries) => (None, Some(entries)),
        Err(error) => (Some(error.to_string()), None),
    }
}

#[test]
fn zip_failures_match_the_go_importers() {
    let fixture = fixture();
    assert_eq!(
        fixture.cases.len(),
        CASES,
        "fixture cardinality is part of the gate"
    );
    let mut failures = Vec::new();
    for case in &fixture.cases {
        let (error, entries) = run(case);
        if let Some(message) = difference(case, error.as_deref(), entries.as_deref()) {
            failures.push(message);
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} zip cases differ from Go:\n{}",
        failures.len(),
        fixture.cases.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The corpus must reach every distinguishable Go error family; a port that
/// collapses them (the old behavior mapped every zip failure to
/// `zip: not a valid zip file`) cannot pass while these exist.
#[test]
fn corpus_reaches_each_go_zip_error_family() {
    let fixture = fixture();
    let normalized: BTreeSet<String> = fixture
        .cases
        .iter()
        .filter_map(|case| case.expected.error.as_ref())
        .map(|text| {
            let mut out = String::new();
            let mut digits = false;
            for ch in text.chars() {
                if ch.is_ascii_digit() {
                    if !digits {
                        out.push('N');
                    }
                    digits = true;
                } else {
                    digits = false;
                    out.push(ch);
                }
            }
            out
        })
        .collect();
    for family in [
        "zip: not a valid zip file",
        "unexpected EOF",
        ": EOF",
        "zip: checksum error",
        "zip: unsupported compression algorithm",
        "flate: corrupt input before offset N",
        "bytes.Reader.ReadAt: negative offset",
    ] {
        assert!(
            normalized.iter().any(|text| text.contains(family)),
            "no corpus case reaches {family:?}"
        );
    }
    assert!(
        normalized.len() >= 25,
        "only {} distinct error texts",
        normalized.len()
    );
}

/// Negative control: the comparison must reject a wrong error text, a wrong
/// acceptance and wrong entries, so a green corpus is not vacuous.
#[test]
fn comparison_rejects_wrong_outcomes() {
    let fixture = fixture();
    let rejected = fixture
        .cases
        .iter()
        .find(|case| {
            case.expected
                .error
                .as_deref()
                .is_some_and(|text| text.contains("unexpected EOF"))
        })
        .expect("a case that fails with unexpected EOF");
    let go = rejected.expected.error.clone().unwrap();
    // The old behavior: every zip problem reported as one text.
    assert!(
        difference(
            rejected,
            Some("open 1pux zip: zip: not a valid zip file"),
            None
        )
        .is_some()
    );
    assert!(difference(rejected, None, Some(&[])).is_some());
    assert!(difference(rejected, Some(&go), None).is_none());

    let accepted = fixture
        .cases
        .iter()
        .find(|case| {
            case.expected
                .entries
                .as_ref()
                .is_some_and(|entries| !entries.is_empty())
        })
        .expect("a case that imports entries");
    let mut wrong = accepted.expected.entries.clone().unwrap();
    wrong[0].path.push('x');
    assert!(difference(accepted, None, Some(&wrong)).is_some());
    assert!(difference(accepted, Some("boom"), None).is_some());
    assert!(difference(accepted, None, accepted.expected.entries.as_deref()).is_none());
}
