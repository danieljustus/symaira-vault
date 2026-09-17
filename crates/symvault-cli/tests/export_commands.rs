#![deny(unsafe_code)]
#![allow(dead_code)]

#[path = "../src/export_commands.rs"]
mod export_commands;

use std::{collections::BTreeMap, fs};

use serde::Deserialize;
use serde_json::json;
use symvault_sync::export::ExportEntry;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/port/cli/export.json"
);

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    oracle: Oracle,
    cases: Vec<Case>,
    invalid: Invalid,
    cancel: Cancel,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    source_digest: String,
    generator_digest: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    format: String,
    mapping: String,
    output: String,
}

#[derive(Debug, Deserialize)]
struct Invalid {
    mapping_error: String,
    format_error: String,
}

#[derive(Debug, Deserialize)]
struct Cancel {
    stderr: String,
    output_still_absent: bool,
}

#[test]
fn go_export_fixture_is_provenance_bound_and_byte_identical() {
    let fixture: Fixture = serde_json::from_str(&fs::read_to_string(FIXTURE).unwrap()).unwrap();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "fca3f894");
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert_eq!(fixture.cases.len(), 4);
    assert_eq!(
        fixture.invalid.mapping_error,
        "invalid mapping pair: \"username\""
    );
    assert_eq!(
        fixture.invalid.format_error,
        "unsupported export format: yaml"
    );
    assert_eq!(
        fixture.cancel.stderr,
        "WARNING: Vault export produces unencrypted output. All secrets will be in plaintext.\nExport canceled.\n"
    );
    assert!(fixture.cancel.output_still_absent);

    let entries = vec![
        ExportEntry {
            path: "work/example".into(),
            data: BTreeMap::from([
                ("password".into(), json!("fixture-pass")),
                ("username".into(), json!("alice")),
                ("note".into(), json!("a,b")),
            ]),
        },
        ExportEntry {
            path: "empty/otp".into(),
            data: BTreeMap::from([
                ("username".into(), json!("bob")),
                ("otp".into(), json!(null)),
            ]),
        },
    ];
    for case in fixture.cases {
        let format = export_commands::ExportFormat::parse(&case.format).unwrap();
        let mapping = export_commands::parse_mapping(&case.mapping).unwrap();
        let input = if case.name.ends_with("_empty") {
            Vec::new()
        } else {
            entries.clone()
        };
        let output =
            String::from_utf8(export_commands::render(format, &input, &mapping).unwrap()).unwrap();
        assert_eq!(output, case.output, "case {}", case.name);
    }
}
