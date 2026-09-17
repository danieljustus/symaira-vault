use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use serde_json::Value;
use std::io::{Cursor, Write};
use symvault_sync::importer::{ImportedEntry, parse_cxf};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

#[derive(Debug, Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    input_b64: String,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    #[serde(default)]
    entries: Option<Vec<ImportedEntry>>,
    error_contains: Option<String>,
}

#[test]
fn cxf_matches_pinned_go_fixture_and_negative_controls() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../../testdata/port/import/cxf.json"))
            .expect("valid generated CXF fixture");
    assert_eq!(
        fixture.cases.len(),
        18,
        "fixture cardinality is part of the gate"
    );
    for case in fixture.cases {
        let input = general_purpose::STANDARD
            .decode(&case.input_b64)
            .expect("fixture input base64");
        let result = parse_cxf(&input);
        match (case.expected.entries, case.expected.error_contains) {
            (Some(expected), None) => {
                let got = result.unwrap_or_else(|error| panic!("{}: {error}", case.id));
                assert_eq!(got, expected, "{}", case.id);
            }
            (None, Some(marker)) => {
                let error = result.expect_err(&case.id);
                assert!(
                    error.to_string().contains(&marker),
                    "{}: error {:?} does not contain {:?}",
                    case.id,
                    error,
                    marker
                );
            }
            (None, None) => {
                let got = result.unwrap_or_else(|error| panic!("{}: {error}", case.id));
                assert!(got.is_empty(), "{}: expected an empty successful import", case.id);
            }
            other => panic!("{}: invalid expected shape: {:?}", case.id, other),
        }
    }
}

#[test]
fn cxf_rejects_total_input_at_limit_without_allocating_a_zip() {
    let input = vec![0_u8; 100 * 1024 * 1024];
    let error = parse_cxf(&input).expect_err("input at the Go limit must fail");
    assert!(error.to_string().contains("104857600"));
}

#[test]
fn cxf_rejects_a_zip_entry_at_limit_before_decompression() {
    let mut output = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut output);
        writer
            .start_file("cxf.json", SimpleFileOptions::default())
            .expect("start synthetic oversized entry");
        let chunk = [0_u8; 1024 * 1024];
        for _ in 0..100 {
            writer.write_all(&chunk).expect("write synthetic entry");
        }
        writer.finish().expect("finish synthetic archive");
    }
    let error = parse_cxf(output.get_ref()).expect_err("entry at the Go limit must fail");
    assert!(error.to_string().contains("zip entry exceeds maximum size"));
}

#[test]
fn cxf_entry_shape_is_json_stable() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../../testdata/port/import/cxf.json"))
            .expect("valid generated CXF fixture");
    let input = general_purpose::STANDARD
        .decode(&fixture.cases[0].input_b64)
        .expect("fixture input base64");
    let got = parse_cxf(&input).expect("feature fixture parses");
    let value = serde_json::to_value(got).expect("entries serialize");
    assert!(value.is_array());
    assert!(
        value
            .as_array()
            .expect("array")
            .iter()
            .all(|entry| entry.get("path").and_then(Value::as_str).is_some())
    );
}
