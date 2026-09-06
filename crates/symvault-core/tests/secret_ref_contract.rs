#![deny(unsafe_code)]

use serde::Deserialize;
use symvault_core::secret_ref::{SecretHandle, SecretRef};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    parse_ref_cases: Vec<ParseRefCase>,
    parse_handle_cases: Vec<ParseHandleCase>,
}

#[derive(Debug, Deserialize)]
struct ParseRefCase {
    name: String,
    input: String,
    valid: bool,
    path: String,
    field: String,
    #[serde(default)]
    error_message: String,
}

#[derive(Debug, Deserialize)]
struct ParseHandleCase {
    name: String,
    input: String,
    valid: bool,
    path: String,
    field: String,
    #[serde(default)]
    string_repr: String,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/core/secret-ref-contract.json");
    serde_json::from_slice(CONTENT).expect("decode Go-generated secret-ref fixture")
}

#[test]
fn parse_ref_cases_match_go_oracle() {
    let fix = fixture();
    assert_eq!(fix.schema_version, 1);

    for tc in fix.parse_ref_cases {
        let result = SecretRef::parse(&tc.input);
        if tc.valid {
            let parsed = result.unwrap_or_else(|err| {
                panic!("case {}: expected valid, got error: {}", tc.name, err);
            });
            assert_eq!(
                parsed.path, tc.path,
                "case {}: path mismatch (input={:?})",
                tc.name, tc.input
            );
            assert_eq!(
                parsed.field, tc.field,
                "case {}: field mismatch (input={:?})",
                tc.name, tc.input
            );
            assert_eq!(
                parsed.to_op_uri(),
                format!("op://{}/{}", tc.path, tc.field),
                "case {}: to_op_uri mismatch",
                tc.name
            );
        } else {
            assert!(
                !tc.error_message.is_empty(),
                "case {}: missing error message in fixture",
                tc.name
            );
            assert!(
                result.is_err(),
                "case {}: expected error for input {:?}, got {:?}",
                tc.name,
                tc.input,
                result.unwrap()
            );
        }
    }
}

#[test]
fn parse_handle_cases_match_go_oracle() {
    let fix = fixture();
    assert_eq!(fix.schema_version, 1);

    for tc in fix.parse_handle_cases {
        let result = SecretHandle::parse(&tc.input);
        if tc.valid {
            let handle = result.unwrap_or_else(|| {
                panic!("case {}: expected valid handle for {:?}", tc.name, tc.input);
            });
            assert_eq!(handle.path, tc.path, "case {}: path mismatch", tc.name);
            let expected_field = if tc.field.is_empty() {
                None
            } else {
                Some(tc.field.clone())
            };
            assert_eq!(
                handle.field, expected_field,
                "case {}: field mismatch",
                tc.name
            );
            assert_eq!(
                handle.to_string(),
                tc.string_repr,
                "case {}: string_repr mismatch",
                tc.name
            );
        } else {
            assert!(
                result.is_none(),
                "case {}: expected invalid handle for input {:?}, got {:?}",
                tc.name,
                tc.input,
                result.unwrap()
            );
        }
    }
}

#[test]
fn secret_ref_to_handle_conversion_preserves_semantics() {
    let r = SecretRef::new("work/aws", "password");
    let h = r.to_handle();
    assert_eq!(h.path, "work/aws");
    assert_eq!(h.field.as_deref(), Some("password"));
    assert_eq!(h.to_string(), "op://work/aws/password");

    let back = h.to_secret_ref().expect("convert back");
    assert_eq!(back, r);
}

#[test]
fn property_handle_roundtrip_all_synthesized_pairs() {
    let paths = [
        "a",
        "foo",
        "foo/bar",
        "long/nested/vault/path",
        "service.account",
    ];
    let fields = ["token", "secret", "password", "api_key", "pin"];

    for p in paths {
        for f in fields {
            let handle = SecretHandle::new(p, Some(f));
            let s = handle.to_string();
            let parsed = SecretHandle::parse(&s).expect("roundtrip parse");
            assert_eq!(parsed.path, p);
            assert_eq!(parsed.field.as_deref(), Some(f));

            let r = SecretRef::new(p, f);
            let parsed_ref = SecretRef::parse(&s).expect("parse op uri as ref");
            assert_eq!(parsed_ref, r);
        }
    }
}
