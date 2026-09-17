use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use symvault_sync::importer::parse_1pux;

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    kind: String,
    input_base64: Option<String>,
    expected: Vec<Value>,
    failed: bool,
    error_contains: Option<String>,
}

#[test]
fn onepux_matches_source_bound_go_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/sync/onepass.json"
    )))
    .expect("parse source-bound fixture");

    for case in fixture
        .cases
        .into_iter()
        .filter(|case| case.kind == "onepux")
    {
        let input = base64::engine::general_purpose::STANDARD
            .decode(case.input_base64.expect("onepux input"))
            .expect("decode onepux input");
        let result = parse_1pux(&input);
        if case.failed {
            let error = result.expect_err(&case.name);
            if let Some(expected) = case.error_contains {
                assert!(
                    error.to_string().contains(&expected),
                    "{}: error {:?} did not contain {:?}",
                    case.name,
                    error,
                    expected
                );
            }
        } else {
            let entries = result.expect(&case.name);
            let actual = serde_json::to_value(entries).expect("serialize onepux entries");
            assert_eq!(actual, Value::Array(case.expected), "{}", case.name);
        }
    }
}
