use serde::Deserialize;
use serde_json::Value;
use symvault_mcp::{ProtocolHandler, run_stream};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    generator_digest: String,
    server_name: String,
    server_version: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_files: Vec<String>,
    source_digest: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    input: Vec<String>,
    output: Vec<Value>,
}

#[test]
fn go_generated_tools_call_fixture_matches_rust_stream() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../../testdata/port/mcp/tools-call.json"))
            .expect("valid Go-generated tools/call fixture");

    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "caadd5e");
    assert_eq!(
        fixture.oracle.commit_sha,
        "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
    );
    assert_eq!(
        fixture.oracle.source_files,
        vec![
            "internal/mcp/server/protocol.go",
            "internal/mcp/server/server_dispatch.go",
            "internal/mcp/transport/transport.go",
        ]
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.generator_digest.len(), 64);
    assert_eq!(fixture.cases.len(), 4);

    for case in &fixture.cases {
        let input = case
            .input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let mut handler = ProtocolHandler::new(&fixture.server_name, &fixture.server_version);
        let actual = run_stream(&input, &mut handler).expect("Rust stream dispatch succeeds");
        let actual = actual
            .iter()
            .map(|line| serde_json::from_str(line).expect("Rust emits JSON responses"))
            .collect::<Vec<Value>>();
        assert_eq!(actual, case.output, "fixture case {}", case.name);
    }
}

#[test]
fn go_fixture_negative_control_does_not_accept_mutated_response() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../../testdata/port/mcp/tools-call.json"))
            .expect("valid Go-generated tools/call fixture");
    let case = fixture
        .cases
        .iter()
        .find(|case| case.name == "locked_call_valid_arguments")
        .expect("fixture has locked call case");
    let input = case
        .input
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let mut handler = ProtocolHandler::new(&fixture.server_name, &fixture.server_version);
    let actual = run_stream(&input, &mut handler).expect("Rust stream dispatch succeeds");
    let actual = actual
        .iter()
        .map(|line| serde_json::from_str(line).expect("Rust emits JSON responses"))
        .collect::<Vec<Value>>();
    let mut mutated = case.output.clone();
    mutated[1]["error"]["code"] = Value::from(-32000);
    assert_ne!(
        actual, mutated,
        "a mutated oracle response must fail closed"
    );
}
