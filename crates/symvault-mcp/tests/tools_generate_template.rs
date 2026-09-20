use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore,
    read_only_tool_names, run_stream,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    server_name: String,
    server_version: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_files: Vec<String>,
    source_hash: String,
    generator_hash: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    input: Vec<String>,
    output: Vec<Value>,
}

#[derive(Clone)]
struct EmptyStore;

impl ReadOnlyStore for EmptyStore {
    fn list(&self) -> Result<Vec<ReadOnlyEntry>, String> {
        Ok(Vec::new())
    }

    fn get(&self, _path: &str) -> Result<Option<ReadOnlyEntry>, String> {
        Ok(None)
    }
}

fn runtime() -> Arc<ReadOnlyRuntime<EmptyStore>> {
    let mut available_tools = read_only_tool_names();
    available_tools.push("generate_template".into());
    Arc::new(ReadOnlyRuntime::new(
        EmptyStore,
        ReadOnlyRuntimeConfig {
            server_name: "symvault".into(),
            server_version: "0.0.0-generate-template-fixture".into(),
            transport: "stdio".into(),
            agent_name: "fixture".into(),
            approval_mode: "none".into(),
            allowed_paths: vec!["*".into()],
            available_tools,
            vault_dir: "<fixture-vault>".into(),
            vault_unlocked: true,
            ..ReadOnlyRuntimeConfig::default()
        },
    ))
}

fn normalize_text(text: &str) -> (String, usize) {
    let mut output = String::new();
    let mut remaining = text;
    let mut marker_index = 0;
    while let Some(start) = remaining.find("<!-- DATA_") {
        output.push_str(&remaining[..start]);
        remaining = &remaining[start..];
        let marker = remaining.get(10..26).expect("16-byte marker");
        if !marker.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            output.push_str(remaining);
            return (
                output,
                marker_index + usize::from(marker.starts_with("<MARKER_")),
            );
        }
        let (open_end, close_suffix) = remaining
            .find(" -->")
            .map(|index| (index + 4, " -->"))
            .or_else(|| remaining.find(" -- >").map(|index| (index + 5, " -- >")))
            .expect("opening boundary");
        let close = format!("<!-- /DATA_{marker}{close_suffix}");
        let close_start = remaining[open_end..]
            .find(&close)
            .expect("matching closing boundary")
            + open_end;
        marker_index += 1;
        let placeholder = format!("<MARKER_{marker_index}>");
        output.push_str(&remaining[..open_end].replacen(marker, &placeholder, 1));
        output.push_str(&remaining[open_end..close_start]);
        output.push_str(&close.replacen(marker, &placeholder, 1));
        remaining = &remaining[close_start + close.len()..];
    }
    output.push_str(remaining);
    (output, marker_index)
}

fn normalize_value(value: &mut Value) {
    match value {
        Value::String(text) => {
            let (normalized, _) = normalize_text(text);
            *text = normalized;
        }
        Value::Array(items) => items.iter_mut().for_each(normalize_value),
        Value::Object(map) => map.values_mut().for_each(normalize_value),
        _ => {}
    }
}

#[test]
fn generate_template_matches_source_bound_go_dry_run_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-generate-template.json"
    ))
    .expect("valid Go generate-template fixture");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "fca3f894");
    assert_eq!(
        fixture.oracle.commit_sha,
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    assert_eq!(fixture.oracle.source_files.len(), 12);
    assert_eq!(fixture.oracle.source_hash.len(), 64);
    assert_eq!(fixture.oracle.generator_hash.len(), 64);

    for case in fixture.cases {
        let mut handler = ProtocolHandler::with_tool_call_runtime(
            &fixture.server_name,
            &fixture.server_version,
            runtime(),
        );
        let input = case
            .input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let actual = run_stream(&input, &mut handler)
            .expect("Rust generate-template stream dispatch")
            .into_iter()
            .map(|line| serde_json::from_str::<Value>(&line).expect("Rust response JSON"))
            .collect::<Vec<_>>();
        let mut expected = case.output;
        expected.iter_mut().for_each(normalize_value);
        assert_eq!(actual.len(), expected.len(), "case {}", case.name);
        let mut actual = actual;
        actual.iter_mut().for_each(normalize_value);
        assert_eq!(actual, expected, "case {}", case.name);
    }
}

#[test]
fn generate_template_rejects_secret_release_and_file_output() {
    let mut handler = ProtocolHandler::with_tool_call_runtime("symvault", "fixture", runtime());
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"clientInfo\":{\"name\":\"fixture\",\"version\":\"1\"},\"capabilities\":{}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"generate_template\",\"arguments\":{\"template_type\":\"env\",\"dry_run\":false}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"generate_template\",\"arguments\":{\"template_type\":\"env\",\"dry_run\":true,\"output_path\":\"out.env\"}}}\n",
    );
    let output = run_stream(input, &mut handler).expect("Rust rejection stream");
    let values = output
        .into_iter()
        .map(|line| serde_json::from_str::<Value>(&line).expect("response JSON"))
        .collect::<Vec<_>>();
    assert!(values[1].to_string().contains("non-dry-run secret release"));
    assert!(values[1].to_string().contains("isError"));
    assert!(
        values[2]
            .to_string()
            .contains("output_path is not supported")
    );
}
