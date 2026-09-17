use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore,
    ReadOnlyUnavailableTool, run_stream,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    generator_digest: Option<String>,
    server_name: String,
    server_version: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_files: Vec<String>,
    source_digest: Option<String>,
    source_hash: Option<String>,
    generator_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    input: Vec<String>,
    output: Vec<Value>,
}

#[derive(Clone)]
struct MemoryStore {
    entries: Vec<ReadOnlyEntry>,
}

impl ReadOnlyStore for MemoryStore {
    fn list(&self) -> Result<Vec<ReadOnlyEntry>, String> {
        Ok(self.entries.clone())
    }

    fn get(&self, path: &str) -> Result<Option<ReadOnlyEntry>, String> {
        Ok(self
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .cloned())
    }
}

fn initialized_runtime() -> ReadOnlyRuntime<MemoryStore> {
    let mut fields = BTreeMap::new();
    fields.insert("password".into(), Value::String("testpass123".into()));
    fields.insert("username".into(), Value::String("testuser".into()));
    let store = MemoryStore {
        entries: vec![ReadOnlyEntry {
            path: "github".into(),
            fields,
            created: "<fixture-time>".into(),
            updated: "<fixture-time>".into(),
            version: 1,
            ..ReadOnlyEntry::default()
        }],
    };
    let unavailable_tools = vec![
        ReadOnlyUnavailableTool {
            name: "execute_api_request".into(),
            code: "not_available".into(),
            reason: "mcp.Tool is not available in the current environment".into(),
        },
        ReadOnlyUnavailableTool {
            name: "get_entry_value".into(),
            code: "blocked_by_agent".into(),
            reason: "Tool \"get_entry_value\" requires tier \"standard\"".into(),
        },
        ReadOnlyUnavailableTool {
            name: "generate_totp".into(),
            code: "not_available".into(),
            reason: "mcp.Tool is not available in the current environment".into(),
        },
    ];
    let available_tools = [
        "get_auth_status",
        "set_auth_method",
        "symaira_audit_self",
        "autotype",
        "prepare_payment",
        "copy_to_clipboard",
        "delete_entry",
        "execute_with_secret",
        "find_entries",
        "generate_password",
        "get_entry",
        "get_entry_metadata",
        "health",
        "list_entries",
        "perplexity_search",
        "perplexity_ask",
        "request_credential",
        "run_command",
        "sanitize_output",
        "symaira_search",
        "search",
        "fetch",
        "secure_input",
        "set_entry_field",
        "request_share",
        "approve_share",
        "revoke_share",
        "list_shares",
        "generate_template",
        "secret_unseal",
        "symaira_whoami",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    ReadOnlyRuntime::new(
        store,
        ReadOnlyRuntimeConfig {
            server_name: "Symaira Vault MCP".into(),
            server_version: "1.0.0".into(),
            transport: "stdio".into(),
            agent_name: "fixture".into(),
            approval_mode: "none".into(),
            allowed_paths: vec!["*".into()],
            available_tools,
            unavailable_tools,
            vault_dir: "<fixture-vault>".into(),
            ..ReadOnlyRuntimeConfig::default()
        },
    )
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
        let open_end = remaining.find(" -->").expect("opening boundary") + 4;
        let close = format!("<!-- /DATA_{marker} -->");
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

fn normalize_value(value: &mut Value) -> usize {
    match value {
        Value::String(text) => {
            if (text.starts_with('{') || text.starts_with('['))
                && let Ok(mut nested) = serde_json::from_str::<Value>(text)
            {
                let count = normalize_value(&mut nested);
                *text = symvault_gojson::to_string(&nested).unwrap();
                return count;
            }
            let (normalized, count) = normalize_text(text);
            *text = normalized;
            count
        }
        Value::Array(items) => items.iter_mut().map(normalize_value).sum(),
        Value::Object(map) => map.values_mut().map(normalize_value).sum(),
        _ => 0,
    }
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
    assert_eq!(
        fixture.oracle.source_digest.as_deref(),
        Some("bba60775cdde857b99272a8ef56ca7a5bbe497288352e15072c0dc7ffaeb0f3d")
    );
    assert_eq!(fixture.generator_digest.as_deref().map(str::len), Some(64));
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
fn initialized_go_fixture_matches_injected_read_only_runtime() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-call-initialized.json"
    ))
    .expect("valid initialized Go tools/call fixture");
    assert_eq!(
        fixture.oracle.commit_sha,
        "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
    );
    assert_eq!(
        fixture.oracle.source_hash.as_deref(),
        Some("8763360bc35000df164ffc2d9586fcdb41b33830567f29c3617b308d7c45c8a9")
    );
    assert_eq!(
        fixture.oracle.generator_hash.as_deref().map(str::len),
        Some(64)
    );
    let case = fixture
        .cases
        .iter()
        .find(|case| case.name == "initialized_read_only_calls")
        .expect("fixture has initialized read-only case");
    let input = case
        .input
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let mut handler = ProtocolHandler::new(&fixture.server_name, &fixture.server_version);
    handler.set_tool_call_runtime(Some(Arc::new(initialized_runtime())));
    let actual = run_stream(&input, &mut handler).expect("Rust stream dispatch succeeds");
    let mut actual = actual
        .iter()
        .map(|line| serde_json::from_str(line).expect("Rust emits JSON responses"))
        .collect::<Vec<Value>>();
    let mut expected = case.output.clone();
    let actual_markers = actual.iter_mut().map(normalize_value).collect::<Vec<_>>();
    let expected_markers = expected.iter_mut().map(normalize_value).collect::<Vec<_>>();
    assert_eq!(actual_markers, expected_markers, "marker counts");
    assert_eq!(actual, expected);
}

#[test]
fn initialized_fixture_negative_control_rejects_mutated_productive_response() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-call-initialized.json"
    ))
    .expect("valid initialized Go tools/call fixture");
    let case = fixture
        .cases
        .iter()
        .find(|case| case.name == "initialized_read_only_calls")
        .expect("fixture has initialized read-only case");
    let input = case
        .input
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let mut handler = ProtocolHandler::new(&fixture.server_name, &fixture.server_version);
    handler.set_tool_call_runtime(Some(Arc::new(initialized_runtime())));
    let actual = run_stream(&input, &mut handler).expect("Rust stream dispatch succeeds");
    let actual = actual
        .iter()
        .map(|line| serde_json::from_str(line).expect("Rust emits JSON responses"))
        .collect::<Vec<Value>>();
    let mut mutated = case.output.clone();
    mutated[2]["result"]["content"][0]["text"] = Value::String("tampered".into());
    assert_ne!(
        actual, mutated,
        "a mutated productive response must fail closed"
    );
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
