use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use symvault_core::policy::{Action, Conditions, Engine, Policy, Rule};
use symvault_crypto::generate_identity;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyRuntimeConfig, ReadOnlyUnavailableTool, read_only_tool_names,
    run_stream,
};
use symvault_store::{Entry, EntryMetadata, SecretMetadata, Store};
use tempfile::tempdir;

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    server_name: String,
    server_version: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit_sha: String,
    source_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    input: Vec<String>,
    output: Vec<Value>,
}

fn fixture_config() -> ReadOnlyRuntimeConfig {
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
        vault_unlocked: true,
        ..ReadOnlyRuntimeConfig::default()
    }
}

fn policy() -> Engine {
    Engine::new([Policy {
        version: "1".into(),
        description: "synthetic MCP read fixture".into(),
        rules: vec![Rule {
            name: "allow fixture reads".into(),
            priority: 10,
            conditions: Conditions {
                agent_id: "fixture".into(),
                path: "*".into(),
                ..Conditions::default()
            },
            action: Action::Allow,
        }],
    }])
}

fn write_synthetic_vault() -> (tempfile::TempDir, symvault_crypto::Identity) {
    let root = tempdir().expect("synthetic vault tempdir");
    fs::write(
        root.path().join("config.yaml"),
        "vault:\n  format_version: 1\n",
    )
    .expect("synthetic vault config");
    fs::write(
        root.path().join("identity.age"),
        b"fixture identity placeholder",
    )
    .expect("synthetic identity marker");
    fs::create_dir(root.path().join("entries")).expect("synthetic entries directory");

    let identity = generate_identity();
    let store = Store::open(root.path(), &identity).expect("open synthetic vault");
    let mut data = BTreeMap::new();
    data.insert("password".into(), Value::String("testpass123".into()));
    data.insert("username".into(), Value::String("testuser".into()));
    store
        .write_new_entry(
            "github",
            &Entry {
                path: "github".into(),
                data,
                metadata: EntryMetadata {
                    created: "<fixture-time>".into(),
                    updated: "<fixture-time>".into(),
                    version: 1,
                    ..EntryMetadata::default()
                },
                secret_metadata: SecretMetadata::default(),
                ..Entry::default()
            },
            &identity,
        )
        .expect("write encrypted synthetic entry");
    (root, identity)
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

fn normalize(value: &mut Value, actual_root: &str) -> usize {
    match value {
        Value::String(text) => {
            if (text.starts_with('{') || text.starts_with('['))
                && let Ok(mut nested) = serde_json::from_str::<Value>(text)
            {
                let count = normalize(&mut nested, actual_root);
                *text = symvault_gojson::to_string(&nested).expect("nested JSON encoding");
                return count;
            }
            let path_count = usize::from(text == actual_root);
            if path_count > 0 {
                *text = "<fixture-vault>".into();
            }
            let (normalized, marker_count) = normalize_text(text);
            *text = normalized;
            marker_count
        }
        Value::Array(items) => items
            .iter_mut()
            .map(|item| normalize(item, actual_root))
            .sum(),
        Value::Object(map) => map
            .values_mut()
            .map(|item| normalize(item, actual_root))
            .sum(),
        _ => 0,
    }
}

#[test]
fn actual_encrypted_store_matches_go_initialized_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-call-initialized.json"
    ))
    .expect("valid Go-generated initialized tools/call fixture");
    assert_eq!(
        fixture.oracle.commit_sha,
        "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
    );
    assert_eq!(
        fixture.oracle.source_hash.as_deref(),
        Some("8763360bc35000df164ffc2d9586fcdb41b33830567f29c3617b308d7c45c8a9")
    );
    assert_eq!(read_only_tool_names().len(), 4);
    let case = fixture
        .cases
        .iter()
        .find(|case| case.name == "initialized_read_only_calls")
        .expect("fixture has initialized read-only case");
    let (root, identity) = write_synthetic_vault();
    let runtime = ProtocolHandler::with_store_read_only_runtime(
        &fixture.server_name,
        &fixture.server_version,
        root.path(),
        identity,
        fixture_config(),
        Some(policy()),
        None,
    )
    .expect("construct store-backed MCP runtime");
    let input = case
        .input
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let mut runtime = runtime;
    let actual = run_stream(&input, &mut runtime)
        .expect("Rust stream dispatch succeeds")
        .iter()
        .map(|line| serde_json::from_str(line).expect("Rust emits JSON responses"))
        .collect::<Vec<Value>>();
    let mut actual = actual;
    let mut expected = case.output.clone();
    let actual_markers = actual
        .iter_mut()
        .map(|value| normalize(value, &root.path().to_string_lossy()))
        .collect::<Vec<_>>();
    let expected_markers = expected
        .iter_mut()
        .map(|value| normalize(value, "<never-present-root>"))
        .collect::<Vec<_>>();
    assert_eq!(actual_markers, expected_markers, "marker counts");
    assert_eq!(actual, expected);
}
