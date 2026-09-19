use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore,
    ReadOnlyUnavailableTool, read_only_tool_names, run_stream,
};

#[derive(Debug, Deserialize)]
struct Fixture {
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

fn fixture_entries() -> Vec<ReadOnlyEntry> {
    let mut totp = BTreeMap::new();
    totp.insert(
        "totp".into(),
        serde_json::json!({
            "secret": "JBSWY3DPEHPK3PXP",
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
            "issuer": "Fixture",
            "account_name": "fixture@example.test"
        }),
    );
    vec![ReadOnlyEntry {
        path: "totp".into(),
        fields: totp,
        created: "<fixture-time>".into(),
        updated: "<fixture-time>".into(),
        version: 1,
        ..ReadOnlyEntry::default()
    }]
}

fn runtime(case_name: &str) -> Arc<ReadOnlyRuntime<MemoryStore>> {
    let denied_by_profile = case_name == "return_denied_approval";
    let available_tools = read_only_tool_names()
        .into_iter()
        .filter(|name| !(denied_by_profile && name == "generate_totp"))
        .collect();
    Arc::new(ReadOnlyRuntime::new(
        MemoryStore {
            entries: fixture_entries(),
        },
        ReadOnlyRuntimeConfig {
            server_name: "Symaira Vault MCP".into(),
            server_version: "1.0.0".into(),
            transport: "stdio".into(),
            agent_name: "fixture".into(),
            approval_mode: if case_name == "return_denied_approval" {
                "deny".into()
            } else {
                "none".into()
            },
            can_read_values: !denied_by_profile,
            now_unix: Some(1_700_000_000),
            available_tools,
            unavailable_tools: if denied_by_profile {
                vec![ReadOnlyUnavailableTool {
                    name: "generate_totp".into(),
                    code: "not_available".into(),
                    reason: "tool \"generate_totp\" is not available in the current environment"
                        .into(),
                }]
            } else {
                Vec::new()
            },
            allowed_paths: vec!["*".into()],
            vault_dir: "<fixture-vault>".into(),
            vault_unlocked: true,
            ..ReadOnlyRuntimeConfig::default()
        },
    ))
}

fn normalize(value: &mut Value) {
    match value {
        Value::Array(items) => items.iter_mut().for_each(normalize),
        Value::Object(map) => {
            if let Some(Value::String(text)) = map.get_mut("code")
                && (text.len() == 6 || text.len() == 8)
            {
                *text = "<totp-code>".into();
            }
            if map.contains_key("expires_at") {
                map.insert("expires_at".into(), Value::String("<fixture-time>".into()));
            }
            map.values_mut().for_each(normalize);
        }
        Value::String(text) if text.starts_with('{') || text.starts_with('[') => {
            if let Ok(mut nested) = serde_json::from_str::<Value>(text) {
                normalize(&mut nested);
                *text = symvault_gojson::to_string(&nested).expect("nested JSON encoding");
            }
        }
        _ => {}
    }
}

#[test]
fn generate_totp_matches_source_bound_go_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-generate-totp.json"
    ))
    .expect("valid Go generate_totp fixture");
    assert_eq!(fixture.oracle.commit, "fca3f894");
    assert_eq!(
        fixture.oracle.commit_sha,
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    assert_eq!(fixture.oracle.source_files.len(), 11);
    assert_eq!(
        fixture.oracle.source_hash,
        "befc6ea1d9b7227fdb76550d494b6501f31c87de85d2acef8db91e6ca76d06bf"
    );

    for case in fixture.cases {
        let mut handler = ProtocolHandler::with_tool_call_runtime(
            &fixture.server_name,
            &fixture.server_version,
            runtime(&case.name),
        );
        let input = case
            .input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let mut actual = run_stream(&input, &mut handler)
            .expect("Rust generate_totp stream dispatch")
            .into_iter()
            .map(|line| serde_json::from_str::<Value>(&line).expect("Rust response JSON"))
            .collect::<Vec<_>>();
        let mut expected = case.output;
        actual.iter_mut().for_each(normalize);
        expected.iter_mut().for_each(normalize);
        assert_eq!(actual, expected, "case {}", case.name);
    }
}
