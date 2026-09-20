use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore,
    read_only_tool_names, run_stream,
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
    let mut alpha = BTreeMap::new();
    alpha.insert("password".into(), Value::String("synthetic".into()));
    alpha.insert("username".into(), Value::String("alice".into()));
    let mut child = BTreeMap::new();
    child.insert("token".into(), Value::String("synthetic".into()));
    let mut quarantine = BTreeMap::new();
    quarantine.insert("password".into(), Value::String("synthetic".into()));
    vec![
        ReadOnlyEntry {
            path: "alpha".into(),
            fields: alpha,
            created: "<fixture-time>".into(),
            updated: "<fixture-time>".into(),
            version: 1,
            ..ReadOnlyEntry::default()
        },
        ReadOnlyEntry {
            path: "nested/child".into(),
            fields: child,
            secret_type: "api_key".into(),
            usage_hint: "API credential".into(),
            auto_rotate: true,
            created: "<fixture-time>".into(),
            updated: "<fixture-time>".into(),
            version: 1,
            ..ReadOnlyEntry::default()
        },
        ReadOnlyEntry {
            path: "quarantine/bad".into(),
            fields: quarantine,
            created: "<fixture-time>".into(),
            updated: "<fixture-time>".into(),
            version: 1,
            ..ReadOnlyEntry::default()
        },
    ]
}

fn runtime(case_name: &str) -> Arc<ReadOnlyRuntime<MemoryStore>> {
    let allowed_paths = if case_name == "scope_denied" {
        vec!["nested/*".into()]
    } else {
        vec!["*".into()]
    };
    Arc::new(ReadOnlyRuntime::new(
        MemoryStore {
            entries: fixture_entries(),
        },
        ReadOnlyRuntimeConfig {
            server_name: "Symaira Vault MCP".into(),
            server_version: "1.0.0".into(),
            transport: "stdio".into(),
            agent_name: "fixture".into(),
            approval_mode: "none".into(),
            available_tools: read_only_tool_names(),
            allowed_paths,
            vault_dir: "<fixture-vault>".into(),
            vault_unlocked: true,
            ..ReadOnlyRuntimeConfig::default()
        },
    ))
}

fn normalize(value: &mut Value) {
    match value {
        Value::String(text) if text.starts_with('{') || text.starts_with('[') => {
            if let Ok(mut nested) = serde_json::from_str::<Value>(text) {
                normalize(&mut nested);
                *text = symvault_gojson::to_string(&nested).expect("nested JSON encoding");
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalize),
        Value::Object(map) => map.values_mut().for_each(normalize),
        _ => {}
    }
}

#[test]
fn list_entries_matches_source_bound_go_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-list-entries.json"
    ))
    .expect("valid Go list_entries fixture");
    assert_eq!(fixture.oracle.commit, "fd55bb73");
    assert_eq!(
        fixture.oracle.commit_sha,
        "fd55bb7350e67350f709cf60aea1b827cdadd40c"
    );
    assert_eq!(fixture.oracle.source_files.len(), 12);
    assert_eq!(
        fixture.oracle.source_hash,
        "bb4c874064954a0663c8ae18ab998b7d9d3a798511022a98c568e18c4943ae2e"
    );

    for case in fixture.cases {
        let runtime = runtime(&case.name);
        let mut handler = ProtocolHandler::with_tool_call_runtime(
            &fixture.server_name,
            &fixture.server_version,
            runtime,
        );
        let input = case
            .input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let mut actual = run_stream(&input, &mut handler)
            .expect("Rust list_entries stream dispatch")
            .into_iter()
            .map(|line| serde_json::from_str::<Value>(&line).expect("Rust response JSON"))
            .collect::<Vec<_>>();
        let mut expected = case.output;
        actual.iter_mut().for_each(normalize);
        expected.iter_mut().for_each(normalize);
        assert_eq!(actual, expected, "case {}", case.name);
    }
}
