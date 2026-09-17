use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore,
    ToolCallRuntime, read_only_tool_names, run_stream,
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
    let mut secret = BTreeMap::new();
    secret.insert("password".into(), Value::String("testpass123".into()));

    let mut payment = BTreeMap::new();
    payment.insert(
        "card_number".into(),
        Value::String("4111111111111111".into()),
    );
    payment.insert("cvc".into(), Value::String("123".into()));
    payment.insert("note".into(), Value::String("safe-note".into()));

    let mut quarantine = BTreeMap::new();
    quarantine.insert("password".into(), Value::String("quarantined".into()));

    let mut classified = BTreeMap::new();
    classified.insert("password".into(), Value::String("classified-secret".into()));

    vec![
        ReadOnlyEntry {
            path: "secret".into(),
            fields: secret,
            created: "<fixture-time>".into(),
            updated: "<fixture-time>".into(),
            version: 1,
            classification: 3,
            ..ReadOnlyEntry::default()
        },
        ReadOnlyEntry {
            path: "payment".into(),
            fields: payment,
            secret_type: "payment".into(),
            created: "<fixture-time>".into(),
            updated: "<fixture-time>".into(),
            version: 1,
            ..ReadOnlyEntry::default()
        },
        ReadOnlyEntry {
            path: "classified".into(),
            fields: classified,
            created: "<fixture-time>".into(),
            updated: "<fixture-time>".into(),
            version: 1,
            classification: 3,
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
    let (allowed_paths, redact_fields) = match case_name {
        "denied_scope" => (vec!["allowed/*".into()], None),
        "explicit_allowed_redacted" => (vec!["*".into()], Some(vec!["note".into()])),
        "classified_redacted" => (vec!["*".into()], Some(vec!["password".into()])),
        _ => (vec!["*".into()], None),
    };
    let config = ReadOnlyRuntimeConfig {
        server_name: "Symaira Vault MCP".into(),
        server_version: "1.0.0".into(),
        transport: "stdio".into(),
        agent_name: "fixture".into(),
        approval_mode: "none".into(),
        can_read_values: true,
        auto_unseal: !matches!(case_name, "default_sealed" | "classified_redacted"),
        available_tools: read_only_tool_names(),
        allowed_paths,
        redact_fields,
        vault_dir: "<fixture-vault>".into(),
        vault_unlocked: true,
        ..ReadOnlyRuntimeConfig::default()
    };
    Arc::new(ReadOnlyRuntime::new(
        MemoryStore {
            entries: fixture_entries(),
        },
        config,
    ))
}

fn normalize_markers(text: &str) -> String {
    let mut result = String::new();
    let mut rest = text;
    let mut marker = 0usize;
    while let Some(start) = rest.find("<!-- DATA_") {
        result.push_str(&rest[..start]);
        let suffix = &rest[start + 10..];
        let Some(end) = suffix.find(" label=") else {
            result.push_str(&rest[start..]);
            return result;
        };
        let raw = &suffix[..end];
        if raw.len() != 16 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            result.push_str(&rest[start..]);
            return result;
        }
        marker += 1;
        let replacement = format!("<MARKER_{marker}>");
        let open_end = suffix.find(" -->").expect("opening marker boundary") + start + 10;
        result.push_str(&rest[start..open_end].replacen(raw, &replacement, 1));
        let close = format!("<!-- /DATA_{raw} -->");
        let close_start = rest[open_end..].find(&close).expect("closing marker") + open_end;
        result.push_str(&rest[open_end..close_start]);
        result.push_str(&close.replacen(raw, &replacement, 1));
        rest = &rest[close_start + close.len()..];
    }
    result.push_str(rest);
    result
}

fn normalize(value: &mut Value) {
    match value {
        Value::String(text) => {
            if (text.starts_with('{') || text.starts_with('['))
                && let Ok(mut nested) = serde_json::from_str::<Value>(text)
            {
                normalize(&mut nested);
                *text = symvault_gojson::to_string(&nested).expect("nested JSON encoding");
            } else {
                *text = normalize_markers(text);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalize),
        Value::Object(map) => map.values_mut().for_each(normalize),
        _ => {}
    }
}

#[test]
fn get_entry_value_matches_source_bound_go_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-get-value.json"
    ))
    .expect("valid Go get_entry_value fixture");
    assert_eq!(fixture.oracle.commit, "fca3f894");
    assert_eq!(
        fixture.oracle.commit_sha,
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    assert_eq!(fixture.oracle.source_files.len(), 12);
    assert_eq!(
        fixture.oracle.source_hash,
        "4485df6b3c711850f0d4b84100cd63034c0c8eb6b2ae9990e29f0f2949baf039"
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
        let actual = run_stream(&input, &mut handler)
            .expect("Rust get_entry_value stream dispatch")
            .into_iter()
            .map(|line| serde_json::from_str::<Value>(&line).expect("Rust response JSON"))
            .collect::<Vec<_>>();
        let mut actual = actual;
        let mut expected = case.output;
        actual.iter_mut().for_each(normalize);
        expected.iter_mut().for_each(normalize);
        assert_eq!(actual, expected, "case {}", case.name);
    }
}

#[test]
fn get_entry_value_fails_closed_without_capability_or_interactive_approval() {
    let config = ReadOnlyRuntimeConfig {
        agent_name: "fixture".into(),
        approval_mode: "prompt".into(),
        available_tools: read_only_tool_names(),
        allowed_paths: vec!["*".into()],
        ..ReadOnlyRuntimeConfig::default()
    };
    let runtime = ReadOnlyRuntime::new(
        MemoryStore {
            entries: fixture_entries(),
        },
        config,
    );
    let error = runtime
        .authorize("get_entry_value", &serde_json::json!({"path": "secret"}))
        .expect_err("prompt approval must fail closed without an approval bridge");
    assert!(error.is_error);
    assert!(error.text.contains("requires approval"));
}
