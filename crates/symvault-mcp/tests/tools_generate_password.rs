use serde::Deserialize;
use serde_json::Value;
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
    Arc::new(ReadOnlyRuntime::new(
        EmptyStore,
        ReadOnlyRuntimeConfig {
            server_name: "Symaira Vault MCP".into(),
            server_version: "1.0.0".into(),
            transport: "stdio".into(),
            agent_name: "fixture".into(),
            approval_mode: "none".into(),
            available_tools: read_only_tool_names(),
            allowed_paths: vec!["*".into()],
            vault_dir: "<fixture-vault>".into(),
            vault_unlocked: true,
            ..ReadOnlyRuntimeConfig::default()
        },
    ))
}

fn is_generated_password(value: &str) -> bool {
    (16..=1024).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'@'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'^'
                        | b'&'
                        | b'*'
                        | b'('
                        | b')'
                        | b'-'
                        | b'_'
                        | b'='
                        | b'+'
                        | b'['
                        | b']'
                        | b'{'
                        | b'}'
                        | b'|'
                        | b';'
                        | b':'
                        | b','
                        | b'.'
                        | b'<'
                        | b'>'
                        | b'?'
                        | b'/'
                        | b'~'
                )
        })
}

fn normalize(value: &mut Value) {
    match value {
        Value::Array(items) => items.iter_mut().for_each(normalize),
        Value::Object(map) => {
            if let Some(Value::String(text)) = map.get_mut("text")
                && is_generated_password(text)
            {
                *text = "<generated-password>".into();
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
fn generate_password_matches_source_bound_go_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-generate-password.json"
    ))
    .expect("valid Go generate_password fixture");
    assert_eq!(fixture.oracle.commit, "fca3f894");
    assert_eq!(
        fixture.oracle.commit_sha,
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    assert_eq!(fixture.oracle.source_files.len(), 8);
    assert_eq!(
        fixture.oracle.source_hash,
        "a584aef6f10a39be9f614cace4e1ee92d9743c919fec66185fef8bb1d7e11329"
    );

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
        let mut actual = run_stream(&input, &mut handler)
            .expect("Rust generate_password stream dispatch")
            .into_iter()
            .map(|line| serde_json::from_str::<Value>(&line).expect("Rust response JSON"))
            .collect::<Vec<_>>();
        let mut expected = case.output;
        actual.iter_mut().for_each(normalize);
        expected.iter_mut().for_each(normalize);
        assert_eq!(actual, expected, "case {}", case.name);
    }
}

#[test]
fn generate_password_does_not_read_store() {
    let runtime = runtime();
    let result = runtime
        .call("generate_password", &serde_json::json!({"length": 16}))
        .expect("password generation");
    assert!(!result.is_error);
    assert_eq!(result.text.len(), 16);
}
