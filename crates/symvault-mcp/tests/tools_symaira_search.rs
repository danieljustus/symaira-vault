use serde::Deserialize;
use serde_json::Value;
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
    available_tools.push("symaira_search".into());
    Arc::new(ReadOnlyRuntime::new(
        EmptyStore,
        ReadOnlyRuntimeConfig {
            server_name: "symvault".into(),
            server_version: "0.0.0-symaira-search-fixture".into(),
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

#[test]
fn symaira_search_matches_source_bound_go_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-symaira-search.json"
    ))
    .expect("valid Go symaira-search fixture");
    assert_eq!(fixture.oracle.commit, "fca3f894");
    assert_eq!(
        fixture.oracle.commit_sha,
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    assert_eq!(fixture.oracle.source_files.len(), 7);
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
            .expect("Rust symaira-search stream dispatch")
            .into_iter()
            .map(|line| serde_json::from_str::<Value>(&line).expect("Rust response JSON"))
            .collect::<Vec<_>>();
        assert_eq!(actual, case.output, "case {}", case.name);
    }
}
