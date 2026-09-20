use std::fs;

use serde::Deserialize;
use serde_json::Value;
use symvault_crypto::generate_identity;
use symvault_mcp::{ReadOnlyRuntimeConfig, read_only_tool_names, run_stream};
use tempfile::{TempDir, tempdir};

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

fn empty_vault() -> (TempDir, symvault_crypto::Identity) {
    let root = tempdir().expect("synthetic auth-status vault tempdir");
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
    (root, generate_identity())
}

fn runtime_config(auth_method: &str) -> ReadOnlyRuntimeConfig {
    ReadOnlyRuntimeConfig {
        server_name: "Symaira Vault MCP".into(),
        server_version: "1.0.0".into(),
        transport: "stdio".into(),
        agent_name: "fixture".into(),
        allowed_paths: vec!["*".into()],
        approval_mode: "none".into(),
        available_tools: read_only_tool_names(),
        auth_method: auth_method.into(),
        touch_id_available: false,
        cache_backend: "memory".into(),
        cache_persistent: false,
        cache_message: "OS keyring unavailable. Sessions are stored in process memory only.".into(),
        ..ReadOnlyRuntimeConfig::default()
    }
}

#[test]
fn auth_status_matches_source_bound_go_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-auth-status.json"
    ))
    .expect("valid Go auth-status fixture");
    assert_eq!(fixture.oracle.commit, "fca3f894");
    assert_eq!(
        fixture.oracle.commit_sha,
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    assert_eq!(fixture.oracle.source_files.len(), 12);
    assert_eq!(
        fixture.oracle.source_hash,
        "30f8c524c7ee29c07915a5d9945582304f0967043a417ba25c2306b3342a46dd"
    );

    for case in fixture.cases {
        let auth_method = if case.name == "touchid" {
            "touchid"
        } else {
            "passphrase"
        };
        let (root, identity) = empty_vault();
        let mut handler = symvault_mcp::ProtocolHandler::with_store_read_only_runtime(
            &fixture.server_name,
            &fixture.server_version,
            root.path(),
            identity,
            runtime_config(auth_method),
            None,
            None,
        )
        .expect("construct store-backed auth-status runtime");
        let input = case
            .input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let actual = run_stream(&input, &mut handler)
            .expect("Rust stream dispatch succeeds")
            .iter()
            .map(|line| serde_json::from_str(line).expect("Rust emits JSON responses"))
            .collect::<Vec<Value>>();
        assert_eq!(actual, case.output, "auth-status case {}", case.name);
    }
}
