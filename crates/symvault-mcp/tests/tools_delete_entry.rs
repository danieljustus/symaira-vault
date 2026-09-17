use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use symvault_core::policy::{Action, Conditions, Engine, Policy, Rule};
use symvault_crypto::{generate_identity, recipient_string};
use symvault_mcp::{
    ProtocolHandler, ReadOnlyRuntimeConfig, StoreReadOnlyRuntime, ToolCallRuntime,
    read_only_tool_names, run_stream,
};
use symvault_store::{Entry, EntryMetadata, Store, StoreError};
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
    state: State,
}

#[derive(Debug, Deserialize)]
struct State {
    exists: bool,
}

#[test]
fn delete_entry_policy_uses_delete_action_before_storage() {
    let (root, identity, _verifier) = write_synthetic_vault();
    let runtime = StoreReadOnlyRuntime::open(
        root.path(),
        identity,
        ReadOnlyRuntimeConfig {
            agent_name: "fixture".into(),
            can_write: true,
            allowed_paths: vec!["*".into()],
            available_tools: read_only_tool_names(),
            ..ReadOnlyRuntimeConfig::default()
        },
        Some(Engine::new([Policy {
            version: "1".into(),
            description: "deny delete fixture".into(),
            rules: vec![Rule {
                name: "deny delete".into(),
                priority: 10,
                conditions: Conditions {
                    agent_id: "fixture".into(),
                    path: "github".into(),
                    action: "delete".into(),
                    ..Conditions::default()
                },
                action: Action::Deny,
            }],
        }])),
        None,
    )
    .expect("open policy runtime");
    let error = runtime
        .authorize("delete_entry", &serde_json::json!({"path": "github"}))
        .expect_err("delete policy must deny before storage");
    assert!(error.is_error);
    assert!(error.text.contains("policy denied tool \"delete_entry\""));
    assert!(
        Store::open(root.path(), &_verifier)
            .unwrap()
            .get("github", &_verifier)
            .is_ok()
    );
}

#[test]
fn delete_entry_matches_source_bound_go_fixture_and_persists() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-delete-entry.json"
    ))
    .expect("valid Go delete_entry fixture");
    assert_eq!(fixture.oracle.commit, "fca3f894");
    assert_eq!(
        fixture.oracle.commit_sha,
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    assert_eq!(fixture.oracle.source_files.len(), 9);
    assert_eq!(
        fixture.oracle.source_hash,
        "3a3229354e809bb4099a2dbdbe1a00e815864bc2e426b763d5e9ce1ad47613ef"
    );

    for case in fixture.cases {
        let (root, identity, verifier) = write_synthetic_vault();
        let mut handler = ProtocolHandler::with_store_read_only_runtime(
            &fixture.server_name,
            &fixture.server_version,
            root.path(),
            identity,
            runtime_config(&case.name),
            None,
            None,
        )
        .expect("open concrete encrypted-store runtime");
        let input = case
            .input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let actual = run_stream(&input, &mut handler)
            .expect("Rust delete_entry stream dispatch")
            .into_iter()
            .map(|line| serde_json::from_str::<Value>(&line).expect("Rust response JSON"))
            .collect::<Vec<_>>();
        assert_eq!(actual, case.output, "case {}", case.name);

        let store = Store::open(root.path(), &verifier).expect("reopen synthetic vault");
        let exists = !matches!(
            store.get("github", &verifier),
            Err(StoreError::EntryNotFound(_))
        );
        assert_eq!(
            exists, case.state.exists,
            "persisted state for {}",
            case.name
        );
    }
}

fn runtime_config(case_name: &str) -> ReadOnlyRuntimeConfig {
    ReadOnlyRuntimeConfig {
        agent_name: "fixture".into(),
        tier: if case_name == "delete_denied_tier" {
            "read-only".into()
        } else {
            String::new()
        },
        approval_mode: if case_name == "delete_denied_approval" {
            "deny".into()
        } else {
            "none".into()
        },
        can_write: case_name != "delete_denied_write",
        allowed_paths: if case_name == "delete_denied_scope" {
            vec!["allowed/*".into()]
        } else {
            vec!["*".into()]
        },
        available_tools: read_only_tool_names(),
        vault_dir: "<fixture-vault>".into(),
        vault_unlocked: true,
        ..ReadOnlyRuntimeConfig::default()
    }
}

fn write_synthetic_vault() -> (
    tempfile::TempDir,
    symvault_crypto::Identity,
    symvault_crypto::Identity,
) {
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
    let verifier = generate_identity();
    fs::write(
        root.path().join("recipients.txt"),
        recipient_string(&verifier),
    )
    .expect("synthetic recipients");
    let store = Store::open(root.path(), &identity).expect("open synthetic vault");
    let mut data = BTreeMap::new();
    data.insert("password".into(), Value::String("StrongP@ssw0rd123".into()));
    data.insert("username".into(), Value::String("fixture-user".into()));
    store
        .write_new_entry(
            "github",
            &Entry {
                path: "github".into(),
                data,
                metadata: EntryMetadata {
                    created: "2026-01-01T00:00:00Z".into(),
                    updated: "2026-01-01T00:00:00Z".into(),
                    version: 1,
                    ..EntryMetadata::default()
                },
                ..Entry::default()
            },
            &identity,
        )
        .expect("write encrypted synthetic entry");
    (root, identity, verifier)
}
