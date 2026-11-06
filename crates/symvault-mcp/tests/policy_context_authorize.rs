//! The runtime's policy gate must evaluate rules against the same context Go's
//! `BuildContext` produces (no tool name; home dir, working dir and the
//! `HOME`/`GIT_BRANCH` environment populated). A deny/prompt/biometry rule that
//! Go applies must apply here, otherwise Rust is more permissive than Go.
//!
//! Go-recorded parity for the field mapping and outcomes lives in
//! `policy_build_context_contract.rs`; this file pins that the production
//! `authorize` call path really uses that context.

use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use symvault_core::policy::{Action, Conditions, Engine, Policy, Rule};
use symvault_crypto::generate_identity;
use symvault_mcp::policy_context::build_context;
use symvault_mcp::{
    ReadOnlyRuntimeConfig, StoreReadOnlyRuntime, ToolCallRuntime, read_only_tool_names,
};
use symvault_store::{Entry, EntryMetadata, Store};
use tempfile::TempDir;

fn rule(name: &str, priority: i32, action: Action, conditions: Conditions) -> Rule {
    Rule {
        name: name.into(),
        priority,
        conditions,
        action,
    }
}

fn allow_all() -> Rule {
    rule("allow-all", 0, Action::Allow, Conditions::default())
}

fn runtime(rules: Vec<Rule>) -> (TempDir, StoreReadOnlyRuntime) {
    let root = tempfile::tempdir().expect("synthetic vault");
    fs::write(
        root.path().join("config.yaml"),
        "vault:\n  format_version: 1\n",
    )
    .unwrap();
    fs::write(
        root.path().join("identity.age"),
        b"fixture identity placeholder",
    )
    .unwrap();
    fs::create_dir(root.path().join("entries")).unwrap();
    let identity = generate_identity();
    let store = Store::open(
        symvault_store::data_safety::test_support_pre_marked(root.path()),
        &identity,
    )
    .expect("open store");
    store
        .write_new_entry(
            "github",
            &Entry {
                path: "github".into(),
                data: [("username".to_owned(), json!("octo"))]
                    .into_iter()
                    .collect(),
                metadata: EntryMetadata {
                    created: "2024-01-01T00:00:00Z".into(),
                    ..EntryMetadata::default()
                },
                ..Entry::default()
            },
            &identity,
        )
        .expect("write entry");
    let runtime = StoreReadOnlyRuntime::open_with_audit(
        root.path(),
        identity,
        ReadOnlyRuntimeConfig {
            agent_name: "fixture".into(),
            transport: "stdio".into(),
            approval_mode: "none".into(),
            allowed_paths: vec!["*".into()],
            available_tools: read_only_tool_names(),
            ..ReadOnlyRuntimeConfig::default()
        },
        Some(Engine::new([Policy {
            version: "1".into(),
            description: String::new(),
            rules,
        }])),
        None,
    )
    .expect("open runtime");
    (root, runtime)
}

fn denied(runtime: &StoreReadOnlyRuntime, tool: &str) -> Option<String> {
    runtime
        .authorize(tool, &json!({"path": "github"}))
        .err()
        .map(|result| result.text)
}

#[test]
fn deny_scoped_by_allowed_tools_applies_to_every_tool_as_in_go() {
    let (_root, runtime) = runtime(vec![
        rule(
            "deny-x",
            10,
            Action::Deny,
            Conditions {
                allowed_tools: vec!["delete_entry".into()],
                ..Conditions::default()
            },
        ),
        allow_all(),
    ]);
    for tool in ["get_entry_metadata", "list_entries", "get_entry"] {
        let text = denied(&runtime, tool).unwrap_or_else(|| panic!("{tool} must be denied"));
        assert!(text.contains("deny-x"), "{tool}: {text}");
    }
}

#[test]
fn allow_scoped_by_allowed_tools_allows_every_tool_as_in_go() {
    let (_root, runtime) = runtime(vec![rule(
        "allow-x",
        0,
        Action::Allow,
        Conditions {
            allowed_tools: vec!["delete_entry".into()],
            ..Conditions::default()
        },
    )]);
    assert_eq!(denied(&runtime, "get_entry_metadata"), None);
}

#[test]
fn deny_on_home_environment_value_applies() {
    // Go always sets EnvVars["HOME"] (the key is present even when empty), so
    // a wildcard deny matches. Before the fix the map was empty in Rust.
    let (_root, runtime) = runtime(vec![
        rule(
            "deny-home",
            10,
            Action::Deny,
            Conditions {
                env_vars: BTreeMap::from([("HOME".into(), "*".into())]),
                ..Conditions::default()
            },
        ),
        allow_all(),
    ]);
    assert!(
        denied(&runtime, "get_entry_metadata")
            .expect("denied")
            .contains("deny-home")
    );
}

#[test]
fn deny_on_git_branch_key_applies() {
    let (_root, runtime) = runtime(vec![
        rule(
            "deny-branch",
            10,
            Action::Deny,
            Conditions {
                env_vars: BTreeMap::from([("GIT_BRANCH".into(), "*".into())]),
                ..Conditions::default()
            },
        ),
        allow_all(),
    ]);
    assert!(
        denied(&runtime, "get_entry_metadata")
            .expect("denied")
            .contains("deny-branch")
    );
}

#[test]
fn deny_on_working_dir_applies() {
    let working_dir = build_context("fixture", "github", "get").working_dir;
    assert!(
        working_dir.starts_with('/'),
        "process working dir resolved: {working_dir:?}"
    );
    let (_root, runtime) = runtime(vec![
        rule(
            "deny-cwd",
            10,
            Action::Deny,
            Conditions {
                working_dir: format!("{working_dir}/**"),
                ..Conditions::default()
            },
        ),
        allow_all(),
    ]);
    assert!(
        denied(&runtime, "get_entry_metadata")
            .expect("denied")
            .contains("deny-cwd")
    );
}
