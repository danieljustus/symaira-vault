use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;
use symvault_core::policy::{Action, Conditions, Engine, Policy, Rule};
use symvault_crypto::{Identity, generate_identity};
use symvault_mcp::store_adapter::ApprovalSeam;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyRuntimeConfig, StoreReadOnlyRuntime, ToolCallRuntime,
    read_only_tool_names, run_stream,
};
use symvault_platform::approval::{ApprovalRequest, ApprovalResult};
use symvault_store::{Entry, Store};
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
struct FixedApproval {
    response: ApprovalResult,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl ApprovalSeam for FixedApproval {
    fn is_tty_present(&self) -> bool {
        true
    }

    fn request(&self, request: &ApprovalRequest) -> ApprovalResult {
        assert!(request.details.contains("allowed/secret/password"));
        assert!(!request.details.contains("synthetic-unseal-fixture-value"));
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.response.clone()
    }
}

fn write_vault() -> (TempDir, Identity) {
    let root = tempdir().expect("synthetic MCP vault tempdir");
    fs::write(
        root.path().join("config.yaml"),
        "vault:\n  format_version: 1\n",
    )
    .expect("synthetic config");
    fs::write(
        root.path().join("identity.age"),
        b"fixture identity placeholder",
    )
    .expect("synthetic identity marker");
    fs::create_dir(root.path().join("entries")).expect("entries directory");
    let identity = generate_identity();
    let store = Store::open(root.path(), &identity).expect("open synthetic store");
    for (path, password, number) in [
        (
            "allowed/secret",
            "synthetic-unseal-fixture-value",
            Some(1_234_567.0),
        ),
        ("allowed", "synthetic-fieldless-value", None),
        ("secret", "synthetic-scope-gap-value", None),
    ] {
        let mut data = BTreeMap::new();
        data.insert("password".into(), Value::String(password.into()));
        if let Some(number) = number {
            data.insert("number".into(), serde_json::json!(number));
        }
        store
            .write_new_entry(
                path,
                &Entry {
                    path: path.into(),
                    data,
                    ..Entry::default()
                },
                &identity,
            )
            .expect("write synthetic entry");
    }
    (root, identity)
}

fn runtime(
    root: &TempDir,
    identity: Identity,
    approval_mode: &str,
    max_secrets: i64,
    policy: Option<Engine>,
) -> StoreReadOnlyRuntime {
    StoreReadOnlyRuntime::open(
        root.path(),
        identity,
        ReadOnlyRuntimeConfig {
            agent_name: "fixture".into(),
            allowed_paths: vec!["allowed".into()],
            approval_mode: approval_mode.into(),
            max_secrets_in_session: max_secrets,
            available_tools: read_only_tool_names(),
            ..ReadOnlyRuntimeConfig::default()
        },
        policy,
        None,
    )
    .expect("open secret_unseal runtime")
}

fn replay(
    runtime: StoreReadOnlyRuntime,
    server_name: &str,
    server_version: &str,
    case: &Case,
) -> Vec<Value> {
    let input = case
        .input
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let mut handler = ProtocolHandler::new(server_name, server_version);
    handler.set_tool_call_runtime(Some(Arc::new(runtime)));
    run_stream(&input, &mut handler)
        .expect("Rust stream dispatch succeeds")
        .iter()
        .map(|line| serde_json::from_str(line).expect("Rust emits JSON responses"))
        .collect()
}

fn fixture() -> Fixture {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-secret-unseal.json"
    ))
    .expect("valid source-bound Go secret_unseal fixture");
    assert_eq!(
        fixture.oracle.commit_sha,
        "0a7946748d0d1f989b268947e04ae7c6d1fc3755"
    );
    assert!(!fixture.oracle.source_files.is_empty());
    assert_eq!(fixture.oracle.source_hash.len(), 64);
    assert_eq!(fixture.oracle.generator_hash.len(), 64);
    assert!(
        read_only_tool_names()
            .iter()
            .any(|name| name == "secret_unseal")
    );
    fixture
}

#[test]
fn secret_unseal_matches_go_fixture_on_allowed_path_and_deny_mode() {
    let fixture = fixture();
    for name in ["leaf_unsealed", "numeric_scalar", "approval_denied"] {
        let case = fixture.cases.iter().find(|case| case.name == name).unwrap();
        let (root, identity) = write_vault();
        let actual = replay(
            runtime(
                &root,
                identity,
                if name == "approval_denied" {
                    "deny"
                } else {
                    "none"
                },
                0,
                None,
            ),
            &fixture.server_name,
            &fixture.server_version,
            case,
        );
        assert_eq!(actual, case.output, "case {name}");
    }
}

#[test]
fn secret_unseal_fails_closed_on_go_scope_bypass_and_policy_denial() {
    let fixture = fixture();
    let go_gap = fixture
        .cases
        .iter()
        .find(|case| case.name == "go_scope_gap")
        .unwrap();
    assert!(
        go_gap.output[1]
            .to_string()
            .contains("synthetic-scope-gap-value")
    );
    let (root, identity) = write_vault();
    let actual = replay(
        runtime(&root, identity, "none", 0, None),
        &fixture.server_name,
        &fixture.server_version,
        go_gap,
    );
    assert!(
        actual[1]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("outside allowed scope")
    );
    assert!(!actual[1].to_string().contains("synthetic-scope-gap-value"));

    let (root, identity) = write_vault();
    let policy = Engine::new([Policy {
        version: "1".into(),
        description: "deny unseal fixture".into(),
        rules: vec![Rule {
            name: "deny allowed secret".into(),
            priority: 10,
            conditions: Conditions {
                agent_id: "fixture".into(),
                path: "allowed/secret".into(),
                action: "get".into(),
                ..Conditions::default()
            },
            action: Action::Deny,
        }],
    }]);
    let runtime = runtime(&root, identity, "none", 0, Some(policy));
    let denied = runtime
        .authorize(
            "secret_unseal",
            &serde_json::json!({"handle":"op://allowed/secret/password"}),
        )
        .expect_err("handle-derived path must go through get policy");
    assert!(denied.text.contains("policy denied tool \"secret_unseal\""));
}

#[test]
fn secret_unseal_rejects_fieldless_handle_that_go_expands_to_full_entry() {
    let fixture = fixture();
    let go_case = fixture
        .cases
        .iter()
        .find(|case| case.name == "go_fieldless_handle_exposes_all_fields")
        .unwrap();
    assert!(
        go_case.output[1]
            .to_string()
            .contains("synthetic-fieldless-value")
    );

    let (root, identity) = write_vault();
    let actual = replay(
        runtime(&root, identity, "none", 0, None),
        &fixture.server_name,
        &fixture.server_version,
        go_case,
    );
    assert!(actual[1]["result"].to_string().contains("field handle"));
    assert!(actual[1]["result"]["isError"].as_bool().unwrap_or(false));
    assert!(!actual[1].to_string().contains("synthetic-fieldless-value"));
}

#[test]
fn secret_unseal_requires_approval_remembers_handles_and_enforces_session_quota() {
    let (root, identity) = write_vault();
    let approval_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let runtime =
        runtime(&root, identity, "prompt", 1, None).with_approval_seam(Arc::new(FixedApproval {
            response: ApprovalResult {
                approved: true,
                remembered: true,
                error: None,
            },
            calls: approval_calls.clone(),
        }));
    let args = serde_json::json!({"handle":"op://allowed/secret/password"});
    runtime
        .authorize("secret_unseal", &args)
        .expect("tool is allowed");
    let first = runtime.call("secret_unseal", &args).expect("first unseal");
    assert_eq!(first.text, "synthetic-unseal-fixture-value");
    runtime
        .authorize("secret_unseal", &args)
        .expect("tool remains allowed");
    let second = runtime
        .call("secret_unseal", &args)
        .expect("quota tool result");
    assert!(second.is_error);
    assert!(second.text.contains("max secrets per session exceeded"));
    assert_eq!(approval_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn secret_unseal_does_not_cache_an_unremembered_approval() {
    let fixture = fixture();
    let go_case = fixture
        .cases
        .iter()
        .find(|case| case.name == "go_unremembered_approval_bypass")
        .unwrap();
    let (root, identity) = write_vault();
    let approval_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let actual = replay(
        runtime(&root, identity, "prompt", 0, None).with_approval_seam(Arc::new(FixedApproval {
            response: ApprovalResult {
                approved: true,
                remembered: false,
                error: None,
            },
            calls: approval_calls.clone(),
        })),
        &fixture.server_name,
        &fixture.server_version,
        go_case,
    );
    assert_eq!(actual, go_case.output);
    assert_eq!(approval_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn secret_unseal_prompt_mode_without_interactive_approval_fails_closed() {
    let (root, identity) = write_vault();
    let runtime = runtime(&root, identity, "prompt", 0, None);
    runtime
        .authorize(
            "secret_unseal",
            &serde_json::json!({"handle":"op://allowed/secret/password"}),
        )
        .expect("tool is allowed before prompt");
    let error = runtime
        .call(
            "secret_unseal",
            &serde_json::json!({"handle":"op://allowed/secret/password"}),
        )
        .expect("approval denial is a tool result");
    assert!(error.is_error);
    assert!(error.text.contains("requires approval"));
    assert!(!error.text.contains("synthetic-unseal-fixture-value"));
}
