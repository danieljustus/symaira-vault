//! `require_biometry` policy action (Go `server_dispatch.go`
//! `validateToolAccess` + `challengeBiometric`, `server_authorize.go`
//! `checkPolicy`), driven through a fake `TouchId`: no test can raise a real
//! Touch ID prompt.
//!
//! Deliberate stricter divergence from Go, pinned below: Go's
//! `validateToolAccess` returns `nil` (the tool proceeds) when the challenge
//! fails or is unavailable; the Rust runtime denies the call with Go's
//! challenge error text instead, and only a successful challenge allows it.

use serde_json::{Value, json};
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use symvault_core::platform::{PlatformError, PlatformErrorKind, TouchId};
use symvault_core::policy::{Action, Conditions, Engine, Policy, Rule};
use symvault_core::session::MemoryKeyring;
use symvault_crypto::generate_identity;
use symvault_mcp::{
    ReadOnlyRuntimeConfig, StoreReadOnlyRuntime, ToolCallRuntime, read_only_tool_names,
};
use symvault_store::{Entry, EntryMetadata, Store, audit::RotationConfig};
use tempfile::TempDir;

struct FakeTouchId {
    available: bool,
    outcome: Result<(), PlatformErrorKind>,
    prompts: AtomicUsize,
    reasons: Mutex<Vec<String>>,
}

impl FakeTouchId {
    fn new(available: bool, outcome: Result<(), PlatformErrorKind>) -> Arc<Self> {
        Arc::new(Self {
            available,
            outcome,
            prompts: AtomicUsize::new(0),
            reasons: Mutex::new(Vec::new()),
        })
    }
}

impl TouchId for FakeTouchId {
    fn is_available(&self) -> bool {
        self.available
    }
    fn authenticate(&self, reason: &str, _: Duration) -> Result<(), PlatformError> {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        self.reasons.lock().unwrap().push(reason.to_owned());
        self.outcome.map_err(|kind| PlatformError {
            kind,
            message: "adapter detail must not reach the agent".into(),
        })
    }
}

struct Fixture {
    root: TempDir,
    runtime: StoreReadOnlyRuntime,
    audit: symvault_mcp::SharedAuditLogger,
}

fn biometry_policy() -> Engine {
    Engine::new([Policy {
        version: "1".into(),
        description: "biometry fixture".into(),
        rules: vec![Rule {
            name: "biometry for fixture".into(),
            priority: 10,
            conditions: Conditions {
                agent_id: "fixture".into(),
                path: "*".into(),
                ..Conditions::default()
            },
            action: Action::RequireBiometry,
        }],
    }])
}

fn fixture(touch_id: Option<Arc<FakeTouchId>>) -> Fixture {
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
    let store = Store::open(root.path(), &identity).expect("open store");
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
    let keyring = MemoryKeyring::new();
    let logger = symvault_store::audit::open_with_keyring(
        "fixture",
        root.path(),
        &keyring,
        RotationConfig::default(),
    )
    .expect("audit logger");
    let audit: symvault_mcp::SharedAuditLogger = Arc::new(Mutex::new(logger));
    let mut runtime = StoreReadOnlyRuntime::open_with_audit(
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
        Some(biometry_policy()),
        Some(audit.clone()),
    )
    .expect("open runtime");
    if let Some(touch_id) = touch_id {
        runtime = runtime.with_touch_id(touch_id);
    }
    Fixture {
        root,
        runtime,
        audit,
    }
}

/// `(action, path, ok, reason)` for every audit record, in order.
fn audit_records(fixture: &Fixture) -> Vec<(String, String, bool, String)> {
    let path = fixture.audit.lock().unwrap().path().to_owned();
    let text = fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let value: Value = serde_json::from_str(line).expect("audit JSON line");
            (
                value["action"].as_str().unwrap_or_default().to_owned(),
                value["path"].as_str().unwrap_or_default().to_owned(),
                value["ok"].as_bool().unwrap_or(false),
                value["reason"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

fn args() -> Value {
    json!({"path": "github"})
}

#[test]
fn approved_challenge_allows_tool_and_audits_passed() {
    let touch = FakeTouchId::new(true, Ok(()));
    let f = fixture(Some(touch.clone()));
    f.runtime
        .authorize("get_entry_metadata", &args())
        .expect("a successful challenge allows the call");
    assert_eq!(touch.prompts.load(Ordering::SeqCst), 1);
    assert_eq!(
        *touch.reasons.lock().unwrap(),
        ["Symaira Vault agent \"fixture\" is requesting tool \"get_entry_metadata\""]
    );
    assert_eq!(
        audit_records(&f),
        [
            (
                "policy_biometry".into(),
                "github".into(),
                false,
                "policy_biometry".into()
            ),
            (
                "policy_biometry_passed".into(),
                "github".into(),
                true,
                String::new()
            ),
        ]
    );
    let result = f
        .runtime
        .call("get_entry_metadata", &args())
        .expect("allowed call runs");
    assert!(!result.is_error, "{}", result.text);
    drop(f.root);
}

#[test]
fn rejected_challenge_denies_with_go_text_and_never_runs_the_tool() {
    for kind in [
        PlatformErrorKind::Canceled,
        PlatformErrorKind::Failed,
        PlatformErrorKind::TimedOut,
    ] {
        let touch = FakeTouchId::new(true, Err(kind));
        let f = fixture(Some(touch.clone()));
        let denied = f
            .runtime
            .authorize("get_entry_metadata", &args())
            .expect_err("Rust denies on a failed challenge (Go would fall through)");
        assert!(denied.is_error);
        assert_eq!(
            denied.text,
            "biometric verification failed for tool \"get_entry_metadata\": biometric verification for get_entry_metadata failed: touch id authentication failed"
        );
        assert_eq!(touch.prompts.load(Ordering::SeqCst), 1);
        assert_eq!(
            audit_records(&f),
            [
                (
                    "policy_biometry".into(),
                    "github".into(),
                    false,
                    "policy_biometry".into()
                ),
                (
                    "policy_biometry_failed".into(),
                    "get_entry_metadata".into(),
                    false,
                    "policy_biometry_failed".into()
                ),
            ]
        );
    }
}

#[test]
fn authenticator_lost_at_prompt_time_uses_go_touch_id_not_available_text() {
    let touch = FakeTouchId::new(true, Err(PlatformErrorKind::Unavailable));
    let f = fixture(Some(touch));
    let denied = f
        .runtime
        .authorize("get_entry_metadata", &args())
        .expect_err("denied");
    assert_eq!(
        denied.text,
        "biometric verification failed for tool \"get_entry_metadata\": biometric verification for get_entry_metadata failed: touch id not available"
    );
}

#[test]
fn unavailable_authenticator_denies_with_go_text_without_prompting() {
    let touch = FakeTouchId::new(false, Ok(()));
    let f = fixture(Some(touch.clone()));
    let denied = f
        .runtime
        .authorize("get_entry_metadata", &args())
        .expect_err("denied");
    assert!(denied.is_error);
    assert_eq!(
        denied.text,
        "policy requires biometric verification for tool \"get_entry_metadata\", but biometric authentication is not available on this platform. Agent \"fixture\" cannot execute this tool"
    );
    assert_eq!(touch.prompts.load(Ordering::SeqCst), 0);
    assert_eq!(
        audit_records(&f),
        [
            (
                "policy_biometry".into(),
                "github".into(),
                false,
                "policy_biometry".into()
            ),
            (
                "policy_biometry_unavailable".into(),
                "get_entry_metadata".into(),
                false,
                "policy_biometry_unavailable".into()
            ),
        ]
    );
}

#[test]
fn runtime_without_injected_authenticator_fails_closed() {
    let f = fixture(None);
    let denied = f
        .runtime
        .authorize("get_entry_metadata", &args())
        .expect_err("default runtime has no authenticator");
    assert!(
        denied
            .text
            .starts_with("policy requires biometric verification for tool \"get_entry_metadata\""),
        "{}",
        denied.text
    );
}

#[test]
fn queries_without_an_entry_path_bypass_path_policy_as_in_go() {
    let touch = FakeTouchId::new(true, Err(PlatformErrorKind::Failed));
    let f = fixture(Some(touch.clone()));
    f.runtime
        .authorize("health", &json!({}))
        .expect("no path, no policy evaluation (Go executeTool)");
    assert_eq!(touch.prompts.load(Ordering::SeqCst), 0);
}
