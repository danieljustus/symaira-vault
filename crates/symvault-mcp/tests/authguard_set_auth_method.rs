//! MCP `set_auth_method` (Go `internal/mcp/server/tools_auth.go`
//! `handleSetAuthMethod`) over fake Touch ID and a fake session/keychain
//! backend. The Go-oracle byte comparison for the states reachable without a
//! real Touch ID prompt lives in `crates/symvault-cli/tests/mcp_set_auth_method_differential.rs`.

use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use symvault_core::platform::{PlatformError, PlatformErrorKind, TouchId};
use symvault_core::session::MemoryKeyring;
use symvault_crypto::generate_identity;
use symvault_mcp::authguard::AuthMethodBackend;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyRuntimeConfig, StoreReadOnlyRuntime, read_only_tool_names, run_stream,
};
use symvault_store::{Store, audit::RotationConfig};
use tempfile::TempDir;
use zeroize::Zeroizing;

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

#[derive(Default)]
struct FakeBackend {
    available: bool,
    session: Option<Vec<u8>>,
    clear_error: Option<String>,
    saved: Mutex<Vec<(String, Vec<u8>)>>,
    cleared: AtomicUsize,
}

impl AuthMethodBackend for FakeBackend {
    fn biometric_available(&self) -> bool {
        self.available
    }
    fn load_session_passphrase(&self, _vault_dir: &str) -> Option<Zeroizing<Vec<u8>>> {
        self.session.clone().map(Zeroizing::new)
    }
    fn save_biometric_passphrase(&self, vault_dir: &Path, passphrase: &[u8]) -> Result<(), String> {
        self.saved.lock().unwrap().push((
            vault_dir.to_string_lossy().into_owned(),
            passphrase.to_vec(),
        ));
        Ok(())
    }
    fn clear_biometric_passphrase(&self, _vault_dir: &Path) -> Result<(), String> {
        self.cleared.fetch_add(1, Ordering::SeqCst);
        self.clear_error.clone().map_or(Ok(()), Err)
    }
}

struct Fixture {
    root: TempDir,
    handler: ProtocolHandler,
    audit: symvault_mcp::SharedAuditLogger,
}

fn fixture(
    can_manage_config: bool,
    touch_id: Option<Arc<FakeTouchId>>,
    backend: Option<Arc<FakeBackend>>,
) -> Fixture {
    let root = tempfile::tempdir().expect("synthetic vault");
    fs::write(
        root.path().join("config.yaml"),
        "authMethod: passphrase\nuseTouchID: false\n",
    )
    .unwrap();
    fs::write(
        root.path().join("identity.age"),
        b"fixture identity placeholder",
    )
    .unwrap();
    fs::create_dir(root.path().join("entries")).unwrap();
    let identity = generate_identity();
    let _ = Store::open(root.path(), &identity).expect("open store");
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
        None,
        Some(audit.clone()),
    )
    .expect("open runtime")
    .with_can_manage_config(can_manage_config);
    if let Some(touch_id) = touch_id {
        runtime = runtime.with_touch_id(touch_id);
    }
    if let Some(backend) = backend {
        runtime = runtime.with_auth_method_backend(backend);
    }
    let handler = ProtocolHandler::with_tool_call_runtime("symaira", "1.0.0", Arc::new(runtime));
    Fixture {
        root,
        handler,
        audit,
    }
}

/// Sends `initialize` + the given tool calls and returns the responses after
/// the initialize reply.
fn call(f: &mut Fixture, calls: &[(&str, Value)]) -> Vec<Value> {
    let mut frames = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ];
    for (index, (name, arguments)) in calls.iter().enumerate() {
        frames.push(json!({"jsonrpc":"2.0","id":index + 2,"method":"tools/call","params":{"name":name,"arguments":arguments}}));
    }
    let input = frames
        .iter()
        .map(|frame| format!("{frame}\n"))
        .collect::<String>();
    run_stream(&input, &mut f.handler)
        .expect("stream")
        .iter()
        .skip(1)
        .map(|line| serde_json::from_str(line).expect("JSON response"))
        .collect()
}

fn text_of(response: &Value) -> (&str, bool) {
    (
        response["result"]["content"][0]["text"].as_str().unwrap(),
        response["result"]["isError"].as_bool().unwrap(),
    )
}

fn audit_records(f: &Fixture) -> Vec<(String, String, bool)> {
    let path = f.audit.lock().unwrap().path().to_owned();
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let value: Value = serde_json::from_str(line).unwrap();
            (
                value["action"].as_str().unwrap_or_default().to_owned(),
                value["path"].as_str().unwrap_or_default().to_owned(),
                value["ok"].as_bool().unwrap_or(false),
            )
        })
        .collect()
}

fn config_text(f: &Fixture) -> String {
    fs::read_to_string(f.root.path().join("config.yaml")).unwrap()
}

#[test]
fn profile_without_can_manage_config_is_denied_with_go_rpc_error() {
    let mut f = fixture(false, None, None);
    let responses = call(
        &mut f,
        &[("set_auth_method", json!({"method": "passphrase"}))],
    );
    assert_eq!(
        responses[0],
        json!({"error":{"message":"agent \"fixture\" cannot manage Symaira Vault configuration","code":-32603},"jsonrpc":"2.0","id":2})
    );
    assert_eq!(
        audit_records(&f),
        [(
            "auth_config_denied".to_owned(),
            "<config>".to_owned(),
            false
        )]
    );
}

#[test]
fn argument_errors_are_tool_errors_with_go_texts() {
    let mut f = fixture(true, None, None);
    let responses = call(
        &mut f,
        &[
            ("set_auth_method", json!({})),
            ("set_auth_method", json!({"method": 7})),
            ("set_auth_method", json!({"method": "Bogus"})),
        ],
    );
    assert_eq!(
        text_of(&responses[0]),
        ("missing string argument \"method\"", true)
    );
    assert_eq!(
        text_of(&responses[1]),
        ("argument \"method\" is not a string", true)
    );
    // Go quotes the caller's original spelling, not the normalized one.
    assert_eq!(
        text_of(&responses[2]),
        (
            "invalid authMethod \"Bogus\" (valid: passphrase, touchid)",
            true
        )
    );
    assert!(audit_records(&f).is_empty());
}

#[test]
fn touchid_without_a_store_or_session_matches_go() {
    let mut f = fixture(true, None, None);
    let responses = call(&mut f, &[("set_auth_method", json!({"method": "touchid"}))]);
    assert_eq!(
        text_of(&responses[0]),
        (
            "Touch ID is not available in this Symaira Vault build or on this Mac",
            true
        )
    );

    let backend = Arc::new(FakeBackend {
        available: true,
        ..FakeBackend::default()
    });
    let mut f = fixture(true, None, Some(backend.clone()));
    let responses = call(
        &mut f,
        &[("set_auth_method", json!({"method": "touch-id"}))],
    );
    assert_eq!(
        text_of(&responses[0]),
        (
            "Touch ID setup requires an active Symaira Vault session; run symvault unlock first",
            true
        )
    );
    assert!(backend.saved.lock().unwrap().is_empty());
    assert!(config_text(&f).contains("authMethod: passphrase"));
}

#[test]
fn touchid_with_session_and_approved_challenge_saves_item_and_config() {
    let touch = FakeTouchId::new(true, Ok(()));
    let backend = Arc::new(FakeBackend {
        available: true,
        session: Some(b"hunter2".to_vec()),
        ..FakeBackend::default()
    });
    let mut f = fixture(true, Some(touch.clone()), Some(backend.clone()));
    let responses = call(
        &mut f,
        &[
            ("set_auth_method", json!({"method": "BIOMETRIC"})),
            ("get_auth_status", json!({})),
        ],
    );
    assert_eq!(
        text_of(&responses[0]),
        ("Auth method set to touchid", false)
    );
    assert_eq!(
        *touch.reasons.lock().unwrap(),
        ["Change Symaira Vault auth method to touchid"]
    );
    let saved = backend.saved.lock().unwrap().clone();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].1, b"hunter2");
    assert_eq!(backend.cleared.load(Ordering::SeqCst), 0);
    let config = config_text(&f);
    assert!(config.contains("authMethod: touchid"), "{config}");
    assert!(config.contains("useTouchID: true"), "{config}");
    assert_eq!(
        audit_records(&f),
        [("auth_config".to_owned(), "<config>".to_owned(), true)]
    );
    // Go mutates its in-memory config, so the status reflects the change.
    let status: Value = serde_json::from_str(text_of(&responses[1]).0).unwrap();
    assert_eq!(status["method"], "touchid");
}

#[test]
fn rejected_challenge_keeps_config_and_audits_failure() {
    let touch = FakeTouchId::new(true, Err(PlatformErrorKind::Canceled));
    let backend = Arc::new(FakeBackend {
        available: true,
        session: Some(b"hunter2".to_vec()),
        ..FakeBackend::default()
    });
    let mut f = fixture(true, Some(touch), Some(backend.clone()));
    let responses = call(&mut f, &[("set_auth_method", json!({"method": "touchid"}))]);
    assert_eq!(
        text_of(&responses[0]),
        (
            "biometric verification required: biometric verification for auth method change failed: touch id authentication failed",
            true
        )
    );
    assert!(config_text(&f).contains("authMethod: passphrase"));
    assert_eq!(
        audit_records(&f),
        [(
            "auth_method_biometric_failed".to_owned(),
            "<config>".to_owned(),
            false
        )]
    );
    // Go saves the unlock item before it challenges; the order is preserved.
    assert_eq!(backend.saved.lock().unwrap().len(), 1);
}

#[test]
fn passphrase_clears_the_item_with_or_without_a_challenger() {
    for touch in [Some(FakeTouchId::new(true, Ok(()))), None] {
        let backend = Arc::new(FakeBackend::default());
        let mut f = fixture(true, touch.clone(), Some(backend.clone()));
        fs::write(
            f.root.path().join("config.yaml"),
            "authMethod: touchid\nuseTouchID: true\n",
        )
        .unwrap();
        let responses = call(&mut f, &[("set_auth_method", json!({"method": ""}))]);
        assert_eq!(
            text_of(&responses[0]),
            ("Auth method set to passphrase", false)
        );
        assert_eq!(backend.cleared.load(Ordering::SeqCst), 1);
        let config = config_text(&f);
        assert!(config.contains("authMethod: passphrase"), "{config}");
        if let Some(touch) = touch {
            assert_eq!(
                *touch.reasons.lock().unwrap(),
                ["Change Symaira Vault auth method to passphrase"]
            );
        }
    }
}

#[test]
fn clear_failure_is_a_protocol_error_and_leaves_config_alone() {
    let backend = Arc::new(FakeBackend {
        clear_error: Some("keychain locked".into()),
        ..FakeBackend::default()
    });
    let mut f = fixture(true, None, Some(backend));
    let responses = call(
        &mut f,
        &[("set_auth_method", json!({"method": "passphrase"}))],
    );
    assert_eq!(
        responses[0],
        json!({"error":{"message":"clear Touch ID unlock item: keychain locked","code":-32603},"jsonrpc":"2.0","id":2})
    );
    assert!(audit_records(&f).is_empty());
}
