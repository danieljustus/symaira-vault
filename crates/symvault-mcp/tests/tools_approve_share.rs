//! MCP `approve_share`: a pending grant is approved only after a human answers
//! the controlling-terminal prompt.
//!
//! The synthetic approval seam stands in for the TTY, so these cases exercise
//! the real handler, the real share store under its write lock, and the real
//! audit log. They follow `internal/mcp/server/tools_sharing.go`
//! (`handleApproveShare`) and `sharing_store.go` at Go oracle fca3f894.

use serde_json::{Value, json};
use std::{
    fs,
    sync::{Arc, Mutex},
};
use symvault_core::session::MemoryKeyring;
use symvault_crypto::generate_identity;
use symvault_mcp::store_adapter::{ApprovalSeam, PlatformApproval};
use symvault_mcp::{
    ProtocolHandler, ReadOnlyRuntimeConfig, StoreReadOnlyRuntime, read_only_tool_names, run_stream,
};
use symvault_platform::approval::{ApprovalError, ApprovalRequest, ApprovalResult};
use symvault_store::{Store, audit::RotationConfig};
use tempfile::TempDir;

/// Synthetic human: records every prompt it is shown and answers with a fixed
/// result, so no case needs a real terminal.
struct FakeApproval {
    tty: bool,
    result: ApprovalResult,
    prompted: Mutex<Vec<ApprovalRequest>>,
}

impl FakeApproval {
    fn answering(tty: bool, approved: bool) -> Arc<Self> {
        Arc::new(Self {
            tty,
            result: ApprovalResult {
                approved,
                remembered: false,
                error: None,
            },
            prompted: Mutex::new(Vec::new()),
        })
    }

    fn failing(tty: bool, error: ApprovalError) -> Arc<Self> {
        Arc::new(Self {
            tty,
            result: ApprovalResult {
                approved: false,
                remembered: false,
                error: Some(error),
            },
            prompted: Mutex::new(Vec::new()),
        })
    }

    fn prompts(&self) -> Vec<ApprovalRequest> {
        self.prompted.lock().expect("prompt log lock").clone()
    }
}

impl ApprovalSeam for FakeApproval {
    fn is_tty_present(&self) -> bool {
        self.tty
    }

    fn request(&self, request: &ApprovalRequest) -> ApprovalResult {
        self.prompted
            .lock()
            .expect("prompt log lock")
            .push(request.clone());
        self.result.clone()
    }
}

const SHARE_FIXTURE: &str = r#"{"version":1,"grants":[{"id":"pending","from_agent":"fixture","to_agent":"bob","secret_path":"prod/a","status":"pending","created_at":"2026-01-02T03:04:05Z"},{"id":"selfpending","from_agent":"alice","to_agent":"bob","secret_path":"prod/self","status":"pending","created_at":"2026-01-02T03:04:05Z"},{"id":"ttlpending","from_agent":"fixture","to_agent":"carol","secret_path":"prod/b","secret_field":"password","status":"pending","created_at":"2026-01-02T03:04:05Z","ttl":3600000000000},{"id":"approved","from_agent":"fixture","to_agent":"bob","secret_path":"prod/c","status":"approved","created_at":"2026-01-02T03:04:05Z","approved_at":"2026-01-02T04:00:00Z","approved_by":"fixture"}]}"#;

fn fixture_runtime(
    seam: Arc<dyn ApprovalSeam>,
) -> (
    TempDir,
    ProtocolHandler,
    Arc<Mutex<symvault_store::audit::Logger>>,
) {
    let root = tempfile::tempdir().expect("synthetic vault tempdir");
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
    fs::write(root.path().join("mcp-shares.json"), SHARE_FIXTURE).expect("Go-shaped share fixture");

    let identity = generate_identity();
    Store::open(root.path(), &identity).expect("open synthetic vault");
    let keyring = MemoryKeyring::new();
    let audit = Arc::new(Mutex::new(
        symvault_store::audit::open_with_keyring(
            "alice",
            root.path(),
            &keyring,
            RotationConfig::default(),
        )
        .expect("open synthetic audit logger"),
    ));
    let config = ReadOnlyRuntimeConfig {
        server_name: "Symaira Vault MCP".into(),
        server_version: "1.0.0".into(),
        transport: "stdio".into(),
        agent_name: "alice".into(),
        approval_mode: "none".into(),
        allowed_paths: vec!["prod".into()],
        available_tools: read_only_tool_names(),
        vault_dir: root.path().to_string_lossy().into_owned(),
        vault_unlocked: true,
        ..ReadOnlyRuntimeConfig::default()
    };
    let runtime = StoreReadOnlyRuntime::open_with_audit(
        root.path(),
        identity,
        config,
        None,
        Some(Arc::clone(&audit)),
    )
    .expect("construct store runtime")
    .with_approval_seam(seam);
    let handler = ProtocolHandler::with_tool_call_runtime("symvault", "1.0.0", Arc::new(runtime));
    (root, handler, audit)
}

fn call_approve(handler: &mut ProtocolHandler, grant_id: &str) -> Value {
    let stream = format!(
        "{}\n{}\n{}\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "approve_share", "arguments": {"grant_id": grant_id}}
        })
    );
    let output = run_stream(&stream, handler).expect("dispatch approve_share protocol stream");
    serde_json::from_str(output.last().expect("call response")).expect("response JSON")
}

fn result_text(response: &Value) -> String {
    response["result"]["content"][0]["text"]
        .as_str()
        .expect("tool result text")
        .to_owned()
}

fn stored_grant(root: &TempDir, id: &str) -> Value {
    let path = root
        .path()
        .canonicalize()
        .expect("canonical vault root")
        .join("mcp-shares.json");
    let store: Value = serde_json::from_str(&fs::read_to_string(path).expect("read share store"))
        .expect("share store JSON");
    store["grants"]
        .as_array()
        .expect("grant array")
        .iter()
        .find(|grant| grant["id"] == id)
        .expect("grant present")
        .clone()
}

fn audit_events(audit: &Arc<Mutex<symvault_store::audit::Logger>>) -> Vec<Value> {
    let path = audit.lock().expect("audit logger lock").path().to_owned();
    fs::read_to_string(path)
        .expect("read audit events")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit JSON"))
        .collect()
}

fn actions(audit: &Arc<Mutex<symvault_store::audit::Logger>>, action: &str) -> Vec<Value> {
    audit_events(audit)
        .into_iter()
        .filter(|event| event["action"] == action)
        .collect()
}

#[test]
fn approve_share_prompts_a_human_and_persists_the_approval() {
    assert!(
        read_only_tool_names()
            .iter()
            .any(|name| name == "approve_share"),
        "approve_share must be an available tool"
    );
    let seam = FakeApproval::answering(true, true);
    let (root, mut handler, audit) = fixture_runtime(Arc::clone(&seam) as Arc<dyn ApprovalSeam>);

    let response = call_approve(&mut handler, "pending");
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(result_text(&response), "Share grant pending approved");

    let prompt = seam.prompts().pop().expect("one prompt");
    assert_eq!(prompt.operation, "approve_share");
    assert_eq!(
        prompt.details,
        "Share pending: fixture → bob, path: prod/a\nAgent requesting approval: alice"
    );
    assert_eq!(prompt.timeout, std::time::Duration::from_secs(60));

    let grant = stored_grant(&root, "pending");
    assert_eq!(grant["status"], "approved");
    assert_eq!(grant["approved_by"], "alice");
    assert!(
        grant["approved_at"]
            .as_str()
            .is_some_and(|at| !at.is_empty()),
        "approval timestamp recorded: {grant}"
    );

    let approved = actions(&audit, "share_approve");
    assert_eq!(approved.len(), 1, "exactly one share_approve event");
    assert_eq!(approved[0]["ok"], true);
    assert_eq!(approved[0]["path"], "prod/a");
    assert!(
        actions(&audit, "share_reject").is_empty(),
        "an approval must not log a rejection"
    );
}

#[test]
fn approve_share_includes_field_and_go_duration_ttl_in_the_prompt() {
    let seam = FakeApproval::answering(true, true);
    let (_root, mut handler, _audit) = fixture_runtime(Arc::clone(&seam) as Arc<dyn ApprovalSeam>);

    let response = call_approve(&mut handler, "ttlpending");
    assert_eq!(response["result"]["isError"], false);

    let prompt = seam.prompts().pop().expect("one prompt");
    // Go renders `grant.TTL` (a time.Duration) with %s: one hour is "1h0m0s".
    assert_eq!(
        prompt.details,
        "Share ttlpendi: fixture → carol, path: prod/b\nAgent requesting approval: alice, field: password, ttl: 1h0m0s"
    );
}

#[test]
fn approve_share_rejects_the_grant_when_the_human_declines() {
    let seam = FakeApproval::answering(true, false);
    let (root, mut handler, audit) = fixture_runtime(Arc::clone(&seam) as Arc<dyn ApprovalSeam>);

    let response = call_approve(&mut handler, "pending");
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(result_text(&response), "Share grant pending rejected");

    assert_eq!(seam.prompts().len(), 1, "the human was actually asked");
    let grant = stored_grant(&root, "pending");
    assert_eq!(grant["status"], "rejected");

    let rejected = actions(&audit, "share_reject");
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["ok"], true);
    assert!(actions(&audit, "share_approve").is_empty());
}

#[test]
fn approve_share_denies_without_a_tty_and_leaves_the_grant_pending() {
    let seam = FakeApproval::answering(false, true);
    let (root, mut handler, audit) = fixture_runtime(Arc::clone(&seam) as Arc<dyn ApprovalSeam>);

    let response = call_approve(&mut handler, "pending");
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        result_text(&response),
        "cannot approve share: no TTY available for human confirmation"
    );
    assert!(
        seam.prompts().is_empty(),
        "no prompt is rendered without a TTY"
    );
    assert_eq!(stored_grant(&root, "pending")["status"], "pending");

    let denied = actions(&audit, "share_approve");
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["ok"], false);
}

#[test]
fn approve_share_refuses_self_approval_before_prompting() {
    let seam = FakeApproval::answering(true, true);
    let (root, mut handler, audit) = fixture_runtime(Arc::clone(&seam) as Arc<dyn ApprovalSeam>);

    // `selfpending` was requested by the calling agent `alice` itself.
    let response = call_approve(&mut handler, "selfpending");
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        result_text(&response),
        "the requesting agent cannot approve its own share request"
    );
    assert!(
        seam.prompts().is_empty(),
        "a self-approval must be refused before the human is asked"
    );
    assert_eq!(stored_grant(&root, "selfpending")["status"], "pending");

    let denied = actions(&audit, "share_approve_denied");
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["ok"], false);
    assert_eq!(denied[0]["path"], "prod/self");
}

#[test]
fn approve_share_reports_missing_and_non_pending_ids_like_go() {
    let seam = FakeApproval::answering(true, true);
    let (_root, mut handler, audit) = fixture_runtime(Arc::clone(&seam) as Arc<dyn ApprovalSeam>);

    let missing = call_approve(&mut handler, "nope");
    assert_eq!(missing["result"]["isError"], true);
    assert_eq!(result_text(&missing), r#"share grant "nope" not found"#);

    let approved = call_approve(&mut handler, "approved");
    assert_eq!(approved["result"]["isError"], true);
    assert_eq!(
        result_text(&approved),
        r#"share grant "approved" is not pending (status: approved)"#
    );

    assert!(
        seam.prompts().is_empty(),
        "neither case may reach the human prompt"
    );
    // Go audits the missing-id case only, with the raw argument as the path.
    let events = actions(&audit, "share_approve");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["ok"], false);
    assert_eq!(events[0]["path"], "nope");
}

#[test]
fn approve_share_surfaces_the_approval_error_with_go_duration_text() {
    let seam = FakeApproval::failing(
        true,
        ApprovalError::Timeout(std::time::Duration::from_secs(60)),
    );
    let (root, mut handler, audit) = fixture_runtime(Arc::clone(&seam) as Arc<dyn ApprovalSeam>);

    let response = call_approve(&mut handler, "pending");
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        result_text(&response),
        "approval failed: approval timed out after 1m0s"
    );
    assert_eq!(stored_grant(&root, "pending")["status"], "pending");

    let events = actions(&audit, "share_approve");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["ok"], false);
}

#[test]
fn production_seam_is_the_platform_prompt_and_never_reads_stdin() {
    // The default seam is the real controlling-terminal implementation. These
    // tests must never call it (there is no TTY in CI), but its presence proves
    // the production wiring does not fall back to stdin.
    let seam: Arc<dyn ApprovalSeam> = Arc::new(PlatformApproval);
    let _ = seam.is_tty_present();
}
