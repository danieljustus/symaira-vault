use serde_json::Value;
use std::{
    fs,
    sync::{Arc, Mutex},
};
use symvault_core::session::MemoryKeyring;
use symvault_crypto::generate_identity;
use symvault_mcp::{ProtocolHandler, ReadOnlyRuntimeConfig, read_only_tool_names, run_stream};
use symvault_store::{Store, audit::RotationConfig};
use tempfile::TempDir;

fn fixture_runtime() -> (
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
    fs::write(
        root.path().join("mcp-shares.json"),
        r#"{"version":1,"grants":[{"id":"pending","from_agent":"fixture","to_agent":"bob","secret_path":"prod/a","status":"pending","created_at":"2026-01-02T03:04:05Z"},{"id":"approved","from_agent":"alice","to_agent":"fixture","secret_path":"prod/b","status":"approved","created_at":"2026-01-02T03:04:05Z"},{"id":"private","from_agent":"mallory","to_agent":"eve","secret_path":"prod/c","status":"approved","created_at":"2026-01-02T03:04:05Z"}]}"#,
    )
    .expect("Go-shaped share fixture");

    let identity = generate_identity();
    Store::open(root.path(), &identity).expect("open synthetic vault");
    let keyring = MemoryKeyring::new();
    let audit = Arc::new(Mutex::new(
        symvault_store::audit::open_with_keyring(
            "fixture",
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
        agent_name: "fixture".into(),
        approval_mode: "none".into(),
        allowed_paths: vec!["*".into()],
        available_tools: read_only_tool_names(),
        vault_dir: root.path().to_string_lossy().into_owned(),
        vault_unlocked: true,
        ..ReadOnlyRuntimeConfig::default()
    };
    let handler = ProtocolHandler::with_store_read_only_runtime_and_audit(
        "symvault",
        "1.0.0",
        root.path(),
        identity,
        config,
        None,
        None,
        Some(Arc::clone(&audit)),
    )
    .expect("construct store runtime");
    (root, handler, audit)
}

#[test]
fn protocol_list_shares_scopes_filters_and_audits_empty_path() {
    // Synthetic values follow internal/mcp/server/tools_sharing.go and
    // sharing_store.go at Go oracle fca3f894. This test exercises Rust's
    // concrete encrypted-store protocol wiring; it does not claim Go stdio
    // execution because the current Go New path leaves shareStore unattached.
    assert!(
        read_only_tool_names()
            .iter()
            .any(|name| name == "list_shares")
    );
    let (_root, mut handler, audit) = fixture_runtime();
    let output = run_stream(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_shares","arguments":{}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_shares","arguments":{"status":"approved","to_agent":"fixture"}}}
"#,
        &mut handler,
    )
    .expect("dispatch list_shares protocol stream");
    assert_eq!(output.len(), 3, "initialize plus two call responses");

    let all: Value = serde_json::from_str(&output[1]).expect("all response JSON");
    assert_eq!(all["result"]["isError"], false);
    let all_text = all["result"]["content"][0]["text"]
        .as_str()
        .expect("list result text");
    let all_grants: Value = serde_json::from_str(all_text).expect("all grants JSON");
    assert_eq!(all_grants.as_array().expect("grant array").len(), 2);
    assert!(
        all_grants
            .as_array()
            .expect("grant array")
            .iter()
            .all(|grant| grant["from_agent"] == "fixture" || grant["to_agent"] == "fixture")
    );
    assert!(
        !all_text.contains("private"),
        "cross-agent grant must stay hidden"
    );

    let filtered: Value = serde_json::from_str(&output[2]).expect("filtered response JSON");
    let filtered_text = filtered["result"]["content"][0]["text"]
        .as_str()
        .expect("filtered result text");
    let filtered_grants: Value = serde_json::from_str(filtered_text).expect("filtered grants JSON");
    assert_eq!(filtered_grants.as_array().expect("grant array").len(), 1);
    assert_eq!(filtered_grants[0]["id"], "approved");

    let audit_path = audit.lock().expect("audit logger lock").path().to_owned();
    let events = fs::read_to_string(audit_path).expect("read audit events");
    let events = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit JSON"))
        .collect::<Vec<_>>();
    let share_events = events
        .iter()
        .filter(|event| event["action"] == "share_list")
        .collect::<Vec<_>>();
    assert_eq!(share_events.len(), 2);
    assert!(share_events.iter().all(|event| {
        event["ok"] == true
            && !event
                .as_object()
                .expect("audit object")
                .contains_key("path")
    }));
}
