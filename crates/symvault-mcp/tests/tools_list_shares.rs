use serde_json::Value;
use std::{
    fs,
    sync::{Arc, Mutex},
};
use symvault_core::session::MemoryKeyring;
use symvault_crypto::generate_identity;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyRuntimeConfig, StoreReadOnlyRuntime, read_only_tool_names, run_stream,
};
use symvault_store::{Store, audit::RotationConfig};
use tempfile::TempDir;

fn fixture_runtime() -> (
    TempDir,
    ProtocolHandler,
    Arc<Mutex<symvault_store::audit::Logger>>,
) {
    fixture_runtime_for_agent("fixture")
}

fn fixture_runtime_for_agent(
    agent_name: &str,
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
        agent_name: agent_name.into(),
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
    .with_grant_signing_key(symvault_crypto::SecretBytes::new(&[42; 32]));
    let handler = ProtocolHandler::with_tool_call_runtime("symvault", "1.0.0", Arc::new(runtime));
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
    assert!(
        read_only_tool_names()
            .iter()
            .any(|name| name == "revoke_share")
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

fn revoke_stream(arguments: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize"}}
{{"jsonrpc":"2.0","method":"notifications/initialized"}}
{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"revoke_share","arguments":{arguments}}}}}
"#
    )
}

fn call_response(output: &[String]) -> Value {
    serde_json::from_str(output.last().expect("call response line")).expect("call response JSON")
}

fn audit_events(audit: &Arc<Mutex<symvault_store::audit::Logger>>) -> Vec<Value> {
    let path = audit.lock().expect("audit logger lock").path().to_owned();
    fs::read_to_string(path)
        .expect("read audit events")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit JSON"))
        .collect()
}

#[test]
fn protocol_revoke_share_rejects_invalid_and_missing_ids_with_go_audit() {
    let (_root, mut handler, audit) = fixture_runtime();
    let output = run_stream(&revoke_stream("{}"), &mut handler).expect("missing grant_id");
    let response = call_response(&output);
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["content"][0]["text"],
        "missing string argument \"grant_id\""
    );
    let event = audit_events(&audit)
        .into_iter()
        .find(|event| event["action"] == "share_revoke")
        .expect("invalid argument audit");
    assert_eq!(event["path"], "<invalid>");
    assert_eq!(event["ok"], false);

    let (_root, mut handler, audit) = fixture_runtime();
    let output = run_stream(&revoke_stream(r#"{"grant_id":true}"#), &mut handler)
        .expect("wrong grant_id type");
    let response = call_response(&output);
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["content"][0]["text"],
        "argument \"grant_id\" is not a string"
    );
    let event = audit_events(&audit)
        .into_iter()
        .find(|event| event["action"] == "share_revoke")
        .expect("wrong type audit");
    assert_eq!(event["path"], "<invalid>");
    assert_eq!(event["ok"], false);

    let (_root, mut handler, audit) = fixture_runtime();
    let output = run_stream(&revoke_stream(r#"{"grant_id":"missing"}"#), &mut handler)
        .expect("missing grant");
    let response = call_response(&output);
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["content"][0]["text"],
        "share grant \"missing\" not found"
    );
    let event = audit_events(&audit)
        .into_iter()
        .find(|event| event["action"] == "share_revoke")
        .expect("not-found audit");
    assert_eq!(event["path"], "missing");
    assert_eq!(event["ok"], false);
}

#[test]
fn protocol_revoke_share_denies_recipient_and_cross_agent_without_file_change() {
    for (agent, grant_id, expected) in [
        (
            "bob",
            "pending",
            "only the source agent \"fixture\" can revoke this share",
        ),
        (
            "fixture",
            "private",
            "only the source agent \"mallory\" can revoke this share",
        ),
    ] {
        let (root, mut handler, _audit) = fixture_runtime_for_agent(agent);
        let path = root.path().join("mcp-shares.json");
        let before = fs::read(&path).expect("read original share store");
        let output = run_stream(
            &revoke_stream(&format!(r#"{{"grant_id":"{grant_id}"}}"#)),
            &mut handler,
        )
        .expect("dispatch unauthorized revoke");
        let response = call_response(&output);
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(response["result"]["content"][0]["text"], expected);
        assert_eq!(fs::read(&path).expect("read unchanged share store"), before);
    }
}

#[test]
fn protocol_revoke_share_source_persists_relist_and_audits_success() {
    let (root, mut handler, audit) = fixture_runtime();
    let input = format!(
        "{}\n{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"list_shares\",\"arguments\":{{\"status\":\"revoked\"}}}}}}\n",
        revoke_stream(r#"{"grant_id":"pending"}"#).trim_end(),
    );
    let output = run_stream(&input, &mut handler).expect("dispatch authorized revoke and relist");
    assert_eq!(
        output.len(),
        3,
        "initialize plus revoke and relist responses"
    );
    let revoked = call_response(&output[..2]);
    assert_eq!(revoked["result"]["isError"], false);
    assert_eq!(
        revoked["result"]["content"][0]["text"],
        "Share grant pending revoked"
    );
    let relist_response: Value = serde_json::from_str(&output[2]).expect("relist response");
    let relisted: Value = serde_json::from_str(
        relist_response["result"]["content"][0]["text"]
            .as_str()
            .expect("relist JSON text"),
    )
    .expect("relisted grants JSON");
    assert_eq!(relisted.as_array().expect("relisted array").len(), 1);
    assert_eq!(relisted[0]["id"], "pending");
    assert_eq!(relisted[0]["status"], "revoked");
    assert!(relisted[0]["revoked_at"].is_string());

    let persisted: Value = serde_json::from_slice(
        &fs::read(root.path().join("mcp-shares.json")).expect("persisted share store"),
    )
    .expect("persisted JSON");
    let grant = persisted["grants"]
        .as_array()
        .expect("persisted grants")
        .iter()
        .find(|grant| grant["id"] == "pending")
        .expect("persisted pending grant");
    assert_eq!(grant["status"], "revoked");
    assert!(grant["revoked_at"].is_string());

    let share_events = audit_events(&audit)
        .into_iter()
        .filter(|event| event["action"] == "share_revoke")
        .collect::<Vec<_>>();
    assert_eq!(share_events.len(), 1);
    assert_eq!(share_events[0]["path"], "prod/a");
    assert_eq!(share_events[0]["ok"], true);
}

#[test]
fn protocol_request_share_persists_signed_pending_grant_and_rejects_invalid_ttl() {
    let (root, mut handler, audit) = fixture_runtime();
    let output = run_stream(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"request_share","arguments":{"to_agent":"bob","secret_path":"prod/new","secret_field":"password","ttl":"1h"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"request_share","arguments":{"to_agent":"bob","secret_path":"prod/new","ttl":"-1s"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"request_share","arguments":{"secret_path":"prod/new"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"request_share","arguments":{"to_agent":"bob","secret_path":"other/new"}}}
"#, &mut handler).unwrap();
    let success: Value = serde_json::from_str(&output[1]).unwrap();
    assert_eq!(success["result"]["isError"], false);
    let grant: Value =
        serde_json::from_str(success["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(grant["status"], "pending");
    assert_eq!(grant["from_agent"], "fixture");
    let stored = symvault_store::sharing::ShareStore::read_verified(
        root.path().join("mcp-shares.json"),
        Some(&[42; 32]),
    )
    .unwrap();
    let persisted = stored
        .grants()
        .iter()
        .find(|entry| entry.id == grant["grant_id"].as_str().unwrap())
        .unwrap();
    assert_eq!(persisted.secret_field, "password");
    assert_eq!(persisted.ttl, 3_600_000_000_000);
    assert_eq!(stored.grants().len(), 4);
    for response in &output[2..4] {
        let error: Value = serde_json::from_str(response).unwrap();
        assert_eq!(error["result"]["isError"], true);
    }
    let events = fs::read_to_string(audit.lock().unwrap().path()).unwrap();
    let events: Vec<Value> = events
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|event: &Value| event["action"] == "share_request")
        .collect();
    let denied: Value = serde_json::from_str(&output[4]).unwrap();
    assert_eq!(denied["error"]["code"], -32603);
    assert!(
        denied["error"]["message"]
            .as_str()
            .unwrap()
            .contains("outside allowed scope")
    );
    assert_eq!(events.len(), 3);
    assert_eq!(events[2]["ok"], false);
    assert_eq!(events[0]["ok"], true);
    assert_eq!(events[1]["ok"], false);
}
