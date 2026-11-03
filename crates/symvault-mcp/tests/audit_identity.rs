//! MCP-003 / HTTP-002: every MCP audit row carries Go's session id, request id
//! and (for a scoped HTTP token) token id; stdio rows have no token id. The
//! byte layout is the shared `LogEntry` serialization, so the HMAC chain still
//! verifies. Go-recorded comparison: `scripts/rust-port/toolhash_process_contract.py`.

use serde_json::Value;
use std::fs;
use std::sync::{Arc, Mutex};
use symvault_core::session::MemoryKeyring;
use symvault_crypto::generate_identity;
use symvault_mcp::store_adapter::StoreReadOnlyRuntime;
use symvault_mcp::{ProtocolHandler, ReadOnlyRuntimeConfig, read_only_tool_names, run_stream};
use symvault_store::{Store, audit::RotationConfig};
use tempfile::TempDir;

fn fixture_vault(
    keyring: &MemoryKeyring,
) -> (
    TempDir,
    symvault_crypto::Identity,
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
    let identity = generate_identity();
    let _store = Store::open(root.path(), &identity).expect("open synthetic vault");
    let logger = symvault_store::audit::open_with_keyring(
        "fixture",
        root.path(),
        keyring,
        RotationConfig::default(),
    )
    .expect("open synthetic audit logger");
    (root, identity, Arc::new(Mutex::new(logger)))
}

fn handler(
    root: &TempDir,
    identity: symvault_crypto::Identity,
    audit: Arc<Mutex<symvault_store::audit::Logger>>,
    agent: &str,
    transport: &str,
) -> ProtocolHandler {
    let config = ReadOnlyRuntimeConfig {
        server_name: "symvault".into(),
        server_version: "0.0.0-fixture".into(),
        transport: transport.into(),
        agent_name: agent.into(),
        approval_mode: "none".into(),
        allowed_paths: vec!["*".into()],
        available_tools: read_only_tool_names(),
        vault_dir: root.path().to_string_lossy().into_owned(),
        vault_unlocked: true,
        ..ReadOnlyRuntimeConfig::default()
    };
    // By day on purpose: these rows are about ids, and an off-hours alert would
    // add an anomaly row (which carries the session id only) on a night run.
    let runtime =
        StoreReadOnlyRuntime::open_with_audit(root.path(), identity, config, None, Some(audit))
            .expect("construct runtime")
            .with_anomaly_clock(Arc::new(symvault_mcp::anomaly::FixedAnomalyClock::midday()));
    ProtocolHandler::with_tool_call_runtime("symvault", "0.0.0-fixture", Arc::new(runtime))
}

fn call(handler: &mut ProtocolHandler, tool: &str, arguments: &str) {
    let input = format!(
        "{}\n{}\n{}\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"probe","version":"1.0"},"capabilities":{}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        format_args!(
            r#"{{"jsonrpc":"2.0","id":777,"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments}}}}}"#
        ),
    );
    run_stream(&input, handler).expect("stream dispatch");
}

fn rows(audit: &Arc<Mutex<symvault_store::audit::Logger>>) -> Vec<Value> {
    let path = audit.lock().unwrap().path().to_path_buf();
    fs::read_to_string(path)
        .expect("audit log")
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit row"))
        .collect()
}

fn is_hex(value: &Value, len: usize) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == len
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[test]
fn stdio_rows_carry_session_and_request_ids_but_no_token_id() {
    let keyring = MemoryKeyring::new();
    let (root, identity, audit) = fixture_vault(&keyring);
    let mut session = handler(&root, identity, audit.clone(), "fixture", "stdio");
    call(
        &mut session,
        "get_entry_metadata",
        r#"{"path":"missing/x"}"#,
    );
    call(&mut session, "list_entries", "{}");
    let rows = rows(&audit);
    assert!(rows.len() >= 2, "rows: {rows:?}");
    let session_id = rows[0]["sess_id"].clone();
    assert!(is_hex(&session_id, 32), "{rows:?}");
    let mut requests = Vec::new();
    for row in &rows {
        assert_eq!(row["sess_id"], session_id, "one session per runtime: {row}");
        assert!(is_hex(&row["req_id"], 16), "request id missing: {row}");
        assert!(
            row.get("token_id").is_none(),
            "stdio has no token id (omitted, not empty): {row}"
        );
        requests.push(row["req_id"].as_str().unwrap().to_owned());
    }
    requests.dedup();
    assert_eq!(requests.len(), rows.len().min(requests.len()));
    assert!(requests.len() >= 2, "each call mints its own request id");
}

#[test]
fn scoped_token_id_is_stamped_on_denials_drift_and_successes() {
    let keyring = MemoryKeyring::new();
    let (root, identity, audit) = fixture_vault(&keyring);
    let base = handler(&root, identity, audit.clone(), "fixture", "http");
    let mut allowed = base.new_session();
    allowed.set_token_scope(&["list_entries".to_owned(), "symaira_search".to_owned()]);
    allowed.set_token_registry_hash("");
    allowed.set_token_id("tok-allowed");
    call(&mut allowed, "list_entries", "{}");
    // scope denial (`tool_denied`)
    call(&mut allowed, "find_entries", r#"{"query":"x"}"#);
    // registry drift
    let mut stale = base.new_session();
    stale.set_token_scope(&["*".to_owned()]);
    stale.set_token_registry_hash("stale-hash-does-not-match");
    stale.set_token_id("tok-stale");
    call(&mut stale, "symaira_search", r#"{"intent":"auth"}"#);
    // legacy bearer: no token id
    let mut legacy = base.new_session();
    legacy.set_token_scope(&["*".to_owned()]);
    legacy.set_token_registry_hash("");
    legacy.set_token_id("");
    call(&mut legacy, "list_entries", "{}");

    let rows = rows(&audit);
    let find = |action: &str| {
        rows.iter()
            .find(|row| row["action"] == action)
            .unwrap_or_else(|| panic!("no {action} row in {rows:?}"))
    };
    assert_eq!(find("tool_denied")["token_id"], "tok-allowed");
    assert_eq!(find("tool_registry_drift")["token_id"], "tok-stale");
    assert!(
        rows.iter()
            .any(|row| row["action"] == "list" && row["token_id"] == "tok-allowed"),
        "successful call row: {rows:?}"
    );
    let legacy_row = rows.last().unwrap();
    assert!(legacy_row.get("token_id").is_none(), "{legacy_row}");
    let sessions: std::collections::BTreeSet<_> =
        rows.iter().map(|row| row["sess_id"].to_string()).collect();
    assert_eq!(
        sessions.len(),
        1,
        "sessions share the runtime's id: {rows:?}"
    );
    for row in &rows {
        assert!(is_hex(&row["req_id"], 16), "{row}");
    }
}

#[test]
fn rows_with_ids_keep_a_valid_hmac_chain() {
    let keyring = MemoryKeyring::new();
    let (root, identity, audit) = fixture_vault(&keyring);
    let mut session = handler(&root, identity, audit.clone(), "fixture", "http");
    session.set_token_scope(&["list_entries".to_owned()]);
    session.set_token_id("tok-chain");
    call(&mut session, "list_entries", "{}");
    call(&mut session, "find_entries", r#"{"query":"x"}"#);
    let (path, kid) = {
        let logger = audit.lock().unwrap();
        (logger.path().to_path_buf(), logger.kid().to_owned())
    };
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"token_id\":\"tok-chain\""), "{text}");
    let key = symvault_store::audit::load_or_create_key_with_keyring(root.path(), &keyring)
        .expect("audit key");
    let keys = std::collections::BTreeMap::from([(kid.clone(), key)]);
    let result = symvault_store::audit::verify_jsonl(text.as_bytes(), &keys, &kid);
    assert!(
        result.valid && result.verified >= 2 && result.tampered == 0,
        "{result:?}"
    );
    // Dropping the id from a row breaks the chain: the ids are HMAC input.
    let stripped = text.replace("\"token_id\":\"tok-chain\",", "");
    let broken = symvault_store::audit::verify_jsonl(stripped.as_bytes(), &keys, &kid);
    assert!(!broken.valid, "{broken:?}");
}
