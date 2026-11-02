//! TOOLHASH-001: the tool-registry hash and the call-time drift refusal against
//! `testdata/port/mcp/tool-registry-hash.json`, recorded from the Go sources
//! by `TestGenerateToolRegistryHashFixture` (`make tool-registry-hash-fixtures-check`).

use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::sync::{Arc, Mutex};
use symvault_core::session::MemoryKeyring;
use symvault_crypto::generate_identity;
use symvault_mcp::toolhash::{
    ToolHashDef, catalog_hash_defs, compute_tool_registry_hash, current_tool_registry_hash,
    is_drift,
};
use symvault_mcp::{ProtocolHandler, ReadOnlyRuntimeConfig, read_only_tool_names, run_stream};
use symvault_store::{Store, audit::RotationConfig};
use tempfile::TempDir;

#[derive(Deserialize)]
struct Fixture {
    oracle: Oracle,
    registry: Registry,
    mutations: Vec<Mutation>,
    synthetic: Vec<Synthetic>,
    drift: Vec<Drift>,
}

#[derive(Deserialize)]
struct Oracle {
    source_files: Vec<String>,
    source_hash: String,
    generator_hash: String,
}

#[derive(Deserialize)]
struct Registry {
    tool_count: usize,
    hash: String,
    tools: Vec<RegistryTool>,
}

#[derive(Deserialize)]
struct RegistryTool {
    name: String,
    description: String,
    input_schema_json: String,
    read_only_hint: bool,
    destructive_hint: bool,
}

#[derive(Deserialize)]
struct Mutation {
    name: String,
    ops: Vec<Op>,
    hash: String,
    changes_hash: bool,
    tool_count: usize,
}

#[derive(Deserialize)]
struct Op {
    op: String,
    #[serde(default)]
    tool: String,
    #[serde(default)]
    property: String,
    #[serde(default)]
    value: Value,
    #[serde(default)]
    def: Option<DefIn>,
}

#[derive(Deserialize)]
struct DefIn {
    name: String,
    description: String,
    input_schema: Value,
    read_only_hint: bool,
    destructive_hint: bool,
}

impl From<DefIn> for ToolHashDef {
    fn from(def: DefIn) -> Self {
        ToolHashDef {
            name: def.name,
            description: def.description,
            input_schema: def.input_schema,
            read_only_hint: def.read_only_hint,
            destructive_hint: def.destructive_hint,
        }
    }
}

#[derive(Deserialize)]
struct Synthetic {
    name: String,
    defs: Vec<DefIn>,
    hash: String,
}

#[derive(Deserialize)]
struct Drift {
    name: String,
    token_hash: String,
    token_hash_is_registry: bool,
    drift: bool,
    agent_name: String,
    tool: String,
    arguments: String,
    result_json: String,
    refused: bool,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tool-registry-hash.json"
    ))
    .expect("valid Go tool-registry-hash fixture")
}

fn apply(defs: &[ToolHashDef], ops: &[Op]) -> Vec<ToolHashDef> {
    let mut out = defs.to_vec();
    for op in ops {
        let position = |out: &Vec<ToolHashDef>| {
            out.iter()
                .position(|def| def.name == op.tool)
                .unwrap_or_else(|| panic!("unknown tool {} in op", op.tool))
        };
        match op.op.as_str() {
            "set_description" => {
                let index = position(&out);
                out[index].description = op.value.as_str().expect("string value").to_owned();
            }
            "set_read_only" => {
                let index = position(&out);
                out[index].read_only_hint = op.value.as_bool().expect("bool value");
            }
            "set_destructive" => {
                let index = position(&out);
                out[index].destructive_hint = op.value.as_bool().expect("bool value");
            }
            "set_schema_property_description" => {
                let index = position(&out);
                let property = out[index]
                    .input_schema
                    .get_mut("properties")
                    .and_then(|properties| properties.get_mut(&op.property))
                    .unwrap_or_else(|| panic!("no property {}", op.property));
                property["description"] = op.value.clone();
            }
            "remove_tool" => {
                let index = position(&out);
                out.remove(index);
            }
            "add_tool" => {
                let def = op.def.as_ref().expect("def");
                out.push(ToolHashDef {
                    name: def.name.clone(),
                    description: def.description.clone(),
                    input_schema: def.input_schema.clone(),
                    read_only_hint: def.read_only_hint,
                    destructive_hint: def.destructive_hint,
                });
            }
            "reverse_order" => out.reverse(),
            other => panic!("unknown op {other}"),
        }
    }
    out
}

#[test]
fn fixture_is_bound_to_go_sources() {
    let fixture = fixture();
    assert_eq!(
        fixture.oracle.source_files,
        [
            "internal/mcp/auth/token.go",
            "internal/mcp/server/server_dispatch.go",
            "internal/mcp/server/setup.go",
            "internal/mcp/server/tool_registry.go",
            "internal/mcp/toolhash.go",
        ]
    );
    assert_eq!(fixture.oracle.source_hash.len(), 64);
    assert_eq!(fixture.oracle.generator_hash.len(), 64);
}

#[test]
fn catalog_hash_equals_go_registry_hash() {
    let fixture = fixture();
    assert_eq!(fixture.registry.tool_count, 35);
    let defs = catalog_hash_defs().expect("catalog");
    assert_eq!(defs.len(), fixture.registry.tool_count);
    assert_eq!(
        compute_tool_registry_hash(&defs),
        fixture.registry.hash,
        "Rust catalog hash must equal the hash Go computes over toolDefinitions()"
    );
    assert_eq!(
        current_tool_registry_hash().expect("hash"),
        fixture.registry.hash
    );
}

/// The per-tool hash material (not only the final digest) matches Go, so a
/// mismatch names the tool and field instead of a bare digest difference.
#[test]
fn catalog_hash_material_matches_go_tool_by_tool() {
    let fixture = fixture();
    let mut defs = catalog_hash_defs().expect("catalog");
    defs.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(defs.len(), fixture.registry.tools.len());
    for (def, go) in defs.iter().zip(&fixture.registry.tools) {
        assert_eq!(def.name, go.name);
        assert_eq!(def.description, go.description, "{} description", go.name);
        assert_eq!(
            def.read_only_hint, go.read_only_hint,
            "{} readOnly",
            go.name
        );
        assert_eq!(
            def.destructive_hint, go.destructive_hint,
            "{} destructive",
            go.name
        );
        let single = compute_tool_registry_hash(std::slice::from_ref(def));
        // Recompute the Go single-tool digest from Go's recorded bytes.
        let line = format!(
            "{}|{}|{}|{}|{}\n",
            go.name, go.description, go.input_schema_json, go.read_only_hint, go.destructive_hint
        );
        assert_eq!(
            single,
            sha256_hex(line.as_bytes()),
            "{} schema serialization differs from Go: {}",
            go.name,
            go.input_schema_json
        );
    }
}

#[test]
fn mutations_match_go_and_the_hash_is_sensitive_to_every_field() {
    let fixture = fixture();
    let base = catalog_hash_defs().expect("catalog");
    assert!(
        fixture
            .mutations
            .iter()
            .any(|mutation| mutation.changes_hash),
        "negative controls must exist"
    );
    for mutation in &fixture.mutations {
        let mutated = apply(&base, &mutation.ops);
        assert_eq!(mutated.len(), mutation.tool_count, "{}", mutation.name);
        let hash = compute_tool_registry_hash(&mutated);
        assert_eq!(hash, mutation.hash, "mutation {}", mutation.name);
        assert_eq!(
            hash != fixture.registry.hash,
            mutation.changes_hash,
            "mutation {}",
            mutation.name
        );
    }
}

#[test]
fn synthetic_registries_match_go_escaping_numbers_and_ordering() {
    for synthetic in fixture().synthetic {
        let defs: Vec<ToolHashDef> = synthetic.defs.into_iter().map(Into::into).collect();
        assert_eq!(
            compute_tool_registry_hash(&defs),
            synthetic.hash,
            "synthetic {}",
            synthetic.name
        );
    }
}

#[test]
fn drift_predicate_matches_go() {
    let current = current_tool_registry_hash().expect("hash");
    for case in fixture().drift {
        let token_hash = if case.token_hash_is_registry {
            current.as_str()
        } else {
            case.token_hash.as_str()
        };
        assert_eq!(is_drift(token_hash, &current), case.drift, "{}", case.name);
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fixture_vault() -> (
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
    let keyring = MemoryKeyring::new();
    let logger = symvault_store::audit::open_with_keyring(
        "fixture",
        root.path(),
        &keyring,
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
) -> ProtocolHandler {
    let config = ReadOnlyRuntimeConfig {
        server_name: "symvault".into(),
        server_version: "0.0.0-fixture".into(),
        transport: "http".into(),
        agent_name: agent.into(),
        approval_mode: "none".into(),
        allowed_paths: vec!["*".into()],
        available_tools: read_only_tool_names(),
        vault_dir: root.path().to_string_lossy().into_owned(),
        vault_unlocked: true,
        ..ReadOnlyRuntimeConfig::default()
    };
    ProtocolHandler::with_store_read_only_runtime_and_audit(
        "symvault",
        "0.0.0-fixture",
        root.path(),
        identity,
        config,
        None,
        None,
        Some(audit),
    )
    .expect("construct runtime")
}

fn call_result(handler: &mut ProtocolHandler, tool: &str, arguments: &str) -> Value {
    let input = format!(
        "{}\n{}\n{}\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"probe","version":"1.0"},"capabilities":{}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        format_args!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments}}}}}"#
        ),
    );
    let lines = run_stream(&input, handler).expect("stream dispatch");
    let response: Value = serde_json::from_str(lines.last().expect("call response")).expect("json");
    assert!(
        response.get("error").is_none(),
        "unexpected RPC error: {response}"
    );
    response["result"].clone()
}

/// Every Go dispatch outcome (refusal text, isError, accepted result) is
/// reproduced; the accepted cases include the legacy empty hash.
#[test]
fn http_dispatch_matches_go_for_stale_legacy_and_matching_tokens() {
    let current = current_tool_registry_hash().expect("hash");
    let mut refused_seen = 0;
    for case in fixture().drift {
        let (root, identity, audit) = fixture_vault();
        let mut session = handler(&root, identity, audit, &case.agent_name);
        let token_hash = if case.token_hash_is_registry {
            current.clone()
        } else {
            case.token_hash.clone()
        };
        session.set_token_scope(&["*".to_owned()]);
        session.set_token_registry_hash(&token_hash);
        let actual = call_result(&mut session, &case.tool, &case.arguments);
        let expected: Value = serde_json::from_str(&case.result_json).expect("Go result json");
        assert_eq!(actual, expected, "case {}", case.name);
        assert_eq!(
            actual["isError"] == Value::Bool(true),
            case.refused,
            "case {}",
            case.name
        );
        refused_seen += usize::from(case.refused);
    }
    assert!(
        refused_seen >= 2,
        "refusals must be exercised, saw {refused_seen}"
    );
}

/// Go order: the drift refusal comes after tier and token-scope denials (those
/// win) and before the entry-policy gate; it also records the
/// `tool_registry_drift` audit action with the tool name as target.
#[test]
fn drift_refusal_is_audited_and_ordered_after_scope_denial() {
    let (root, identity, audit) = fixture_vault();
    let base = handler(&root, identity, audit, "fixture");
    let mut audit_reader = base.new_session();

    let mut stale = base.new_session();
    stale.set_token_scope(&["symaira_search".to_owned(), "symaira_audit_self".to_owned()]);
    stale.set_token_registry_hash("stale-hash-does-not-match");

    // An out-of-scope tool is a scope denial even for a drifted token.
    let denied = call_result(&mut stale, "find_entries", r#"{"query":"x"}"#);
    assert_eq!(denied["isError"], Value::Bool(true));
    assert!(
        denied["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("token_scope"),
        "scope denial wins over drift: {denied}"
    );

    let refused = call_result(&mut stale, "symaira_search", r#"{"intent":"auth"}"#);
    assert_eq!(refused["isError"], Value::Bool(true));
    assert_eq!(
        refused["content"][0]["text"],
        "tool registry has changed since this token was issued \u{2014} re-issue the token with 'symvault agent token new fixture'"
    );

    let events = call_result(&mut audit_reader, "symaira_audit_self", r#"{"limit":50}"#);
    let text = events["content"][0]["text"].as_str().expect("audit text");
    assert!(
        text.contains("\"tool\":\"tool_registry_drift\"")
            && text.contains("\"path\":\"symaira_search\"")
            && text.contains("\"status\":\"error\"")
            && text.contains("\"code\":\"tool_registry_drift\""),
        "drift audit entry missing: {text}"
    );
}
