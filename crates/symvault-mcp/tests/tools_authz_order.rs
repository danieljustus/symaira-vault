//! Go `validateToolAccess` ordering and the `autotype` handler, through the
//! protocol handler over a disposable encrypted store. The full 22-profile
//! matrix against Go lives in `symvault-cli/tests/mcp_authz_matrix.rs`; these
//! cases pin the individual rules with zero-side-effect checks.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex};
use symvault_core::platform::{Autotype, PlatformError};
use symvault_crypto::generate_identity;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyRuntimeConfig, ReadOnlyUnavailableTool, StoreReadOnlyRuntime,
    read_only_tool_names, run_stream,
};
use symvault_store::{Entry, EntryMetadata, Store};
use tempfile::tempdir;

#[derive(Default)]
struct RecordingAutotype {
    typed: Mutex<Vec<String>>,
}

impl Autotype for RecordingAutotype {
    fn type_text(&self, text: &str) -> Result<(), PlatformError> {
        self.typed.lock().unwrap().push(text.to_owned());
        Ok(())
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    handler: ProtocolHandler,
    typed: Arc<RecordingAutotype>,
}

fn fixture(config: ReadOnlyRuntimeConfig, with_autotype: bool) -> Fixture {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("config.yaml"),
        "vault:\n  format_version: 1\n",
    )
    .unwrap();
    fs::write(root.path().join("identity.age"), b"fixture identity").unwrap();
    fs::create_dir(root.path().join("entries")).unwrap();
    let identity = generate_identity();
    let store = Store::open(
        symvault_store::data_safety::test_support_pre_marked(root.path()),
        &identity,
    )
    .unwrap();
    store
        .write_new_entry(
            "public/site",
            &Entry {
                path: "public/site".into(),
                data: BTreeMap::from([
                    ("password".into(), json!("hunter2-fixture")),
                    ("attempts".into(), json!(3)),
                ]),
                metadata: EntryMetadata::default(),
                ..Entry::default()
            },
            &identity,
        )
        .unwrap();
    let mut config = config;
    config.allowed_paths = vec!["public".into()];
    config.available_tools = read_only_tool_names();
    config.available_tools.push("execute_api_request".into());
    let typed = Arc::new(RecordingAutotype::default());
    let mut runtime = StoreReadOnlyRuntime::open(root.path(), identity, config, None, None)
        .expect("open synthetic runtime");
    if with_autotype {
        runtime = runtime.with_autotype(typed.clone());
    }
    let mut handler = ProtocolHandler::with_tool_call_runtime("fixture", "1", Arc::new(runtime));
    run_stream(
        &(json!({"jsonrpc":"2.0","id":0,"method":"initialize"}).to_string() + "\n"),
        &mut handler,
    )
    .unwrap();
    Fixture {
        _root: root,
        handler,
        typed,
    }
}

fn call(fixture: &mut Fixture, name: &str, arguments: Value) -> Value {
    let input =
        json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":name,"arguments":arguments}})
            .to_string()
            + "\n";
    let output = run_stream(&input, &mut fixture.handler).unwrap();
    serde_json::from_str(&output[0]).unwrap()
}

fn text(response: &Value) -> &str {
    response["result"]["content"][0]["text"].as_str().unwrap()
}

fn rpc_error(response: &Value) -> (i64, &str) {
    (
        response["error"]["code"].as_i64().unwrap(),
        response["error"]["message"].as_str().unwrap(),
    )
}

#[test]
fn token_scope_is_checked_after_availability_and_tier_and_before_capabilities() {
    let mut config = ReadOnlyRuntimeConfig {
        tier: "standard".into(),
        approval_mode: "none".into(),
        ..ReadOnlyRuntimeConfig::default()
    };
    config.unavailable_tools = vec![ReadOnlyUnavailableTool {
        name: "execute_api_request".into(),
        code: "not_available".into(),
        reason: "tool \"execute_api_request\" is not available in the current environment".into(),
    }];
    let mut f = fixture(config, false);
    f.handler.set_token_scope(&["health".to_owned()]);

    // Unknown tool: the registry lookup precedes the token scope.
    let unknown = call(&mut f, "no_such_tool", json!({}));
    assert_eq!(rpc_error(&unknown), (-32603, "unknown tool: no_such_tool"));
    // Availability, then profile tier, both before the token scope.
    let unavailable = call(&mut f, "execute_api_request", json!({}));
    assert_eq!(
        text(&unavailable),
        "tool \"execute_api_request\" is not available in the current environment"
    );
    let tier = call(&mut f, "run_command", json!({}));
    assert_eq!(text(&tier), "Tool \"run_command\" requires tier \"admin\"");
    // A tool allowed by the profile but outside the token scope.
    let scoped = call(&mut f, "list_entries", json!({}));
    assert_eq!(
        text(&scoped),
        "Tool \"list_entries\" requires tier \"token_scope\""
    );
    // The token scope also precedes the handler's capability check.
    let capability = call(&mut f, "secret_unseal", json!({}));
    assert_eq!(
        text(&capability),
        "Tool \"secret_unseal\" requires tier \"token_scope\""
    );
    // Control: a tool inside the scope reaches its handler.
    assert!(
        text(&call(&mut f, "health", json!({}))).contains("healthy"),
        "tool named by the token must run"
    );
}

#[test]
fn command_capability_denial_follows_the_token_scope() {
    let config = ReadOnlyRuntimeConfig {
        tier: "admin".into(),
        approval_mode: "none".into(),
        can_run_commands: false,
        ..ReadOnlyRuntimeConfig::default()
    };
    let mut f = fixture(config, false);
    f.handler.set_token_scope(&["health".to_owned()]);
    let excluded = call(&mut f, "run_command", json!({}));
    assert_eq!(
        text(&excluded),
        "Tool \"run_command\" requires tier \"token_scope\""
    );
    f.handler.set_token_scope(&["run_command".to_owned()]);
    let denied = call(&mut f, "run_command", json!({}));
    assert_eq!(rpc_error(&denied).0, -32603);
    assert!(
        rpc_error(&denied)
            .1
            .starts_with("command execution not permitted")
    );
}

#[test]
fn value_read_approval_gate_follows_argument_validation_and_scope() {
    let config = ReadOnlyRuntimeConfig {
        approval_mode: "deny".into(),
        can_read_values: false,
        ..ReadOnlyRuntimeConfig::default()
    };
    let mut f = fixture(config, false);
    assert_eq!(
        text(&call(&mut f, "get_entry_value", json!({}))),
        "missing string argument \"path\""
    );
    let outside = call(&mut f, "get_entry_value", json!({"path": "private/other"}));
    assert_eq!(
        rpc_error(&outside),
        (
            -32603,
            "access denied: path \"private/other\" outside allowed scope"
        )
    );
    let gated = call(&mut f, "get_entry_value", json!({"path": "public/site"}));
    assert_eq!(
        text(&gated),
        "get_entry_value denied: approval mode is 'deny'"
    );
    assert!(!gated.to_string().contains("hunter2-fixture"));
}

fn autotype_config() -> ReadOnlyRuntimeConfig {
    ReadOnlyRuntimeConfig {
        tier: "admin".into(),
        approval_mode: "none".into(),
        can_use_autotype: true,
        ..ReadOnlyRuntimeConfig::default()
    }
}

#[test]
fn autotype_types_only_after_capability_scope_and_approval() {
    // Capability first: a JSON-RPC internal error, nothing typed.
    let mut f = fixture(
        ReadOnlyRuntimeConfig {
            can_use_autotype: false,
            ..autotype_config()
        },
        true,
    );
    let denied = call(&mut f, "autotype", json!({"path": "public/site"}));
    assert_eq!(
        rpc_error(&denied),
        (-32603, "autotype operations not permitted for this agent")
    );
    assert!(f.typed.typed.lock().unwrap().is_empty());

    let mut f = fixture(autotype_config(), true);
    assert_eq!(
        text(&call(&mut f, "autotype", json!({}))),
        "missing string argument \"path\""
    );
    let outside = call(&mut f, "autotype", json!({"path": "elsewhere/site"}));
    assert_eq!(
        rpc_error(&outside),
        (
            -32603,
            "access denied: path \"elsewhere/site\" outside allowed scope"
        )
    );
    assert_eq!(
        text(&call(
            &mut f,
            "autotype",
            json!({"path": "public/site", "field": "missing"})
        )),
        "field \"missing\" not found in entry public/site"
    );
    assert_eq!(
        text(&call(
            &mut f,
            "autotype",
            json!({"path": "public/site", "field": "attempts"})
        )),
        "field \"attempts\" is not a string"
    );
    assert!(
        f.typed.typed.lock().unwrap().is_empty(),
        "nothing typed yet"
    );
    let ok = call(&mut f, "autotype", json!({"path": "public/site"}));
    assert_eq!(text(&ok), r#"{"success": true}"#);
    assert_eq!(*f.typed.typed.lock().unwrap(), vec!["hunter2-fixture"]);
    assert!(!ok.to_string().contains("hunter2-fixture"));

    // An approval policy cannot be satisfied for autotype.
    let mut f = fixture(
        ReadOnlyRuntimeConfig {
            approval_mode: "prompt".into(),
            ..autotype_config()
        },
        true,
    );
    let refused = call(&mut f, "autotype", json!({"path": "public/site"}));
    assert_eq!(
        rpc_error(&refused),
        (
            -32603,
            "autotype denied: approval required but cannot be granted"
        )
    );
    assert!(f.typed.typed.lock().unwrap().is_empty());

    // No backend installed: Go's platform-unavailable tool error.
    let mut f = fixture(autotype_config(), false);
    assert_eq!(
        text(&call(&mut f, "autotype", json!({"path": "public/site"}))),
        "autotype not available on this platform"
    );
}

#[test]
fn autotype_is_blocked_for_read_only_tier_before_any_work() {
    let mut f = fixture(
        ReadOnlyRuntimeConfig {
            tier: "read-only".into(),
            ..autotype_config()
        },
        true,
    );
    let blocked = call(&mut f, "autotype", json!({"path": "public/site"}));
    assert_eq!(
        text(&blocked),
        "Tool \"autotype\" requires tier \"standard\""
    );
    assert!(f.typed.typed.lock().unwrap().is_empty());
}
