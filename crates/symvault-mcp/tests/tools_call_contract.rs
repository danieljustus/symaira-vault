use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use symvault_mcp::{
    ProtocolHandler, ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore,
    ToolCallResult, ToolCallRuntime, run_stream,
};

#[derive(Clone)]
struct MemoryStore {
    entries: Vec<ReadOnlyEntry>,
}

impl ReadOnlyStore for MemoryStore {
    fn list(&self) -> Result<Vec<ReadOnlyEntry>, String> {
        Ok(self.entries.clone())
    }

    fn get(&self, path: &str) -> Result<Option<ReadOnlyEntry>, String> {
        Ok(self
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .cloned())
    }
}

struct RecordingRuntime<R> {
    inner: R,
    authorized: Mutex<Vec<String>>,
    called: Mutex<Vec<String>>,
}

impl<R> ToolCallRuntime for RecordingRuntime<R>
where
    R: ToolCallRuntime,
{
    fn authorize(&self, name: &str, arguments: &Value) -> Result<(), ToolCallResult> {
        self.authorized.lock().unwrap().push(name.to_owned());
        self.inner.authorize(name, arguments)
    }

    fn call(&self, name: &str, arguments: &Value) -> Result<ToolCallResult, String> {
        self.called.lock().unwrap().push(name.to_owned());
        self.inner.call(name, arguments)
    }
}

struct DenyRuntime;

impl ToolCallRuntime for DenyRuntime {
    fn authorize(&self, _name: &str, _arguments: &Value) -> Result<(), ToolCallResult> {
        Err(ToolCallResult::error("tool denied by fixture policy"))
    }

    fn call(&self, _name: &str, _arguments: &Value) -> Result<ToolCallResult, String> {
        panic!("denied calls must not reach storage");
    }
}

fn fixture_runtime() -> RecordingRuntime<ReadOnlyRuntime<MemoryStore>> {
    let mut fields = BTreeMap::new();
    fields.insert("password".into(), Value::String("testpass123".into()));
    fields.insert("username".into(), Value::String("testuser".into()));
    let store = MemoryStore {
        entries: vec![ReadOnlyEntry {
            path: "github".into(),
            fields,
            created: "<fixture-time>".into(),
            updated: "<fixture-time>".into(),
            version: 1,
            ..ReadOnlyEntry::default()
        }],
    };
    let config = ReadOnlyRuntimeConfig {
        server_name: "Symaira Vault MCP".into(),
        server_version: "1.0.0".into(),
        transport: "stdio".into(),
        agent_name: "fixture".into(),
        approval_mode: "none".into(),
        allowed_paths: vec!["*".into()],
        available_tools: vec![
            "health".into(),
            "symaira_whoami".into(),
            "find_entries".into(),
            "get_entry_metadata".into(),
        ],
        vault_dir: "<fixture-vault>".into(),
        ..ReadOnlyRuntimeConfig::default()
    };
    RecordingRuntime {
        inner: ReadOnlyRuntime::new(store, config),
        authorized: Mutex::new(Vec::new()),
        called: Mutex::new(Vec::new()),
    }
}

fn initialize() -> &'static str {
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}
{"jsonrpc":"2.0","method":"notifications/initialized"}
"#
}

#[test]
fn call_requires_initialize_before_locked_check() {
    let runtime = Arc::new(fixture_runtime());
    let mut handler = ProtocolHandler::with_tool_call_runtime("fixture", "0.0.0", runtime.clone());
    let output = run_stream(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"bad"}
"#,
        &mut handler,
    )
    .unwrap();
    let response: Value = serde_json::from_str(&output[0]).unwrap();
    assert_eq!(response["error"]["code"], -32000);
    assert_eq!(response["error"]["message"], "Server not initialized");
    assert!(runtime.authorized.lock().unwrap().is_empty());
}

#[test]
fn default_runtime_returns_locked_before_argument_decoding() {
    let mut handler = ProtocolHandler::new("fixture", "0.0.0");
    let output = run_stream(
        &format!(
            "{}{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":\"bad\"}}\n",
            initialize()
        ),
        &mut handler,
    )
    .unwrap();
    let response: Value = serde_json::from_str(&output[1]).unwrap();
    assert_eq!(response["error"]["code"], -32603);
    assert_eq!(
        response["error"]["message"],
        "vault locked: run 'symvault unlock' first"
    );
}

#[test]
fn initialized_call_authorizes_then_dispatches_read_only_tools() {
    let runtime = Arc::new(fixture_runtime());
    let mut handler = ProtocolHandler::with_tool_call_runtime("fixture", "0.0.0", runtime.clone());
    let input = format!(
        "{}{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"health\"}}}}\n{{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{{\"name\":\"symaira_whoami\"}}}}\n{{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{{\"name\":\"find_entries\",\"arguments\":{{\"query\":\"test\"}}}}}}\n{{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{{\"name\":\"get_entry_metadata\",\"arguments\":{{\"path\":\"github\"}}}}}}\n",
        initialize()
    );
    let output = run_stream(&input, &mut handler).unwrap();
    assert_eq!(output.len(), 5);
    let health: Value = serde_json::from_str(&output[1]).unwrap();
    assert_eq!(health["result"]["isError"], false);
    assert_eq!(
        health["result"]["content"][0]["text"],
        r#"{"server":"Symaira Vault MCP","status":"healthy","transport":"stdio","version":"1.0.0"}"#
    );
    let find: Value = serde_json::from_str(&output[3]).unwrap();
    assert_eq!(
        find["result"]["content"][0]["text"],
        r#"[{"Path":"github","Fields":["password","username"]}]"#
    );
    let whoami: Value = serde_json::from_str(&output[2]).unwrap();
    assert_eq!(whoami["result"]["content"][0]["type"], "text");
    let metadata: Value = serde_json::from_str(&output[4]).unwrap();
    assert!(
        metadata["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("op://github/password")
    );
    assert_eq!(
        *runtime.authorized.lock().unwrap(),
        vec![
            "health",
            "symaira_whoami",
            "find_entries",
            "get_entry_metadata"
        ]
    );
    assert_eq!(
        *runtime.called.lock().unwrap(),
        vec![
            "health",
            "symaira_whoami",
            "find_entries",
            "get_entry_metadata"
        ]
    );
}

#[test]
fn authorization_denial_is_tool_result_and_storage_is_not_called() {
    let runtime = Arc::new(DenyRuntime);
    let mut handler = ProtocolHandler::with_tool_call_runtime("fixture", "0.0.0", runtime);
    let input = format!(
        "{}{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"health\"}}}}\n",
        initialize()
    );
    let output = run_stream(&input, &mut handler).unwrap();
    let response: Value = serde_json::from_str(&output[1]).unwrap();
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["content"][0]["text"],
        "tool denied by fixture policy"
    );
}

#[test]
fn malformed_call_arguments_are_internal_after_outer_params_decode() {
    let runtime = Arc::new(fixture_runtime());
    let mut handler = ProtocolHandler::with_tool_call_runtime("fixture", "0.0.0", runtime);
    let input = format!(
        "{}{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"health\",\"arguments\":[]}}}}\n",
        initialize()
    );
    let output = run_stream(&input, &mut handler).unwrap();
    let response: Value = serde_json::from_str(&output[1]).unwrap();
    assert_eq!(response["error"]["code"], -32603);
    assert_eq!(
        response["error"]["message"],
        "parse arguments: json: cannot unmarshal array into Go value of type map[string]interface {}"
    );
}
