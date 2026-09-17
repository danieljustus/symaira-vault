use serde_json::Value;
use std::sync::{Arc, Mutex};
use symvault_mcp::{ProtocolHandler, ToolCallResult, ToolCallRuntime, run_stream};

#[derive(Default)]
struct FixtureRuntime {
    authorized: Mutex<Vec<String>>,
    called: Mutex<Vec<String>>,
    deny: bool,
}

impl ToolCallRuntime for FixtureRuntime {
    fn authorize(&self, name: &str, _arguments: &Value) -> Result<(), ToolCallResult> {
        self.authorized.lock().unwrap().push(name.to_owned());
        if self.deny {
            return Err(ToolCallResult::error("tool denied by fixture policy"));
        }
        Ok(())
    }

    fn call(&self, name: &str, arguments: &Value) -> Result<ToolCallResult, String> {
        self.called.lock().unwrap().push(name.to_owned());
        match name {
            "health" => Ok(ToolCallResult::text(
                r#"{"status":"healthy","untrusted":"<fixture>"}"#,
            )),
            "symaira_whoami" => Ok(ToolCallResult::structured(
                "fixture agent",
                serde_json::json!({"agent":"fixture","vault":{"unlocked":true}}),
            )),
            "find_entries" => match arguments.get("query").and_then(Value::as_str) {
                Some(query) => Ok(ToolCallResult::text(format!(r#"{{"query":"{query}"}}"#))),
                None => Ok(ToolCallResult::error("missing string argument \"query\"")),
            },
            "get_entry_metadata" => match arguments.get("path").and_then(Value::as_str) {
                Some(path) => Ok(ToolCallResult::text(format!(
                    r#"{{"path":"{path}","has_value":true}}"#
                ))),
                None => Ok(ToolCallResult::error("missing string argument \"path\"")),
            },
            _ => Err(format!("fixture has no handler for {name}")),
        }
    }
}

fn initialize() -> &'static str {
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}
{"jsonrpc":"2.0","method":"notifications/initialized"}
"#
}

#[test]
fn call_requires_initialize_before_locked_check() {
    let runtime = Arc::new(FixtureRuntime::default());
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
    let runtime = Arc::new(FixtureRuntime::default());
    let mut handler = ProtocolHandler::with_tool_call_runtime("fixture", "0.0.0", runtime.clone());
    let input = format!(
        "{}{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"health\"}}}}\n{{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{{\"name\":\"symaira_whoami\"}}}}\n{{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{{\"name\":\"find_entries\",\"arguments\":{{\"query\":\"fixture\"}}}}}}\n{{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{{\"name\":\"get_entry_metadata\",\"arguments\":{{\"path\":\"fixture/path\"}}}}}}\n",
        initialize()
    );
    let output = run_stream(&input, &mut handler).unwrap();
    assert_eq!(output.len(), 5);
    let health: Value = serde_json::from_str(&output[1]).unwrap();
    assert_eq!(health["result"]["isError"], false);
    assert_eq!(
        health["result"]["content"][0]["text"],
        r#"{"status":"healthy","untrusted":"<fixture>"}"#
    );
    let whoami: Value = serde_json::from_str(&output[2]).unwrap();
    assert_eq!(whoami["result"]["structuredContent"]["agent"], "fixture");
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
    let runtime = Arc::new(FixtureRuntime {
        deny: true,
        ..FixtureRuntime::default()
    });
    let mut handler = ProtocolHandler::with_tool_call_runtime("fixture", "0.0.0", runtime.clone());
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
    assert_eq!(*runtime.called.lock().unwrap(), Vec::<String>::new());
}

#[test]
fn malformed_call_params_are_invalid_after_unlock() {
    let runtime = Arc::new(FixtureRuntime::default());
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
