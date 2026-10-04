use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use symvault_mcp::{
    ProtocolHandler, ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore,
    ToolCallResult, ToolCallRuntime, ToolListConfig, run_stream,
};

struct UntouchedStore;
impl ReadOnlyStore for UntouchedStore {
    fn list(&self) -> Result<Vec<ReadOnlyEntry>, String> {
        panic!("denial reached store list")
    }
    fn get(&self, _: &str) -> Result<Option<ReadOnlyEntry>, String> {
        panic!("denial reached store get")
    }
}
struct RecordingRuntime {
    inner: ReadOnlyRuntime<UntouchedStore>,
    calls: AtomicUsize,
}
impl ToolCallRuntime for RecordingRuntime {
    fn authorize(&self, name: &str, args: &Value) -> Result<(), ToolCallResult> {
        self.inner.authorize(name, args)
    }
    fn call(&self, name: &str, args: &Value) -> Result<ToolCallResult, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.call(name, args)
    }
}
fn initialized_calls(
    config: ReadOnlyRuntimeConfig,
    calls: &[(&str, Value)],
) -> (Vec<Value>, usize) {
    let runtime = Arc::new(RecordingRuntime {
        inner: ReadOnlyRuntime::new(UntouchedStore, config),
        calls: AtomicUsize::new(0),
    });
    let mut handler = ProtocolHandler::with_tool_call_runtime("fixture", "1", runtime.clone());
    let mut input = json!({"jsonrpc":"2.0","id":0,"method":"initialize"}).to_string() + "\n";
    for (id, (name, args)) in calls.iter().enumerate() {
        input += &(json!({"jsonrpc":"2.0","id":id+1,"method":"tools/call","params":{"name":name,"arguments":args}}).to_string()+"\n");
    }
    let output = run_stream(&input, &mut handler)
        .unwrap()
        .into_iter()
        .skip(1)
        .map(|line| serde_json::from_str(&line).unwrap())
        .collect();
    (output, runtime.calls.load(Ordering::SeqCst))
}

#[test]
fn tier_overrides_never_reach_handlers_or_storage() {
    for (tier, required) in [("read-only", "standard"), ("standard", "admin")] {
        let names = [
            "run_command",
            "execute_with_secret",
            "execute_api_request",
            "delete_entry",
            "symaira_delete",
        ];
        let config = ReadOnlyRuntimeConfig {
            tier: tier.into(),
            can_run_commands: true,
            can_write: true,
            can_read_values: true,
            approval_mode: "none".into(),
            available_tools: names.iter().map(|n| (*n).into()).collect(),
            ..ReadOnlyRuntimeConfig::default()
        };
        let calls:Vec<_> = names.iter().map(|name|(*name,json!({"path":"public/fixture","command":["should-not-run"],"env":{"TOKEN":"public/fixture.password"}}))).collect();
        let (responses, called) = initialized_calls(config, &calls);
        assert_eq!(called, 0);
        for (response, name) in responses.iter().zip(names) {
            assert_eq!(response["result"]["isError"], true);
            assert_eq!(
                response["result"]["content"][0]["text"],
                format!("Tool {name:?} requires tier {required:?}")
            );
        }
    }
}

#[test]
fn explicit_operator_allowlist_restricts_discovery_and_direct_calls() {
    let tools = ToolListConfig {
        tier: Some("admin".into()),
        allowed_tools: vec!["health".into()],
        execute_api_available: true,
        ..ToolListConfig::default()
    };
    let config = ReadOnlyRuntimeConfig {
        tier: "admin".into(),
        can_run_commands: true,
        available_tools: vec!["get_entry_value".into(), "run_command".into()],
        tool_list_config: Some(tools.clone()),
        ..ReadOnlyRuntimeConfig::default()
    };
    let (responses, called) = initialized_calls(
        config,
        &[
            ("get_entry_value", json!({"path":"public/fixture"})),
            ("run_command", json!({"command":["should-not-run"]})),
        ],
    );
    assert_eq!(called, 0);
    assert_eq!(
        responses[0]["result"]["content"][0]["text"],
        "tool \"get_entry_value\" is not allowed"
    );
    assert_eq!(
        responses[1]["result"]["content"][0]["text"],
        "tool \"run_command\" is not allowed"
    );
    let mut handler = ProtocolHandler::with_tool_list_config("fixture", "1", tools);
    let frames = run_stream("{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"include_all_tools\":true}}\n",&mut handler).unwrap();
    let listed: Value = serde_json::from_str(&frames[1]).unwrap();
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 1);
    assert_eq!(listed["result"]["tools"][0]["name"], "health");
}

#[test]
fn command_capability_denial_preserves_rpc_error_without_dispatch() {
    let config = ReadOnlyRuntimeConfig {
        tier: "admin".into(),
        agent_name: "fixture".into(),
        available_tools: vec!["run_command".into(), "execute_with_secret".into()],
        ..ReadOnlyRuntimeConfig::default()
    };
    let (responses, called) = initialized_calls(
        config,
        &[
            ("run_command", json!({})),
            ("execute_with_secret", json!({})),
        ],
    );
    assert_eq!(called, 0);
    for response in responses {
        assert_eq!(response["error"]["code"], -32603);
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("command execution not permitted for this agent:")
        );
        assert!(response.get("result").is_none());
    }
}
