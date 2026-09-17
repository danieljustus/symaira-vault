//! MCP-002 focused slice: Go-generated registry schemas and list-time filters.

use serde::Deserialize;
use serde_json::Value;
use symvault_mcp::{ProtocolHandler, ToolListConfig, run_stream};

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    catalog: Vec<Value>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_hash: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    profile: String,
    include_all_tools: bool,
    #[serde(default)]
    expose_value_tools: Option<bool>,
    runtime: Runtime,
    tools: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct Runtime {
    execute_api: bool,
    secure_input: bool,
    generate_totp: bool,
}

fn load() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/mcp/tool-list.json"
    );
    serde_json::from_slice(&std::fs::read(path).expect("read MCP-002 fixture"))
        .expect("parse MCP-002 fixture")
}

fn config(case: &Case) -> ToolListConfig {
    if case.profile.is_empty() {
        return ToolListConfig {
            execute_api_available: case.runtime.execute_api,
            secure_input_available: case.runtime.secure_input,
            generate_totp_available: case.runtime.generate_totp,
            ..ToolListConfig::default()
        };
    }
    let mut config = ToolListConfig::for_tier(
        &case.profile,
        case.runtime.execute_api,
        case.runtime.secure_input,
        case.runtime.generate_totp,
    );
    if case.expose_value_tools.is_none() {
        config.expose_value_tools = None;
    } else {
        config.expose_value_tools = case.expose_value_tools;
    }
    config
}

fn request(case: &Case) -> String {
    if case.include_all_tools {
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{\"include_all_tools\":true}}\n".to_string()
    } else {
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n".to_string()
    }
}

#[test]
fn fixture_pins_the_go_oracle() {
    let fx = load();
    assert_eq!(fx.oracle.commit, "fca3f894");
    assert_eq!(
        fx.oracle.commit_sha,
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    assert_eq!(
        fx.oracle.source_hash,
        "84035cd3f669596d81313612c00f29fc45432ea22a6cb61b0c59ddc3f811a14c"
    );
}

#[test]
fn catalog_matches_go_registry_and_every_case() {
    let fx = load();
    assert_eq!(fx.catalog.len(), 35);
    let admin = fx
        .cases
        .iter()
        .find(|case| case.name == "admin_all")
        .expect("admin catalog case");
    assert_eq!(fx.catalog, admin.tools);

    for case in &fx.cases {
        let mut handler =
            ProtocolHandler::with_tool_list_config("symvault", "0.0.0-fixture", config(case));
        let output = run_stream(&request(case), &mut handler).expect("Rust MCP stream");
        assert_eq!(output.len(), 2, "case {} response count", case.name);
        let response: Value = serde_json::from_str(&output[1]).expect("tools/list JSON");
        assert_eq!(
            response
                .get("result")
                .and_then(|result| result.get("tools")),
            Some(&Value::Array(case.tools.clone())),
            "case {} differs from Go registry/filtering",
            case.name
        );
    }
}

#[test]
fn tools_list_requires_initialize() {
    let mut handler = ProtocolHandler::new("symvault", "0.0.0-fixture");
    let output = run_stream(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n",
        &mut handler,
    )
    .expect("Rust MCP stream");
    let response: Value = serde_json::from_str(&output[0]).expect("JSON-RPC error");
    assert_eq!(response["error"]["code"], -32000);
    assert_eq!(response["error"]["message"], "Server not initialized");
}

#[test]
fn negative_control_does_not_accept_a_missing_tool() {
    let fx = load();
    let case = fx
        .cases
        .iter()
        .find(|case| case.name == "admin_all")
        .expect("admin catalog case");
    let mut wrong = case.tools.clone();
    wrong.pop();
    let mut handler =
        ProtocolHandler::with_tool_list_config("symvault", "0.0.0-fixture", config(case));
    let output = run_stream(&request(case), &mut handler).expect("Rust MCP stream");
    let response: Value = serde_json::from_str(&output[1]).expect("tools/list JSON");
    assert_ne!(
        response
            .get("result")
            .and_then(|result| result.get("tools")),
        Some(&Value::Array(wrong)),
        "comparison must reject a mutated expected catalog"
    );
}
