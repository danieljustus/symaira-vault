#![allow(dead_code)]
//! MCP-002/MCP-003 call-time authorization matrix: the frozen Go outcome of a
//! minimal `tools/call` for every registered tool plus an unknown name, under
//! 22 agent profiles and three token scopes (`testdata/port/mcp/authz-matrix.json`,
//! recorded by `scripts/rust-port/mcp_authz_matrix.py` from the pinned Go
//! oracle), replayed through the production CLI assembly
//! (`mcp_commands::build_handler`: config profile -> runtime config -> store
//! runtime) over a disposable encrypted store. Arguments are inert (`{}`), so
//! no clipboard, autotype, payment, Perplexity, network or child process runs.

#[path = "../src/mcp_commands.rs"]
mod mcp_commands;
#[path = "../src/run_commands.rs"]
mod run_commands;

use serde_json::{Value, json};
use std::{collections::BTreeMap, fs};
use symvault_core::{config::Config, session::MemoryKeyring};
use symvault_crypto::generate_identity;
use symvault_mcp::handle_line;
use symvault_store::{Entry, EntryMetadata, Store};

const FIXTURE: &str = include_str!("../../../testdata/port/mcp/authz-matrix.json");

/// Rust-side counterpart of the recorder's `normalize`/`mask`: only the
/// disposable HOME prefix, nested JSON text (compared as JSON), the host Touch
/// ID capability and the two documented random/audit-trail results are
/// rewritten.
fn normalize(value: &Value, home: &str, tool: &str) -> Value {
    fn walk(value: &Value, home: &str) -> Value {
        match value {
            Value::String(text) => {
                let text = text.replace(home, "__HOME__");
                match serde_json::from_str::<Value>(&text) {
                    Ok(nested @ (Value::Object(_) | Value::Array(_))) => {
                        json!({"json_text": walk(&nested, home)})
                    }
                    _ => Value::String(text),
                }
            }
            Value::Array(items) => Value::Array(items.iter().map(|v| walk(v, home)).collect()),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, value)| {
                        let value = if key == "touchIDAvailable" {
                            json!("<host-dependent>")
                        } else {
                            walk(value, home)
                        };
                        (key.clone(), value)
                    })
                    .collect(),
            ),
            other => other.clone(),
        }
    }
    let mut value = walk(value, home);
    let ok_text = value
        .pointer("/result/isError")
        .is_some_and(|is_error| is_error == &json!(false))
        .then(|| value.pointer("/result/content/0/text").cloned())
        .flatten();
    if let Some(text) = ok_text {
        let replacement = match tool {
            "generate_password" => Some(json!({
                "masked": "random_password",
                "length": text.as_str().unwrap_or_default().chars().count()
            })),
            "symaira_audit_self" => Some(json!({
                "masked": "audit_rows",
                "json_array": text.get("json_text").is_some_and(Value::is_array)
            })),
            _ => None,
        };
        if let Some(replacement) = replacement {
            *value.pointer_mut("/result/content/0/text").unwrap() = replacement;
        }
    }
    value
}

fn allowlist_whoami_matches(
    allowed: &[Value],
    ordered_tools: &[&str],
    go: &Value,
    rust: &Value,
) -> bool {
    const TOOLS: &str = "/result/content/0/text/json_text/tools";
    let (Some(go_tools), Some(rust_tools)) = (go.pointer(TOOLS), rust.pointer(TOOLS)) else {
        return false;
    };
    let is_allowed = |name: &str| allowed.iter().any(|entry| entry == name);
    let available: Vec<Value> = go_tools["available"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|name| is_allowed(name.as_str().unwrap()))
        .cloned()
        .collect();
    let go_unavailable = go_tools["unavailable"].as_array().unwrap();
    let unavailable: Vec<Value> = ordered_tools
        .iter()
        .filter(|name| !available.iter().any(|entry| entry == *name))
        .map(|name| {
            if is_allowed(name) {
                go_unavailable
                    .iter()
                    .find(|entry| entry["name"] == *name)
                    .cloned()
                    .unwrap_or(Value::Null)
            } else {
                json!({"name": name, "code": "blocked_by_agent",
                    "reason": format!("tool \"{name}\" is not allowed")})
            }
        })
        .collect();
    let mut expected = go.clone();
    *expected.pointer_mut(TOOLS).unwrap() =
        json!({"available": available, "unavailable": unavailable});
    &expected == rust && rust_tools["available"] == json!(available)
}

fn tool_error(id: &Value, text: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":text}],"isError":true}})
}

/// Differences between the Go recording and Rust that are deliberate (ADR 0016
/// and the Go-bug records below). Each rule matches an exact, fully asserted
/// Rust response for a precisely characterised case; any other difference
/// fails the replay, and the per-rule counts are pinned by the test.
fn declared_difference(
    profile: &Value,
    ordered_tools: &[&str],
    case: &Value,
    go: &Value,
    rust: &Value,
) -> Option<&'static str> {
    let tool = case["tool"].as_str().unwrap();
    let overlay = &profile["overlay"];
    let id = &rust["id"];
    // Go's production server never installs a ShareStore: the four share tools
    // dereference nil and would crash a real Go process. Rust serves them.
    if go.get("go_panic").is_some()
        && matches!(
            tool,
            "list_shares" | "request_share" | "approve_share" | "revoke_share"
        )
        && rust.get("jsonrpc") == Some(&json!("2.0"))
        && (rust.get("result").is_some() || rust.get("error").is_some())
    {
        return Some("go-nil-share-store-panic");
    }
    // ADR 0016 "Explicit allowed_tools": Go ignores an operator allowlist for
    // calls; Rust applies it to every registered tool outside the list, before
    // any other check, for every token mode.
    let allowlist = overlay["allowed_tools"].as_array();
    if let Some(allowed) = allowlist
        && !allowed.iter().any(|name| name == tool)
        && tool != "mcp_authz_unknown_tool"
        && rust == &tool_error(id, &format!("tool \"{tool}\" is not allowed"))
    {
        return Some("operator-allowlist-call");
    }
    // ADR 0016: discovery metadata (`symaira_whoami`) applies the same
    // operator allowlist. Rust must equal Go's complete result with exactly
    // the available list filtered and every other tool reported as
    // blocked_by_agent (Go's own unavailable entries are kept for allowed ones).
    if tool == "symaira_whoami"
        && let Some(allowed) = allowlist
        && allowlist_whoami_matches(allowed, ordered_tools, go, rust)
    {
        return Some("operator-allowlist-whoami");
    }
    // ADR 0016 "Deprecated symaira_delete": Go checks only `delete_entry` in the
    // tier map, so the alias reaches the handler; Rust authorizes the alias
    // against the canonical tier restriction.
    if tool == "symaira_delete"
        && let Some(required) = match overlay["tier"].as_str() {
            Some("read-only") => Some("standard"),
            Some("standard") => Some("admin"),
            _ => None,
        }
        && rust
            == &tool_error(
                id,
                &format!("Tool \"symaira_delete\" requires tier \"{required}\""),
            )
    {
        return Some("canonical-delete-alias-tier");
    }
    None
}

#[test]
fn authorization_matrix_matches_go_recording() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("parse frozen Go matrix");
    assert_eq!(fixture["schema_version"], json!(1));
    assert_eq!(fixture["oracle"]["commit_sha"].as_str().unwrap().len(), 40);
    let profiles = fixture["profiles"].as_array().unwrap();
    let tools = fixture["tools"].as_array().unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(profiles.len(), 22, "all 22 agent profiles recorded");
    assert_eq!(tools.len(), 36, "35 registered tools plus one unknown name");
    assert_eq!(
        cases.len(),
        22 * 36 * 3,
        "every profile x tool x token mode"
    );

    // Registry order of the discoverable tools (the deprecated alias and the
    // unknown probe name are not listed by `symaira_whoami`).
    let ordered_tools: Vec<&str> = tools
        .iter()
        .map(|tool| tool.as_str().unwrap())
        .filter(|tool| {
            *tool != "symaira_delete" && *tool != fixture["unknown_tool"].as_str().unwrap()
        })
        .collect();
    // Go was recorded with SYMVAULT_SECUREUI=none, so `secure_input` and
    // `request_credential` are unavailable. With a controlling terminal the
    // Rust CLI only agrees when it is told the same (`make
    // mcp-authz-differential` exports it); fail loudly instead of skipping.
    assert!(
        std::env::var("SYMVAULT_SECUREUI").as_deref() == Ok("none")
            || !symvault_platform::approval::is_tty_present(),
        "run with SYMVAULT_SECUREUI=none when a controlling terminal is present"
    );
    let keyring = MemoryKeyring::new();
    let mut executed = 0usize;
    let mut declared: BTreeMap<&str, usize> = BTreeMap::new();
    let mut failures = Vec::new();
    for profile in profiles {
        let name = profile["name"].as_str().unwrap();
        let agent = profile["agent"].as_str().unwrap();
        let temporary = tempfile::tempdir().expect("private disposable home");
        let home = temporary.path().canonicalize().unwrap();
        let root = home.join("vault");
        fs::create_dir(&root).unwrap();
        let config_yaml = profile["config_yaml"]
            .as_str()
            .unwrap()
            .replace("__HOME__", home.to_str().unwrap());
        fs::write(root.join("config.yaml"), &config_yaml).unwrap();
        fs::write(root.join("identity.age"), b"synthetic identity marker").unwrap();
        fs::create_dir(root.join("entries")).unwrap();
        let identity = generate_identity();
        let store = Store::open(&root, &identity).expect("open synthetic encrypted store");
        store
            .write_new_entry(
                "public/fixture",
                &Entry {
                    path: "public/fixture".into(),
                    data: BTreeMap::from([
                        ("username".into(), json!("public-fixture-user")),
                        ("password".into(), json!("public-mcp-secret-6af2")),
                        (
                            "nested".into(),
                            json!({"token": "public-nested-secret-88d1"}),
                        ),
                    ]),
                    metadata: EntryMetadata::default(),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("write synthetic entry");
        let config =
            Config::load(root.join("config.yaml")).expect("load Go-written profile config");
        let agent_profile = config.agents.get(agent).expect("recorded agent profile");
        let base = mcp_commands::build_handler_for_contract_test(
            &root,
            agent,
            agent_profile,
            identity,
            &keyring,
            "stdio",
            "passphrase",
            &(
                true,
                "memory".into(),
                false,
                "OS keyring unavailable. Sessions are stored in process memory only.".into(),
            ),
        )
        .expect("assemble production CLI MCP runtime");
        let mut request_id = 100;
        for case in cases.iter().filter(|case| case["profile"] == json!(name)) {
            request_id += 1;
            let tool = case["tool"].as_str().unwrap();
            let mut session = base.new_session();
            handle_line(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
                &mut session,
            )
            .unwrap();
            match case["token"].as_str().unwrap() {
                "none" => {}
                "excluding" => session.set_token_scope(&[if tool == "health" {
                    "symaira_whoami".to_owned()
                } else {
                    "health".to_owned()
                }]),
                "including" => session.set_token_scope(&[tool.to_owned()]),
                other => panic!("unknown token mode {other}"),
            }
            let request = json!({"jsonrpc":"2.0","id":request_id,"method":"tools/call",
                "params":{"name":tool,"arguments":{}}});
            let line = handle_line(&request.to_string(), &mut session)
                .unwrap()
                .expect("tools/call response");
            let rust: Value = serde_json::from_str(&line).unwrap();
            let rust = normalize(&rust, home.to_str().unwrap(), tool);
            let go = &case["response"];
            executed += 1;
            if &rust != go {
                match declared_difference(profile, &ordered_tools, case, go, &rust) {
                    Some(rule) => *declared.entry(rule).or_default() += 1,
                    None => failures.push(format!(
                        "{name} / {tool} / token={}:\n  go:   {go}\n  rust: {rust}",
                        case["token"].as_str().unwrap()
                    )),
                }
            }
        }
    }
    println!(
        "executed {executed} Go/Rust authorization cases ({} profiles x {} tools x 3 token modes); declared differences: {declared:?}; unexplained: {}",
        profiles.len(),
        tools.len(),
        failures.len()
    );
    assert_eq!(executed, cases.len(), "every recorded case executed");
    // Pin the deliberate differences exactly: a rule that starts matching more
    // (or fewer) cases is a behavior change that needs a new decision.
    assert_eq!(
        declared,
        BTreeMap::from([
            ("canonical-delete-alias-tier", 21),
            ("go-nil-share-store-panic", 44),
            ("operator-allowlist-call", 297),
            ("operator-allowlist-whoami", 2),
        ])
    );
    assert!(
        failures.is_empty(),
        "{} unexplained differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
