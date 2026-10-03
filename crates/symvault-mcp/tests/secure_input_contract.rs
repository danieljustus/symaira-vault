use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    sync::{Arc, Mutex},
};
use symvault_mcp::store_adapter::{ApprovalSeam, SecureInputSeam};
use symvault_mcp::{
    ReadOnlyRuntimeConfig, ReadOnlyUnavailableTool, StoreReadOnlyRuntime, ToolCallRuntime,
    read_only_tool_names,
};
use symvault_platform::approval::{
    ApprovalError, ApprovalRequest, ApprovalResult, SecureInputError, SecureInputRequest,
};
use symvault_store::{Entry, Store};
use tempfile::tempdir;

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    normalizations: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit_sha: String,
    source_hash: String,
    generator_hash: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    tool: String,
    arguments: Value,
    response: Option<Value>,
    raw_error: Option<String>,
    stored_value: Option<String>,
    prompt_calls: usize,
    prompt_title: Option<String>,
    prompt_path: Option<String>,
    prompt_field: Option<String>,
    prompt_description: Option<String>,
    prompt_hidden: bool,
    input_value: Option<String>,
    approval_reads: usize,
    call_order: Vec<String>,
}

#[derive(Default)]
struct FakeSecureInput {
    tty: bool,
    value: Option<String>,
    error: Option<String>,
    requests: Mutex<Vec<SecureInputRequest>>,
    order: Arc<Mutex<Vec<String>>>,
}

impl SecureInputSeam for FakeSecureInput {
    fn is_tty_present(&self) -> bool {
        self.tty
    }

    fn prompt(&self, request: &SecureInputRequest) -> Result<String, SecureInputError> {
        self.requests.lock().unwrap().push(request.clone());
        self.order.lock().unwrap().push("secure_input".into());
        match self.error.as_deref() {
            Some("timeout") => Err(SecureInputError::Timeout),
            Some("cancel") => Err(SecureInputError::Canceled),
            _ => Ok(self.value.clone().unwrap_or_default()),
        }
    }
}

struct FakeApproval {
    approved: bool,
    error: Option<ApprovalError>,
    requests: Mutex<Vec<ApprovalRequest>>,
    order: Arc<Mutex<Vec<String>>>,
}

impl ApprovalSeam for FakeApproval {
    fn is_tty_present(&self) -> bool {
        true
    }

    fn request(&self, request: &ApprovalRequest) -> ApprovalResult {
        self.requests.lock().unwrap().push(request.clone());
        self.order.lock().unwrap().push("approval".into());
        ApprovalResult {
            approved: self.approved,
            remembered: false,
            error: self.error.clone(),
        }
    }
}

#[test]
fn secure_input_contract_replays_source_bound_go_handlers() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../../testdata/port/mcp/secure-input.json"))
            .expect("decode actual Go secure input fixture");
    assert_eq!(
        fixture.oracle.commit_sha,
        "1add155a1ab213cbe8bb42a24254f972cda0ffc1"
    );
    assert!(!fixture.oracle.source_hash.is_empty());
    assert!(!fixture.oracle.generator_hash.is_empty());
    assert_eq!(
        fixture.normalizations,
        [
            "Rust deliberately suppresses terminal echo for secure input; Go's go-tty ReadString echoes printable runes despite the hidden-input prompt."
        ]
    );
    assert_eq!(fixture.cases.len(), 11);

    for case in fixture.cases {
        let root = tempdir().expect("synthetic disposable vault");
        fs::write(
            root.path().join("config.yaml"),
            "vault:\n  format_version: 1\n",
        )
        .expect("write synthetic config");
        fs::write(
            root.path().join("identity.age"),
            b"synthetic identity marker",
        )
        .expect("write identity marker");
        fs::create_dir(root.path().join("entries")).expect("create entries");
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(root.path(), &identity).expect("open synthetic store");
        store
            .write_new_entry(
                "allowed/service",
                &Entry {
                    path: "allowed/service".into(),
                    data: BTreeMap::from([("existing".into(), json!("synthetic-before"))]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("seed synthetic entry");

        let order = Arc::new(Mutex::new(Vec::new()));
        let secure = Arc::new(FakeSecureInput {
            tty: case.name != "backend_unavailable",
            value: case.input_value.clone(),
            error: (case.name == "input_timeout").then(|| "timeout".into()),
            requests: Mutex::new(Vec::new()),
            order: Arc::clone(&order),
        });
        let approval = Arc::new(FakeApproval {
            approved: case.name != "approval_denied_before_prompt",
            error: None,
            requests: Mutex::new(Vec::new()),
            order: Arc::clone(&order),
        });
        let mut available_tools = read_only_tool_names();
        if case.name != "backend_unavailable" {
            available_tools.push(case.tool.clone());
        }
        let unavailable_tools = if case.name == "backend_unavailable" {
            vec![ReadOnlyUnavailableTool {
                name: case.tool.clone(),
                code: "not_available".into(),
                reason: format!(
                    "tool \"{}\" is not available in the current environment (requires TTY or GUI dialog). Alternatives: set_entry_field",
                    case.tool
                ),
            }]
        } else {
            Vec::new()
        };
        let identity_for_runtime = {
            let encoded = symvault_crypto::identity_string(&identity);
            symvault_crypto::parse_identity(
                std::str::from_utf8(encoded.as_bytes()).expect("generated identity is UTF-8"),
            )
            .expect("parse synthetic runtime identity")
        };
        let runtime = StoreReadOnlyRuntime::open(
            root.path(),
            identity_for_runtime,
            ReadOnlyRuntimeConfig {
                agent_name: "secure-input-fixture".into(),
                tier: "admin".into(),
                approval_mode: match case.name.as_str() {
                    "approval_then_secure_input" | "approval_denied_before_prompt" => "prompt",
                    "approval_mode_deny" => "deny",
                    _ => "none",
                }
                .into(),
                can_write: case.name != "write_capability_denied",
                allowed_paths: vec!["allowed".into()],
                available_tools,
                unavailable_tools,
                ..ReadOnlyRuntimeConfig::default()
            },
            None,
            None,
        )
        .expect("open secure input runtime")
        .with_secure_input_seam(Arc::clone(&secure) as Arc<dyn SecureInputSeam>)
        .with_approval_seam(Arc::clone(&approval) as Arc<dyn ApprovalSeam>);

        let result = match runtime.authorize(&case.tool, &case.arguments) {
            Err(result) => Ok(result),
            Ok(()) => runtime.call(&case.tool, &case.arguments),
        };
        match (&case.raw_error, result) {
            (Some(expected), Err(actual)) => assert_eq!(actual, *expected, "{}", case.name),
            (None, Ok(actual)) => {
                let expected = case.response.as_ref().expect("Go handler response");
                let expected_error = expected["isError"].as_bool().unwrap_or(false);
                let expected_text = expected["content"][0]["text"].as_str().unwrap_or_default();
                assert_eq!(actual.is_error, expected_error, "{}", case.name);
                assert_eq!(actual.text, expected_text, "{}", case.name);
            }
            (Some(expected), Ok(actual)) => {
                assert!(
                    actual.is_error,
                    "{} should preserve handler failure",
                    case.name
                );
                assert_eq!(actual.text, *expected, "{}", case.name);
            }
            (None, Err(actual)) => panic!("{}: unexpected Rust error: {actual}", case.name),
        }

        let requests = secure.requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            case.prompt_calls,
            "prompt count {}",
            case.name
        );
        if let Some(request) = requests.first() {
            assert_eq!(
                Some(request.title.as_str()),
                case.prompt_title.as_deref(),
                "{}",
                case.name
            );
            assert_eq!(
                Some(request.path.as_str()),
                case.prompt_path.as_deref(),
                "{}",
                case.name
            );
            assert_eq!(
                Some(request.field.as_str()),
                case.prompt_field.as_deref(),
                "{}",
                case.name
            );
            assert_eq!(
                request.description.as_str(),
                case.prompt_description.as_deref().unwrap_or_default(),
                "{}",
                case.name
            );
            assert!(case.prompt_hidden, "Go prompt should mark its input hidden");
        }
        assert_eq!(
            approval.requests.lock().unwrap().len(),
            case.approval_reads,
            "approval prompt count {}",
            case.name
        );
        assert_eq!(
            *order.lock().unwrap(),
            case.call_order,
            "call order {}",
            case.name
        );

        let store = Store::open(root.path(), &identity).expect("reopen synthetic vault");
        let entry = store
            .get("allowed/service", &identity)
            .expect("read synthetic entry");
        let stored = case
            .arguments
            .get("field")
            .and_then(Value::as_str)
            .and_then(|field| entry.data.get(field))
            .and_then(Value::as_str);
        assert_eq!(
            stored,
            case.stored_value.as_deref(),
            "stored value {}",
            case.name
        );
    }
}
