use std::{collections::BTreeMap, fs, path::Path, sync::Arc, time::Duration};

use serde::Deserialize;
use serde_json::{Value, json};
use symvault_core::session::MemoryKeyring;
use symvault_mcp::store_adapter::ApprovalSeam;
use symvault_mcp::{
    CommandExecution, CommandExecutor, ReadOnlyRuntimeConfig, StoreReadOnlyRuntime, ToolCallRuntime,
};
use symvault_platform::approval::{ApprovalError, ApprovalRequest, ApprovalResult};
use symvault_store::{Entry, Store};
use tempfile::tempdir;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    cases: Vec<Case>,
    approval_observations: Vec<ApprovalObservation>,
}

#[derive(Deserialize)]
struct ApprovalObservation {
    name: String,
    attempt_outcomes: Vec<String>,
    attempt_errors: Vec<String>,
    remembered: bool,
    approval_counter: i64,
    prompt_count: usize,
    request_counters: Vec<i64>,
    events: Vec<ApprovalEvent>,
    #[serde(default)]
    visible_details: Vec<String>,
}

#[derive(Deserialize)]
struct ApprovalEvent {
    action: String,
    path: String,
    ok: bool,
}

#[derive(Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_files: Vec<String>,
    generator_digest: String,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    phase: String,
    input: Value,
    output: Expected,
}

#[derive(Deserialize)]
struct Expected {
    text: String,
    is_error: bool,
    #[serde(default)]
    error: String,
}

struct FixtureExecutor {
    timeout: bool,
}

impl CommandExecutor for FixtureExecutor {
    fn run(
        &self,
        command: &[String],
        environment: &BTreeMap<String, String>,
        files: &BTreeMap<String, Vec<u8>>,
        additional_redactions: &[Vec<u8>],
        working_directory: Option<&Path>,
        timeout: Duration,
    ) -> Result<CommandExecution, String> {
        if self.timeout {
            assert_eq!(command, ["<fixture-timeout-child>"]);
            assert_eq!(timeout, Duration::from_secs(1));
            assert_eq!(
                environment
                    .get("SYMAIRA_EXECUTE_SECRET_TIMEOUT_CHILD")
                    .map(String::as_str),
                Some("1")
            );
            return Ok(CommandExecution {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: -1,
                timed_out: true,
                duration: Duration::from_secs(1),
            });
        }
        assert_eq!(command, ["go", "run", "<fixture-child-go-source>"]);
        assert_eq!(
            environment.get("GITHUB_PASSWORD").map(String::as_str),
            Some("testpass123")
        );
        assert_eq!(
            environment.get("PLAIN").map(String::as_str),
            Some("literal-value")
        );
        assert!(files.is_empty());
        assert_eq!(additional_redactions, [b"testpass123".to_vec()]);
        assert!(working_directory.is_none());
        assert_eq!(timeout, Duration::from_secs(30));
        Ok(CommandExecution {
            stdout: "testpass123:literal-value".into(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
            duration: Duration::ZERO,
        })
    }
}

#[test]
fn source_bound_go_execute_with_secret_contract() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/execute-with-secret.json"
    ))
    .expect("decode Go oracle fixture");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle.commit,
        "12d8c616ae98b954a9b906e0984af1613ca05fde"
    );
    assert_eq!(fixture.oracle.commit_sha, fixture.oracle.commit);
    assert!(!fixture.oracle.source_files.is_empty());
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_files.len(), 8);
    for path in [
        "internal/mcp/server/approval_test.go",
        "internal/mcp/server/tools_run_test.go",
        "internal/mcp/server/tools_test_helpers.go",
    ] {
        assert!(
            fixture
                .oracle
                .generator_files
                .iter()
                .any(|file| file == path)
        );
    }
    assert_eq!(fixture.oracle.generator_digest.len(), 64);

    for case in fixture.cases {
        let mut config = ReadOnlyRuntimeConfig {
            available_tools: vec!["execute_with_secret".into()],
            can_run_commands: true,
            allowed_executables: vec!["go".into(), "true".into()],
            allowed_paths: vec!["*".into()],
            approval_mode: "none".into(),
            ..ReadOnlyRuntimeConfig::default()
        };
        match case.name.as_str() {
            "can_run_commands_denied" => {
                config.can_run_commands = false;
                config.agent_name = "fixture-readonly".into();
            }
            "executable_allowlist_denied" => config.allowed_executables = vec!["echo".into()],
            "reference_scope_denied" => config.allowed_paths = vec!["other".into()],
            "dotted_resolution_scope_denied" => config.allowed_paths = vec!["allowed/foo".into()],
            "approval_mode_denied" => config.approval_mode = "deny".into(),
            "timeout_protocol_error" => config.allowed_executables.clear(),
            _ => {}
        }
        let directory = tempdir().expect("temporary vault");
        fs::create_dir(directory.path().join("entries")).expect("entries directory");
        fs::write(
            directory.path().join("config.yaml"),
            b"vault:\n  format_version: 2\n",
        )
        .expect("vault config");
        fs::write(directory.path().join("identity.age"), b"fixture marker")
            .expect("identity marker");
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(directory.path(), &identity).expect("open fixture vault");
        for (path, data) in [
            (
                "github",
                BTreeMap::from([("password".into(), json!("testpass123"))]),
            ),
            (
                "allowed/foo",
                BTreeMap::from([("other".into(), json!("inside"))]),
            ),
            (
                "allowed/foo.bar",
                BTreeMap::from([("token".into(), json!("outside"))]),
            ),
        ] {
            store
                .write_new_entry(
                    path,
                    &Entry {
                        path: path.into(),
                        data,
                        ..Entry::default()
                    },
                    &identity,
                )
                .expect("write source-bound synthetic entry");
        }
        let runtime = StoreReadOnlyRuntime::open(directory.path(), identity, config, None, None)
            .expect("open case runtime")
            .with_command_executor(Arc::new(FixtureExecutor {
                timeout: case.name == "timeout_protocol_error",
            }));
        let expected_text = normalize_result_text(&case.output.text);
        if case.phase == "authorize" {
            let error = runtime
                .authorize("execute_with_secret", &case.input)
                .expect_err("Go fixture records an authorization rejection");
            assert_eq!(error.text, case.output.error, "{} authorization", case.name);
            continue;
        }
        runtime
            .authorize("execute_with_secret", &case.input)
            .unwrap_or_else(|error| panic!("{} authorization: {}", case.name, error.text));
        match runtime.call("execute_with_secret", &case.input) {
            Ok(actual) => {
                assert_eq!(
                    actual.is_error, case.output.is_error,
                    "{} error flag",
                    case.name
                );
                assert_eq!(
                    normalize_result_text(&actual.text),
                    expected_text,
                    "{} text",
                    case.name
                );
                assert_eq!(
                    case.output.error, "",
                    "{} unexpected Go handler error",
                    case.name
                );
            }
            Err(actual_error) => {
                assert_eq!(
                    case.output.error, actual_error,
                    "{} handler error",
                    case.name
                );
                assert!(case.output.text.is_empty(), "{} expected text", case.name);
            }
        }
    }
}

#[derive(Clone)]
struct ContractApproval {
    result: ApprovalResult,
    requests: Arc<std::sync::Mutex<Vec<ApprovalRequest>>>,
}

impl ApprovalSeam for ContractApproval {
    fn is_tty_present(&self) -> bool {
        true
    }

    fn request(&self, request: &ApprovalRequest) -> ApprovalResult {
        self.requests
            .lock()
            .expect("request log")
            .push(request.clone());
        self.result.clone()
    }
}

struct ApprovalContractExecutor;

impl CommandExecutor for ApprovalContractExecutor {
    fn run(
        &self,
        _command: &[String],
        _environment: &BTreeMap<String, String>,
        _files: &BTreeMap<String, Vec<u8>>,
        _additional_redactions: &[Vec<u8>],
        _working_directory: Option<&Path>,
        _timeout: Duration,
    ) -> Result<CommandExecution, String> {
        Ok(CommandExecution {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
            duration: Duration::ZERO,
        })
    }
}

#[test]
fn source_bound_go_execute_with_secret_approval_contract() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/execute-with-secret.json"
    ))
    .expect("decode Go oracle fixture");
    for observation in fixture.approval_observations {
        let directory = tempdir().expect("temporary approval vault");
        fs::create_dir(directory.path().join("entries")).expect("entries directory");
        fs::write(
            directory.path().join("config.yaml"),
            b"vault:\n  format_version: 2\n",
        )
        .expect("vault config");
        fs::write(directory.path().join("identity.age"), b"fixture marker")
            .expect("identity marker");
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(directory.path(), &identity).expect("open fixture vault");
        store
            .write_new_entry(
                "github",
                &Entry {
                    path: "github".into(),
                    data: BTreeMap::from([("password".into(), json!("testpass123"))]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("write synthetic secret");
        let keyring = MemoryKeyring::new();
        let audit = Arc::new(std::sync::Mutex::new(
            symvault_store::audit::open_with_keyring(
                "fixture-approval-agent",
                directory.path(),
                &keyring,
                symvault_store::audit::RotationConfig::default(),
            )
            .expect("audit logger"),
        ));
        let (approved, remembered, error) = match observation.name.as_str() {
            "granted" => (true, false, None),
            "granted_twice" => (true, false, None),
            "denied" => (false, false, None),
            "remembered" => (true, true, None),
            "helper_error" => (
                false,
                false,
                Some(ApprovalError::RawMode("fixture raw failure".into())),
            ),
            other => panic!("unknown Go approval observation {other}"),
        };
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seam = ContractApproval {
            result: ApprovalResult {
                approved,
                remembered,
                error: error.clone(),
            },
            requests: Arc::clone(&requests),
        };
        let config = ReadOnlyRuntimeConfig {
            available_tools: vec!["execute_with_secret".into()],
            can_run_commands: true,
            allowed_executables: vec!["true".into()],
            allowed_paths: vec!["*".into()],
            approval_mode: "prompt".into(),
            agent_name: "fixture-approval-agent".into(),
            approval_timeout: Duration::ZERO,
            ..ReadOnlyRuntimeConfig::default()
        };
        let runtime = StoreReadOnlyRuntime::open_with_audit(
            directory.path(),
            identity,
            config,
            None,
            Some(Arc::clone(&audit)),
        )
        .expect("runtime")
        .with_approval_seam(Arc::new(seam))
        .with_command_executor(Arc::new(ApprovalContractExecutor));
        let input = json!({
            "command": ["true", "testpass123"],
            "secret_refs": ["op://vault/github/password"],
            "timeout": 5
        });
        let mut actual_outcomes = Vec::new();
        let mut actual_errors = Vec::new();
        for _ in &observation.attempt_outcomes {
            match runtime.call("execute_with_secret", &input) {
                Ok(_) => {
                    actual_outcomes.push("granted".to_owned());
                    actual_errors.push(String::new());
                }
                Err(error) => {
                    actual_outcomes.push("error".to_owned());
                    actual_errors.push(error);
                }
            }
        }
        assert_eq!(
            actual_outcomes, observation.attempt_outcomes,
            "{} outcomes",
            observation.name
        );
        assert_eq!(
            actual_errors, observation.attempt_errors,
            "{} errors",
            observation.name
        );
        assert_eq!(
            observation.remembered,
            observation
                .events
                .iter()
                .any(|event| event.action == "approval.execute_with_secret.remembered"),
            "{} remember cache state",
            observation.name
        );
        assert_eq!(
            requests.lock().expect("request log").len(),
            observation.prompt_count,
            "{} prompt count",
            observation.name
        );
        let requests = requests.lock().expect("request log");
        let actual_request_counters = requests
            .iter()
            .map(|request| request.secrets_accessed)
            .collect::<Vec<_>>();
        assert_eq!(
            actual_request_counters, observation.request_counters,
            "{} live approval counter at each prompt",
            observation.name
        );
        if observation.name == "granted_twice" {
            assert_eq!(actual_request_counters, [0, 1]);
        }
        let expected_final_counter = if approved && error.is_none() {
            requests.len() as i64
        } else {
            0
        };
        assert_eq!(
            observation.approval_counter, expected_final_counter,
            "{} final Go/Rust approval counter",
            observation.name
        );
        if let Some(request) = requests.first() {
            assert_eq!(
                request.timeout,
                Duration::from_secs(30),
                "zero timeout Go fallback"
            );
            assert!(
                request.details.contains("[REDACTED]"),
                "Rust prompt redacts command secrets"
            );
            assert!(
                !request.details.contains("testpass123"),
                "Rust prompt does not expose the Go fixture secret"
            );
            // The fixture's named normalization is limited to visible prompt details.
            if !observation.visible_details.is_empty() {
                assert!(observation.visible_details[0].contains("testpass1"));
            }
        }
        let event_path = audit.lock().expect("audit logger").path().to_owned();
        let actual_events = fs::read_to_string(event_path)
            .expect("read audit log")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("audit event"))
            .map(|event| {
                (
                    event["action"].as_str().unwrap_or_default().to_owned(),
                    event["path"].as_str().unwrap_or_default().to_owned(),
                    event["ok"].as_bool().unwrap_or(false),
                )
            })
            .collect::<Vec<_>>();
        let expected_events = observation
            .events
            .into_iter()
            .map(|event| (event.action, event.path, event.ok))
            .collect::<Vec<_>>();
        assert_eq!(
            actual_events, expected_events,
            "{} audit order",
            observation.name
        );
    }
}

fn normalize_result_text(text: &str) -> String {
    let normalized = normalize_marker(text);
    let Ok(mut value) = serde_json::from_str::<Value>(&normalized) else {
        return normalized;
    };
    if let Some(object) = value.as_object_mut() {
        if object.contains_key("duration_ms") {
            object.insert("duration_ms".into(), Value::from(0));
        }
        for key in ["stdout", "stderr"] {
            if let Some(output) = object
                .get_mut(key)
                .and_then(|value| value.as_str())
                .map(str::to_owned)
            {
                object.insert(key.into(), Value::String(normalize_marker(&output)));
            }
        }
    }
    serde_json::to_string(&value).expect("encode normalized result")
}

fn normalize_marker(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"DATA_")
            && bytes.get(index + 5..index + 21).is_some_and(|marker| {
                marker.len() == 16 && marker.iter().all(u8::is_ascii_hexdigit)
            })
        {
            output.push_str("DATA_FIXTURE");
            index += 21;
        } else {
            let character = text[index..].chars().next().expect("valid UTF-8 boundary");
            output.push(character);
            index += character.len_utf8();
        }
    }
    output
}
