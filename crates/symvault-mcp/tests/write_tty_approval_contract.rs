use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    sync::{Arc, Mutex},
    time::Duration,
};
use symvault_mcp::approval::ApprovalQueue;
use symvault_mcp::store_adapter::ApprovalSeam;
use symvault_mcp::{
    ReadOnlyRuntimeConfig, StoreReadOnlyRuntime, ToolCallRuntime, read_only_tool_names,
};
use symvault_platform::approval::{ApprovalError, ApprovalRequest, ApprovalResult};
use symvault_store::{
    Entry, EntryMetadata, Store,
    audit::{AuditKey, Logger, RotationConfig},
};
use tempfile::tempdir;

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    normalizations: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_files: Vec<String>,
    source_hash: String,
    generator_files: Vec<String>,
    generator_hash: String,
}

#[test]
fn invalid_approval_mode_fails_closed_on_the_direct_queue_path() {
    let (root, identity, verifier) = synthetic_vault();
    let queue = Arc::new(ApprovalQueue::default());
    let runtime = StoreReadOnlyRuntime::open(
        root.path(),
        identity,
        ReadOnlyRuntimeConfig {
            agent_name: "fixture".into(),
            tier: "admin".into(),
            approval_mode: "unrecognized".into(),
            can_write: true,
            allowed_paths: vec!["*".into()],
            available_tools: read_only_tool_names(),
            ..ReadOnlyRuntimeConfig::default()
        },
        None,
        None,
    )
    .expect("open invalid-mode runtime")
    .with_approval_queue(Arc::clone(&queue));
    let result = runtime
        .call(
            "set_entry_field",
            &json!({"path":"github", "field":"username", "value":"must-not-write"}),
        )
        .expect("invalid-mode response");
    assert!(result.is_error);
    assert!(result.text.contains("unknown approval mode"));
    assert!(queue.pending().expect("inspect pending queue").is_empty());
    let store = Store::open(root.path(), &verifier).expect("reopen invalid-mode vault");
    let entry = store
        .get("github", &verifier)
        .expect("read unchanged entry");
    assert_eq!(entry.data.get("username"), Some(&json!("fixture-user")));
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    tool: String,
    arguments: Value,
    text: String,
    error_class: String,
    is_error: bool,
    exists: bool,
    username: Option<String>,
    audit_actions: Vec<String>,
    approval_calls: usize,
    prompt_details: Vec<String>,
    summary_details: Vec<String>,
    prompt_risks: Vec<String>,
    can_remember: Vec<bool>,
    secrets_accessed: Vec<i64>,
    prompt_timeout_seconds: Vec<u64>,
}

#[derive(Default)]
struct FakeApproval {
    tty: bool,
    outcomes: Mutex<VecDeque<ApprovalResult>>,
    requests: Mutex<Vec<ApprovalRequest>>,
}

impl ApprovalSeam for FakeApproval {
    fn is_tty_present(&self) -> bool {
        self.tty
    }

    fn request(&self, request: &ApprovalRequest) -> ApprovalResult {
        self.requests
            .lock()
            .expect("requests lock")
            .push(request.clone());
        self.outcomes
            .lock()
            .expect("outcomes lock")
            .pop_front()
            .expect("fixture provides every approval outcome")
    }
}

#[test]
fn set_and_delete_tty_approval_replay_go_handlers_and_mutation_order() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/write-tty-approval.json"
    ))
    .expect("valid Go write approval fixture");
    assert_eq!(fixture.oracle.commit, "a581df7b");
    assert_eq!(
        fixture.oracle.commit_sha,
        "a581df7b09630a0d8c572af727b7cf096d2557ad"
    );
    assert_eq!(
        fixture.oracle.source_hash,
        "04b595dcf89bb40db57e6de6b6919a518fd076e15e8c78fbfccbab82d0011fc7"
    );
    assert_eq!(
        fixture.oracle.generator_hash,
        "b70ad2c27469d7f4e8c4d11e76f9ad2418fd1f236233a8dcc902e4e6cc8ec931"
    );
    assert_eq!(fixture.oracle.source_files.len(), 89);
    assert_eq!(fixture.oracle.generator_files.len(), 4);
    assert_eq!(
        fixture.normalizations,
        [
            "terminal read/raw error wording is compared by approval failure class; Go and Rust terminal backends expose different low-level messages",
            "terminal Directory/Git/Project context rows are omitted; they describe the checkout rather than approval behavior"
        ]
    );

    for case in fixture.cases {
        let (root, identity, verifier) = synthetic_vault();
        let audit_path = root.path().join("write-approval-audit.jsonl");
        let audit = Arc::new(Mutex::new(
            Logger::open(
                &audit_path,
                AuditKey::new([0x5a; 32]).expect("audit fixture key"),
                RotationConfig::default(),
            )
            .expect("open fixture audit log"),
        ));
        let repeat = case.name == "set_approved_twice";
        let approved = matches!(case.name.as_str(), "set_approved_twice" | "delete_approved");
        let error = match case.name.as_str() {
            "set_prompt_read_error" => Some(ApprovalError::Read("fixture read error".into())),
            "delete_prompt_raw_error" => Some(ApprovalError::RawMode("fixture raw error".into())),
            "set_prompt_timeout" => Some(ApprovalError::Timeout(Duration::from_secs(30))),
            _ => None,
        };
        let count = if repeat {
            2
        } else if case.name == "set_no_tty" {
            0
        } else {
            1
        };
        let fake = Arc::new(FakeApproval {
            tty: case.name != "set_no_tty",
            outcomes: Mutex::new(
                (0..count)
                    .map(|_| ApprovalResult {
                        approved,
                        remembered: false,
                        error: error.clone(),
                    })
                    .collect(),
            ),
            requests: Mutex::new(Vec::new()),
        });
        let config = ReadOnlyRuntimeConfig {
            agent_name: "fixture".into(),
            tier: "admin".into(),
            approval_mode: "prompt".into(),
            approval_timeout: Duration::ZERO,
            can_write: true,
            allowed_paths: vec!["*".into()],
            available_tools: read_only_tool_names(),
            ..ReadOnlyRuntimeConfig::default()
        };
        let runtime =
            StoreReadOnlyRuntime::open_with_audit(root.path(), identity, config, None, Some(audit))
                .expect("open synthetic store runtime")
                .with_approval_seam(Arc::clone(&fake) as Arc<dyn ApprovalSeam>);

        let calls = if repeat { 2 } else { 1 };
        let mut result = None;
        for _ in 0..calls {
            result = Some(
                runtime
                    .call(&case.tool, &case.arguments)
                    .expect("write handler result"),
            );
        }
        let result = result.expect("at least one handler call");
        assert_eq!(
            result.is_error, case.is_error,
            "error flag for {}",
            case.name
        );
        match case.error_class.as_str() {
            "none" => {
                assert!(!result.is_error, "{} should succeed", case.name);
                assert_eq!(result.text, case.text, "response text for {}", case.name);
            }
            "denied" => {
                assert!(
                    result.text.contains("denied"),
                    "{}: {}",
                    case.name,
                    result.text
                );
                assert_eq!(result.text, case.text, "denial text for {}", case.name);
            }
            "no_tty" => assert_eq!(result.text, case.text, "no-TTY text for {}", case.name),
            "approval_failed" => assert!(
                result.text.contains("approval failed"),
                "{}: {}",
                case.name,
                result.text
            ),
            other => panic!("unrecognized Go error class {other}"),
        }

        let requests = fake.requests.lock().expect("requests lock");
        assert_eq!(
            requests.len(),
            case.approval_calls,
            "approval calls for {}",
            case.name
        );
        assert!(requests.len() <= case.summary_details.len());
        assert_eq!(case.prompt_details.len(), case.prompt_risks.len());
        assert_eq!(case.prompt_details.len(), case.can_remember.len());
        assert_eq!(case.prompt_details.len(), case.secrets_accessed.len());
        assert_eq!(case.prompt_details.len(), case.prompt_timeout_seconds.len());
        for (index, request) in requests.iter().enumerate() {
            assert_eq!(request.operation, case.tool);
            assert_eq!(
                request.details, case.summary_details[index],
                "Go summary for {}",
                case.name
            );
            if index >= case.prompt_details.len() {
                // Go's fake Raw failure happens before RequestApproval writes
                // any prompt bytes, so there is no rendered detail row to
                // compare for that failed terminal open.
                continue;
            }
            assert_eq!(request.risk_level.label(), case.prompt_risks[index]);
            assert_eq!(request.can_remember, case.can_remember[index]);
            assert_eq!(request.secrets_accessed, case.secrets_accessed[index]);
            assert_eq!(
                request.timeout.as_secs(),
                case.prompt_timeout_seconds[index]
            );
        }
        drop(requests);

        let audit_text = fs::read_to_string(&audit_path).expect("read Rust audit log");
        let audit_actions = audit_text
            .lines()
            .map(|line| {
                serde_json::from_str::<Value>(line).expect("Rust audit JSON")["action"]
                    .as_str()
                    .expect("audit action")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            audit_actions, case.audit_actions,
            "audit order for {}",
            case.name
        );

        let store = Store::open(root.path(), &verifier).expect("reopen synthetic vault");
        let entry = store.get("github", &verifier);
        let exists = entry.is_ok();
        assert_eq!(exists, case.exists, "entry existence for {}", case.name);
        if let (Ok(entry), Some(username)) = (entry, case.username) {
            assert_eq!(entry.data.get("username"), Some(&Value::String(username)));
        }
    }
}

fn synthetic_vault() -> (
    tempfile::TempDir,
    symvault_crypto::Identity,
    symvault_crypto::Identity,
) {
    let root = tempdir().expect("synthetic vault tempdir");
    fs::write(
        root.path().join("config.yaml"),
        "vault:\n  format_version: 1\n",
    )
    .expect("write vault config");
    fs::write(root.path().join("identity.age"), b"fixture identity marker")
        .expect("write identity marker");
    fs::create_dir(root.path().join("entries")).expect("create entries directory");
    let identity = symvault_crypto::generate_identity();
    let verifier = symvault_crypto::generate_identity();
    fs::write(
        root.path().join("recipients.txt"),
        symvault_crypto::recipient_string(&verifier),
    )
    .expect("write recipient");
    let store = Store::open(root.path(), &identity).expect("open fixture store");
    let data = BTreeMap::from([
        ("password".into(), json!("StrongP@ssw0rd123")),
        ("username".into(), json!("fixture-user")),
    ]);
    store
        .write_new_entry(
            "github",
            &Entry {
                path: "github".into(),
                data,
                metadata: EntryMetadata {
                    created: "2026-01-01T00:00:00Z".into(),
                    updated: "2026-01-01T00:00:00Z".into(),
                    version: 1,
                    ..EntryMetadata::default()
                },
                ..Entry::default()
            },
            &identity,
        )
        .expect("write encrypted fixture entry");
    (root, identity, verifier)
}
