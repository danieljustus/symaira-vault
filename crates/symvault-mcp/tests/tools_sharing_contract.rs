//! MCP-003 sharing corpus: `request_share`, `approve_share`, `revoke_share` and
//! `list_shares` replayed against `testdata/port/mcp/tools-sharing.json`.
//!
//! The fixture is recorded by the real Go handlers
//! (`internal/mcp/server/mcp_sharing_fixture_generator_test.go`, check target
//! `make mcp-sharing-fixtures-check`). Every step compares the tool result
//! (content text, `isError`, JSON-RPC error) with Go's, the approval prompt
//! bytes shown to the human, the on-disk share store and the audit rows.
//! Per-run values are canonicalised with the rules in the fixture's
//! `normalizations` (ids, nonces, clock timestamps, Go's unspecified list order).

use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use std::{
    collections::BTreeMap,
    fs,
    sync::{Arc, Mutex},
};
use symvault_core::session::MemoryKeyring;
use symvault_crypto::generate_identity;
use symvault_mcp::store_adapter::ApprovalSeam;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyRuntimeConfig, StoreReadOnlyRuntime, read_only_tool_names, run_stream,
};
use symvault_platform::approval::{ApprovalError, ApprovalRequest, ApprovalResult, build_prompt};
use symvault_store::{Store, audit::RotationConfig};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// The injected clock of every replay. The fixture only knows "the running
/// clock" (`@NOW@`), so any fixed instant works.
const CLOCK_UNIX: i64 = 1_780_000_000;
const TIME_KEYS: [&str; 4] = ["created_at", "approved_at", "revoked_at", "expires_at"];
const EXPECTED_CASES: usize = 87;
const EXPECTED_STEPS: usize = 240;
const EXPECTED_PROMPTS: usize = 20;
/// Steps minus the four production nil-store pins, which Rust cannot run.
const EXPECTED_EXECUTED: usize = 236;

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_files: Vec<String>,
    source_hash: String,
    generator_hash: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    kind: String,
    agent: String,
    allowed_paths: Vec<String>,
    signing_key: bool,
    #[serde(default)]
    no_share_store: bool,
    seed: Option<Vec<Value>>,
    approval: Approval,
    steps: Vec<Step>,
    #[serde(default)]
    id_shapes: Vec<String>,
    store: Vec<Value>,
    audit: Vec<AuditRow>,
}

#[derive(Debug, Deserialize)]
struct Approval {
    tty: bool,
    #[serde(default)]
    reply: String,
    #[serde(default)]
    error: String,
}

#[derive(Debug, Deserialize)]
struct Step {
    tool: String,
    arguments: Value,
    response: Option<Value>,
    go_panic: Option<String>,
    #[serde(default)]
    prompt: String,
}

#[derive(Debug, Deserialize, PartialEq)]
struct AuditRow {
    action: String,
    #[serde(default)]
    path: String,
    ok: bool,
}

/// Synthetic human: answers like the Go terminal mock of the recording.
struct FakeHuman {
    tty: bool,
    result: ApprovalResult,
    prompted: Mutex<Vec<ApprovalRequest>>,
}

impl FakeHuman {
    fn from_fixture(approval: &Approval) -> Arc<Self> {
        let error = match approval.error.as_str() {
            "" => None,
            "timeout" => Some(ApprovalError::Timeout(std::time::Duration::from_secs(60))),
            other => match other.split_once(':') {
                Some(("read", text)) => Some(ApprovalError::Read(text.to_owned())),
                Some(("raw", text)) => Some(ApprovalError::RawMode(text.to_owned())),
                _ => panic!("unknown approval error kind {other:?}"),
            },
        };
        // Go's parseApprovalResponse: y, yes, r and remember (any case, trimmed).
        let approved = matches!(
            approval.reply.trim().to_lowercase().as_str(),
            "y" | "yes" | "r" | "remember"
        );
        Arc::new(Self {
            tty: approval.tty,
            result: ApprovalResult {
                approved: error.is_none() && approved,
                remembered: false,
                error,
            },
            prompted: Mutex::new(Vec::new()),
        })
    }

    fn take_prompts(&self) -> Vec<ApprovalRequest> {
        std::mem::take(&mut *self.prompted.lock().expect("prompt log lock"))
    }

    /// The bytes Go wrote to the terminal for this request: the box, then the
    /// echoed decision. A raw-mode failure happens before anything is written;
    /// a timeout or read error leaves the prompt without an echo.
    fn terminal_bytes(&self, request: &ApprovalRequest) -> String {
        match &self.result.error {
            Some(ApprovalError::RawMode(_)) => String::new(),
            Some(_) => build_prompt(request),
            None if self.result.approved => format!("{}yes\n", build_prompt(request)),
            None => format!("{}no\n", build_prompt(request)),
        }
    }
}

impl ApprovalSeam for FakeHuman {
    fn is_tty_present(&self) -> bool {
        self.tty
    }

    fn request(&self, request: &ApprovalRequest) -> ApprovalResult {
        self.prompted
            .lock()
            .expect("prompt log lock")
            .push(request.clone());
        self.result.clone()
    }
}

struct Replay {
    root: tempfile::TempDir,
    handler: ProtocolHandler,
    audit: Arc<Mutex<symvault_store::audit::Logger>>,
    human: Arc<FakeHuman>,
    /// Real ids in creation order (`@GRANT_n@`).
    ids: Vec<String>,
    seed_times: BTreeMap<String, BTreeMap<String, String>>,
}

fn clock() -> String {
    OffsetDateTime::from_unix_timestamp(CLOCK_UNIX)
        .expect("clock")
        .format(&Rfc3339)
        .expect("format clock")
}

fn clock_plus_ttl(ttl_ns: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(
        i128::from(CLOCK_UNIX) * 1_000_000_000 + i128::from(ttl_ns),
    )
    .expect("clock plus ttl")
    .format(&Rfc3339)
    .expect("format clock plus ttl")
}

fn open_replay(case: &Case) -> Replay {
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
    let mut seed_times: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    if let Some(seed) = &case.seed {
        fs::write(
            root.path().join("mcp-shares.json"),
            json!({"version": 1, "grants": seed}).to_string(),
        )
        .expect("seed share store");
        for grant in seed {
            let id = grant["id"].as_str().expect("seed id").to_owned();
            let times = seed_times.entry(id).or_default();
            for key in TIME_KEYS {
                if let Some(value) = grant[key].as_str() {
                    times.insert(key.to_owned(), value.to_owned());
                }
            }
        }
    }

    let identity = generate_identity();
    Store::open(
        symvault_store::data_safety::test_support_pre_marked(root.path()),
        &identity,
    )
    .expect("open synthetic vault");
    let keyring = MemoryKeyring::new();
    let audit = Arc::new(Mutex::new(
        symvault_store::audit::open_with_keyring(
            &case.agent,
            root.path(),
            &keyring,
            RotationConfig::default(),
        )
        .expect("open synthetic audit logger"),
    ));
    let config = ReadOnlyRuntimeConfig {
        server_name: "Symaira Vault MCP".into(),
        server_version: "1.0.0".into(),
        transport: "stdio".into(),
        agent_name: case.agent.clone(),
        tier: "admin".into(),
        approval_mode: "none".into(),
        can_write: true,
        allowed_paths: case.allowed_paths.clone(),
        available_tools: read_only_tool_names(),
        vault_dir: root.path().to_string_lossy().into_owned(),
        vault_unlocked: true,
        now_unix: Some(CLOCK_UNIX),
        ..ReadOnlyRuntimeConfig::default()
    };
    let human = FakeHuman::from_fixture(&case.approval);
    let mut runtime = StoreReadOnlyRuntime::open_with_audit(
        root.path(),
        identity,
        config,
        None,
        Some(Arc::clone(&audit)),
    )
    .expect("construct store runtime")
    .with_approval_seam(Arc::clone(&human) as Arc<dyn ApprovalSeam>);
    if case.signing_key {
        runtime = runtime.with_grant_signing_key(symvault_crypto::SecretBytes::new(&[42; 32]));
    }
    let handler = ProtocolHandler::with_tool_call_runtime("symvault", "1.0.0", Arc::new(runtime));
    Replay {
        root,
        handler,
        audit,
        human,
        ids: Vec::new(),
        seed_times,
    }
}

impl Replay {
    fn placeholder(index: usize) -> String {
        format!("@GRANT_{}@", index + 1)
    }

    /// Replace a placeholder argument by the real id issued in this replay.
    fn unplace(&self, value: &Value) -> Value {
        match value {
            Value::String(text) => self
                .ids
                .iter()
                .enumerate()
                .find(|(index, _)| *text == Self::placeholder(*index))
                .map_or_else(|| value.clone(), |(_, id)| Value::String(id.clone())),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, item)| (key.clone(), self.unplace(item)))
                    .collect(),
            ),
            Value::Array(items) => Value::Array(items.iter().map(|i| self.unplace(i)).collect()),
            other => other.clone(),
        }
    }

    /// Ids, then HMAC nonces, then the first eight bytes of every id.
    fn mask_id(&self, text: &str) -> String {
        let mut text = text.to_owned();
        for (index, id) in self.ids.iter().enumerate() {
            text = text.replace(id, &Self::placeholder(index));
        }
        for (index, id) in self.ids.iter().enumerate() {
            if let Some((nonce, _)) = id.split_once(':') {
                let label = Self::placeholder(index);
                text = text.replace(nonce, &format!("{}_NONCE@", label.trim_end_matches('@')));
            }
        }
        for (index, id) in self.ids.iter().enumerate() {
            if id.len() >= 8 {
                let label = Self::placeholder(index);
                text = text.replace(&id[..8], &format!("{}_ID8@", label.trim_end_matches('@')));
            }
        }
        text
    }

    fn mask_value(&self, value: &Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.mask_id(text)),
            Value::Array(items) => Value::Array(items.iter().map(|i| self.mask_value(i)).collect()),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, item)| (key.clone(), self.mask_value(item)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// Sort a `list_shares` array by masked id keeping each element's exact
    /// bytes, with clock-derived timestamps replaced by `@TS@`.
    fn canonical_list(&self, text: &str) -> String {
        let Ok(elements) = serde_json::from_str::<Vec<Box<RawValue>>>(text) else {
            return text.to_owned();
        };
        let mut items = elements
            .iter()
            .map(|raw| {
                let grant: Value = serde_json::from_str(raw.get()).expect("listed grant");
                let id = grant["id"].as_str().expect("listed id").to_owned();
                let mut element = raw.get().to_owned();
                for key in TIME_KEYS {
                    let Some(value) = grant[key].as_str() else {
                        continue;
                    };
                    if self
                        .seed_times
                        .get(&id)
                        .and_then(|times| times.get(key))
                        .is_some_and(|seeded| seeded == value)
                    {
                        continue;
                    }
                    element = element.replace(
                        &format!("\"{key}\":\"{value}\""),
                        &format!("\"{key}\":\"@TS@\""),
                    );
                }
                (self.mask_id(&id), self.mask_id(&element))
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.0.cmp(&right.0));
        format!(
            "[{}]",
            items
                .into_iter()
                .map(|(_, element)| element)
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    fn canonical_store(&self) -> Vec<Value> {
        let path = self
            .root
            .path()
            .canonicalize()
            .expect("canonical vault root")
            .join("mcp-shares.json");
        let Ok(data) = fs::read_to_string(path) else {
            return Vec::new();
        };
        let file: Value = serde_json::from_str(&data).expect("share store JSON");
        assert_eq!(file["version"], 1, "share store version");
        let now = clock();
        let mut grants = file["grants"]
            .as_array()
            .expect("grant array")
            .iter()
            .map(|grant| {
                let id = grant["id"].as_str().expect("stored id").to_owned();
                let mut masked = grant.clone();
                for key in TIME_KEYS {
                    let Some(value) = grant[key].as_str() else {
                        continue;
                    };
                    if self
                        .seed_times
                        .get(&id)
                        .and_then(|times| times.get(key))
                        .is_some_and(|seeded| seeded == value)
                    {
                        continue;
                    }
                    let ttl = grant["ttl"].as_i64().unwrap_or(0);
                    let label = if key != "expires_at" {
                        (value == now).then_some("@NOW@")
                    } else if ttl > 0
                        && grant["approved_at"].as_str() == Some(now.as_str())
                        && value == clock_plus_ttl(ttl)
                    {
                        Some("@APPROVED_AT+TTL@")
                    } else if ttl > 0
                        && grant["created_at"].as_str() == Some(now.as_str())
                        && value == clock_plus_ttl(ttl)
                    {
                        Some("@CREATED_AT+TTL@")
                    } else {
                        None
                    };
                    if let Some(label) = label {
                        masked[key] = Value::String(label.to_owned());
                    }
                }
                self.mask_value(&masked)
            })
            .collect::<Vec<_>>();
        grants.sort_by(|left, right| {
            left["id"]
                .as_str()
                .unwrap_or_default()
                .cmp(right["id"].as_str().unwrap_or_default())
        });
        grants
    }

    fn audit_rows(&self) -> Vec<AuditRow> {
        let path = self.audit.lock().expect("audit lock").path().to_owned();
        fs::read_to_string(path)
            .expect("read audit")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("audit JSON"))
            .map(|event| AuditRow {
                action: event["action"].as_str().unwrap_or_default().to_owned(),
                path: self.mask_id(event["path"].as_str().unwrap_or_default()),
                ok: event["ok"].as_bool().unwrap_or(false),
            })
            .collect()
    }

    fn call(&mut self, index: usize, step: &Step) -> Value {
        let line = json!({
            "jsonrpc": "2.0",
            "id": index + 2,
            "method": "tools/call",
            "params": {"name": step.tool, "arguments": self.unplace(&step.arguments)}
        });
        let stream = format!(
            "{}\n{}\n{line}\n",
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        );
        let output = run_stream(&stream, &mut self.handler).expect("dispatch sharing stream");
        serde_json::from_str(output.last().expect("call response")).expect("response JSON")
    }
}

fn result_text(response: &Value) -> Option<&str> {
    response["result"]["content"][0]["text"].as_str()
}

fn is_error(response: &Value) -> bool {
    response["result"]["isError"] == true || response.get("error").is_some()
}

fn id_shape(id: &str) -> &'static str {
    let hex = |text: &str, len: usize| {
        text.len() == len
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    match id.split_once(':') {
        None if hex(id, 32) => "hex32",
        Some((nonce, mac)) if hex(nonce, 32) && hex(mac, 64) => "hmac",
        _ => "unexpected",
    }
}

fn load_fixture() -> Fixture {
    // CRLF checkouts must not change the recorded strings' meaning.
    let text = include_str!("../../../testdata/port/mcp/tools-sharing.json").replace("\r\n", "\n");
    serde_json::from_str(&text).expect("valid Go sharing fixture")
}

#[test]
fn sharing_fixture_is_source_bound_and_complete() {
    let fixture = load_fixture();
    assert_eq!(fixture.oracle.commit, "ac481774");
    assert_eq!(
        fixture.oracle.commit_sha,
        "ac481774bad3cf5c3445c2fbd680d3b29940e723"
    );
    assert!(
        fixture
            .oracle
            .source_files
            .iter()
            .any(|file| file == "internal/mcp/server/tools_sharing.go")
    );
    assert!(
        fixture
            .oracle
            .source_files
            .iter()
            .any(|file| file == "internal/mcp/server/sharing_store.go")
    );
    assert_eq!(fixture.oracle.source_hash.len(), 64);
    assert_eq!(fixture.oracle.generator_hash.len(), 64);
    assert_eq!(fixture.cases.len(), EXPECTED_CASES);
    assert_eq!(
        fixture.cases.iter().map(|c| c.steps.len()).sum::<usize>(),
        EXPECTED_STEPS
    );
    for tool in [
        "request_share",
        "approve_share",
        "revoke_share",
        "list_shares",
    ] {
        assert!(
            fixture
                .cases
                .iter()
                .any(|c| c.steps.iter().any(|s| s.tool == tool)),
            "no recorded case for {tool}"
        );
        assert!(read_only_tool_names().iter().any(|name| name == tool));
    }
    let mut names = fixture
        .cases
        .iter()
        .map(|c| c.name.as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), fixture.cases.len(), "case names are unique");
}

#[test]
fn sharing_tools_match_the_go_corpus() {
    let fixture = load_fixture();
    let mut executed_steps = 0;
    let mut prompts_compared = 0;
    // Every mismatch is collected so one run lists all divergences.
    let mut diffs: Vec<String> = Vec::new();
    for case in &fixture.cases {
        if case.no_share_store {
            // Production Go never attaches a share store: every sharing tool
            // panics (authz-matrix.json pins the same). Rust always has a
            // store, so only the recorded fact is checked.
            assert_eq!(case.kind, "go_defect", "{}", case.name);
            assert!(
                case.steps.iter().all(|s| s.go_panic.as_deref()
                    == Some("runtime error: invalid memory address or nil pointer dereference")),
                "{}: the nil-store pin changed",
                case.name
            );
            continue;
        }
        let mut replay = open_replay(case);
        let mut shapes = Vec::new();
        let mut diverges_from_go_panic = false;
        for (index, step) in case.steps.iter().enumerate() {
            let label = format!("{} / step {index} ({})", case.name, step.tool);
            let mut response = replay.call(index, step);
            executed_steps += 1;

            if step.tool == "request_share"
                && !is_error(&response)
                && let Some(text) = result_text(&response)
            {
                let issued: Value = serde_json::from_str(text).expect("request_share result");
                let id = issued["grant_id"].as_str().expect("grant_id").to_owned();
                shapes.push(id_shape(&id).to_owned());
                replay.ids.push(id);
            }
            if let Some(panic) = &step.go_panic {
                // Go crashed here; Rust answers instead. The difference is
                // documented in docs/rust-port/upstream-go-bugs.md and the
                // Rust answer must at least be a well-formed JSON-RPC reply.
                assert!(
                    panic.starts_with("runtime error:"),
                    "{label}: unexpected Go panic text {panic:?}"
                );
                assert_eq!(response["jsonrpc"], "2.0", "{label}");
                diverges_from_go_panic = true;
                let _ = replay.human.take_prompts();
                continue;
            }
            if step.tool == "list_shares"
                && !is_error(&response)
                && let Some(text) = result_text(&response)
            {
                response["result"]["content"][0]["text"] =
                    Value::String(replay.canonical_list(text));
            }
            let expected = step.response.as_ref().expect("recorded response");
            let actual_response = replay.mask_value(&response);
            if &actual_response != expected {
                diffs.push(format!(
                    "{label}: response\n   go:   {expected}\n   rust: {actual_response}"
                ));
            }

            let prompts = replay.human.take_prompts();
            let actual_prompt = prompts
                .last()
                .map(|request| replay.human.terminal_bytes(request))
                .unwrap_or_default();
            if replay.mask_id(&actual_prompt) != step.prompt {
                diffs.push(format!(
                    "{label}: approval prompt\n   go:   {:?}\n   rust: {:?}",
                    step.prompt,
                    replay.mask_id(&actual_prompt)
                ));
            }
            if !step.prompt.is_empty() {
                prompts_compared += 1;
            }
        }
        if shapes != case.id_shapes {
            diffs.push(format!(
                "{}: issued id shapes {shapes:?} != {:?}",
                case.name, case.id_shapes
            ));
        }
        if diverges_from_go_panic {
            continue;
        }
        let store = replay.canonical_store();
        if store != case.store {
            diffs.push(format!(
                "{}: share store\n   go:   {}\n   rust: {}",
                case.name,
                Value::Array(case.store.clone()),
                Value::Array(store)
            ));
        }
        let audit = replay.audit_rows();
        if audit != case.audit {
            diffs.push(format!(
                "{}: audit rows\n   go:   {:?}\n   rust: {:?}",
                case.name, case.audit, audit
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "{} divergences from the Go corpus:\n{}",
        diffs.len(),
        diffs.join("\n")
    );
    assert_eq!(executed_steps, EXPECTED_EXECUTED, "executed steps");
    assert_eq!(
        prompts_compared, EXPECTED_PROMPTS,
        "approval prompts compared"
    );
}
