//! PLATFORM-002 / ADR 0034 item 29: the anomaly detector wired into the Rust
//! MCP call path like Go's `detectAnomalyAsync` (`server_dispatch.go`, pinned by
//! `testdata/port/mcp/anomaly-detector.json`): the `anomaly_<type>` audit row,
//! the warning log, the approval-cache invalidation and the calls the detector
//! must not see. The clock is injected; nothing depends on the wall clock.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex};
use symvault_core::platform::{Clipboard, PlatformError};
use symvault_core::session::MemoryKeyring;
use symvault_mcp::anomaly::AnomalyClock;
use symvault_mcp::store_adapter::{ApprovalSeam, StoreReadOnlyRuntime};
use symvault_mcp::{ProtocolHandler, ReadOnlyRuntimeConfig, read_only_tool_names, run_stream};
use symvault_platform::approval::{ApprovalRequest, ApprovalResult};
use symvault_store::{Entry, Store, audit::RotationConfig};
use tempfile::TempDir;
use time::{OffsetDateTime, UtcOffset};

/// 2026-11-03 12:00:00 +01:00.
const NOON: i64 = 1_793_703_600;

struct TestClock(Mutex<OffsetDateTime>);

impl TestClock {
    fn at_local_hour(hour: u8) -> Arc<Self> {
        let clock = Self(Mutex::new(
            OffsetDateTime::from_unix_timestamp(NOON)
                .unwrap()
                .to_offset(UtcOffset::from_hms(1, 0, 0).unwrap())
                .replace_hour(hour)
                .unwrap(),
        ));
        Arc::new(clock)
    }

    fn advance(&self, seconds: i64) {
        let mut now = self.0.lock().unwrap();
        *now += time::Duration::seconds(seconds);
    }
}

impl AnomalyClock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

struct FakeClipboard;

impl Clipboard for FakeClipboard {
    fn set(&self, _text: &[u8]) -> Result<(), PlatformError> {
        Ok(())
    }

    fn clear(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}

struct FakeApproval {
    requests: Mutex<usize>,
}

impl ApprovalSeam for FakeApproval {
    fn is_tty_present(&self) -> bool {
        true
    }

    fn request(&self, _request: &ApprovalRequest) -> ApprovalResult {
        *self.requests.lock().unwrap() += 1;
        ApprovalResult {
            approved: true,
            remembered: true,
            error: None,
        }
    }
}

struct Session {
    root: TempDir,
    keyring: MemoryKeyring,
    handler: ProtocolHandler,
    runtime: Arc<StoreReadOnlyRuntime>,
    audit: Arc<Mutex<symvault_store::audit::Logger>>,
    clock: Arc<TestClock>,
    log: Arc<Mutex<Vec<String>>>,
    approval: Arc<FakeApproval>,
}

#[derive(Clone, Copy)]
struct Options {
    hour: u8,
    canary_flag: bool,
    can_read_values: bool,
}

const DAY: Options = Options {
    hour: 12,
    canary_flag: true,
    can_read_values: false,
};

fn session(options: Options) -> Session {
    session_with_sink(options, None)
}

/// `sink` replaces the default recording log sink when given.
fn session_with_sink(options: Options, sink: Option<symvault_mcp::anomaly::WarnSink>) -> Session {
    let root = tempfile::tempdir().expect("synthetic vault");
    fs::write(
        root.path().join("config.yaml"),
        "vault:\n  format_version: 1\n",
    )
    .unwrap();
    fs::write(
        root.path().join("identity.age"),
        b"synthetic identity marker",
    )
    .unwrap();
    fs::create_dir(root.path().join("entries")).unwrap();
    let identity = symvault_crypto::generate_identity();
    let store = Store::open(
        symvault_store::data_safety::test_support_pre_marked(root.path()),
        &identity,
    )
    .unwrap();
    for (path, canary) in [
        ("github", false),
        ("honey/pot", options.canary_flag),
        ("plain/pot", false),
    ] {
        store
            .write_new_entry(
                path,
                &Entry {
                    path: path.into(),
                    data: BTreeMap::from([
                        ("username".into(), json!("fixture-user")),
                        ("password".into(), json!("StrongP@ssw0rd123")),
                    ]),
                    canary,
                    ..Entry::default()
                },
                &identity,
            )
            .unwrap();
    }
    let keyring = MemoryKeyring::new();
    let logger = symvault_store::audit::open_with_keyring(
        "fixture",
        root.path(),
        &keyring,
        RotationConfig::default(),
    )
    .unwrap();
    let audit = Arc::new(Mutex::new(logger));
    let clock = TestClock::at_local_hour(options.hour);
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink_log = log.clone();
    let approval = Arc::new(FakeApproval {
        requests: Mutex::new(0),
    });
    let runtime = Arc::new(
        StoreReadOnlyRuntime::from_store_with_audit(
            store,
            identity,
            ReadOnlyRuntimeConfig {
                server_name: "symvault".into(),
                server_version: "0.0.0-fixture".into(),
                transport: "stdio".into(),
                agent_name: "fixture".into(),
                tier: "admin".into(),
                allowed_paths: vec!["*".into()],
                approval_mode: "prompt".into(),
                can_use_clipboard: true,
                can_read_values: options.can_read_values,
                available_tools: read_only_tool_names(),
                vault_dir: "<fixture-vault>".into(),
                vault_unlocked: true,
                ..ReadOnlyRuntimeConfig::default()
            },
            None,
            Some(audit.clone()),
        )
        .unwrap()
        .with_clipboard(Arc::new(FakeClipboard))
        .with_approval_seam(approval.clone())
        .with_anomaly_clock(clock.clone())
        .with_anomaly_log(sink.unwrap_or_else(|| {
            Arc::new(move |line| {
                sink_log.lock().unwrap().push(line.to_owned());
            })
        })),
    );
    let handler =
        ProtocolHandler::with_tool_call_runtime("symvault", "0.0.0-fixture", runtime.clone());
    Session {
        root,
        keyring,
        handler,
        runtime,
        audit,
        clock,
        log,
        approval,
    }
}

impl Session {
    fn call(&mut self, tool: &str, arguments: Value) -> Value {
        let input = format!(
            "{}\n{}\n{}\n",
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"probe","version":"1.0"},"capabilities":{}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            json!({"jsonrpc":"2.0","id":777,"method":"tools/call",
                   "params":{"name":tool,"arguments":arguments}}),
        );
        let out = run_stream(&input, &mut self.handler).expect("stream dispatch");
        serde_json::from_str(out.last().expect("tool response")).expect("response JSON")
    }

    fn rows(&self) -> Vec<Value> {
        let path = self.audit.lock().unwrap().path().to_path_buf();
        fs::read_to_string(path)
            .expect("audit log")
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit row"))
            .collect()
    }

    fn anomaly_rows(&self) -> Vec<Value> {
        self.rows()
            .into_iter()
            .filter(|row| row["action"].as_str().unwrap_or("").starts_with("anomaly_"))
            .collect()
    }

    /// Verifies the whole audit file against the HMAC chain; `mutate` may
    /// tamper with the text first.
    fn chain_valid(&self, mutate: impl Fn(String) -> String) -> bool {
        let (path, kid) = {
            let logger = self.audit.lock().unwrap();
            (logger.path().to_path_buf(), logger.kid().to_owned())
        };
        let text = mutate(fs::read_to_string(path).unwrap());
        let key =
            symvault_store::audit::load_or_create_key_with_keyring(self.root.path(), &self.keyring)
                .expect("audit key");
        let keys = BTreeMap::from([(kid.clone(), key)]);
        let result = symvault_store::audit::verify_jsonl(text.as_bytes(), &keys, &kid);
        result.valid && result.tampered == 0 && result.verified >= 1
    }

    fn log_lines(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn prompts(&self) -> usize {
        *self.approval.requests.lock().unwrap()
    }
}

fn is_hex(value: &Value, len: usize) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// The row Go writes: failure row named after the type, the alert's path, the
/// session id and nothing else that identifies the triggering call.
fn assert_go_anomaly_row(row: &Value, kind: &str, path: &str) {
    assert_eq!(row["action"], format!("anomaly_{kind}"));
    assert_eq!(row["agent"], "fixture");
    assert_eq!(row["transport"], "stdio");
    assert_eq!(row["ok"], false);
    assert_eq!(row["reason"], format!("anomaly_{kind}"));
    if path.is_empty() {
        // `path` is omitempty in Go's audit row, like every other empty field.
        assert!(row.get("path").is_none(), "{row}");
    } else {
        assert_eq!(row["path"], path);
    }
    assert!(is_hex(&row["sess_id"], 32), "{row}");
    assert!(
        row.get("req_id").is_none(),
        "Go logs with context.Background(): {row}"
    );
    assert!(row.get("token_id").is_none(), "{row}");
}

#[test]
fn off_hours_access_writes_the_go_row_and_both_warning_lines() {
    let mut s = session(Options { hour: 3, ..DAY });
    let response = s.call("get_entry", json!({"path": "github"}));
    assert_eq!(response["result"]["isError"], false, "{response}");

    let rows = s.anomaly_rows();
    assert_eq!(rows.len(), 1, "{:?}", s.rows());
    assert_go_anomaly_row(&rows[0], "off_hours", "github");
    // The triggering call keeps its own identified row, before the anomaly row.
    let all = s.rows();
    let get = all
        .iter()
        .position(|r| r["action"] == "get")
        .expect("get row");
    assert!(is_hex(&all[get]["req_id"], 16));
    assert!(
        all.iter()
            .position(|r| r["action"] == "anomaly_off_hours")
            .unwrap()
            > get
    );
    assert_eq!(rows[0]["sess_id"], all[get]["sess_id"]);

    // Go logs the detector hook (type, severity, agent, description) and then
    // the dispatch line (adds path and request_id).
    let lines = s.log_lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    let desc = "description=\"Entry access during off-hours by agent fixture\"";
    assert_eq!(
        lines[0],
        format!(
            "2026/11/03 03:00:00 WARN anomaly detected type=off_hours severity=low agent=fixture {desc}"
        )
    );
    assert!(
        lines[1].starts_with(
            "2026/11/03 03:00:00 WARN anomaly detected type=off_hours severity=low agent=fixture path=github request_id="
        ) && lines[1].ends_with(&format!(" {desc}")),
        "{}",
        lines[1]
    );
    assert!(is_hex(
        &json!(&lines[1][lines[1].find("request_id=").unwrap() + 11..][..16]),
        16
    ));
    assert_eq!(s.runtime.anomaly_window_len(), 1);

    // The anomaly row is an ordinary link of the HMAC chain; renaming it breaks it.
    assert!(s.chain_valid(|text| text));
    assert!(!s.chain_valid(|text| text.replace("anomaly_off_hours", "anomaly_sweep")));
}

#[test]
fn daytime_access_to_an_ordinary_entry_is_silent() {
    let mut s = session(DAY);
    for _ in 0..3 {
        s.call("get_entry", json!({"path": "github"}));
    }
    assert!(s.anomaly_rows().is_empty(), "{:?}", s.rows());
    assert!(s.log_lines().is_empty());
    assert_eq!(s.runtime.anomaly_window_len(), 3);
}

#[test]
fn canary_access_is_critical_and_only_the_first_alert_is_audited() {
    // Off-hours and canary fire on the same call; Go's hooks log both, but the
    // dispatch audits, logs and invalidates for `alerts[0]` only (canary first).
    let mut s = session(Options { hour: 3, ..DAY });
    s.call("get_entry", json!({"path": "honey/pot"}));
    let rows = s.anomaly_rows();
    assert_eq!(rows.len(), 1, "{:?}", s.rows());
    assert_go_anomaly_row(&rows[0], "canary_access", "honey/pot");
    let lines = s.log_lines();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines[0].contains("type=canary_access severity=critical agent=fixture description="));
    assert!(lines[1].contains("type=off_hours severity=low agent=fixture description="));
    assert!(
        lines[2].contains(
            "type=canary_access severity=critical agent=fixture path=honey/pot request_id="
        )
    );
}

#[test]
fn canary_flag_off_is_the_negative_control() {
    let mut s = session(Options {
        canary_flag: false,
        ..DAY
    });
    s.call("get_entry", json!({"path": "honey/pot"}));
    assert!(s.anomaly_rows().is_empty(), "{:?}", s.rows());
    assert!(s.log_lines().is_empty());
}

#[test]
fn rate_anomaly_fires_on_the_31st_call_inside_the_window_with_an_empty_path() {
    let mut s = session(DAY);
    for i in 0..30 {
        s.call("list_entries", json!({}));
        assert!(s.anomaly_rows().is_empty(), "call {i}");
    }
    s.call("list_entries", json!({}));
    let rows = s.anomaly_rows();
    assert_eq!(rows.len(), 1);
    assert_go_anomaly_row(&rows[0], "rate_anomaly", "");
    let lines = s.log_lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[1].contains("type=rate_anomaly severity=medium agent=fixture path=\"\" request_id=")
    );
    assert!(lines[1].ends_with("description=\"Rate anomaly: fixture made 31 requests\""));

    // Aged out of the 60 s window the counter starts over.
    s.clock.advance(61);
    s.call("list_entries", json!({}));
    assert_eq!(s.anomaly_rows().len(), 1);
}

#[test]
fn an_anomaly_invalidates_the_approval_cache_so_the_next_call_is_reapproved() {
    let mut s = session(DAY);
    let copy = || json!({"path": "github"});
    s.call("copy_to_clipboard", copy());
    assert_eq!(s.prompts(), 1, "first call prompts and is remembered");
    s.call("copy_to_clipboard", copy());
    assert_eq!(s.prompts(), 1, "second call is served from the cache");
    assert!(s.anomaly_rows().is_empty());

    // The canary read raises an anomaly: the cache is cleared.
    s.call("get_entry", json!({"path": "honey/pot"}));
    assert_eq!(s.anomaly_rows().len(), 1);
    s.call("copy_to_clipboard", copy());
    assert_eq!(
        s.prompts(),
        2,
        "the next call after an anomaly is re-approved"
    );
    s.call("copy_to_clipboard", copy());
    assert_eq!(s.prompts(), 2, "and is remembered again");
}

#[test]
fn without_an_anomaly_the_cache_survives_other_calls_negative_control() {
    let mut s = session(DAY);
    s.call("copy_to_clipboard", json!({"path": "github"}));
    s.call("get_entry", json!({"path": "plain/pot"}));
    s.call("copy_to_clipboard", json!({"path": "github"}));
    assert_eq!(s.prompts(), 1);
    assert!(s.anomaly_rows().is_empty());
}

#[test]
fn off_hours_alone_also_invalidates_the_cache_any_alert_does() {
    let mut s = session(DAY);
    s.call("copy_to_clipboard", json!({"path": "github"}));
    assert_eq!(s.prompts(), 1);
    s.clock.advance(15 * 3600); // 03:00 next day
    s.call("get_entry", json!({"path": "plain/pot"}));
    let rows = s.anomaly_rows();
    assert_eq!(rows.len(), 1);
    assert_go_anomaly_row(&rows[0], "off_hours", "plain/pot");
    s.call("copy_to_clipboard", json!({"path": "github"}));
    // The copy itself is off-hours too (another invalidation), and it re-prompted.
    assert_eq!(s.prompts(), 2);
}

#[test]
fn denied_unknown_and_rate_limited_calls_never_reach_the_detector() {
    let mut s = session(Options { hour: 3, ..DAY });
    // Token-scope denial: Go returns before the detector.
    s.handler.set_token_scope(&["get_entry".to_string()]);
    let denied = s.call("list_entries", json!({"prefix": "github"}));
    assert_eq!(denied["result"]["isError"], true, "{denied}");
    // Unknown tool: a JSON-RPC error before the detector.
    let unknown = s.call("not_a_tool", json!({"path": "github"}));
    assert!(unknown.get("error").is_some(), "{unknown}");
    assert_eq!(s.runtime.anomaly_window_len(), 0);
    assert!(s.anomaly_rows().is_empty(), "{:?}", s.rows());
    assert!(s.log_lines().is_empty());

    // A rate-limit pre-hook failure also returns before the detector.
    s.runtime.set_rate_limit_per_minute(Some(1));
    s.call("get_entry", json!({"path": "github"}));
    assert_eq!(s.runtime.anomaly_window_len(), 1);
    let limited = s.call("get_entry", json!({"path": "github"}));
    assert!(limited.get("error").is_some(), "{limited}");
    assert_eq!(
        s.runtime.anomaly_window_len(),
        1,
        "the refused call was not observed"
    );
    assert_eq!(s.anomaly_rows().len(), 1, "only the admitted call alerted");
}

#[test]
fn tool_result_errors_are_observed_like_go() {
    // A missing entry is a tool-result error (Go: handler returned a result,
    // `ok=true`, no field length); the detector still sees the call and the
    // path-bearing off-hours rule fires for it.
    let mut s = session(Options { hour: 3, ..DAY });
    s.call("get_entry", json!({"path": "missing/entry"}));
    let rows = s.anomaly_rows();
    assert_eq!(rows.len(), 1, "{:?}", s.rows());
    assert_go_anomaly_row(&rows[0], "off_hours", "missing/entry");
}

/// A log sink that fails (panics) on its first line must not be able to undo
/// or pre-empt the durable effects: the audit row is appended and the approval
/// cache cleared before any warning line is written.
#[test]
fn a_failing_log_sink_cannot_suppress_the_audit_row_or_the_cache_invalidation() {
    let mut s = session_with_sink(DAY, Some(Arc::new(|_| panic!("sink failed"))));
    let copy = || json!({"path": "github"});
    s.call("copy_to_clipboard", copy());
    assert_eq!(s.prompts(), 1);

    let canary = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.call("get_entry", json!({"path": "honey/pot"}))
    }));
    assert!(
        canary.is_err(),
        "the sink must have been reached and failed"
    );

    let rows = s.anomaly_rows();
    assert_eq!(rows.len(), 1, "audit row written before the sink ran");
    assert_go_anomaly_row(&rows[0], "canary_access", "honey/pot");
    assert!(s.chain_valid(|text| text));

    s.call("copy_to_clipboard", copy());
    assert_eq!(s.prompts(), 2, "cache was invalidated before the sink ran");
}

/// The sink only ever observes state that already includes the audit row.
#[test]
fn the_sink_runs_after_the_audit_row_is_persisted() {
    let audit_path = Arc::new(Mutex::new(None::<std::path::PathBuf>));
    let seen = Arc::new(Mutex::new(Vec::<usize>::new()));
    let (path_for_sink, seen_for_sink) = (audit_path.clone(), seen.clone());
    let mut s = session_with_sink(
        Options { hour: 3, ..DAY },
        Some(Arc::new(move |_| {
            let path = path_for_sink.lock().unwrap().clone().expect("audit path");
            let anomalies = fs::read_to_string(path)
                .unwrap()
                .lines()
                .filter(|line| line.contains("\"anomaly_off_hours\""))
                .count();
            seen_for_sink.lock().unwrap().push(anomalies);
        })),
    );
    *audit_path.lock().unwrap() = Some(s.audit.lock().unwrap().path().to_path_buf());
    s.call("get_entry", json!({"path": "github"}));
    assert_eq!(*seen.lock().unwrap(), vec![1, 1], "both lines saw the row");
}
