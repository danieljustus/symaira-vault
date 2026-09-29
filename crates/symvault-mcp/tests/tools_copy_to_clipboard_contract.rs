use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use symvault_core::platform::{Clipboard, PlatformError};
use symvault_mcp::store_adapter::{ApprovalSeam, StoreReadOnlyRuntime};
use symvault_mcp::{ProtocolHandler, ReadOnlyRuntimeConfig, read_only_tool_names, run_stream};
use symvault_platform::approval::{ApprovalRequest, ApprovalResult};
use symvault_store::{Entry, Store};
use tempfile::tempdir;

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    server_name: String,
    server_version: String,
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
    can_use_clipboard: bool,
    allowed_paths: Vec<String>,
    approval_mode: String,
    tty: bool,
    auto_clear_duration: u64,
    input: Vec<String>,
    output: Vec<Value>,
    clipboard_events: Vec<String>,
    approval_reads: usize,
    #[serde(default)]
    approval_counters: Vec<i64>,
    #[serde(default)]
    approval_prompt_contains: Vec<String>,
}

#[derive(Default)]
struct FakeClipboard {
    writes: Mutex<Vec<Vec<u8>>>,
    fail: bool,
}

impl Clipboard for FakeClipboard {
    fn set(&self, text: &[u8]) -> Result<(), PlatformError> {
        if self.fail {
            return Err(PlatformError::unavailable("synthetic clipboard failure"));
        }
        self.writes.lock().unwrap().push(text.to_vec());
        Ok(())
    }

    fn clear(&self) -> Result<(), PlatformError> {
        self.set(b"")
    }
}

struct FakeApproval {
    tty: bool,
    approved: bool,
    remembered: bool,
    requests: Mutex<Vec<ApprovalRequest>>,
}

impl ApprovalSeam for FakeApproval {
    fn is_tty_present(&self) -> bool {
        self.tty
    }

    fn request(&self, request: &ApprovalRequest) -> ApprovalResult {
        self.requests.lock().unwrap().push(request.clone());
        ApprovalResult {
            approved: self.approved,
            remembered: self.remembered,
            error: None,
        }
    }
}

#[test]
fn copy_to_clipboard_replays_source_bound_go_dispatcher() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/copy-clipboard.json"
    ))
    .expect("decode actual Go copy_to_clipboard fixture");
    assert_eq!(
        fixture.oracle.commit_sha,
        "00d1187cc27abb782acfadf4462708c38d66fb25"
    );
    assert_eq!(fixture.oracle.source_hash.len(), 64);
    assert_eq!(fixture.oracle.generator_hash.len(), 64);
    assert_eq!(fixture.cases.len(), 16);

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
        .expect("write synthetic identity marker");
        fs::create_dir(root.path().join("entries")).expect("create entries");
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(root.path(), &identity).expect("open synthetic store");
        store
            .write_new_entry(
                "github",
                &Entry {
                    path: "github".into(),
                    data: BTreeMap::from([
                        ("username".into(), serde_json::json!("fixture-user")),
                        ("password".into(), serde_json::json!("StrongP@ssw0rd123")),
                    ]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("seed password entry");
        store
            .write_new_entry(
                "missing-password",
                &Entry {
                    path: "missing-password".into(),
                    data: BTreeMap::from([("username".into(), serde_json::json!("fixture-user"))]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("seed entry without password");
        store
            .write_new_entry(
                "wrong-type",
                &Entry {
                    path: "wrong-type".into(),
                    data: BTreeMap::from([("password".into(), serde_json::json!(17))]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("seed entry with non-string password");

        let clipboard = Arc::new(FakeClipboard {
            fail: case.name == "clipboard_write_error",
            ..FakeClipboard::default()
        });
        let approval = Arc::new(FakeApproval {
            tty: case.tty,
            approved: case.name != "approval_prompt_denied",
            remembered: case.name == "approval_remembered_cache",
            requests: Mutex::new(Vec::new()),
        });
        let runtime = StoreReadOnlyRuntime::from_store(
            store,
            identity,
            ReadOnlyRuntimeConfig {
                server_name: fixture.server_name.clone(),
                server_version: fixture.server_version.clone(),
                transport: "stdio".into(),
                agent_name: "clipboard-fixture".into(),
                tier: "admin".into(),
                allowed_paths: case.allowed_paths.clone(),
                approval_mode: case.approval_mode.clone(),
                can_use_clipboard: case.can_use_clipboard,
                available_tools: read_only_tool_names(),
                vault_dir: "<fixture-vault>".into(),
                vault_unlocked: true,
                ..ReadOnlyRuntimeConfig::default()
            },
            None,
            None,
        )
        .expect("construct synthetic runtime")
        .with_clipboard(clipboard.clone())
        .with_clipboard_auto_clear_duration(Duration::from_secs(case.auto_clear_duration))
        .with_approval_seam(approval.clone());
        let mut handler = ProtocolHandler::with_tool_call_runtime(
            &fixture.server_name,
            &fixture.server_version,
            Arc::new(runtime),
        );
        let input = case
            .input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let actual: Vec<Value> = run_stream(&input, &mut handler)
            .expect("Rust copy_to_clipboard protocol dispatch")
            .iter()
            .map(|line| serde_json::from_str(line).expect("Rust response is JSON"))
            .collect();
        assert_eq!(actual, case.output, "clipboard case {}", case.name);
        let secret_text = serde_json::to_string(&actual).expect("encode responses");
        assert!(
            !secret_text.contains("StrongP@ssw0rd123"),
            "{} returned its synthetic password",
            case.name
        );

        if case.auto_clear_duration > 0 && case.clipboard_events.contains(&"clear".into()) {
            let deadline = Instant::now() + Duration::from_secs(3);
            while clipboard.writes.lock().unwrap().len() < case.clipboard_events.len()
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let actual_events = clipboard
            .writes
            .lock()
            .unwrap()
            .iter()
            .map(|value| {
                if value.is_empty() {
                    "clear"
                } else {
                    assert_eq!(value, b"StrongP@ssw0rd123", "clipboard value");
                    "secret"
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual_events, case.clipboard_events,
            "clipboard events {}",
            case.name
        );
        let requests = approval.requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            case.approval_reads,
            "approval count {}",
            case.name
        );
        let actual_counters = requests
            .iter()
            .map(|request| request.secrets_accessed)
            .collect::<Vec<_>>();
        assert_eq!(
            actual_counters, case.approval_counters,
            "approval request counters {}",
            case.name
        );
        for request in requests.iter() {
            assert_eq!(request.operation, "copy_to_clipboard");
            assert_eq!(request.details, "copy password from github to clipboard");
            assert_eq!(
                request.risk_level,
                symvault_platform::approval::RiskLevel::High
            );
            assert!(request.can_remember);
        }
        if case.approval_reads > 0 {
            assert_eq!(
                case.approval_prompt_contains,
                [
                    "Risk:      🟠 HIGH",
                    "r=remember",
                    "copy password from github to clipboard"
                ],
                "Go approval prompt markers {}",
                case.name
            );
        } else {
            assert!(case.approval_prompt_contains.is_empty());
        }
    }
}

#[cfg(unix)]
#[test]
fn copy_to_clipboard_signal_clears_active_timer_and_continues() {
    use std::{
        env,
        io::{Read, Write},
        process::{Command, Output, Stdio},
        thread,
        time::Instant,
    };

    fn bounded_output(mut command: Command, timeout: Duration) -> Output {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .expect("spawn bounded clipboard signal process");
        let mut stdout = child.stdout.take().expect("capture child stdout");
        let mut stderr = child.stderr.take().expect("capture child stderr");
        let stdout_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).expect("read child stdout");
            bytes
        });
        let stderr_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).expect("read child stderr");
            bytes
        });
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll clipboard signal process") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                panic!("clipboard signal process exceeded {timeout:?}");
            }
            thread::sleep(Duration::from_millis(10));
        };
        Output {
            status,
            stdout: stdout_reader.join().expect("join stdout reader"),
            stderr: stderr_reader.join().expect("join stderr reader"),
        }
    }

    fn signal_child(pid: &str, signal: &str) {
        let mut command = Command::new("kill");
        command.args([signal, pid]);
        let output = bounded_output(command, Duration::from_secs(2));
        assert!(
            output.status.success(),
            "signal {signal} failed: {output:?}"
        );
    }

    if env::var_os("SYMVAULT_MCP_CLIPBOARD_SIGNAL_CHILD").is_some() {
        use std::process::id;

        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../../testdata/port/mcp/copy-clipboard.json"
        ))
        .expect("decode source-bound Go clipboard fixture");
        let case = fixture
            .cases
            .iter()
            .find(|case| case.name == "success_auto_clear")
            .expect("Go auto-clear case");
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
        .expect("write synthetic identity marker");
        fs::create_dir(root.path().join("entries")).expect("create entries");
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(root.path(), &identity).expect("open synthetic store");
        store
            .write_new_entry(
                "github",
                &Entry {
                    path: "github".into(),
                    data: BTreeMap::from([(
                        "password".into(),
                        serde_json::json!("synthetic-clipboard-value"),
                    )]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("seed synthetic password entry");
        let clipboard = Arc::new(FakeClipboard::default());
        symvault_platform::approval::install_stdio_clipboard_signal_router(clipboard.clone())
            .expect("install process-owned child signal router");
        let runtime = StoreReadOnlyRuntime::from_store(
            store,
            identity,
            ReadOnlyRuntimeConfig {
                server_name: fixture.server_name.clone(),
                server_version: fixture.server_version.clone(),
                transport: "stdio".into(),
                agent_name: "signal-child".into(),
                tier: "admin".into(),
                allowed_paths: case.allowed_paths.clone(),
                approval_mode: "none".into(),
                can_use_clipboard: true,
                available_tools: read_only_tool_names(),
                vault_dir: "<fixture-vault>".into(),
                vault_unlocked: true,
                ..ReadOnlyRuntimeConfig::default()
            },
            None,
            None,
        )
        .expect("construct synthetic runtime")
        .with_clipboard(clipboard.clone())
        .with_clipboard_auto_clear_duration(Duration::from_secs(30));
        let mut handler = ProtocolHandler::with_tool_call_runtime(
            &fixture.server_name,
            &fixture.server_version,
            Arc::new(runtime),
        );
        let input = case
            .input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let responses = run_stream(&input, &mut handler).expect("dispatch actual clipboard tool");
        assert_eq!(responses.len(), case.output.len());
        assert!(clipboard.writes.lock().unwrap()[0].starts_with(b"synthetic-clipboard-value"));

        let pid = id().to_string();
        signal_child(&pid, "-TERM");
        let deadline = Instant::now() + Duration::from_secs(3);
        while clipboard.writes.lock().unwrap().len() < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(clipboard.writes.lock().unwrap().len(), 2);
        assert!(clipboard.writes.lock().unwrap()[1].is_empty());
        println!("RUST_MCP_CLIPBOARD_SIGNAL_RECEIPT clear=1 continued=true");
        std::io::stdout().flush().unwrap();
        return;
    }

    let mut command = Command::new(env::current_exe().expect("current test binary"));
    command
        .arg("--exact")
        .arg("copy_to_clipboard_signal_clears_active_timer_and_continues")
        .arg("--nocapture")
        .env("SYMVAULT_MCP_CLIPBOARD_SIGNAL_CHILD", "1");
    let output = bounded_output(command, Duration::from_secs(10));
    assert!(
        output.status.success(),
        "active clipboard signal child did not continue: status={:?}, stdout={}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("RUST_MCP_CLIPBOARD_SIGNAL_RECEIPT clear=1 continued=true"),
        "child did not prove active timer clear-and-continue: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
