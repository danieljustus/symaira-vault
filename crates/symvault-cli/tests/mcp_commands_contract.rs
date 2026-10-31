#![allow(dead_code)]

#[path = "../src/mcp_commands.rs"]
mod mcp_commands;
#[path = "../src/run_commands.rs"]
mod run_commands;

/// Go's `symvault mcp --stdio` subscribes SIGINT/SIGTERM/SIGQUIT for the whole
/// process (`cmd/mcp/serve_deps.go`: `ServeSignalNotify(sigCh, SIGINT, SIGTERM,
/// SIGQUIT)`), so an external SIGINT/SIGTERM never takes the OS default action:
/// it cancels the serve context and the command returns nil, i.e. exit code 0.
/// `internal/secureui/backend_tty.go` and go-tty only `signal.Stop` their own
/// channels, which leaves that subscription in place after the terminal is
/// restored. Actual Go oracle 0cc78062 under a controlling PTY (idle after a
/// completed secure-input prompt; during an ordinary approval prompt) ends with
/// `WIFEXITED` and status 0, never `WIFSIGNALED`.
#[cfg(unix)]
fn assert_go_signal_shutdown(status: std::process::ExitStatus, context: &str) {
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        (status.code(), status.signal()),
        (Some(0), None),
        "{context}: Go cancels its context on SIGINT/SIGTERM and exits 0 (not by signal)"
    );
}

#[cfg(unix)]
#[ignore = "run via scripts/rust-port/mcp-approval-pty.py for real controlling-TTY acceptance"]
#[test]
fn unix_platform_approval_pty_acceptance() {
    assert_eq!(std::env::var("SYMVAULT_PTY_ACCEPTANCE").as_deref(), Ok("1"));

    use std::{
        collections::BTreeMap,
        fs,
        io::{BufRead, BufReader, Read, Write},
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };
    use symvault_crypto::{generate_identity, identity_string};
    use symvault_mcp::store_adapter::{ApprovalSeam, PlatformApproval};
    use symvault_store::{Entry, EntryMetadata, Store};
    use tempfile::tempdir;

    assert!(
        PlatformApproval.is_tty_present(),
        "explicit PTY acceptance must run with a real controlling terminal"
    );

    let temporary = tempdir().expect("private synthetic PTY fixture directory");
    let vault = temporary.path().join("vault");
    fs::create_dir(&vault).expect("create synthetic vault");
    fs::set_permissions(&vault, fs::Permissions::from_mode(0o700))
        .expect("restrict synthetic vault permissions");
    fs::write(
        vault.join("config.yaml"),
        "vault:\n  format_version: 1\ndefaultAgent: pty-test\nauthMethod: passphrase\nagents:\n  pty-test:\n    tier: admin\n    approvalMode: prompt\n    requireApproval: true\n    approvalTimeout: 4s\n    canWrite: true\n    canRunCommands: true\n    allowedPaths:\n      - fixture\n    allowed_tools:\n      - set_entry_field\n      - execute_with_secret\n      - secure_input\n      - request_credential\n    allowedExecutables:\n      - \"true\"\n",
    )
    .expect("write synthetic prompt profile");
    fs::write(vault.join("identity.age"), b"synthetic identity marker")
        .expect("write synthetic vault identity marker");
    fs::create_dir(vault.join("entries")).expect("create synthetic entries directory");

    let identity = generate_identity();
    let identity_path = temporary.path().join("synthetic-identity.txt");
    fs::write(&identity_path, identity_string(&identity).as_bytes())
        .expect("write synthetic identity");
    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
        .expect("restrict synthetic identity permissions");

    let store = Store::open(&vault, &identity).expect("open synthetic vault");
    store
        .write_new_entry(
            "fixture",
            &Entry {
                path: "fixture".into(),
                data: BTreeMap::from([("username".into(), serde_json::json!("before"))]),
                metadata: EntryMetadata::default(),
                ..Entry::default()
            },
            &identity,
        )
        .expect("write synthetic entry");

    let executable = std::env::current_exe().expect("locate MCP test helper binary");

    /// One spawned stdio worker with isolated pipes. Responses are read from a
    /// reader thread so a hung worker is bounded by the deadline, not by the pipe.
    struct Worker {
        child: std::process::Child,
        stdin: Option<std::process::ChildStdin>,
        lines: mpsc::Receiver<std::io::Result<String>>,
        stderr: Option<thread::JoinHandle<String>>,
        stdout: String,
        responses: Vec<serde_json::Value>,
        last_response_at: Instant,
        deadline: Instant,
        name: &'static str,
    }

    enum Event {
        Response(serde_json::Value),
        Exited(std::process::ExitStatus),
    }

    impl Worker {
        fn spawn(
            name: &'static str,
            executable: &std::path::Path,
            vault: &std::path::Path,
            identity_path: &std::path::Path,
            frames: &str,
        ) -> Self {
            // Threaded libtest framing keeps the status prefix off protocol
            // stdout. Each child still selects exactly one worker.
            let mut child = Command::new(executable)
                .args([
                    "--ignored",
                    "--exact",
                    "unix_platform_approval_stdio_worker",
                    "--nocapture",
                    "--test-threads=2",
                ])
                .env("SYMVAULT_PTY_STDIO_WORKER", "1")
                .env("SYMVAULT_PTY_VAULT", vault)
                .env("SYMVAULT_PTY_IDENTITY", identity_path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| panic!("spawn {name} MCP worker: {error}"));
            let mut stdin = child.stdin.take().expect("MCP pipe stdin");
            stdin
                .write_all(frames.as_bytes())
                .unwrap_or_else(|error| panic!("send {name} MCP frames: {error}"));
            let stdout_pipe = child.stdout.take().expect("MCP worker stdout pipe");
            let (sender, lines) = mpsc::channel();
            thread::spawn(move || {
                for line in BufReader::new(stdout_pipe).lines() {
                    if sender.send(line).is_err() {
                        return;
                    }
                }
            });
            let stderr_pipe = child.stderr.take().expect("MCP worker stderr pipe");
            let stderr = thread::spawn(move || {
                let mut text = String::new();
                let _ = BufReader::new(stderr_pipe).read_to_string(&mut text);
                text
            });
            Self {
                child,
                stdin: Some(stdin),
                lines,
                stderr: Some(stderr),
                stdout: String::new(),
                responses: Vec::new(),
                last_response_at: Instant::now(),
                deadline: Instant::now() + Duration::from_secs(20),
                name,
            }
        }

        fn id(&self) -> u32 {
            self.child.id()
        }

        fn send(&mut self, frame: &str) {
            self.stdin
                .as_mut()
                .expect("MCP pipe stdin remains open")
                .write_all(frame.as_bytes())
                .unwrap_or_else(|error| panic!("send {} frame: {error}", self.name));
        }

        /// Next JSON response, or the exit once stdout closed.
        fn next(&mut self) -> Event {
            loop {
                match self.lines.recv_timeout(Duration::from_millis(50)) {
                    Ok(Ok(line)) => {
                        self.stdout.push_str(&line);
                        self.stdout.push('\n');
                        if let Ok(response) = serde_json::from_str::<serde_json::Value>(&line) {
                            self.responses.push(response.clone());
                            self.last_response_at = Instant::now();
                            return Event::Response(response);
                        }
                    }
                    Ok(Err(error)) => panic!("read {} worker stdout: {error}", self.name),
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        let status = self.child.wait().expect("reap MCP worker");
                        return Event::Exited(status);
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                if Instant::now() >= self.deadline {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    panic!(
                        "{} worker exceeded its bounded PTY acceptance deadline; stdout={}",
                        self.name, self.stdout
                    );
                }
            }
        }

        fn expect_response(&mut self, id: i64) -> serde_json::Value {
            match self.next() {
                Event::Response(response) if response["id"] == serde_json::json!(id) => response,
                Event::Response(response) => {
                    panic!("{}: unexpected response {response:?}", self.name)
                }
                Event::Exited(status) => panic!(
                    "{} worker exited ({status:?}) before response {id}; stdout={}",
                    self.name, self.stdout
                ),
            }
        }

        /// Waits for the exit after the last response and returns its status,
        /// stderr and the time the exit took after that response.
        fn expect_exit(&mut self) -> (std::process::ExitStatus, String, Duration) {
            let status = match self.next() {
                Event::Exited(status) => status,
                Event::Response(response) => panic!(
                    "{}: unexpected extra response {response:?}; stdout={}",
                    self.name, self.stdout
                ),
            };
            let latency = self.last_response_at.elapsed();
            drop(self.stdin.take());
            let stderr = self
                .stderr
                .take()
                .expect("stderr reader")
                .join()
                .expect("join stderr reader");
            (status, stderr, latency)
        }

        fn assert_clean_stdout(&self) {
            assert!(
                !self.stdout.contains("MCP OPERATION APPROVAL REQUIRED"),
                "{}: approval prompt leaked to MCP stdout: {}",
                self.name,
                self.stdout
            );
            for line in self.stdout.lines().filter(|line| !line.is_empty()) {
                if serde_json::from_str::<serde_json::Value>(line).is_err() {
                    assert!(
                        line == "running 1 test"
                            || line.starts_with("test unix_platform_approval_stdio_worker ... ok")
                            || line.starts_with("test result: ok. 1 passed; 0 failed;"),
                        "{}: unexpected non-protocol worker stdout (only the libtest wrapper is allowed): {line:?}",
                        self.name
                    );
                }
            }
        }
    }

    // Go cancels its serve context on SIGINT/SIGTERM, answers the in-flight
    // request and exits 0 well inside the 2 s shutdown grace (oracle 0cc78062:
    // about 1 s for secure input, 0.5 s for approval).
    let assert_prompt_signal_shutdown =
        |worker_name: &str, status, stderr: &str, latency: Duration, stdout: &str| {
            assert_go_signal_shutdown(
                status,
                &format!("{worker_name}: stdout={stdout} stderr={stderr}"),
            );
            assert!(
                latency < Duration::from_millis(1500),
                "{worker_name}: exit took {latency:?} after the answer (grace-period wait?)"
            );
        };
    let assert_json_rpc_error = |response: &serde_json::Value, message: &str| {
        assert_eq!(response["error"]["code"], -32603, "{response:?}");
        assert_eq!(response["error"]["message"], message, "{response:?}");
        assert!(response.get("result").is_none(), "{response:?}");
    };

    let check_terminal_restored = || -> Result<(), String> {
        let terminal = std::fs::File::open("/dev/tty")
            .map_err(|error| format!("open controlling TTY: {error}"))?;
        let state = Command::new("stty")
            .arg("-a")
            .stdin(Stdio::from(terminal))
            .output()
            .map_err(|error| format!("run stty: {error}"))?;
        if !state.status.success() {
            return Err(format!("stty failed: {state:?}"));
        }
        let state = String::from_utf8_lossy(&state.stdout);
        if state.split_whitespace().any(|part| part == "echo")
            && state.split_whitespace().any(|part| part == "icanon")
        {
            Ok(())
        } else {
            Err(format!("terminal was not restored: {state}"))
        }
    };
    let read_fixture = || {
        Store::open(&vault, &identity)
            .expect("reopen synthetic vault")
            .get("fixture", &identity)
            .expect("read synthetic entry")
    };

    const INIT: &str = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
    );
    let call = |id: u32, tool: &str, arguments: &str| {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"{tool}\",\"arguments\":{arguments}}}}}\n"
        )
    };

    // Worker 1: prompts 0-10. Approved/denied writes, stored secure input,
    // raw Ctrl-C (user cancel, keeps serving), then an external SIGINT during
    // secure input: Go answers `secure input failed: context canceled` and
    // shuts down (exit 0), so nothing after it is served.
    let protocol_input = [
        INIT.to_owned(),
        call(
            2,
            "set_entry_field",
            r#"{"path":"fixture","field":"username","value":"approved-user"}"#,
        ),
        call(
            3,
            "execute_with_secret",
            r#"{"command":["/usr/bin/true"],"secret_refs":[],"env_vars":{"PTY_FIXTURE":"synthetic"}}"#,
        ),
        call(
            4,
            "set_entry_field",
            r#"{"path":"fixture","field":"username","value":"denied-user"}"#,
        ),
        call(
            5,
            "secure_input",
            r#"{"path":"fixture","field":"secure-token","description":"synthetic local test"}"#,
        ),
        call(
            6,
            "request_credential",
            r#"{"path":"fixture","field":"requested-token","reason":"synthetic local test"}"#,
        ),
        call(
            7,
            "secure_input",
            r#"{"path":"fixture","field":"canceled-token","description":"cancel then verify restore"}"#,
        ),
    ]
    .concat();
    let mut worker = Worker::spawn(
        "raw-ctrl-c-then-sigint",
        &executable,
        &vault,
        &identity_path,
        &protocol_input,
    );
    let mut terminal_restore_error = None;
    for expected in 1..=7 {
        let response = worker.expect_response(expected);
        if expected == 7 {
            if response["result"]["isError"] != true
                || response["result"]["content"][0]["text"] != "secure input canceled by user"
            {
                terminal_restore_error = Some(format!(
                    "raw Ctrl-C did not produce the cancellation response: {response:?}"
                ));
            }
            if let Err(error) = check_terminal_restored() {
                terminal_restore_error = Some(error);
            }
            println!("PTY_SECURE_INPUT_CANCELLED termios_restore_check=required");
            println!("PTY_SIGNAL_TARGET pid={} signal=SIGINT", worker.id());
            worker.send(&call(
                8,
                "secure_input",
                r#"{"path":"fixture","field":"signal-canceled-token","description":"SIGINT while secure input is active"}"#,
            ));
        }
    }
    let sigint_secure_response = worker.expect_response(8);
    let (status, stderr, latency) = worker.expect_exit();
    assert_prompt_signal_shutdown(
        "external SIGINT during secure input",
        status,
        &stderr,
        latency,
        &worker.stdout,
    );
    check_terminal_restored().expect("restore TTY after active SIGINT");
    println!("PTY_SECURE_INPUT_CANCELLED termios_restore_check=required");
    assert!(
        terminal_restore_error.is_none(),
        "raw Ctrl-C did not restore terminal before the next call: {terminal_restore_error:?}"
    );
    worker.assert_clean_stdout();
    assert_eq!(
        worker
            .responses
            .iter()
            .filter_map(|response| response.get("id").and_then(serde_json::Value::as_i64))
            .collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6, 7, 8],
        "worker stdout must contain exactly the eight MCP responses and nothing after the shutdown"
    );
    assert_json_rpc_error(
        &sigint_secure_response,
        "secure input failed: context canceled",
    );
    let responses = worker.responses.clone();
    let by_id = |id| {
        responses
            .iter()
            .find(|response| response.get("id") == Some(&serde_json::json!(id)))
            .unwrap_or_else(|| panic!("missing MCP response {id}: {responses:?}"))
    };
    assert_eq!(by_id(2)["result"]["isError"], false, "{responses:?}");
    assert_eq!(by_id(3)["result"]["isError"], false, "{responses:?}");
    assert!(
        by_id(3)["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("\"exit_code\":0")
    );
    assert_eq!(by_id(4)["result"]["isError"], true, "{responses:?}");
    assert_eq!(
        by_id(4)["result"]["content"][0]["text"],
        "set_entry_field denied: user did not approve",
        "a real `n` response must be distinguishable from approval timeout"
    );
    for id in [5, 6] {
        assert_eq!(by_id(id)["result"]["isError"], false, "{responses:?}");
        let text = by_id(id)["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("= *** (value hidden from agent)"), "{text:?}");
        assert!(!text.contains("synthetic-credential"), "{text:?}");
    }
    assert_eq!(by_id(7)["result"]["isError"], true, "{responses:?}");
    assert_eq!(
        by_id(7)["result"]["content"][0]["text"],
        "secure input canceled by user",
        "raw Ctrl-C must cancel promptly rather than become a timeout"
    );

    let entry = read_fixture();
    assert_eq!(entry.data["username"], "approved-user");
    assert_eq!(entry.data["secure-token"], "synthetic-credential-one");
    assert_eq!(entry.data["requested-token"], "synthetic-credential-two");
    assert!(!entry.data.contains_key("canceled-token"));
    assert!(
        !entry.data.contains_key("signal-canceled-token"),
        "an externally canceled secure input must not store the pre-cancel input"
    );

    // Worker 2: a completed secure input followed by an idle SIGINT (prompts
    // 11-12) proves the terminal is usable and idle SIGINT still exits 0.
    let mut idle_sigint_worker = Worker::spawn(
        "idle SIGINT after secure input",
        &executable,
        &vault,
        &identity_path,
        &[
            INIT.to_owned(),
            call(
                2,
                "secure_input",
                r#"{"path":"fixture","field":"after-signal-token","description":"terminal usable before idle SIGINT"}"#,
            ),
        ]
        .concat(),
    );
    idle_sigint_worker.expect_response(1);
    let response = idle_sigint_worker.expect_response(2);
    assert_eq!(response["result"]["isError"], false, "{response:?}");
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("= *** (value hidden from agent)"),
        "{response:?}"
    );
    check_terminal_restored().expect("restore TTY after completed secure input");
    println!(
        "PTY_IDLE_SIGNAL pid={} signal=SIGINT after=success",
        idle_sigint_worker.id()
    );
    let (status, stderr, _) = idle_sigint_worker.expect_exit();
    assert_go_signal_shutdown(
        status,
        &format!(
            "idle SIGINT after terminal restoration: stdout={} stderr={stderr}",
            idle_sigint_worker.stdout
        ),
    );
    idle_sigint_worker.assert_clean_stdout();
    assert_eq!(
        read_fixture().data["after-signal-token"],
        "synthetic-credential-three"
    );

    // Worker 3: an external SIGTERM during secure input answers the same
    // context-canceled error and exits 0 (prompts 13-14).
    let mut term_worker = Worker::spawn(
        "external SIGTERM during secure input",
        &executable,
        &vault,
        &identity_path,
        &[
            INIT.to_owned(),
            call(
                2,
                "secure_input",
                r#"{"path":"fixture","field":"sigterm-canceled-token","description":"SIGTERM cancellation fixture"}"#,
            ),
        ]
        .concat(),
    );
    println!("PTY_SIGNAL_TARGET pid={} signal=SIGTERM", term_worker.id());
    term_worker.expect_response(1);
    let response = term_worker.expect_response(2);
    assert_json_rpc_error(&response, "secure input failed: context canceled");
    let (status, stderr, latency) = term_worker.expect_exit();
    assert_prompt_signal_shutdown(
        "external SIGTERM during secure input",
        status,
        &stderr,
        latency,
        &term_worker.stdout,
    );
    check_terminal_restored().expect("restore TTY after active SIGTERM");
    println!("PTY_SECURE_INPUT_CANCELLED termios_restore_check=required");
    term_worker.assert_clean_stdout();
    assert!(
        !read_fixture().data.contains_key("sigterm-canceled-token"),
        "an externally canceled secure input must not store the pre-cancel input"
    );

    // Worker 4: idle SIGTERM (no prompt) still exits 0.
    let mut idle_term_worker = Worker::spawn(
        "idle SIGTERM",
        &executable,
        &vault,
        &identity_path,
        &[
            INIT.to_owned(),
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n".to_owned(),
        ]
        .concat(),
    );
    idle_term_worker.expect_response(1);
    idle_term_worker.expect_response(2);
    println!(
        "PTY_IDLE_SIGNAL pid={} signal=SIGTERM after=idle",
        idle_term_worker.id()
    );
    let (status, stderr, _) = idle_term_worker.expect_exit();
    assert_go_signal_shutdown(
        status,
        &format!(
            "idle SIGTERM: stdout={} stderr={stderr}",
            idle_term_worker.stdout
        ),
    );
    idle_term_worker.assert_clean_stdout();

    // Workers 5 and 6: an external SIGINT/SIGTERM during an ordinary approval
    // prompt answers Go's isError result `<tool> approval failed: failed to
    // read from terminal: context canceled`, restores the terminal, never
    // commits the write and exits 0 (prompts 15 and 16).
    for (signal_name, field) in [
        ("SIGINT", "approval-signal-must-not-commit"),
        ("SIGTERM", "approval-term-must-not-commit"),
    ] {
        let mut approval_worker = Worker::spawn(
            if signal_name == "SIGINT" {
                "ordinary approval SIGINT"
            } else {
                "ordinary approval SIGTERM"
            },
            &executable,
            &vault,
            &identity_path,
            &[
                INIT.to_owned(),
                call(
                    2,
                    "set_entry_field",
                    &format!(r#"{{"path":"fixture","field":"{field}","value":"forbidden"}}"#),
                ),
            ]
            .concat(),
        );
        println!(
            "PTY_SIGNAL_TARGET pid={} signal={signal_name}",
            approval_worker.id()
        );
        approval_worker.expect_response(1);
        let response = approval_worker.expect_response(2);
        assert_eq!(response["result"]["isError"], true, "{response:?}");
        assert_eq!(
            response["result"]["content"][0]["text"],
            "set_entry_field approval failed: failed to read from terminal: context canceled",
            "{signal_name} during an approval prompt must answer Go's context-canceled result"
        );
        let (status, stderr, latency) = approval_worker.expect_exit();
        check_terminal_restored().expect("restore terminal after approval signal");
        println!("PTY_APPROVAL_SIGNAL_RESTORED termios_restore_check=required");
        assert_prompt_signal_shutdown(
            &format!("ordinary approval {signal_name}"),
            status,
            &stderr,
            latency,
            &approval_worker.stdout,
        );
        approval_worker.assert_clean_stdout();
        assert!(
            !read_fixture().data.contains_key(field),
            "an interrupted approval must not commit the write"
        );
    }

    println!(
        "PTY_ACCEPTANCE_RECEIPT {{\"controlling_tty\":true,\"mcp_stdin_piped\":true,\"set_approved\":true,\"execute_approved\":true,\"deny_left_store_unchanged\":true,\"secure_input_stored\":true,\"request_credential_stored\":true,\"canceled_input_not_stored\":true,\"raw_ctrl_c_keeps_serving\":true,\"external_sigint_secure_context_canceled_exit0\":true,\"idle_sigint_exit0\":true,\"external_sigterm_secure_context_canceled_exit0\":true,\"idle_sigterm_exit0\":true,\"approval_sigint_context_canceled_exit0\":true,\"approval_sigterm_context_canceled_exit0\":true,\"worker_prompts\":17}}"
    );
}

#[cfg(unix)]
#[ignore = "spawned by unix_platform_approval_pty_acceptance"]
#[test]
fn unix_platform_approval_stdio_worker() {
    assert_eq!(
        std::env::var("SYMVAULT_PTY_STDIO_WORKER").as_deref(),
        Ok("1")
    );

    use std::{fs, path::Path};
    use symvault_core::session::MemoryKeyring;
    use symvault_crypto::parse_identity;
    use symvault_platform::approval::is_tty_present;

    assert!(
        is_tty_present(),
        "MCP worker must inherit the controlling PTY while stdin is a pipe"
    );
    let vault = std::env::var_os("SYMVAULT_PTY_VAULT").expect("synthetic vault path");
    let identity_path = std::env::var_os("SYMVAULT_PTY_IDENTITY").expect("identity path");
    let identity_text = fs::read_to_string(identity_path).expect("read synthetic identity");
    let identity = parse_identity(identity_text.trim()).expect("parse synthetic identity");
    let keyring = MemoryKeyring::new();
    let result = mcp_commands::run(
        Path::new(&vault),
        Some("pty-test"),
        identity,
        &keyring,
        true,
        "127.0.0.1",
        0,
        "",
        "",
        "",
        || {
            (
                false,
                "test-memory".into(),
                false,
                "synthetic PTY test".into(),
            )
        },
    );
    assert!(result.is_ok(), "MCP stdio server failed: {result:?}");
}

#[test]
fn cli_runtime_executes_source_bound_api_template_fixture() {
    run_source_bound_api_template_fixture(|| {});
}

#[test]
fn api_template_fixture_slow_setup_preserves_serving_budget() {
    run_source_bound_api_template_fixture(|| {
        // Preparation may take longer than the entire ten-second serving budget.
        std::thread::sleep(std::time::Duration::from_secs(11));
    });
}

fn run_source_bound_api_template_fixture(before_setup: impl FnOnce()) {
    use serde::Deserialize;
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        fs,
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };
    use symvault_core::{config::AgentProfile, session::MemoryKeyring};
    use symvault_crypto::generate_identity;
    use symvault_mcp::handle_line;
    use symvault_store::{Entry, EntryMetadata, Store};
    use tempfile::tempdir;

    #[derive(Deserialize)]
    struct Fixture {
        oracle: Oracle,
        cases: Vec<Case>,
    }
    #[derive(Deserialize)]
    struct Oracle {
        commit_sha: String,
        source_digest: String,
    }
    #[derive(Deserialize)]
    struct Case {
        name: String,
        arguments: Value,
        template_yaml: Option<String>,
        entry_fields: Option<Value>,
        request: Option<ExpectedRequest>,
        text: String,
        is_error: bool,
        error: Option<String>,
        requests: usize,
    }
    #[derive(Deserialize, Debug, Clone, PartialEq)]
    struct ExpectedRequest {
        method: String,
        request_uri: String,
        headers: BTreeMap<String, String>,
        body: String,
    }

    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/execute-api-request.json"
    ))
    .expect("decode source-bound production Go fixture");
    assert_eq!(
        fixture.oracle.commit_sha,
        "d1cd0f97ac550bc3020bc86b0514989f8d28d95c"
    );
    assert!(!fixture.oracle.source_digest.is_empty());
    let go_success = fixture
        .cases
        .iter()
        .find(|case| case.name == "bearer_get_response_redaction")
        .expect("Go success case");
    assert_eq!(go_success.requests, 1);
    assert!(!go_success.is_error);
    let expected: Value = serde_json::from_str(&go_success.text).expect("Go response projection");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local synthetic API");
    let address = listener.local_addr().expect("read test endpoint");
    listener.set_nonblocking(true).expect("bound accept loop");
    let query_secret = fixture
        .cases
        .iter()
        .find(|case| case.name == "query_auth_get")
        .and_then(|case| case.entry_fields.as_ref())
        .and_then(|fields| fields.get("param_value"))
        .and_then(Value::as_str)
        .expect("source-bound query auth secret")
        .to_owned();
    let hits = Arc::new(AtomicUsize::new(0));
    let observed_requests = Arc::new(std::sync::Mutex::new(Vec::<ExpectedRequest>::new()));
    let server_hits = Arc::clone(&hits);
    let observed_server_requests = Arc::clone(&observed_requests);
    let serve = move || {
        // The server exits after its seventh request; the deadline only bounds a
        // broken run. 10 s closed the listener before the last case on a loaded
        // host (6 of 7 hits, `upstream request failed`, #1565).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while server_hits.load(Ordering::SeqCst) < 7 && std::time::Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("accept API request: {error}"),
            };
            stream
                .set_nonblocking(false)
                .expect("make accepted API stream blocking");
            stream
                // Setup bound, not the behavior under test: generous so load and coverage
                // instrumentation cannot win the race (#1564-#1567).
                .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                .expect("bound API request read");
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(30)))
                .expect("bound API response write");
            let mut reader = BufReader::new(stream.try_clone().expect("clone API request stream"));
            let mut first_line = String::new();
            reader
                .read_line(&mut first_line)
                .expect("read request line");
            let path = first_line
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            let method = first_line
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
            let mut headers = String::new();
            let mut parsed_headers = BTreeMap::new();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("read request headers");
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.trim_end().split_once(':') {
                    let name = name.to_ascii_lowercase();
                    let value = value.trim().to_owned();
                    if name == "content-length" {
                        content_length = value.parse().expect("valid request Content-Length");
                    }
                    parsed_headers.insert(name, value);
                }
                headers.push_str(&line);
            }
            let mut request_body = vec![0; content_length];
            if content_length > 0 {
                reader
                    .read_exact(&mut request_body)
                    .expect("read request body");
            }
            server_hits.fetch_add(1, Ordering::SeqCst);
            if path == "/v1/large" {
                let body = format!("{}€", "a".repeat(102398));
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .expect("write bounded large response");
            } else if path.starts_with("/v1/semantic/") {
                let selected = [
                    "authorization",
                    "x-api-key",
                    "x-override",
                    "x-caller",
                    "content-type",
                ]
                .into_iter()
                .map(|name| {
                    (
                        name.to_owned(),
                        parsed_headers.get(name).cloned().unwrap_or_default(),
                    )
                })
                .collect();
                observed_server_requests
                    .lock()
                    .expect("record request")
                    .push(ExpectedRequest {
                        method,
                        request_uri: path.clone(),
                        headers: selected,
                        body: String::from_utf8(request_body).expect("UTF-8 synthetic body"),
                    });
                let (body, echo_header) = if path.starts_with("/v1/semantic/query-auth?") {
                    let body = format!(
                        r#"{{"echo":{}}}"#,
                        serde_json::to_string(&query_secret).expect("encode query secret")
                    );
                    (body, format!("X-Auth-Echo: {query_secret}\r\n"))
                } else {
                    (r#"{"accepted":true}"#.to_owned(), String::new())
                };
                write!(stream, "HTTP/1.1 200 OK\r\nDate: <fixture-date>\r\nContent-Type: application/json\r\n{echo_header}Content-Length: {}\r\n\r\n{}", body.len(), body)
                    .expect("write semantic response");
            } else {
                assert_eq!(path, "/v1/status");
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains("authorization: bearer fixture-api-token"),
                    "{headers}"
                );
                let body = r#"{"token":"fixture-api-token","long":"fixture-api-token-extra","note":"fixture-private-note","card":"4111111111111111","existing":"[REDACTED]"}"#;
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Token: fixture-api-token\r\nX-Long: fixture-api-token-extra\r\nSet-Cookie: private=cookie\r\nWWW-Authenticate: Bearer private-challenge\r\nAuthorization: Bearer private-response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            .expect("write synthetic API response");
            }
        }
        assert_eq!(
            server_hits.load(Ordering::SeqCst),
            7,
            "expected two bearer cases and five API-template semantic requests"
        );
    };
    let keyring = MemoryKeyring::new();
    let cases_by_name = fixture
        .cases
        .iter()
        .map(|case| (case.name.as_str(), case))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut before_setup = Some(before_setup);
    let mut prepare_case = |case: &Case, profile: AgentProfile, with_entry: bool| {
        if let Some(before_setup) = before_setup.take() {
            before_setup();
        }
        let temporary = tempdir().expect("private API case directory");
        let root = temporary.path().join("vault");
        fs::create_dir(&root).expect("create synthetic vault");
        fs::create_dir(root.join("templates")).expect("create templates directory");
        let template = case.template_yaml.as_deref().map(|template| {
            template.lines().map(|line| {
                if line.starts_with("base_url: ") { format!("base_url: http://{address}") } else { line.to_owned() }
            }).collect::<Vec<_>>().join("\n") + "\n"
        }).unwrap_or_else(|| format!("base_url: http://{address}\nauth_type: bearer\nentry_ref: api-fixture\nallowed_endpoints:\n  - /v1/*\nallowed_methods:\n  - GET\nallow_private: true\n"));
        fs::write(root.join("templates/fixture.yaml"), template).expect("write API template");
        fs::write(root.join("config.yaml"), "vault:\n  format_version: 2\n")
            .expect("write synthetic vault config");
        fs::write(root.join("identity.age"), b"synthetic identity marker")
            .expect("write synthetic identity marker");
        fs::create_dir(root.join("entries")).expect("create synthetic entry directory");
        let identity = generate_identity();
        let store = Store::open(&root, &identity).expect("open synthetic encrypted store");
        if with_entry {
            let entry_fields = case.entry_fields.as_ref().and_then(Value::as_object)
                .map(|fields| fields.iter().map(|(key, value)| (key.clone(), value.clone())).collect())
                .unwrap_or_else(|| BTreeMap::from([
                    ("credential".into(), json!("fixture-api-token")),
                    ("nested".into(), json!({"private_note":"fixture-private-note","long_secret":"fixture-api-token-extra"})),
                ]));
            store
                .write_new_entry(
                    "api-fixture",
                    &Entry {
                        path: "api-fixture".into(),
                        data: entry_fields,
                        metadata: EntryMetadata::default(),
                        ..Entry::default()
                    },
                    &identity,
                )
                .expect("write synthetic API credential entry");
        }
        let mut handler = mcp_commands::build_handler_for_contract_test(
            &root,
            "api-fixture",
            &profile,
            identity,
            &keyring,
            "stdio",
            "passphrase",
            &(false, "test-memory".into(), false, "fixture".into()),
        )
        .expect("assemble production CLI MCP runtime");
        let initialized = handle_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}"#,
            &mut handler,
        )
        .expect("initialize MCP protocol")
        .expect("initialize response");
        assert!(initialized.contains("\"result\""));
        let request = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_api_request","arguments":case.arguments}}).to_string();
        (temporary, handler, request)
    };

    let success_profile = AgentProfile {
        tier: Some("admin".into()),
        approval_mode: Some("none".into()),
        allowed_paths: vec!["*".into()],
        can_run_commands: true,
        allowed_tools: vec!["execute_api_request".into()],
        ..AgentProfile::default()
    };
    let status_case = cases_by_name["bearer_get_response_redaction"];
    let negative_profiles = [
        ("endpoint_denied_no_request", success_profile.clone(), false),
        ("method_denied_no_request", success_profile.clone(), false),
        (
            "capability_denied_no_request",
            AgentProfile {
                can_run_commands: false,
                allowed_paths: vec!["*".into()],
                allowed_tools: vec!["execute_api_request".into()],
                ..AgentProfile::default()
            },
            false,
        ),
        (
            "approval_denied_no_request",
            AgentProfile {
                can_run_commands: true,
                allowed_paths: vec!["*".into()],
                allowed_tools: vec!["execute_api_request".into()],
                approval_mode: Some("deny".into()),
                ..AgentProfile::default()
            },
            false,
        ),
        (
            "scope_denied_no_request",
            AgentProfile {
                can_run_commands: true,
                allowed_paths: vec!["elsewhere/*".into()],
                allowed_tools: vec!["execute_api_request".into()],
                approval_mode: Some("none".into()),
                ..AgentProfile::default()
            },
            false,
        ),
    ];
    // Finish encrypted stores, entries and handler assembly before starting
    // the single bounded serving phase, including setup for denial cases.
    let mut prepared_cases = fixture
        .cases
        .iter()
        .map(|case| {
            let (profile, with_entry) = negative_profiles
                .iter()
                .find(|(name, _, _)| *name == case.name)
                .map(|(_, profile, with_entry)| (profile.clone(), *with_entry))
                .unwrap_or_else(|| (success_profile.clone(), true));
            (case.name.as_str(), prepare_case(case, profile, with_entry))
        })
        .collect::<BTreeMap<_, _>>();
    for tier in ["read-only", "standard"] {
        let mut restricted = success_profile.clone();
        restricted.tier = Some(tier.into());
        prepared_cases.insert(tier, prepare_case(status_case, restricted, true));
    }
    let server = thread::spawn(serve);
    let mut execute_case = |name: &str| {
        let (temporary, mut handler, request) = prepared_cases
            .remove(name)
            .expect("case prepared before API server startup");
        let wire = handle_line(&request, &mut handler)
            .expect("dispatch production tools/call")
            .expect("tool call response");
        let response: Value = serde_json::from_str(&wire).expect("decode MCP response");
        (temporary, handler, response)
    };
    for tier in ["read-only", "standard"] {
        let (_, _, denied) = execute_case(tier);
        let required = if tier == "read-only" {
            "standard"
        } else {
            "admin"
        };
        assert_eq!(denied["result"]["isError"], true);
        assert_eq!(
            denied["result"]["content"][0]["text"],
            format!("Tool \"execute_api_request\" requires tier {required:?}")
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "tier denial contacted upstream"
        );
    }
    let (status_vault, mut status_handler, status_response) = execute_case(&status_case.name);
    assert_eq!(
        status_response["result"]["isError"], false,
        "{status_response}"
    );
    let status_actual: Value = serde_json::from_str(
        status_response["result"]["content"][0]["text"]
            .as_str()
            .expect("API result text"),
    )
    .expect("decode API result");
    assert_eq!(
        status_actual["body"], expected["body"],
        "full sanitized body must match Go"
    );
    assert_eq!(status_actual["status_code"], expected["status_code"]);
    assert_eq!(status_actual["body_truncated"], expected["body_truncated"]);
    assert_eq!(status_actual["content_type"], expected["content_type"]);
    assert_eq!(
        status_actual["headers"]["X-Token"],
        expected["headers"]["X-Token"]
    );
    assert_eq!(
        status_actual["headers"]["X-Long"],
        expected["headers"]["X-Long"]
    );
    let response_headers = status_actual["headers"].as_object().expect("safe headers");
    for name in [
        "set-cookie",
        "authorization",
        "www-authenticate",
        "proxy-authenticate",
        "proxy-authorization",
    ] {
        assert!(
            response_headers
                .keys()
                .all(|key| !key.eq_ignore_ascii_case(name)),
            "sensitive response header leaked ({name}): {response_headers:?}"
        );
    }

    fs::write(
        status_vault.path().join("vault/templates/fixture.yaml"),
        format!("base_url: http://{address}\nauth_type: bearer\nentry_ref: api-fixture\nallowed_endpoints:\n  - /v1/admin\nallowed_methods:\n  - GET\nallow_private: true\n"),
    )
    .expect("revoke the previously allowed endpoint while MCP remains running");
    let revoked_request = json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_api_request","arguments":{"template":"fixture","endpoint":"/v1/status"}}}).to_string();
    let revoked_wire = handle_line(&revoked_request, &mut status_handler)
        .expect("dispatch request after template revocation")
        .expect("revocation response");
    let revoked: Value = serde_json::from_str(&revoked_wire).expect("decode revocation result");
    assert_eq!(revoked["result"]["isError"], true, "{revoked}");
    assert_eq!(
        revoked["result"]["content"][0]["text"], "endpoint not allowed: /v1/status",
        "the running handler must observe the updated template policy"
    );

    let large_case = cases_by_name["response_truncated_invalid_utf8"];
    let (_large_vault, _large_handler, large_response) = execute_case(&large_case.name);
    assert_eq!(
        large_response["result"]["isError"], false,
        "{large_response}"
    );
    let large_actual: Value = serde_json::from_str(
        large_response["result"]["content"][0]["text"]
            .as_str()
            .expect("API result text"),
    )
    .expect("decode truncated API result");
    let large_expected: Value = serde_json::from_str(&large_case.text).expect("Go large response");
    assert_eq!(large_actual["body"], large_expected["body"]);
    assert_eq!(large_actual["body_truncated"], true);

    let mut expected_wire = Vec::new();
    for case in fixture.cases.iter().filter(|case| case.request.is_some()) {
        assert_eq!(
            case.requests, 1,
            "Go oracle should send one {} request",
            case.name
        );
        let (_vault, _handler, response) = execute_case(&case.name);
        assert_eq!(
            response["result"]["isError"], false,
            "{}: {response}",
            case.name
        );
        let actual_response: Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("API result text"),
        )
        .expect("decode semantic API result");
        let go_response: Value = serde_json::from_str(&case.text).expect("decode Go API response");
        assert_eq!(
            actual_response, go_response,
            "{} response projection",
            case.name
        );
        expected_wire.push(case.request.as_ref().expect("request case").clone());
    }
    assert_eq!(
        expected_wire.len(),
        5,
        "the source-bound fixture must retain all five semantic request cases"
    );
    assert_eq!(
        *observed_requests.lock().expect("read captured requests"),
        expected_wire,
        "Rust request wire must match the production Go handler's captured method, URL, headers and body"
    );

    for (name, _, _) in negative_profiles {
        let case = cases_by_name[name];
        assert_eq!(case.requests, 0, "Go oracle must not send {name}");
        assert!(
            case.is_error || case.error.is_some(),
            "Go fixture must capture an error for {name}"
        );
        let (_vault, _handler, response) = execute_case(name);
        // The source fixture invokes the Go handler directly. The complete
        // production registry denies an unavailable API tool before reaching
        // that handler, as measured by the native MCP process contract.
        let expected_error = if name == "capability_denied_no_request" {
            assert_eq!(response["result"]["isError"], true);
            assert!(response.get("error").is_none());
            "tool \"execute_api_request\" is not available in the current environment"
        } else {
            case.error.as_deref().unwrap_or(&case.text)
        };
        let actual_error = response["error"]["message"]
            .as_str()
            .or_else(|| response["result"]["content"][0]["text"].as_str())
            .unwrap_or_else(|| panic!("{name}: unexpected MCP response {response}"));
        assert_eq!(actual_error, expected_error, "{name}: {response}");
    }
    for name in [
        "substitution_missing_field_no_request",
        "basic_auth_missing_field_no_request",
        "invalid_caller_header_no_request",
    ] {
        let case = cases_by_name[name];
        assert_eq!(case.requests, 0, "Go oracle must not send {name}");
        let (_vault, _handler, response) = execute_case(name);
        let expected_error = case.error.as_deref().unwrap_or(&case.text);
        let actual_error = response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: unexpected MCP response {response}"));
        assert_eq!(actual_error, expected_error, "{name}: {response}");
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        7,
        "only the seven Go-approved calls may reach the API"
    );
    server.join().expect("bounded local API server");
    assert!(
        prepared_cases.is_empty(),
        "every prepared case must execute"
    );
}

#[test]
fn api_template_loader_is_strict_bounded_and_symlink_safe() {
    use std::fs;
    use tempfile::tempdir;

    let root = tempdir().expect("private template loader fixture");
    let templates = root.path().join("templates");
    fs::create_dir(&templates).expect("create template directory");
    fs::write(
        templates.join("unknown.yaml"),
        "base_url: http://127.0.0.1:1\nauth_type: bearer\nentry_ref: fixture\nallowed_endpoints: [/v1/*]\nallowed_methods: [GET]\nallow_private: true\nunsupported_auth_option: secret\n",
    )
    .expect("write strict schema case");
    fs::write(
        templates.join("oversized.yaml"),
        format!("#{}", "x".repeat(65_536)),
    )
    .expect("write oversized template");
    assert!(
        symvault_mcp::store_adapter::load_api_template_definition(root.path(), "unknown")
            .unwrap_err()
            .contains("unsupported_auth_option")
    );
    assert!(
        symvault_mcp::store_adapter::load_api_template_definition(root.path(), "oversized")
            .unwrap_err()
            .contains("65536-byte limit")
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        fs::write(
            root.path().join("outside.yaml"),
            "base_url: http://127.0.0.1:1\nauth_type: bearer\nentry_ref: fixture\nallowed_endpoints: [/v1/*]\nallowed_methods: [GET]\nallow_private: true\n",
        )
        .expect("write external template target");
        symlink(
            root.path().join("outside.yaml"),
            templates.join("linked.yaml"),
        )
        .expect("create external template symlink");
        assert!(
            symvault_mcp::store_adapter::load_api_template_definition(root.path(), "linked")
                .unwrap_err()
                .contains("regular file")
        );
    }
}
