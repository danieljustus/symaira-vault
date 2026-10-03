#![allow(dead_code)]

#[path = "../src/mcp_commands.rs"]
mod mcp_commands;
#[path = "../src/run_commands.rs"]
mod run_commands;

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
    let mut worker = Command::new(&executable)
        .args([
            "--ignored",
            "--exact",
            "unix_platform_approval_stdio_worker",
            "--nocapture",
        ])
        .env("SYMVAULT_PTY_STDIO_WORKER", "1")
        .env("SYMVAULT_PTY_VAULT", &vault)
        .env("SYMVAULT_PTY_IDENTITY", &identity_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn MCP worker with separate stdio pipes");

    let protocol_input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"set_entry_field\",\"arguments\":{\"path\":\"fixture\",\"field\":\"username\",\"value\":\"approved-user\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"execute_with_secret\",\"arguments\":{\"command\":[\"/usr/bin/true\"],\"secret_refs\":[],\"env_vars\":{\"PTY_FIXTURE\":\"synthetic\"}}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"set_entry_field\",\"arguments\":{\"path\":\"fixture\",\"field\":\"username\",\"value\":\"denied-user\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"secure_input\",\"arguments\":{\"path\":\"fixture\",\"field\":\"secure-token\",\"description\":\"synthetic local test\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"request_credential\",\"arguments\":{\"path\":\"fixture\",\"field\":\"requested-token\",\"reason\":\"synthetic local test\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"secure_input\",\"arguments\":{\"path\":\"fixture\",\"field\":\"canceled-token\",\"description\":\"cancel then verify restore\"}}}\n",
    );
    let mut worker_stdin = Some(worker.stdin.take().expect("MCP pipe stdin"));
    worker_stdin
        .as_mut()
        .expect("MCP pipe stdin remains open")
        .write_all(protocol_input.as_bytes())
        .expect("send MCP frames over the isolated pipe");

    let stdout_pipe = worker.stdout.take().expect("MCP worker stdout pipe");
    let (stdout_sender, stdout_receiver) = mpsc::channel();
    let stdout_reader = thread::spawn(move || {
        for line in BufReader::new(stdout_pipe).lines() {
            if stdout_sender.send(line).is_err() {
                return;
            }
        }
    });
    let stderr_pipe = worker.stderr.take().expect("MCP worker stderr pipe");
    let stderr_reader = thread::spawn(move || {
        let mut text = String::new();
        let mut pipe = BufReader::new(stderr_pipe);
        let _ = pipe.read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut stdout = String::new();
    let mut responses = Vec::new();
    let mut process_status = None;
    let mut sent_after_cancel = false;
    let mut idle_signal_requested = false;
    let mut terminal_restore_error = None;
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
    loop {
        match stdout_receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(Ok(line)) => {
                stdout.push_str(&line);
                stdout.push('\n');
                if let Ok(response) = serde_json::from_str::<serde_json::Value>(&line) {
                    if response.get("id") == Some(&serde_json::json!(7)) {
                        if response["result"]["isError"] != true
                            || response["result"]["content"][0]["text"]
                                != "secure input canceled by user"
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
                        if let Err(error) = worker_stdin
                            .as_mut()
                            .expect("MCP pipe stdin remains open")
                            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"secure_input\",\"arguments\":{\"path\":\"fixture\",\"field\":\"signal-canceled-token\",\"description\":\"SIGINT while secure input is active\"}}}\n")
                        {
                            terminal_restore_error = Some(format!("send SIGINT cancellation request: {error}"));
                        }
                    } else if response.get("id") == Some(&serde_json::json!(8)) {
                        if response["result"]["isError"] != true
                            || response["result"]["content"][0]["text"]
                                != "secure input canceled by user"
                        {
                            terminal_restore_error = Some(format!(
                                "external SIGINT did not cancel secure input: {response:?}"
                            ));
                        }
                        if let Err(error) = check_terminal_restored() {
                            terminal_restore_error = Some(error);
                        }
                        println!("PTY_SECURE_INPUT_CANCELLED termios_restore_check=required");
                        if let Err(error) = worker_stdin
                            .as_mut()
                            .expect("MCP pipe stdin remains open")
                            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"secure_input\",\"arguments\":{\"path\":\"fixture\",\"field\":\"after-signal-token\",\"description\":\"terminal usable after external cancellation\"}}}\n")
                        {
                            terminal_restore_error = Some(format!("send post-signal call: {error}"));
                        } else {
                            sent_after_cancel = true;
                        }
                    } else if response.get("id") == Some(&serde_json::json!(9)) {
                        if response["result"]["isError"] != false {
                            terminal_restore_error = Some(format!(
                                "secure input after SIGINT did not complete: {response:?}"
                            ));
                        }
                        if let Err(error) = check_terminal_restored() {
                            terminal_restore_error = Some(error);
                        }
                        println!(
                            "PTY_IDLE_SIGNAL pid={} signal=SIGINT after=success",
                            worker.id()
                        );
                        idle_signal_requested = true;
                    }
                    responses.push(response);
                }
            }
            Ok(Err(error)) => panic!("read MCP worker stdout: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if process_status.is_none() {
            process_status = worker.try_wait().expect("poll MCP worker");
        }
        if Instant::now() >= deadline {
            let _ = worker.kill();
            let _ = worker.wait();
            panic!("MCP worker exceeded its bounded PTY acceptance deadline; stdout={stdout}");
        }
        if process_status.is_some() && (!sent_after_cancel || !idle_signal_requested) {
            panic!("MCP worker exited before the cancellation/idle-signal checks; stdout={stdout}");
        }
    }
    let status = process_status.unwrap_or_else(|| worker.wait().expect("reap MCP worker"));
    drop(worker_stdin);
    let _ = stdout_reader.join();
    let stderr = stderr_reader.join().expect("join stderr reader");
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(2),
            "idle SIGINT should retain default termination after terminal restoration: stdout={stdout} stderr={stderr}"
        );
    }
    assert!(
        terminal_restore_error.is_none(),
        "raw Ctrl-C did not restore terminal before the next call: {terminal_restore_error:?}"
    );
    assert!(
        !stdout.contains("MCP OPERATION APPROVAL REQUIRED"),
        "approval prompt leaked to MCP stdout: {stdout}"
    );
    for line in stdout.lines().filter(|line| !line.is_empty()) {
        if serde_json::from_str::<serde_json::Value>(line).is_err() {
            assert!(
                line == "running 1 test"
                    || line == "PTY_SECURE_INPUT_CANCELLED termios_restore_check=required"
                    || line.starts_with("PTY_SIGNAL_TARGET pid=")
                    || line.starts_with("PTY_IDLE_SIGNAL pid=")
                    || line.starts_with("test unix_platform_approval_stdio_worker ... ok")
                    || line.starts_with("test result: ok. 1 passed; 0 failed;"),
                "unexpected non-protocol worker stdout (only the libtest wrapper is allowed): {line:?}"
            );
        }
    }
    assert_eq!(
        responses
            .iter()
            .filter_map(|response| response.get("id").and_then(serde_json::Value::as_i64))
            .collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6, 7, 8, 9],
        "worker stdout must contain exactly the nine MCP responses"
    );
    assert_eq!(
        responses.len(),
        9,
        "worker stdout must not contain extra JSON responses without IDs"
    );
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
    assert_eq!(by_id(8)["result"]["isError"], true, "{responses:?}");
    assert_eq!(
        by_id(8)["result"]["content"][0]["text"],
        "secure input canceled by user"
    );
    assert_eq!(by_id(9)["result"]["isError"], false, "{responses:?}");
    assert!(
        by_id(9)["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("= *** (value hidden from agent)"),
        "follow-up secure input must work after SIGINT cancellation: {responses:?}"
    );

    let store = Store::open(&vault, &identity).expect("reopen synthetic vault");
    let entry = store
        .get("fixture", &identity)
        .expect("read synthetic entry");
    assert_eq!(entry.data["username"], "approved-user");
    assert_eq!(entry.data["secure-token"], "synthetic-credential-one");
    assert_eq!(entry.data["requested-token"], "synthetic-credential-two");
    assert_eq!(
        entry.data["after-signal-token"],
        "synthetic-credential-three"
    );
    assert!(!entry.data.contains_key("canceled-token"));
    assert!(!entry.data.contains_key("signal-canceled-token"));

    // A second process proves SIGTERM cancels secure input and that a later
    // idle SIGTERM resumes the normal default termination behavior.
    let mut term_worker = Command::new(&executable)
        .args([
            "--ignored",
            "--exact",
            "unix_platform_approval_stdio_worker",
            "--nocapture",
        ])
        .env("SYMVAULT_PTY_STDIO_WORKER", "1")
        .env("SYMVAULT_PTY_VAULT", &vault)
        .env("SYMVAULT_PTY_IDENTITY", &identity_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn second MCP worker with separate stdio pipes");
    let mut term_stdin = Some(term_worker.stdin.take().expect("SIGTERM worker stdin"));
    term_stdin
        .as_mut()
        .unwrap()
        .write_all(concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"secure_input\",\"arguments\":{\"path\":\"fixture\",\"field\":\"sigterm-canceled-token\",\"description\":\"SIGTERM cancellation fixture\"}}}\n",
        ).as_bytes())
        .expect("send secure-input call to SIGTERM worker");
    println!("PTY_SIGNAL_TARGET pid={} signal=SIGTERM", term_worker.id());

    let (term_sender, term_receiver) = mpsc::channel();
    let term_stdout = BufReader::new(term_worker.stdout.take().expect("SIGTERM stdout"));
    let term_reader = thread::spawn(move || {
        for line in term_stdout.lines() {
            if term_sender.send(line).is_err() {
                return;
            }
        }
    });
    let term_stderr = term_worker.stderr.take().expect("SIGTERM stderr");
    let term_stderr_reader = thread::spawn(move || {
        let mut text = String::new();
        let mut pipe = BufReader::new(term_stderr);
        let _ = pipe.read_to_string(&mut text);
        text
    });
    let term_deadline = Instant::now() + Duration::from_secs(20);
    let mut term_stdout_text = String::new();
    let mut term_status = None;
    let mut term_followup_sent = false;
    let mut term_idle_signal_requested = false;
    while term_status.is_none() {
        match term_receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(Ok(line)) => {
                term_stdout_text.push_str(&line);
                term_stdout_text.push('\n');
                if let Ok(response) = serde_json::from_str::<serde_json::Value>(&line) {
                    if response.get("id") == Some(&serde_json::json!(2)) {
                        assert_eq!(response["result"]["isError"], true, "{response:?}");
                        assert_eq!(
                            response["result"]["content"][0]["text"],
                            "secure input canceled by user",
                            "external SIGTERM must cancel the active secure-input prompt"
                        );
                        check_terminal_restored().expect("restore TTY after active SIGTERM");
                        println!("PTY_SECURE_INPUT_CANCELLED termios_restore_check=required");
                        term_stdin
                            .as_mut()
                            .unwrap()
                            .write_all(
                                b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}\n",
                            )
                            .expect("send no-prompt request after SIGTERM cancellation");
                        term_followup_sent = true;
                    } else if response.get("id") == Some(&serde_json::json!(3)) {
                        println!(
                            "PTY_IDLE_SIGNAL pid={} signal=SIGTERM after=canceled",
                            term_worker.id()
                        );
                        term_idle_signal_requested = true;
                    }
                }
            }
            Ok(Err(error)) => panic!("read SIGTERM MCP worker stdout: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if term_status.is_none() {
            term_status = term_worker.try_wait().expect("poll SIGTERM worker");
        }
        if Instant::now() >= term_deadline {
            let _ = term_worker.kill();
            let _ = term_worker.wait();
            panic!("SIGTERM worker exceeded its bounded deadline: {term_stdout_text}");
        }
        if term_status.is_some() && (!term_followup_sent || !term_idle_signal_requested) {
            panic!("SIGTERM worker exited before cancellation/idle checks: {term_stdout_text}");
        }
    }
    let term_status =
        term_status.unwrap_or_else(|| term_worker.wait().expect("reap SIGTERM worker"));
    drop(term_stdin);
    let _ = term_reader.join();
    let term_stderr_text = term_stderr_reader
        .join()
        .expect("join SIGTERM stderr reader");
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            term_status.signal(),
            Some(15),
            "idle SIGTERM should retain default termination after terminal restoration: stdout={term_stdout_text} stderr={term_stderr_text}"
        );
    }
    let store = Store::open(&vault, &identity).expect("reopen fixture after SIGTERM cancellation");
    let entry = store
        .get("fixture", &identity)
        .expect("read fixture after SIGTERM cancellation");
    assert!(!entry.data.contains_key("sigterm-canceled-token"));

    // Ordinary approvals still terminate on an external signal, but only after
    // the shared raw-terminal scope restores cooked mode.
    let mut approval_worker = Command::new(&executable)
        .args([
            "--ignored",
            "--exact",
            "unix_platform_approval_stdio_worker",
            "--nocapture",
        ])
        .env("SYMVAULT_PTY_STDIO_WORKER", "1")
        .env("SYMVAULT_PTY_VAULT", &vault)
        .env("SYMVAULT_PTY_IDENTITY", &identity_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ordinary-approval signal worker");
    let mut approval_stdin = approval_worker.stdin.take().expect("approval worker stdin");
    approval_stdin
        .write_all(concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"set_entry_field\",\"arguments\":{\"path\":\"fixture\",\"field\":\"approval-signal-must-not-commit\",\"value\":\"forbidden\"}}}\n",
        ).as_bytes())
        .expect("send pending approved-write call");
    println!(
        "PTY_SIGNAL_TARGET pid={} signal=SIGINT",
        approval_worker.id()
    );
    let mut approval_stdout =
        BufReader::new(approval_worker.stdout.take().expect("approval stdout"));
    let mut unexpected_response = String::new();
    let mut approval_stderr = approval_worker.stderr.take().expect("approval stderr");
    let deadline = Instant::now() + Duration::from_secs(20);
    let approval_status = loop {
        if let Some(status) = approval_worker
            .try_wait()
            .expect("poll approval signal worker")
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = approval_worker.kill();
            let _ = approval_worker.wait();
            panic!("ordinary approval signal worker exceeded its bounded deadline");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    drop(approval_stdin);
    let _ = approval_stdout.read_to_string(&mut unexpected_response);
    let mut approval_stderr_text = String::new();
    let _ = approval_stderr.read_to_string(&mut approval_stderr_text);
    check_terminal_restored().expect("restore terminal before default approval SIGINT");
    println!("PTY_APPROVAL_SIGNAL_RESTORED termios_restore_check=required");
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            approval_status.signal(),
            Some(2),
            "ordinary approval should keep default SIGINT termination after restoring termios; stdout={unexpected_response} stderr={approval_stderr_text}"
        );
    }
    assert!(
        !unexpected_response.lines().any(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .is_some_and(|value| value.get("id") == Some(&serde_json::json!(2)))
        }),
        "an interrupted approval must not produce a successful MCP response: {unexpected_response}"
    );
    let store = Store::open(&vault, &identity).expect("reopen fixture after approval signal");
    let entry = store
        .get("fixture", &identity)
        .expect("read fixture after approval signal");
    assert!(!entry.data.contains_key("approval-signal-must-not-commit"));

    let mut term_approval_worker = Command::new(&executable)
        .args([
            "--ignored",
            "--exact",
            "unix_platform_approval_stdio_worker",
            "--nocapture",
        ])
        .env("SYMVAULT_PTY_STDIO_WORKER", "1")
        .env("SYMVAULT_PTY_VAULT", &vault)
        .env("SYMVAULT_PTY_IDENTITY", &identity_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ordinary-approval SIGTERM worker");
    let mut term_approval_stdin = term_approval_worker
        .stdin
        .take()
        .expect("SIGTERM approval worker stdin");
    term_approval_stdin
        .write_all(concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"set_entry_field\",\"arguments\":{\"path\":\"fixture\",\"field\":\"approval-term-must-not-commit\",\"value\":\"forbidden\"}}}\n",
        ).as_bytes())
        .expect("send pending SIGTERM approval call");
    println!(
        "PTY_SIGNAL_TARGET pid={} signal=SIGTERM",
        term_approval_worker.id()
    );
    let mut term_approval_stdout = BufReader::new(
        term_approval_worker
            .stdout
            .take()
            .expect("SIGTERM approval stdout"),
    );
    let mut term_unexpected_response = String::new();
    let mut term_approval_stderr = term_approval_worker
        .stderr
        .take()
        .expect("SIGTERM approval stderr");
    let deadline = Instant::now() + Duration::from_secs(20);
    let term_approval_status = loop {
        if let Some(status) = term_approval_worker
            .try_wait()
            .expect("poll SIGTERM approval worker")
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = term_approval_worker.kill();
            let _ = term_approval_worker.wait();
            panic!("ordinary SIGTERM approval worker exceeded its bounded deadline");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    drop(term_approval_stdin);
    let _ = term_approval_stdout.read_to_string(&mut term_unexpected_response);
    let mut term_approval_stderr_text = String::new();
    let _ = term_approval_stderr.read_to_string(&mut term_approval_stderr_text);
    check_terminal_restored().expect("restore terminal before default approval SIGTERM");
    println!("PTY_APPROVAL_SIGNAL_RESTORED termios_restore_check=required");
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            term_approval_status.signal(),
            Some(15),
            "ordinary approval should keep default SIGTERM termination after restoring termios; stdout={term_unexpected_response} stderr={term_approval_stderr_text}"
        );
    }
    assert!(
        !term_unexpected_response.lines().any(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .is_some_and(|value| value.get("id") == Some(&serde_json::json!(2)))
        }),
        "an interrupted SIGTERM approval must not produce an MCP response: {term_unexpected_response}"
    );
    let store = Store::open(&vault, &identity).expect("reopen fixture after approval SIGTERM");
    let entry = store
        .get("fixture", &identity)
        .expect("read fixture after approval SIGTERM");
    assert!(!entry.data.contains_key("approval-term-must-not-commit"));

    println!(
        "PTY_ACCEPTANCE_RECEIPT {{\"controlling_tty\":true,\"mcp_stdin_piped\":true,\"set_approved\":true,\"execute_approved\":true,\"deny_left_store_unchanged\":true,\"secure_input_stored\":true,\"request_credential_stored\":true,\"canceled_input_not_stored\":true,\"post_cancel_input_stored\":true,\"external_sigint_canceled\":true,\"idle_sigint_terminated\":true,\"external_sigterm_canceled\":true,\"idle_sigterm_terminated\":true,\"approval_sigint_terminated\":true,\"approval_sigterm_terminated\":true,\"worker_prompts\":17}}"
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
        "55da4ca13ead39d4000cf6f866ac8671ca86d8f2"
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
    let server = thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
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
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("bound API request read");
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
    });
    let keyring = MemoryKeyring::new();
    let cases_by_name = fixture
        .cases
        .iter()
        .map(|case| (case.name.as_str(), case))
        .collect::<std::collections::BTreeMap<_, _>>();
    let execute_case = |case: &Case, profile: AgentProfile, with_entry: bool| {
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
        let wire = handle_line(&request, &mut handler)
            .expect("dispatch production tools/call")
            .expect("tool call response");
        let response: Value = serde_json::from_str(&wire).expect("decode MCP response");
        (temporary, handler, response)
    };

    let success_profile = AgentProfile {
        tier: Some("standard".into()),
        approval_mode: Some("none".into()),
        allowed_paths: vec!["*".into()],
        can_run_commands: true,
        allowed_tools: vec!["execute_api_request".into()],
        ..AgentProfile::default()
    };
    let status_case = cases_by_name["bearer_get_response_redaction"];
    let (status_vault, mut status_handler, status_response) =
        execute_case(status_case, success_profile.clone(), true);
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
    let (_large_vault, _large_handler, large_response) =
        execute_case(large_case, success_profile.clone(), true);
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
        let (_vault, _handler, response) = execute_case(case, success_profile.clone(), true);
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
    for (name, profile, with_entry) in negative_profiles {
        let case = cases_by_name[name];
        assert_eq!(case.requests, 0, "Go oracle must not send {name}");
        assert!(
            case.is_error || case.error.is_some(),
            "Go fixture must capture an error for {name}"
        );
        let (_vault, _handler, response) = execute_case(case, profile, with_entry);
        let expected_error = case.error.as_deref().unwrap_or(&case.text);
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
        let (_vault, _handler, response) = execute_case(case, success_profile.clone(), true);
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
