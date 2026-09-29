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
        io::Write,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
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
        "vault:\n  format_version: 1\ndefaultAgent: pty-test\nauthMethod: passphrase\nagents:\n  pty-test:\n    tier: standard\n    approvalMode: prompt\n    requireApproval: true\n    approvalTimeout: 4s\n    canWrite: true\n    canRunCommands: true\n    allowedPaths:\n      - fixture\n    allowed_tools:\n      - set_entry_field\n      - execute_with_secret\n    allowedExecutables:\n      - \"true\"\n",
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
    let mut worker = Command::new(executable)
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
    );
    worker
        .stdin
        .take()
        .expect("MCP pipe stdin")
        .write_all(protocol_input.as_bytes())
        .expect("send MCP frames over the isolated pipe");

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if worker.try_wait().expect("poll MCP worker").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = worker.kill();
            let output = worker
                .wait_with_output()
                .expect("reap timed-out MCP worker");
            panic!(
                "MCP worker exceeded its bound; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
    let output = worker
        .wait_with_output()
        .expect("collect MCP worker output");
    assert!(
        output.status.success(),
        "MCP worker failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("MCP OPERATION APPROVAL REQUIRED"),
        "approval prompt leaked to MCP stdout: {stdout}"
    );
    let mut responses = Vec::new();
    for line in stdout.lines().filter(|line| !line.is_empty()) {
        if let Ok(response) = serde_json::from_str::<serde_json::Value>(line) {
            responses.push(response);
        } else {
            assert!(
                line == "running 1 test"
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
        [1, 2, 3, 4],
        "worker stdout must contain exactly the four MCP responses"
    );
    assert_eq!(
        responses.len(),
        4,
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

    let store = Store::open(&vault, &identity).expect("reopen synthetic vault");
    let entry = store
        .get("fixture", &identity)
        .expect("read synthetic entry");
    assert_eq!(entry.data["username"], "approved-user");
    println!(
        "PTY_ACCEPTANCE_RECEIPT {{\"controlling_tty\":true,\"mcp_stdin_piped\":true,\"set_approved\":true,\"execute_approved\":true,\"deny_left_store_unchanged\":true,\"worker_prompts\":3}}"
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
