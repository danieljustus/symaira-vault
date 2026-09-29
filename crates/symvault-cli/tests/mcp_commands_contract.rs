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

#[test]
fn cli_runtime_executes_source_bound_api_template_fixture() {
    use serde::Deserialize;
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        fs,
        io::{BufRead, BufReader, Write},
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
        text: String,
        is_error: bool,
        error: Option<String>,
        requests: usize,
    }

    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/execute-api-request.json"
    ))
    .expect("decode source-bound production Go fixture");
    assert_eq!(
        fixture.oracle.commit_sha,
        "c94a10d78181caa91e7f3b977139e9d977315735"
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
    let hits = Arc::new(AtomicUsize::new(0));
    let server_hits = Arc::clone(&hits);
    let server = thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while server_hits.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("accept API request: {error}"),
            };
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("bound API request read");
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
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("read request headers");
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                headers.push_str(&line);
            }
            let headers_lower = headers.to_ascii_lowercase();
            assert!(
                headers_lower.contains("authorization: bearer fixture-api-token"),
                "{headers}"
            );
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
            } else {
                assert_eq!(path, "/v1/status");
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
            2,
            "expected exactly two successful API requests"
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
        fs::write(
            root.join("templates/fixture.yaml"),
            format!("base_url: http://{address}\nauth_type: bearer\nentry_ref: api-fixture\nallowed_endpoints:\n  - /v1/*\nallowed_methods:\n  - GET\nallow_private: true\n"),
        )
        .expect("write API template");
        fs::write(root.join("config.yaml"), "vault:\n  format_version: 2\n")
            .expect("write synthetic vault config");
        fs::write(root.join("identity.age"), b"synthetic identity marker")
            .expect("write synthetic identity marker");
        fs::create_dir(root.join("entries")).expect("create synthetic entry directory");
        let identity = generate_identity();
        let store = Store::open(&root, &identity).expect("open synthetic encrypted store");
        if with_entry {
            store
                .write_new_entry(
                    "api-fixture",
                    &Entry {
                        path: "api-fixture".into(),
                        data: BTreeMap::from([
                            ("credential".into(), json!("fixture-api-token")),
                            ("nested".into(), json!({"private_note":"fixture-private-note","long_secret":"fixture-api-token-extra"})),
                        ]),
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
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "only the two Go-approved calls may reach the API"
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
