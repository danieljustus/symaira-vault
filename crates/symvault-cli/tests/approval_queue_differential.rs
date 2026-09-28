use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;

const ENROLL_SECRET: &str = "mcp-server.enroll-secret";

fn run(binary: &Path, vault: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .arg("--vault")
        .arg(vault)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("CI", "1")
        .output()
        .expect("run Rust CLI")
}

#[derive(Debug, Deserialize)]
struct Fixture {
    approve_id: String,
    deny_id: String,
    quiet_id: String,
}

#[derive(Debug, Deserialize)]
struct RuntimeTls {
    certificate: String,
    client_ca_file: String,
    client_certificate: String,
    client_key: String,
    client_auth_required: bool,
}

struct GoApprovalServer(Child);

impl GoApprovalServer {
    fn start(go_root: &Path, vault: &Path) -> Self {
        let mut child = Command::new(go_root.join("approval_queue_server"))
            .arg("--vault")
            .arg(vault)
            .env("GOTOOLCHAIN", "go1.26.6")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start production Go approval handler");
        let ready = vault.join(".ready");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if ready.is_file() {
                return Self(child);
            }
            if let Some(status) = child.try_wait().expect("check Go approval server") {
                let output = child.wait_with_output().expect("read Go server output");
                panic!(
                    "Go approval server exited before readiness ({status}): {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().expect("read stopped Go server");
                panic!(
                    "Go approval server startup timed out: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for GoApprovalServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn build_go_server(output: &Path, repo: &Path) {
    let build = Command::new("go")
        .args(["build", "-o"])
        .arg(output.join("approval_queue_server"))
        .arg("./crates/symvault-cli/tests/approval_queue_server")
        .current_dir(repo)
        .env("GOTOOLCHAIN", "go1.26.6")
        .output()
        .expect("build local Go production-handler seam");
    assert!(
        build.status.success(),
        "build Go approval handler: {}",
        String::from_utf8_lossy(&build.stderr)
    );
}

fn setup_vault(path: &Path) {
    fs::create_dir_all(path).expect("create isolated vault");
    fs::write(
        path.join("identity.age"),
        b"test-only initialization marker",
    )
    .expect("write isolated identity marker");
    fs::write(path.join("config.yaml"), b"{}\n").expect("write isolated config marker");
}

#[test]
fn approval_queue_cli_uses_go_handler_hmac_mtls_and_decision_contract() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let go_root = temp.path().join("go");
    let vault = temp.path().join("vault");
    let home = temp.path().join("home");
    fs::create_dir_all(&go_root).expect("create Go build directory");
    fs::create_dir_all(&home).expect("create isolated home");
    setup_vault(&vault);

    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    build_go_server(&go_root, repo);
    let _server = GoApprovalServer::start(&go_root, &vault);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let fixture: Fixture =
        serde_json::from_slice(&fs::read(vault.join(".fixture.json")).expect("Go fixture"))
            .expect("decode Go fixture");

    let secret_path = vault.join(ENROLL_SECRET);
    let secret = fs::read(&secret_path).expect("Go-generated proof secret");
    assert_eq!(secret.len(), 32, "Go proof secret size");
    fs::write(&secret_path, [0xA5; 32]).expect("install invalid proof secret");
    let invalid_proof = run(&rust_binary, &vault, &home, &["approval", "list", "--json"]);
    assert_eq!(
        invalid_proof.status.code(),
        Some(1),
        "invalid proof output: {invalid_proof:?}"
    );
    assert!(invalid_proof.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&invalid_proof.stderr)
            .contains("approval server: missing or invalid proof of vault-directory ownership"),
        "Go handler did not reject invalid HMAC: {invalid_proof:?}"
    );
    fs::write(&secret_path, &secret).expect("restore Go-generated proof secret");

    let tls_path = vault.join(".runtime-tls-cert");
    let tls: RuntimeTls = serde_json::from_slice(&fs::read(&tls_path).expect("runtime TLS record"))
        .expect("decode runtime TLS record");
    assert!(tls.client_auth_required);

    // mTLS remains fail-closed if the dedicated identity fields are absent.
    let missing_identity = serde_json::json!({
        "certificate": tls.certificate,
        "client_auth_required": true
    });
    fs::write(&tls_path, serde_json::to_vec(&missing_identity).unwrap())
        .expect("remove configured client identity");
    let missing = run(&rust_binary, &vault, &home, &["approval", "list"]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&missing.stderr)
            .contains("dedicated local approval client certificate")
    );

    // A server identity can never be reused as the approval client identity.
    let server_cert = vault.join("mcp-server.crt");
    let server_key = vault.join("mcp-server.key");
    let reused_identity = serde_json::json!({
        "certificate": tls.certificate,
        "client_auth_required": true,
        "client_ca_file": tls.client_ca_file,
        "client_certificate": server_cert,
        "client_key": server_key
    });
    fs::write(&tls_path, serde_json::to_vec(&reused_identity).unwrap())
        .expect("configure reused server identity");
    let reused = run(&rust_binary, &vault, &home, &["approval", "list"]);
    assert_eq!(reused.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&reused.stderr)
            .contains("refuses to reuse the MCP server certificate identity")
    );

    let wrong_ca = serde_json::json!({
        "certificate": tls.certificate,
        "client_auth_required": true,
        "client_ca_file": server_cert,
        "client_certificate": tls.client_certificate,
        "client_key": tls.client_key
    });
    fs::write(&tls_path, serde_json::to_vec(&wrong_ca).unwrap())
        .expect("configure unrelated client CA");
    let untrusted = run(&rust_binary, &vault, &home, &["approval", "list"]);
    assert_eq!(untrusted.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&untrusted.stderr)
            .contains("verify local approval client identity")
    );

    let wrong_key = serde_json::json!({
        "certificate": tls.certificate,
        "client_auth_required": true,
        "client_ca_file": tls.client_ca_file,
        "client_certificate": tls.client_certificate,
        "client_key": server_key
    });
    fs::write(&tls_path, serde_json::to_vec(&wrong_key).unwrap())
        .expect("configure unrelated client private key");
    let mismatched = run(&rust_binary, &vault, &home, &["approval", "list"]);
    assert_eq!(mismatched.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&mismatched.stderr)
            .contains("load local approval client identity failed")
    );

    let correct_tls = serde_json::json!({
        "certificate": tls.certificate,
        "client_auth_required": true,
        "client_ca_file": tls.client_ca_file,
        "client_certificate": tls.client_certificate,
        "client_key": tls.client_key
    });
    fs::write(&tls_path, serde_json::to_vec(&correct_tls).unwrap())
        .expect("restore dedicated approval identity");

    let list = run(&rust_binary, &vault, &home, &["approval", "list", "--json"]);
    assert!(list.status.success(), "list failed: {list:?}");
    assert!(list.stderr.is_empty(), "unexpected list stderr: {list:?}");
    let listed: serde_json::Value = serde_json::from_slice(&list.stdout).expect("list JSON");
    let requests = listed["requests"].as_array().expect("requests array");
    assert_eq!(
        requests.len(),
        3,
        "Go handler returns only pending requests"
    );
    assert!(
        requests
            .iter()
            .any(|entry| entry["id"] == fixture.approve_id)
    );
    assert!(requests.iter().any(|entry| entry["id"] == fixture.deny_id));
    assert!(
        requests
            .iter()
            .any(|entry| entry["reason"] == "approve fixture")
    );

    let text_list = run(&rust_binary, &vault, &home, &["approval", "list"]);
    assert!(
        text_list.status.success(),
        "text list failed: {text_list:?}"
    );
    let text = String::from_utf8_lossy(&text_list.stdout);
    assert!(text.contains("REQUEST ID") && text.contains("agent-e2e"));

    let yaml_list = run(
        &rust_binary,
        &vault,
        &home,
        &["approval", "list", "--output", "yaml"],
    );
    assert!(
        yaml_list.status.success(),
        "YAML list failed: {yaml_list:?}"
    );
    assert!(String::from_utf8_lossy(&yaml_list.stdout).contains("requests:"));

    let quiet_list = run(
        &rust_binary,
        &vault,
        &home,
        &["approval", "list", "--quiet"],
    );
    assert!(
        quiet_list.status.success(),
        "quiet list failed: {quiet_list:?}"
    );
    assert!(quiet_list.stdout.is_empty() && quiet_list.stderr.is_empty());

    let approved = run(
        &rust_binary,
        &vault,
        &home,
        &[
            "approval",
            "decide",
            &fixture.approve_id,
            "--approve",
            "--json",
        ],
    );
    assert!(approved.status.success(), "approve failed: {approved:?}");
    let approved: serde_json::Value =
        serde_json::from_slice(&approved.stdout).expect("approve JSON");
    assert_eq!(approved["outcome"]["id"], fixture.approve_id);
    assert_eq!(approved["outcome"]["status"], "approved");

    let denied = run(
        &rust_binary,
        &vault,
        &home,
        &["approval", "decide", &fixture.deny_id, "--deny"],
    );
    assert!(denied.status.success(), "deny failed: {denied:?}");
    assert!(String::from_utf8_lossy(&denied.stdout).contains("denied"));

    let quiet_decision = run(
        &rust_binary,
        &vault,
        &home,
        &["approval", "decide", &fixture.quiet_id, "--deny", "--quiet"],
    );
    assert!(
        quiet_decision.status.success(),
        "quiet decision failed: {quiet_decision:?}"
    );
    assert!(quiet_decision.stdout.is_empty() && quiet_decision.stderr.is_empty());

    let repeated = run(
        &rust_binary,
        &vault,
        &home,
        &["approval", "decide", &fixture.approve_id, "--approve"],
    );
    assert_eq!(repeated.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&repeated.stderr).contains("approval server: approval request "),
        "repeat decision error missing Go API wrapper: {repeated:?}"
    );
    assert!(
        String::from_utf8_lossy(&repeated.stderr).contains("already approved"),
        "repeat decision was not rejected by Go queue: {repeated:?}"
    );
}

#[test]
fn approval_cli_rejects_non_loopback_binding_and_invalid_decision_flags() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let vault = temp.path().join("vault");
    let home = temp.path().join("home");
    setup_vault(&vault);
    fs::create_dir_all(&home).expect("create isolated home");
    fs::write(
        vault.join(".runtime-port"),
        br#"{"port":18443,"bind":"0.0.0.0"}"#,
    )
    .expect("write non-loopback runtime record");
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let list = run(&rust_binary, &vault, &home, &["approval", "list"]);
    assert_eq!(list.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&list.stderr)
            .contains("approval CLI requires a server bound to loopback")
    );

    for args in [
        &["approval", "decide", "apr-test"][..],
        &["approval", "decide", "apr-test", "--approve", "--deny"][..],
    ] {
        let output = run(&rust_binary, &vault, &home, args);
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("exactly one of --approve or --deny is required")
        );
    }
}
