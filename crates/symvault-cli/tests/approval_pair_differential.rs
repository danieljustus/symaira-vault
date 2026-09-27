use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const ENROLL_SECRET: &str = "mcp-server.enroll-secret";

fn run(binary: &Path, root: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .arg("--vault")
        .arg(root)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .output()
        .expect("run CLI")
}

struct GoApprovalServer(Child);

impl GoApprovalServer {
    fn start(server_binary: &Path, vault: &Path) -> Self {
        let mut child = Command::new(server_binary)
            .arg("--vault")
            .arg(vault)
            .env("GOTOOLCHAIN", "go1.26.6")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start Go approval handler");
        let metadata = vault.join(".ready");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if metadata.is_file() {
                return Self(child);
            }
            if let Some(status) = child.try_wait().expect("check Go server") {
                let output = child.wait_with_output().expect("read Go server output");
                panic!(
                    "Go approval handler exited before publishing runtime metadata ({status}): {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().expect("read stopped Go server");
                panic!(
                    "Go approval handler startup timed out: {}",
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

#[test]
fn approval_pair_rejects_loopback_server_like_go_oracle() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let go_binary = PathBuf::from(go_binary);
    let guard = tempfile::tempdir().expect("temporary directory");
    let go_root = guard.path().join("go-vault");
    let rust_root = guard.path().join("rust-vault");
    let home = guard.path().join("home");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&go_root).expect("Go vault root");
    fs::create_dir_all(&rust_root).expect("Rust vault root");

    let go_init = run(
        &go_binary,
        &go_root,
        &home,
        &["init", "--auth", "passphrase"],
    );
    assert!(go_init.status.success(), "Go init: {go_init:?}");
    let rust_init = run(
        &rust_binary,
        &rust_root,
        &home,
        &["init", "--auth", "passphrase"],
    );
    assert!(rust_init.status.success(), "Rust init: {rust_init:?}");

    for root in [&go_root, &rust_root] {
        fs::write(
            root.join(".runtime-port"),
            br#"{"port":18443,"bind":"127.0.0.1"}"#,
        )
        .expect("write runtime server metadata");
    }

    let go_pair = run(
        &go_binary,
        &go_root,
        &home,
        &["device", "approval-pair", "--host", "192.168.1.42"],
    );
    let rust_pair = run(
        &rust_binary,
        &rust_root,
        &home,
        &["device", "approval-pair", "--host", "192.168.1.42"],
    );
    assert!(
        !go_pair.status.success(),
        "Go unexpectedly paired: {go_pair:?}"
    );
    assert!(
        !rust_pair.status.success(),
        "Rust unexpectedly paired: {rust_pair:?}"
    );
    for (name, output) in [("Go", go_pair), ("Rust", rust_pair)] {
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(
            message.contains("127.0.0.1 (loopback-only)"),
            "{name} error did not explain loopback binding: {message}"
        );
    }
}

#[test]
fn approval_pair_proves_vault_ownership_against_go_handler() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go handler integration: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let go_binary = PathBuf::from(go_binary);
    let guard = tempfile::tempdir().expect("temporary directory");
    let vault = guard.path().join("vault");
    let home = guard.path().join("home");
    let server_binary = guard
        .path()
        .join(format!("approval_pair_server{}", env::consts::EXE_SUFFIX));
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    let build_server = Command::new("go")
        .args(["build", "-o"])
        .arg(&server_binary)
        .arg("./crates/symvault-cli/tests/approval_pair_server")
        .current_dir(repo)
        .env("GOTOOLCHAIN", "go1.26.6")
        .output()
        .expect("build Go approval handler");
    assert!(
        build_server.status.success(),
        "build Go approval handler: {}",
        String::from_utf8_lossy(&build_server.stderr)
    );
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&vault).expect("vault root");

    let init = run(&go_binary, &vault, &home, &["init", "--auth", "passphrase"]);
    assert!(init.status.success(), "Go init: {init:?}");
    let _server = GoApprovalServer::start(&server_binary, &vault);
    let secret_path = vault.join(ENROLL_SECRET);
    let secret = fs::read(&secret_path).expect("Go handler's enroll secret");
    assert_eq!(secret.len(), 32, "Go enroll secret length");

    fs::write(&secret_path, [0xA5; 32]).expect("install invalid proof secret");
    let invalid = run(
        &rust_binary,
        &vault,
        &home,
        &["device", "approval-pair", "--host", "192.168.1.42"],
    );
    assert!(
        !invalid.status.success(),
        "invalid proof was accepted: {invalid:?}"
    );
    assert!(
        String::from_utf8_lossy(&invalid.stderr)
            .contains("missing or invalid proof of vault-directory ownership"),
        "Go handler did not reject the invalid HMAC proof: {invalid:?}"
    );

    fs::write(&secret_path, &secret).expect("restore Go handler's enroll secret");
    let paired = run(
        &rust_binary,
        &vault,
        &home,
        &["device", "approval-pair", "--host", "192.168.1.42"],
    );
    assert!(
        paired.status.success(),
        "valid proof was rejected: {paired:?}"
    );
    let output = String::from_utf8_lossy(&paired.stdout);
    for expected in [
        "=== Approval Device Pairing ===",
        "Scan this with the Symaira Vault iOS app",
        "Host:        192.168.1.42",
        "Port:",
        "Code:",
        "Fingerprint:",
        "Expires:",
    ] {
        assert!(
            output.contains(expected),
            "pair output missing {expected:?}: {output}"
        );
    }
    assert!(
        output.chars().any(|glyph| matches!(glyph, '█' | '▀' | '▄')),
        "expected QR output at the deterministic 80-column non-terminal width"
    );

    let quiet = run(
        &rust_binary,
        &vault,
        &home,
        &[
            "device",
            "approval-pair",
            "--host",
            "192.168.1.42",
            "--quiet",
        ],
    );
    assert!(quiet.status.success(), "quiet pairing failed: {quiet:?}");
    assert!(quiet.stdout.is_empty(), "--quiet wrote stdout: {quiet:?}");
    assert!(quiet.stderr.is_empty(), "--quiet wrote stderr: {quiet:?}");
}
