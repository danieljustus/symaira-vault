use std::{
    env,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    process::{Command, Output},
};

fn run(binary: &Path, args: &[&str], home: &Path, vault: &Path) -> Output {
    run_with_passphrase(binary, args, home, vault, None)
}

fn run_with_passphrase(
    binary: &Path,
    args: &[&str],
    home: &Path,
    vault: &Path,
    passphrase: Option<&str>,
) -> Output {
    let mut command = Command::new(binary);
    command
        .args(["--vault", vault.to_str().expect("vault path")])
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env_remove("SYMVAULT_VAULT")
        .env_remove("SYMVAULT_PASSPHRASE")
        .env_remove("SYMVAULT_ALLOW_ENV_PASSPHRASE")
        .env("SYMVAULT_NO_ENV_WARNING", "1")
        .env("CI", "1");
    command.env("SYMVAULT_RUN_BROKER_PROBE", "1");
    if let Some(passphrase) = passphrase {
        command
            .env("SYMVAULT_PASSPHRASE", passphrase)
            .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
            .env("SYMVAULT_TEST_KEYRING", "memory");
    }
    command.output().expect("run CLI")
}

#[test]
fn run_broker_flags_parse_before_uninitialized_vault_error() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = std::path::PathBuf::from(go_binary);
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let home = tempfile::tempdir().expect("temporary HOME");
    let vault = home.path().join("vault");

    for args in [
        &[
            "run",
            "--broker",
            "--broker-passthrough",
            "corp.internal",
            "--",
            "/usr/bin/true",
        ][..],
        &["run", "--broker-strict", "--", "/usr/bin/true"],
        &[
            "run",
            "--broker-passthrough",
            "corp.internal,legacy.example.com",
            "--",
            "/usr/bin/true",
        ],
        &[
            "run",
            "--broker",
            "--broker-strict",
            "--broker-passthrough",
            "corp.internal,legacy.example.com",
            "--",
            "/usr/bin/true",
        ],
    ] {
        let go = run(&go_binary, args, home.path(), &vault);
        let rust = run(rust_binary, args, home.path(), &vault);
        assert_eq!(
            rust.status.code(),
            go.status.code(),
            "status differs for {args:?}\nGo stderr: {:?}\nRust stderr: {:?}",
            go.stderr,
            rust.stderr
        );
        assert_eq!(rust.stdout, go.stdout, "stdout differs for {args:?}");
        assert_eq!(rust.stderr, go.stderr, "stderr differs for {args:?}");
    }

    assert!(!vault.exists(), "argument checks must not create the vault");
}

#[test]
fn run_broker_fails_closed_before_spawning_child() {
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let home = tempfile::tempdir().expect("temporary HOME");
    let vault = home.path().join("vault");
    let marker = home.path().join("child-ran");
    let marker_arg = marker.to_str().expect("marker path");
    let output = run_with_passphrase(
        rust_binary,
        &["run", "--broker", "--", "/usr/bin/touch", marker_arg],
        home.path(),
        &vault,
        None,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout={:?}", output.stdout);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--broker-passthrough requires at least one host"),
        "stderr={:?}",
        output.stderr
    );
    assert!(
        !vault.exists(),
        "missing allowlist must fail before vault access"
    );
    assert!(!marker.exists(), "run spawned the child despite --broker");
}

#[test]
fn run_broker_executes_child_that_reaches_loopback_proxy() {
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let home = tempfile::tempdir().expect("temporary HOME");
    let vault = home.path().join("vault");
    let passphrase = "fixture-passphrase-for-broker";

    let init = run_with_passphrase(
        rust_binary,
        &["init", "--auth", "passphrase"],
        home.path(),
        &vault,
        Some(passphrase),
    );
    assert!(
        init.status.success(),
        "Rust init failed: status={:?}, stdout={:?}, stderr={:?}",
        init.status.code(),
        init.stdout,
        init.stderr
    );

    let child = env::current_exe().expect("integration test executable");
    let args = [
        "run",
        "--broker",
        "--broker-strict",
        "--broker-passthrough",
        "example.com",
        "--passthrough",
        "SYMVAULT_RUN_BROKER_PROBE",
        "--",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain([
        child.to_string_lossy().into_owned(),
        "--exact".to_owned(),
        "run_broker_child_connects_to_the_loopback_proxy".to_owned(),
        "--nocapture".to_owned(),
    ])
    .collect::<Vec<_>>();
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    let output = run_with_passphrase(
        rust_binary,
        &arg_refs,
        home.path(),
        &vault,
        Some(passphrase),
    );
    assert!(
        output.status.success(),
        "run broker failed: status={:?}, stdout={:?}, stderr={:?}",
        output.status.code(),
        output.stdout,
        output.stderr
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("broker-proxy-child-ok"),
        "child did not report a successful CONNECT response: {:?}",
        output.stdout
    );
}

#[test]
fn run_broker_child_connects_to_the_loopback_proxy() {
    if env::var("SYMVAULT_RUN_BROKER_PROBE").ok().as_deref() != Some("1") {
        return;
    }
    let proxy = env::var("HTTPS_PROXY").expect("run must export HTTPS_PROXY");
    assert_eq!(env::var("HTTP_PROXY").ok().as_deref(), Some(proxy.as_str()));
    assert_eq!(
        env::var("NO_PROXY").ok().as_deref(),
        Some("127.0.0.1,localhost")
    );
    let address = proxy
        .strip_prefix("http://")
        .expect("plain loopback proxy URL")
        .parse::<SocketAddr>()
        .expect("proxy socket address");
    let mut connection = TcpStream::connect(address).expect("connect to run broker");
    connection
        .write_all(b"CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n")
        .expect("send CONNECT request");
    let mut response = String::new();
    connection
        .read_to_string(&mut response)
        .expect("read CONNECT response");
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden")
            && response.contains("host is outside the passthrough allowlist"),
        "unexpected broker response: {response:?}"
    );
    println!("broker-proxy-child-ok");
}
