use std::{
    env,
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
        &["run", "--broker", "--", "/usr/bin/true"][..],
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
    assert!(
        vault.join("config.yaml").is_file(),
        "vault was not initialized"
    );

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
    assert_eq!(
        output.stderr,
        b"Error: run --broker is not implemented in the Rust CLI yet\nError: run --broker is not implemented in the Rust CLI yet\n"
    );
    assert!(!marker.exists(), "run spawned the child despite --broker");
}
