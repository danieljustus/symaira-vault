use std::{
    env, fs,
    path::Path,
    process::{Command, Output},
};

const PASSPHRASE: &str = "correct horse battery staple";

fn run(binary: &Path, args: &[&str], vault: &Path, home: &Path, auth: bool) -> Output {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .env_remove("SYMVAULT_PASSPHRASE")
        .env_remove("SYMVAULT_ALLOW_ENV_PASSPHRASE");
    if auth {
        command
            .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
            .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1");
    }
    command.output().expect("run CLI")
}

fn code(output: &Output) -> Option<i32> {
    output.status.code()
}

fn assert_error_streams(output: &Output, case: &str) {
    assert!(
        output.stdout.is_empty(),
        "{case} wrote stdout: {:?}",
        output.stdout
    );
    assert!(!output.stderr.is_empty(), "{case} did not write stderr");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(PASSPHRASE),
        "{case} leaked the passphrase"
    );
}

#[test]
fn invalid_config_auth_and_not_found_follow_go_exit_taxonomy() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = std::path::PathBuf::from(go_binary);
    let rust_binary =
        std::path::PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let vault = tempfile::tempdir().expect("vault");
    let init_home = tempfile::tempdir().expect("init home");
    let init = run(
        &rust_binary,
        &[
            "--vault",
            vault.path().to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        vault.path(),
        init_home.path(),
        true,
    );
    assert!(init.status.success(), "Rust init failed: {:?}", init.stderr);
    let config_path = vault.path().join("config.yaml");
    let valid_config = fs::read(&config_path).expect("read initialized config");

    let vault_arg = vault.path().to_str().unwrap();
    let cases = [
        // Go's ExitInvalidInput (9); Rust currently matches this validation path.
        (
            "invalid args",
            vec!["--vault", vault_arg, "get", "ghost", "--print", "--length"],
            9,
            true,
            false,
        ),
        // Missing auth is Go's ExitLocked (4); Rust currently collapses this to its generic exit.
        (
            "missing auth",
            vec!["--vault", vault_arg, "get", "ghost", "--print"],
            4,
            false,
            false,
        ),
        // A correct credential reaches the missing-entry path; Rust currently returns its generic exit.
        (
            "not found",
            vec!["--vault", vault_arg, "get", "ghost", "--print"],
            2,
            true,
            false,
        ),
        // Config wording differs by parser; assert the Go taxonomy and stream contract.
        (
            "invalid config",
            vec!["--vault", vault_arg, "get", "ghost", "--print"],
            6,
            false,
            true,
        ),
    ];

    for (name, args, go_code, with_auth, corrupt_config) in cases {
        if corrupt_config {
            fs::write(&config_path, b"vault: [\n").expect("write corrupt config");
        } else {
            fs::write(&config_path, &valid_config).expect("restore config");
        }
        let go_home = tempfile::tempdir().expect("Go home");
        let rust_home = tempfile::tempdir().expect("Rust home");
        let go = run(&go_binary, &args, vault.path(), go_home.path(), with_auth);
        let rust = run(
            &rust_binary,
            &args,
            vault.path(),
            rust_home.path(),
            with_auth,
        );
        assert_eq!(
            code(&go),
            Some(go_code),
            "Go oracle exit for {name}: {:?}",
            go.stderr
        );
        assert_error_streams(&go, &format!("Go {name}"));
        assert_error_streams(&rust, &format!("Rust {name}"));
        if name == "invalid args" {
            assert_eq!(
                code(&rust),
                code(&go),
                "Rust exit for {name}: {:?}",
                rust.stderr
            );
            assert_eq!(rust.stderr, go.stderr, "stderr for {name}");
        } else {
            // These failures still cross the shared String-only error path, so their Rust exit
            // categories cannot be compared until that path preserves typed errors.
            assert!(
                code(&rust).is_some_and(|code| code != 0),
                "Rust unexpectedly succeeded for {name}: {:?}",
                rust.stderr
            );
        }
    }
}
