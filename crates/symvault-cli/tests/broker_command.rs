use std::{env, path::Path, process::Command};

fn run(binary: &Path, args: &[&str]) -> std::process::Output {
    Command::new(binary).args(args).output().expect("run CLI")
}

#[test]
fn broker_flags_match_go_and_unknown_flags_fail_before_vault_access() {
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let go_binary = env::var_os("SYMVAULT_GO_BINARY").map(std::path::PathBuf::from);
    let mut binaries = vec![rust_binary];
    if let Some(go) = go_binary.as_deref() {
        binaries.push(go);
    } else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
    }
    for binary in &binaries {
        let output = run(binary, &["broker", "--help"]);
        assert!(output.status.success());
        let help = String::from_utf8_lossy(&output.stdout);
        for flag in ["--addr", "--strict", "--passthrough"] {
            assert!(
                help.contains(flag),
                "missing {flag} from broker help: {help}"
            );
        }
    }

    let home = tempfile::tempdir().expect("temporary HOME");
    let vault = home.path().join("vault");
    let mut statuses = Vec::new();
    for binary in binaries {
        let output = Command::new(binary)
            .args(["--vault", vault.to_str().unwrap(), "broker", "--unknown"])
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("SYMVAULT_NO_ENV_WARNING", "1")
            .output()
            .expect("run invalid broker flag");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        statuses.push(output.status.code());
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        assert!(
            stderr.contains("unknown") || stderr.contains("unexpected"),
            "{stderr}"
        );
        assert!(
            !vault.exists(),
            "flag parsing accessed or created the vault"
        );
    }
    if statuses.len() == 2 {
        assert_eq!(statuses[0], statuses[1], "unknown-flag exit status differs");
    }
}

#[test]
fn broker_rejects_remote_bind_before_vault_access() {
    let binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let home = tempfile::tempdir().expect("temporary HOME");
    let vault = home.path().join("vault");
    let output = Command::new(binary)
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "broker",
            "--addr",
            "0.0.0.0:8080",
            "--passthrough",
            "example.com",
        ])
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .output()
        .expect("run broker with remote bind");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("broker listener must bind to a loopback address")
    );
    assert!(!vault.exists());
}

#[test]
fn broker_rejects_an_uninitialized_vault_before_listening() {
    let binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let home = tempfile::tempdir().expect("temporary HOME");
    let vault = home.path().join("vault");
    let output = Command::new(binary)
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "broker",
            "--passthrough",
            "example.com",
        ])
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .output()
        .expect("run broker with uninitialized vault");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("vault not initialized"));
    assert!(!vault.exists());
}

#[test]
fn broker_requires_an_explicit_passthrough_allowlist_before_vault_access() {
    let binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let home = tempfile::tempdir().expect("temporary HOME");
    let vault = home.path().join("vault");
    let output = Command::new(binary)
        .args(["--vault", vault.to_str().unwrap(), "broker"])
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .output()
        .expect("run broker without passthrough hosts");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--passthrough requires at least one host")
    );
    assert!(!vault.exists());
}
