//! `agent upgrade` biometric gate (Go `cmd/mcp/agent_upgrade.go`
//! `requireBiometricForUpgrade`) through the installed binary.
//!
//! The binary is always run with `CI=1`, which closes the Touch ID gate
//! (`authguard::default_touch_id`), so these cases pin the *unavailable*
//! branch byte for byte and can never raise a system prompt. The
//! approve/reject/unavailable decision matrix with a fake `TouchId` lives in
//! the unit tests of `agent_upgrade_commands.rs`.
//!
//! With `SYMVAULT_GO_BINARY` pointing at a `CGO_ENABLED=0` oracle (no Touch ID,
//! so it takes the same unavailable branch) the same runs are compared with Go.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tempfile::TempDir;

struct Run {
    status: Option<i32>,
    stdout: String,
    stderr: String,
    config: String,
}

fn run(binary: &Path, args: &[&str]) -> Run {
    let root = TempDir::new().expect("sandbox");
    let home = root.path().join("home");
    let vault = root.path().join("vault");
    let work = root.path().join("work");
    for dir in [&home, &vault, &work] {
        fs::create_dir_all(dir).expect("sandbox dir");
    }
    fs::write(
        vault.join("config.yaml"),
        "defaultAgent: hermes\nagents:\n  hermes:\n    tier: standard\n",
    )
    .expect("seed config");
    let mut child = Command::new(binary)
        .args(["--vault"])
        .arg(&vault)
        .args(["agent", "upgrade", "hermes"])
        .args(args)
        .current_dir(&work)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("TMPDIR", &work)
        .env("CI", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    drop(child.stdin.take().expect("stdin").flush());
    let output = child.wait_with_output().expect("wait");
    Run {
        status: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr)
            .replace(root.path().to_str().expect("utf-8 root"), "<root>"),
        config: fs::read_to_string(vault.join("config.yaml"))
            .unwrap_or_default()
            .replace(root.path().to_str().expect("utf-8 root"), "<root>"),
    }
}

fn rust() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_symvault"))
}

const YES: [&str; 5] = ["--tier", "admin", "--yes", "--reason", "unit"];

#[test]
fn unavailable_with_yes_is_the_go_non_interactive_error() {
    let outcome = run(&rust(), &YES);
    assert_eq!(outcome.status, Some(1));
    assert!(outcome.stdout.is_empty());
    assert!(
        outcome.stderr.contains(
            "Error: biometric verification is required for non-interactive tier upgrades on this platform.\nRe-run with --no-biometric to bypass (not recommended)\n"
        ),
        "{}",
        outcome.stderr
    );
    assert!(
        outcome.config.contains("tier: standard"),
        "{}",
        outcome.config
    );
}

#[test]
fn unavailable_interactive_warns_and_cancels_without_a_terminal() {
    let outcome = run(&rust(), &["--tier", "admin"]);
    assert_eq!(outcome.status, Some(0));
    assert!(
        outcome.stderr.contains(
            "⚠ Biometric verification is not available on this platform.\n   The upgrade will proceed after interactive confirmation.\nUpgrade canceled.\n"
        ),
        "{}",
        outcome.stderr
    );
    assert!(outcome.config.contains("tier: standard"));
}

#[test]
fn no_biometric_flag_bypasses_the_gate() {
    let outcome = run(
        &rust(),
        &[
            "--tier",
            "admin",
            "--yes",
            "--reason",
            "unit",
            "--no-biometric",
        ],
    );
    assert_eq!(outcome.status, Some(0));
    assert!(!outcome.stderr.contains("Biometric verification"));
    assert!(
        outcome
            .stderr
            .contains("✓ Profile for \"hermes\" upgraded to \"admin\"")
    );
    assert!(outcome.config.contains("tier: admin"), "{}", outcome.config);
}

#[test]
fn unavailable_branch_matches_the_no_touch_id_go_oracle() {
    let Some(go) = std::env::var_os("SYMVAULT_GO_BINARY").map(PathBuf::from) else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let cases: [&[&str]; 3] = [
        &YES,
        &["--tier", "admin"],
        &[
            "--tier",
            "admin",
            "--yes",
            "--reason",
            "unit",
            "--no-biometric",
        ],
    ];
    for args in cases {
        let expected = run(&go, args);
        assert!(
            !expected.stderr.is_empty(),
            "oracle produced no output for {args:?}"
        );
        let actual = run(&rust(), args);
        assert_eq!(actual.status, expected.status, "{args:?}: exit status");
        assert_eq!(actual.stdout, expected.stdout, "{args:?}: stdout");
        assert_eq!(actual.stderr, expected.stderr, "{args:?}: stderr");
        assert_eq!(actual.config, expected.config, "{args:?}: config.yaml");
    }
}
