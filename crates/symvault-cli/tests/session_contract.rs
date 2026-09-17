#![deny(unsafe_code)]

use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
}

#[derive(Debug, Deserialize)]
struct Expected {
    exit_code: u8,
    #[serde(default)]
    stdout_bytes: Vec<u8>,
    #[serde(default)]
    stderr_contains: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    #[allow(dead_code)]
    description: String,
    args: Vec<String>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    oracle: Oracle,
    cases: Vec<Case>,
}

fn fixture() -> Fixture {
    serde_json::from_slice(include_bytes!("../../../testdata/port/cli/session.json"))
        .expect("session fixture parses")
}

fn run_case(case: &Case, root: &Path) -> std::process::Output {
    let vault = root.join("missing-vault");
    let args: Vec<_> = case
        .args
        .iter()
        .map(|arg| arg.replace("__VAULT__", vault.to_str().expect("UTF-8 temp path")))
        .collect();
    Command::new(env!("CARGO_BIN_EXE_symvault"))
        .args(args)
        .env("HOME", root.join("home"))
        .env("USERPROFILE", root.join("home"))
        .env("SYMVAULT_VAULT", &vault)
        .env_remove("SYMVAULT_PROFILE")
        .env_remove("SYMVAULT_PASSPHRASE")
        .output()
        .expect("run Rust session CLI case")
}

#[test]
fn fixture_pins_go_sources_and_runs_empty_vault_cases() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle.commit,
        "4373522deb8891d850b6028ac7ef5c9b401f3156"
    );
    assert_eq!(fixture.oracle.commit_sha, fixture.oracle.commit);
    assert_eq!(fixture.oracle.release, "unreleased");
    assert_eq!(
        fixture.oracle.source_files,
        [
            "cmd/auth/auth.go",
            "cmd/auth/lock.go",
            "cmd/auth/unlock.go",
            "internal/cli/cli.go",
            "internal/session/session.go",
        ]
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert_eq!(fixture.cases.len(), 3);
    assert!(
        fixture
            .cases
            .iter()
            .all(|case| case.expected.exit_code != 0)
    );

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("symvault-session-cli-{unique}"));
    fs::create_dir_all(&root).expect("create isolated roots");
    let mut failures = Vec::new();
    for case in &fixture.cases {
        let output = run_case(case, &root);
        let status = output.status.code().unwrap_or(255);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if status != i32::from(case.expected.exit_code)
            || output.stdout != case.expected.stdout_bytes
            || (!case.expected.stderr_contains.is_empty()
                && !stderr.contains(&case.expected.stderr_contains))
        {
            failures.push(format!(
                "{}: status={status}, stdout={:?}, stderr={stderr:?}",
                case.name,
                String::from_utf8_lossy(&output.stdout),
            ));
        }
    }
    let _ = fs::remove_dir_all(&root);
    assert!(failures.is_empty(), "session CLI mismatches: {failures:#?}");
}
