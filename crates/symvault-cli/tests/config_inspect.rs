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
    stdout_bytes: Vec<u16>,
    #[serde(default)]
    stderr_contains: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    #[allow(dead_code)]
    description: String,
    #[serde(default)]
    config_bytes: Vec<u16>,
    #[serde(default)]
    write_config: bool,
    #[serde(default)]
    default_path: bool,
    #[serde(default)]
    clear_home: bool,
    args: Vec<String>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    cases: Vec<Case>,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/cli/config-inspect.json");
    serde_json::from_slice(CONTENT).expect("config CLI fixture parses")
}

fn run_case(case: &Case, root: &Path) -> std::process::Output {
    let home = root.join("home");
    let config = if case.default_path {
        home.join(".symvault/config.yaml")
    } else {
        root.join(format!("{}.yaml", case.name))
    };
    if case.write_config {
        if let Some(parent) = config.parent() {
            fs::create_dir_all(parent).expect("create isolated config directory");
        }
        let bytes: Vec<u8> = case
            .config_bytes
            .iter()
            .map(|value| u8::try_from(*value).expect("fixture byte is in range"))
            .collect();
        fs::write(&config, bytes).expect("write isolated raw config");
    }
    let args: Vec<String> = case
        .args
        .iter()
        .map(|arg| arg.replace("__CONFIG__", config.to_str().expect("config path is UTF-8")))
        .collect();
    let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
    command
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CACHE_HOME", root.join("xdg-cache"))
        .env_remove("SYMVAULT_PASSPHRASE")
        .env_remove("SYMVAULT_ALLOW_ENV_PASSPHRASE");
    if case.clear_home {
        command.env_remove("HOME");
        command.env_remove("USERPROFILE");
    } else {
        command.env("HOME", &home);
    }
    command
        .args(args)
        .output()
        .expect("run symvault config case")
}

#[test]
fn fixture_pins_go_oracle_and_exercises_raw_list_edges() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle.commit,
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    assert_eq!(fixture.oracle.commit_sha, fixture.oracle.commit);
    assert_eq!(fixture.oracle.release, "unreleased");
    assert_eq!(
        fixture.oracle.source_files,
        [
            "cmd/admin/config.go",
            "internal/cli/cli.go",
            "internal/cli/output/output.go"
        ]
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert!(
        fixture
            .cases
            .iter()
            .any(|case| case.expected.exit_code != 0)
    );
    assert!(
        fixture
            .cases
            .iter()
            .any(|case| case.expected.stdout_bytes.is_empty())
    );
    assert!(
        fixture
            .cases
            .iter()
            .any(|case| !case.expected.stdout_bytes.is_empty())
    );
    assert!(fixture.cases.iter().any(|case| case.clear_home));
    assert!(fixture.cases.iter().any(|case| case.default_path));
}

#[test]
fn config_list_cases_match_go_generated_contract() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("symvault-config-cli-{unique}"));
    fs::create_dir_all(&root).expect("create isolated roots");
    let fixture = fixture();
    let mut failures = Vec::new();
    for case in &fixture.cases {
        let output = run_case(case, &root);
        let status = output.status.code().unwrap_or(255);
        let expected_stdout: Vec<u8> = case
            .expected
            .stdout_bytes
            .iter()
            .map(|value| u8::try_from(*value).expect("fixture byte is in range"))
            .collect();
        if status != i32::from(case.expected.exit_code)
            || output.stdout != expected_stdout
            || (!case.expected.stderr_contains.is_empty()
                && !String::from_utf8_lossy(&output.stderr)
                    .contains(&case.expected.stderr_contains))
        {
            failures.push(format!(
                "{}: status={status}, stdout={:?}, stderr={:?}",
                case.name,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    let _ = fs::remove_dir_all(&root);
    assert!(
        failures.is_empty(),
        "config list CLI mismatches: {failures:#?}"
    );
}
