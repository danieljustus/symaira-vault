//! Source-pinned byte replay of Go's local-only `update apply --dry-run`
//! behavior for non-release builds. No update request or installer is needed.

use std::path::Path;
use std::process::{Command, Output};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");

#[derive(Debug, Deserialize)]
struct Oracle {
    source_files: Vec<String>,
    source_digest: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    argv: Vec<String>,
    exit: i32,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    cases: Vec<Case>,
}

fn fixture() -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/update-apply-nonrelease/cases.json");
    let raw = std::fs::read_to_string(path).expect("read update-apply fixture");
    serde_json::from_str(&raw.replace("\r\n", "\n")).expect("parse update-apply fixture")
}

fn run(args: &[String], home: &Path) -> Output {
    Command::new(BINARY)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env_remove("SYMVAULT_VAULT")
        .env_remove("SYMVAULT_PASSPHRASE")
        .env_remove("SYMVAULT_AGENT")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .expect("run symvault update apply")
}

#[test]
fn nonrelease_apply_dry_run_matches_go_oracle_bytes() {
    let fixture = fixture();
    let dir = TempDir::new().expect("temp home");
    for case in &fixture.cases {
        let output = run(&case.argv, dir.path());
        assert_eq!(
            output.status.code(),
            Some(case.exit),
            "{}: exit differs (stderr: {})",
            case.id,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.stdout,
            case.stdout.as_bytes(),
            "{}: stdout differs",
            case.id
        );
        assert_eq!(
            output.stderr,
            case.stderr.as_bytes(),
            "{}: stderr differs",
            case.id
        );
    }
}

#[test]
fn fixture_source_digest_matches_pinned_go_sources() {
    let fixture = fixture();
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut hasher = Sha256::new();
    for name in &fixture.oracle.source_files {
        let data = std::fs::read(repo_root.join(name))
            .unwrap_or_else(|error| panic!("read {name}: {error}"));
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(&data);
        hasher.update([0]);
    }
    assert_eq!(
        format!("{:x}", hasher.finalize()),
        fixture.oracle.source_digest,
        "pinned Go sources changed; recapture the update-apply fixture"
    );
}
