//! Source-pinned Go CLI replay for the update-apply install-method refusal.
//! A forced Homebrew identity must fail before checking the network or writing
//! the update cache.

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
    corekit_pin: String,
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
        .join("tests/fixtures/update-apply-unsupported/cases.json");
    let raw = std::fs::read_to_string(path).expect("read update-apply unsupported fixture");
    serde_json::from_str(&raw.replace("\r\n", "\n")).expect("parse fixture")
}

fn run(args: &[String], home: &Path) -> Output {
    let executable_dir = std::fs::canonicalize(BINARY)
        .expect("resolve Rust CLI binary")
        .parent()
        .expect("binary has parent")
        .to_path_buf();
    Command::new(BINARY)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("HOMEBREW_PREFIX", executable_dir)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env_remove("SYMVAULT_VAULT")
        .env_remove("SYMVAULT_PASSPHRASE")
        .env_remove("SYMVAULT_AGENT")
        .output()
        .expect("run symvault update apply")
}

#[test]
fn unsupported_install_method_matches_go_and_stops_before_side_effects() {
    let fixture = fixture();
    let home = TempDir::new().expect("isolated home");
    for case in &fixture.cases {
        let output = run(&case.argv, home.path());
        assert_eq!(output.status.code(), Some(case.exit), "{}: exit", case.id);
        assert_eq!(output.stdout, case.stdout.as_bytes(), "{}: stdout", case.id);
        assert_eq!(output.stderr, case.stderr.as_bytes(), "{}: stderr", case.id);
        assert!(
            !home.path().join("cache").exists(),
            "{}: unsupported install method touched update cache",
            case.id
        );
    }
}

#[test]
fn fixture_binds_go_sources_and_corekit_pin() {
    let fixture = fixture();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut hasher = Sha256::new();
    for name in &fixture.oracle.source_files {
        let bytes = std::fs::read(root.join(name))
            .unwrap_or_else(|error| panic!("read Go oracle source {name}: {error}"));
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(&bytes);
        hasher.update([0]);
    }
    assert_eq!(
        format!("{:x}", hasher.finalize()),
        fixture.oracle.source_digest,
        "pinned Go update-apply sources changed"
    );
    let go_mod = std::fs::read_to_string(root.join("go.mod")).expect("read go.mod");
    assert!(go_mod.contains(&fixture.oracle.corekit_pin));
}
