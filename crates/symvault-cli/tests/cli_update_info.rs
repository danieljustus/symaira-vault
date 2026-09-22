//! Byte-differential replay of the frozen Go-oracle fixture for
//! `symvault update` / `symvault update info` (oracle commit `d4aa2b13`,
//! fixture `tests/fixtures/update-info/cases.json`, captured 2026-09-22).
//!
//! Documented non-goals:
//! - Help rendering (CLI-help class): the oracle prints the cobra help for
//!   bare `update`; Rust exits 0 and stays silent, exactly like the
//!   `symvault help` / `import review`-bare precedent. `update --help`
//!   renders clap's help instead; asserted via exit status only.
//! - Parser error style: `update info --bogus` reaches cobra's flag parser
//!   in the oracle (exit 1, single line) while clap reports its own error
//!   and exit code. `cligap` explicitly does not measure argument-error
//!   style; the test asserts only that Rust fails closed.
//!
//! Cases marked `platform: unix` are replayed on Unix only: corekit's
//! writability fallback returns `build-from-source` on Windows, so the
//! oracle bytes captured on darwin do not apply there. The Windows branch
//! of the detector itself is unit-tested in `update_commands`.

use std::path::Path;
use std::process::{Command, Output};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");
const BINARY_MARKER: &str = "{{BINARY}}";

#[derive(Debug, Deserialize)]
struct Oracle {
    #[allow(dead_code)]
    commit: String,
    #[allow(dead_code)]
    binary: String,
    #[allow(dead_code)]
    sha256: String,
    #[allow(dead_code)]
    captured: String,
    #[allow(dead_code)]
    generated_on: String,
    source_files: Vec<String>,
    source_digest: String,
    #[allow(dead_code)]
    corekit_pin: String,
    #[allow(dead_code)]
    env: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    #[allow(dead_code)]
    desc: String,
    argv: Vec<String>,
    exit: i32,
    stdout: String,
    stderr: String,
    platform: String,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    cases: Vec<Case>,
}

fn load_fixture() -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/update-info/cases.json");
    let raw = std::fs::read_to_string(&path).expect("read update-info fixture");
    // Repository rule: fixture loaders normalize CRLF to LF.
    serde_json::from_str(&raw.replace("\r\n", "\n")).expect("parse update-info fixture")
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
        .env_remove("HOMEBREW_PREFIX")
        .env_remove("GOPATH")
        .env_remove("GOMODCACHE")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .output()
        .expect("run symvault update")
}

#[test]
fn update_cases_match_go_oracle_bytes() {
    let fixture = load_fixture();
    let dir = TempDir::new().expect("temp home");
    let home = dir.path();

    for case in &fixture.cases {
        if case.platform == "unix" && cfg!(windows) {
            eprintln!(
                "skipping {} on Windows: fixture captured on darwin; \
                 corekit's writability fallback is platform-specific",
                case.id
            );
            continue;
        }

        let output = run(&case.argv, home);
        let exit = output.status.code();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        match case.id.as_str() {
            // Rust exits 0 and stays silent where the oracle prints the
            // cobra help (documented help-rendering non-goal).
            "update-bare" | "update-parent-output-text" => {
                assert_eq!(exit, Some(case.exit), "{}: exit differs", case.id);
                assert!(
                    output.stdout.is_empty(),
                    "{}: expected silence, got stdout {stdout:?}",
                    case.id
                );
                assert!(
                    output.stderr.is_empty(),
                    "{}: expected silence, got stderr {stderr:?}",
                    case.id
                );
            }
            // `update --help` renders clap's help (help-rendering non-goal);
            // only the exit status and a clean stderr are asserted.
            "update-help" => {
                assert_eq!(exit, Some(case.exit), "{}: exit differs", case.id);
                assert!(
                    output.stderr.is_empty(),
                    "{}: expected empty stderr, got {stderr:?}",
                    case.id
                );
                assert!(
                    !output.stdout.is_empty(),
                    "{}: expected help on stdout",
                    case.id
                );
            }
            // Parser error style is out of scope (cligap's non-claim);
            // Rust must still fail closed.
            "update-unknown-flag-info" => {
                assert_ne!(exit, Some(0), "{}: must fail closed", case.id);
            }
            _ => {
                let expected_stdout = case.stdout.replace(BINARY_MARKER, BINARY);
                let expected_stderr = case.stderr.replace(BINARY_MARKER, BINARY);
                assert_eq!(
                    exit,
                    Some(case.exit),
                    "{}: exit differs (stderr: {stderr:?})",
                    case.id
                );
                assert_eq!(
                    output.stdout,
                    expected_stdout.as_bytes(),
                    "{}: stdout differs\nexpected: {expected_stdout:?}\ngot: {stdout:?}",
                    case.id
                );
                assert_eq!(
                    output.stderr,
                    expected_stderr.as_bytes(),
                    "{}: stderr differs\nexpected: {expected_stderr:?}\ngot: {stderr:?}",
                    case.id
                );
            }
        }
    }
}

#[test]
fn fixture_source_digest_matches_pinned_go_sources() {
    let fixture = load_fixture();
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
    let digest = hasher.finalize();
    let digest = format!("{digest:x}");
    assert_eq!(
        digest, fixture.oracle.source_digest,
        "pinned Go sources changed; regenerate \
         crates/symvault-cli/tests/fixtures/update-info/cases.json"
    );
}
