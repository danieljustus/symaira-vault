//! Byte-differential replay of the frozen Go-oracle fixture for
//! `symvault import review list|promote` (oracle commit a226a6f7,
//! fixture `tests/fixtures/import-review/cases.json`, captured 2026-09-22).
//!
//! Documented non-goal (CLI-help class): bare `import review` prints the
//! cobra group help in the oracle — Rust matches exit status 0 and stays
//! silent instead, exactly like the `symvault help` / agent-skill-bare
//! precedent.
//!
//! Accepted parser-model difference (not fixture-covered): flags declared
//! on the import parent (`--overwrite`, `--format`, ...) stay accepted
//! after any review word under clap, while cobra scopes them per
//! subcommand.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const PASSPHRASE: &str = "correct horse battery staple";

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    #[allow(dead_code)]
    binary: String,
    #[allow(dead_code)]
    sha256: String,
    #[allow(dead_code)]
    captured: String,
    source_files: Vec<String>,
    source_digest: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    #[allow(dead_code)]
    desc: String,
    seed: Vec<Vec<String>>,
    argv: Vec<String>,
    exit: i32,
    stdout: String,
    stderr: String,
    #[serde(default)]
    post_argv: Option<Vec<String>>,
    #[serde(default)]
    post_exit: Option<i32>,
    #[serde(default)]
    post_stdout: String,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    cases: Vec<Case>,
}

fn load_fixture() -> Fixture {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/import-review/cases.json");
    let raw = std::fs::read_to_string(&path).expect("read import-review fixture");
    // Repository rule: fixture loaders normalize CRLF to LF.
    serde_json::from_str(&raw.replace("\r\n", "\n")).expect("parse import-review fixture")
}

struct Roots {
    _dir: TempDir,
    home: PathBuf,
    vault: PathBuf,
}

impl Roots {
    fn new() -> Self {
        let dir = TempDir::new().expect("temp home");
        let home = dir.path().to_path_buf();
        let vault = home.join("vault");
        Self {
            _dir: dir,
            home,
            vault,
        }
    }
}

fn run(binary: &str, args: &[String], roots: &Roots) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", &roots.home)
        .env("USERPROFILE", &roots.home)
        .env("XDG_CONFIG_HOME", roots.home.join(".config"))
        .env("XDG_DATA_HOME", roots.home.join(".local/share"))
        .env("SYMVAULT_VAULT", &roots.vault)
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env_remove("SYMVAULT_MCP_TOKEN")
        .env_remove("SYMVAULT_NO_ENV_WARNING")
        .env_remove("SYMVAULT_PROFILE")
        // The oracle capture pinned PATH=/usr/bin:/bin (fixture-generation
        // rule). FreeBSD installs git in /usr/local/bin; Windows needs its
        // inherited PATH. Both need git for the init seed.
        .env("PATH", {
            #[cfg(target_os = "freebsd")]
            {
                "/usr/local/bin:/usr/bin:/bin"
            }
            #[cfg(all(unix, not(target_os = "freebsd")))]
            {
                "/usr/bin:/bin"
            }
            #[cfg(not(unix))]
            {
                std::env::var_os("PATH").unwrap_or_default()
            }
        })
        .output()
        .expect("run symvault")
}

#[test]
fn import_review_matches_frozen_go_oracle() {
    let fixture = load_fixture();
    assert_eq!(fixture.cases.len(), 17, "fixture case count");
    let binary = env!("CARGO_BIN_EXE_symvault");

    for case in &fixture.cases {
        let roots = Roots::new();
        for seed in &case.seed {
            let out = run(binary, seed, &roots);
            assert!(
                out.status.success(),
                "case {}: seed {:?} failed: {}",
                case.id,
                seed,
                String::from_utf8_lossy(&out.stderr)
            );
        }

        let out = run(binary, &case.argv, &roots);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(case.exit), "case {}: exit", case.id);

        if case.id == "review-bare" {
            // Documented non-goal: cobra help rendering (module docs).
            assert!(
                stdout.is_empty(),
                "case {}: bare review must stay silent, got: {stdout}",
                case.id
            );
        } else {
            assert_eq!(stdout, case.stdout, "case {}: stdout", case.id);
        }
        assert_eq!(stderr, case.stderr, "case {}: stderr", case.id);

        if let Some(post) = &case.post_argv {
            let out = run(binary, post, &roots);
            let post_stdout = String::from_utf8_lossy(&out.stdout);
            assert_eq!(
                out.status.code(),
                case.post_exit,
                "case {}: post exit",
                case.id
            );
            assert_eq!(
                post_stdout, case.post_stdout,
                "case {}: post stdout",
                case.id
            );
        }
    }
}

#[test]
fn fixture_source_digest_matches_checkout() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.oracle.commit.len(),
        40,
        "oracle commit is a full sha"
    );
    assert_eq!(
        fixture.oracle.source_digest.len(),
        64,
        "digest is sha256 hex"
    );

    // provenance.Digest format: sha256 over sorted name/NUL/content/NUL.
    let mut names = fixture.oracle.source_files.clone();
    names.sort();
    assert_eq!(
        names, fixture.oracle.source_files,
        "source_files must be stored sorted for a stable digest"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut hasher = Sha256::new();
    for name in &names {
        let content =
            std::fs::read(root.join(name)).unwrap_or_else(|error| panic!("read {name}: {error}"));
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
        hasher.update(&content);
        hasher.update([0u8]);
    }
    let digest = format!("{:x}", hasher.finalize());
    assert_eq!(
        digest, fixture.oracle.source_digest,
        "Go contract source changed since fixture capture — re-freeze \
         crates/symvault-cli/tests/fixtures/import-review/cases.json"
    );
}
