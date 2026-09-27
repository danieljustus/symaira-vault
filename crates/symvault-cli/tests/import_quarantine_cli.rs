//! CLI dispatch contract for `symvault import --quarantine`.
//!
//! `cmd/admin/import.go` resolves and validates the import format before it
//! checks any flag conflict (`RunE`: format detection → `isSupportedImportFormat`
//! → CSV sniff → dry-run report → `--skip-existing`/`--overwrite` →
//! `--quarantine`/`--prefix`), so an invocation that cannot run reports the
//! format error and never announces a quarantine batch ID. The module-level
//! tests in `import_commands.rs` cover the prefix resolver itself; these cases
//! pin the ordering in the command dispatcher, which also proves the conflict
//! checks run before any vault is resolved or unlocked.
use std::env;
use std::path::PathBuf;
use std::process::{Command, Output};

const PASSPHRASE: &str = "correct horse battery staple";

struct Roots {
    _dir: tempfile::TempDir,
    home: PathBuf,
    vault: PathBuf,
}

fn roots() -> Roots {
    let dir = tempfile::TempDir::new().expect("temp home");
    let home = dir.path().to_path_buf();
    let vault = home.join("vault");
    Roots {
        _dir: dir,
        home,
        vault,
    }
}

fn run(args: &[&str], roots: &Roots) -> Output {
    let binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    Command::new(binary)
        .args(args)
        .env("HOME", &roots.home)
        .env("XDG_CONFIG_HOME", roots.home.join("config"))
        .env("XDG_DATA_HOME", roots.home.join("data"))
        .env("XDG_CACHE_HOME", roots.home.join("cache"))
        .env("SYMVAULT_VAULT", &roots.vault)
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .output()
        .expect("run symvault")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Collapse whitespace so a wrapped help line still matches the oracle's
/// single-line usage string.
fn collapsed(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn undetectable_format_wins_over_quarantine_flag_conflicts() {
    let roots = roots();
    let source = roots.home.join("import.txt");
    std::fs::write(
        &source,
        b"title,username,password\nGitHub,alice,gh-secret\n",
    )
    .expect("write source");
    let source = source.to_str().expect("utf-8 source").to_owned();

    let output = run(
        &[
            "--vault",
            roots.vault.to_str().expect("utf-8 vault"),
            "import",
            &source,
            "--quarantine",
            "--prefix",
            "work/",
        ],
        &roots,
    );
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "exit code\nstderr={stderr}");
    assert!(
        !stdout.contains("Quarantine import ID"),
        "no batch ID may be announced for an invocation that cannot run: {stdout}"
    );
    assert!(
        stderr
            .contains("cannot detect format from file extension \".txt\"; use --format to specify"),
        "format error expected: {stderr}"
    );
    assert!(
        !stderr.contains("--quarantine and --prefix cannot be used together"),
        "the flag conflict is evaluated after format resolution: {stderr}"
    );
}

#[test]
fn quarantine_prefix_conflict_fails_before_any_vault_access() {
    let roots = roots();
    let source = roots.home.join("import.csv");
    std::fs::write(
        &source,
        b"title,username,password\nGitHub,alice,gh-secret\n",
    )
    .expect("write source");
    let source = source.to_str().expect("utf-8 source").to_owned();

    let output = run(
        &[
            "--vault",
            roots.vault.to_str().expect("utf-8 vault"),
            "import",
            &source,
            "--format",
            "csv",
            "--quarantine",
            "--prefix",
            "work/",
        ],
        &roots,
    );
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(1),
        "exit code\nstdout={stdout}\nstderr={stderr}"
    );
    assert_eq!(stdout, "", "conflict is reported before the ID line");
    assert!(
        stderr.contains("--quarantine and --prefix cannot be used together"),
        "conflict message expected: {stderr}"
    );
    assert!(
        !roots.vault.exists(),
        "the conflict is decided before the vault is resolved"
    );
}

#[test]
fn quarantine_flag_help_carries_the_go_usage_text() {
    let roots = roots();
    let output = run(
        &[
            "--vault",
            roots.vault.to_str().expect("utf-8 vault"),
            "import",
            "--help",
        ],
        &roots,
    );
    assert_eq!(output.status.code(), Some(0), "help exit code");
    let help = collapsed(&text(&output.stdout));
    assert!(
        help.contains(
            "--quarantine Import entries into quarantine/<import-id>/ for human review before agent access"
        ),
        "usage text must match the oracle flag help: {help}"
    );
}
