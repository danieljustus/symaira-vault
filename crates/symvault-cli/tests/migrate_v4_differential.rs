//! `migrate v4` against the pinned Go oracle.
//!
//! The oracle iterates `cfg.Agents`, a Go map, so the order of the
//! `  <name> → <tier>` lines is nondeterministic; Rust walks a `BTreeMap` and is
//! therefore sorted. Byte parity is unachievable for that block without
//! reproducing Go's map iteration, so the comparison is on the *set* of lines
//! (plus the stable surrounding lines verbatim). The assignment itself — which
//! profile gets which tier, the backup, and idempotence — must match exactly.

use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

const PASSPHRASE: &str = "migrate-v4-differential";

fn run(binary: &Path, args: &[&str], vault: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .arg("--vault")
        .arg(vault)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run migrate v4")
}

/// Creates a vault and strips every `tier:` line so the migration has work.
fn fixture(rust: &Path, name: &str) -> (TempDir, PathBuf) {
    let root = tempfile::tempdir().expect("fixture root");
    let vault = root.path().join(name);
    let init = run(rust, &["init"], &vault);
    assert!(
        init.status.success(),
        "init failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    let config = vault.join("config.yaml");
    let stripped: String = fs::read_to_string(&config)
        .expect("read config")
        .lines()
        .filter(|line| !line.trim_start().starts_with("tier:"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&config, format!("{stripped}\n")).expect("write config");
    (root, vault)
}

fn lines(output: &Output) -> Vec<String> {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    text.lines()
        .map(str::to_owned)
        .filter(|line| !line.contains("SYMVAULT_PASSPHRASE is active"))
        .filter(|line| !line.trim().is_empty())
        .collect()
}

/// Splits the report into the per-profile block and the stable remainder.
fn split_report(output: &Output) -> (BTreeSet<String>, Vec<String>) {
    let mut assignments = BTreeSet::new();
    let mut stable = Vec::new();
    for line in lines(output) {
        if line.starts_with("  ") && line.contains('\u{2192}') {
            assignments.insert(line.trim().to_owned());
        } else {
            stable.push(line);
        }
    }
    (assignments, stable)
}

fn tier_of(config: &str, profile: &str) -> Option<String> {
    let mut in_profile = false;
    for line in config.lines() {
        let indented = line.len() - line.trim_start().len();
        if indented == 4 && line.trim_end().ends_with(':') {
            in_profile = line.trim().trim_end_matches(':') == profile;
            continue;
        }
        if in_profile && indented == 8 && line.trim_start().starts_with("tier:") {
            return Some(line.trim().trim_start_matches("tier:").trim().to_owned());
        }
    }
    None
}

#[test]
fn migrate_v4_matches_go_assignments_and_stays_idempotent() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));

    let (_go_root, go_vault) = fixture(&rust_binary, "go");
    let (_rust_root, rust_vault) = fixture(&rust_binary, "rust");

    // Dry-run must report the same pending set and write nothing.
    let go_dry = run(&go_binary, &["migrate", "v4", "--dry-run"], &go_vault);
    let rust_dry = run(&rust_binary, &["migrate", "v4", "--dry-run"], &rust_vault);
    assert_eq!(rust_dry.status, go_dry.status, "dry-run status differs");
    let (go_set, go_stable) = split_report(&go_dry);
    let (rust_set, rust_stable) = split_report(&rust_dry);
    assert_eq!(rust_set, go_set, "dry-run tier assignment differs");
    assert_eq!(rust_stable, go_stable, "dry-run stable lines differ");
    // Guard against a vacuous pass: the oracle must actually report work.
    assert_eq!(
        go_set.len(),
        7,
        "expected 7 pending profiles in the oracle output, got {}",
        go_set.len()
    );
    assert!(
        !fs::read_dir(&rust_vault)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("v3-backup")),
        "dry-run wrote a backup"
    );

    // The real run assigns the same tiers as the oracle.
    let go_run = run(&go_binary, &["migrate", "v4", "-y"], &go_vault);
    let rust_run = run(&rust_binary, &["migrate", "v4", "-y"], &rust_vault);
    assert_eq!(rust_run.status, go_run.status, "run status differs");
    let (go_run_set, _) = split_report(&go_run);
    let (rust_run_set, _) = split_report(&rust_run);
    assert_eq!(rust_run_set, go_run_set, "run tier assignment differs");

    let go_config = fs::read_to_string(go_vault.join("config.yaml")).expect("go config");
    let rust_config = fs::read_to_string(rust_vault.join("config.yaml")).expect("rust config");
    for profile in [
        "claude-code",
        "cli",
        "codex",
        "default",
        "hermes",
        "openclaw",
        "opencode",
    ] {
        assert_eq!(
            tier_of(&rust_config, profile),
            tier_of(&go_config, profile),
            "tier differs for {profile}"
        );
    }

    // A backup exists on both sides and holds the pre-migration config.
    let backups = |vault: &Path| -> Vec<PathBuf> {
        fs::read_dir(vault)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().contains("v3-backup"))
            .collect()
    };
    for (label, vault) in [("go", &go_vault), ("rust", &rust_vault)] {
        let found = backups(vault);
        assert_eq!(found.len(), 1, "{label}: expected exactly one backup");
        let backed_up = fs::read_to_string(&found[0]).expect("read backup");
        assert!(
            !backed_up.contains("tier:"),
            "{label}: backup is not the pre-migration config"
        );
    }

    // Idempotence: the second run reports nothing pending and adds no backup.
    let go_again = run(&go_binary, &["migrate", "v4", "-y"], &go_vault);
    let rust_again = run(&rust_binary, &["migrate", "v4", "-y"], &rust_vault);
    assert_eq!(
        rust_again.status, go_again.status,
        "second-run status differs"
    );
    assert_eq!(
        lines(&rust_again),
        lines(&go_again),
        "second-run output differs"
    );
    assert_eq!(
        backups(&rust_vault).len(),
        1,
        "second run wrote another backup"
    );
    assert_eq!(
        fs::read_to_string(rust_vault.join("config.yaml")).unwrap(),
        rust_config,
        "second run changed the config"
    );
}
