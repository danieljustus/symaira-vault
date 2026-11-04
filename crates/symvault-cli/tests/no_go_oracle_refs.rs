//! Go-oracle reference lint (enabled at Go removal).
//!
//! Once the Go tree is deleted, nothing under `crates/` or `scripts/` may reach
//! for a Go oracle: no oracle-binary env var, no Go toolchain pin, no
//! `Command::new("go")`, no "skipping Go" soft-skip. Capture-side code that
//! legitimately records Go once (the shared helper and the capture scripts) is
//! on an explicit allowlist below and disappears with the Go tree.
//!
//! Excluded from the scan: `scripts/rust-port/cmd/**` and
//! `scripts/rust-port/internal/**` (the Go generators themselves), `*.go.txt`
//! frozen sources, docs, and `target/`.
//!
//! The test is `#[ignore]`d until the other branches that still carry hits have
//! landed; run it with `cargo test -p symvault-cli --test no_go_oracle_refs --
//! --ignored` to print the current hit list.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: [&str; 6] = [
    "SYMVAULT_GO_BINARY",
    "SYMVAULT_FFI_GO_DRIVER",
    "SYMVAULT_GO_ORACLE",
    "GOTOOLCHAIN",
    "Command::new(\"go\")",
    "skipping Go",
];

/// Capture-mode code paths: they record Go output once and are never part of a
/// replay gate.
const ALLOWLIST: [&str; 5] = [
    "crates/symvault-cli/tests/common/go_oracle.rs",
    "crates/symvault-cli/tests/common/go_oracle_ext.rs",
    "crates/symvault-cli/tests/no_go_oracle_refs.rs",
    "scripts/rust-port/check_config_rewrite.sh",
    "scripts/rust-port/check_output_modes_cli.sh",
];

const TEXT_EXTENSIONS: [&str; 7] = ["rs", "sh", "py", "toml", "json", "yml", "yaml"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn excluded(relative: &str) -> bool {
    relative.starts_with("scripts/rust-port/cmd/")
        || relative.starts_with("scripts/rust-port/internal/")
        || relative.ends_with(".go.txt")
        || relative.contains("/target/")
        || ALLOWLIST.contains(&relative)
}

fn scan(dir: &Path, root: &Path, hits: &mut Vec<String>, scanned: &mut usize) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let relative = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if path.is_dir() {
            if matches!(
                path.file_name().and_then(|n| n.to_str()),
                Some("target" | ".git")
            ) {
                continue;
            }
            scan(&path, root, hits, scanned);
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if excluded(&relative) || !TEXT_EXTENSIONS.contains(&ext) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        *scanned += 1;
        for (number, line) in text.lines().enumerate() {
            for needle in FORBIDDEN {
                if line.contains(needle) {
                    hits.push(format!("{relative}:{}: {needle}", number + 1));
                }
            }
        }
    }
}

fn hits_under(subdirs: &[&str]) -> (Vec<String>, usize) {
    let root = repo_root();
    let mut hits = Vec::new();
    let mut scanned = 0;
    for sub in subdirs {
        scan(&root.join(sub), &root, &mut hits, &mut scanned);
    }
    hits.sort();
    (hits, scanned)
}

#[test]
#[ignore = "enabled at Go removal"]
fn crates_and_scripts_have_no_go_oracle_references() {
    let (hits, scanned) = hits_under(&["crates", "scripts"]);
    assert!(scanned > 100, "scanner saw only {scanned} files");
    assert!(
        hits.is_empty(),
        "{} Go oracle reference(s):\n{}",
        hits.len(),
        hits.join("\n")
    );
}

/// Always-on guard: the scanner itself must find a planted reference, so the
/// ignored test cannot silently pass because it looks at nothing.
#[test]
fn scanner_detects_a_planted_reference() {
    let dir = std::env::temp_dir().join(format!("no-go-oracle-refs-{}", std::process::id()));
    fs::create_dir_all(dir.join("crates")).unwrap();
    fs::write(
        dir.join("crates/x.rs"),
        "let _ = env::var(\"SYMVAULT_GO_BINARY\");\n",
    )
    .unwrap();
    fs::write(dir.join("crates/ok.rs"), "let _ = 1;\n").unwrap();
    let mut hits = Vec::new();
    let mut scanned = 0;
    scan(&dir.join("crates"), &dir, &mut hits, &mut scanned);
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(scanned, 2);
    assert_eq!(hits, vec!["crates/x.rs:1: SYMVAULT_GO_BINARY".to_owned()]);
}
