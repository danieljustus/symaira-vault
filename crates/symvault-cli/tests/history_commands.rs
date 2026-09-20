#![deny(unsafe_code)]

#[path = "../src/history_commands.rs"]
mod history_commands;

use std::{fs, io::Cursor, path::PathBuf};

use symvault_sync::{CommitOptions, GitRepository};

/// Returns a guard that owns a unique temporary directory plus the (initially
/// non-existent) root inside it that the code under test creates.
///
/// The previous helper built the name from `SystemTime::now().as_nanos()`, which
/// is only microsecond-coarse on macOS (measured 2026-09-20: 30 samples, 9
/// distinct values, every one ending in `000`, and 4 threads starting together
/// received 3 distinct values). Tests of this binary therefore received the same
/// directory name, ran `git init` into one directory twice, and failed with
/// `cannot copy '.../info/exclude' ... File exists` on the macOS runner.
fn temporary_root() -> (tempfile::TempDir, PathBuf) {
    let guard = tempfile::Builder::new()
        .prefix("symvault-cli-history-")
        .tempdir()
        .expect("temp dir");
    let root = guard.path().join("root");
    (guard, root)
}

#[test]
fn git_log_matches_go_text_and_path_filter_contract() {
    let (_guard, root) = temporary_root();
    fs::create_dir_all(&root).expect("root");
    let repo = GitRepository::init(&root).expect("git init");
    fs::write(root.join("vault.txt"), b"one").expect("first file");
    repo.commit(CommitOptions {
        message: "first".to_owned(),
        ..CommitOptions::default()
    })
    .expect("first commit");
    fs::write(root.join("other.txt"), b"other").expect("second file");
    repo.commit(CommitOptions {
        message: "other".to_owned(),
        ..CommitOptions::default()
    })
    .expect("other commit");
    fs::write(root.join("vault.txt"), b"two").expect("third file");
    repo.commit(CommitOptions {
        message: "second".to_owned(),
        ..CommitOptions::default()
    })
    .expect("second commit");

    let all = history_commands::log(&root, None, 0).expect("all history");
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].message, "second");
    assert_eq!(all[1].message, "other");
    assert_eq!(all[2].message, "first");

    let vault = history_commands::log(&root, Some("vault.txt"), 0).expect("path history");
    assert_eq!(vault.len(), 2);
    assert_eq!(vault[0].message, "second");
    assert_eq!(vault[1].message, "first");
    assert!(history_commands::log(&root, Some("../vault.txt"), 0).is_err());

    let mut output = Cursor::new(Vec::new());
    history_commands::write_log(&mut output, &vault, false).expect("render history");
    let rendered = String::from_utf8(output.into_inner()).expect("UTF-8 history");
    assert!(rendered.contains("  20"));
    assert!(rendered.contains("  second\n  Author: Symaira Vault\n"));
    assert!(rendered.contains("  first\n  Author: Symaira Vault\n"));

    let mut quiet = Cursor::new(Vec::new());
    history_commands::write_log(&mut quiet, &all, true).expect("quiet history");
    assert!(quiet.into_inner().is_empty());
}

#[test]
fn missing_repository_is_an_empty_history_like_go() {
    let (_guard, root) = temporary_root();
    assert!(
        history_commands::log(&root, None, 0)
            .expect("missing repository")
            .is_empty()
    );
}

#[test]
fn explicit_transfers_without_repository_or_remote_are_noops_like_go() {
    let (_guard, root) = temporary_root();
    assert!(history_commands::transfer(&root, "invalid").is_err());
    for action in ["push", "pull"] {
        assert!(history_commands::transfer(&root, action).is_ok());
    }
    let repo = GitRepository::init(&root).unwrap();
    assert!(repo.pull("origin").skipped);
    for action in ["push", "pull"] {
        assert!(history_commands::transfer(&root, action).is_ok());
    }
}
