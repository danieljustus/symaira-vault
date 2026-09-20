#![deny(unsafe_code)]

#[path = "../src/history_commands.rs"]
mod history_commands;

use std::{
    fs,
    io::Cursor,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use symvault_sync::{CommitOptions, GitRepository};

fn temporary_root() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("symvault-cli-history-{suffix}"))
}

#[test]
fn git_log_matches_go_text_and_path_filter_contract() {
    let root = temporary_root();
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
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn missing_repository_is_an_empty_history_like_go() {
    let root = temporary_root();
    assert!(
        history_commands::log(&root, None, 0)
            .expect("missing repository")
            .is_empty()
    );
}

#[test]
fn explicit_transfers_without_repository_or_remote_are_noops_like_go() {
    let root = temporary_root();
    assert!(history_commands::transfer(&root, "invalid").is_err());
    for action in ["push", "pull"] {
        assert!(history_commands::transfer(&root, action).is_ok());
    }
    let repo = GitRepository::init(&root).unwrap();
    assert!(repo.pull("origin").skipped);
    for action in ["push", "pull"] {
        assert!(history_commands::transfer(&root, action).is_ok());
    }
    fs::remove_dir_all(root).unwrap();
}
