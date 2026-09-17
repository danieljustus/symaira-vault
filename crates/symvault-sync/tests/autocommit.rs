use std::collections::BTreeMap;
use std::fs;

use symvault_crypto::generate_identity;
use symvault_store::{Entry, EntryMetadata, Store};
use symvault_sync::{CommitOptions, GitRepository, auto_commit_entry};
use tempfile::tempdir;

#[test]
fn auto_commit_entry_records_message_and_affected_paths() {
    let root = tempdir().expect("external synthetic git fixture tempdir");
    fs::write(
        root.path().join("config.yaml"),
        "git:\n  auto_push: false\n  auto_pull: false\n  auto_pull_interval: 0\n  commit_template: ''\n",
    )
    .expect("git-enabled fixture config");
    fs::write(root.path().join("identity.age"), b"fixture identity marker")
        .expect("identity marker");
    fs::create_dir(root.path().join("entries")).expect("entries directory");
    let identity = generate_identity();
    let store = Store::open(root.path(), &identity).expect("open store");
    let mut data = BTreeMap::new();
    data.insert(
        "username".into(),
        serde_json::Value::String("before".into()),
    );
    store
        .write_new_entry(
            "github",
            &Entry {
                path: "github".into(),
                data,
                metadata: EntryMetadata {
                    created: "2026-01-01T00:00:00Z".into(),
                    updated: "2026-01-01T00:00:00Z".into(),
                    version: 1,
                    ..EntryMetadata::default()
                },
                ..Entry::default()
            },
            &identity,
        )
        .expect("write initial entry");
    let repo = GitRepository::init(root.path()).expect("init git fixture");
    repo.commit(CommitOptions {
        message: "initial fixture".into(),
        ..CommitOptions::default()
    })
    .expect("initial commit");

    let mut updated = store.get("github", &identity).expect("read entry");
    updated
        .data
        .insert("username".into(), serde_json::Value::String("after".into()));
    store
        .write_entry_with_recipients_at("github", &updated, &identity, "2026-01-02T00:00:00Z", None)
        .expect("write updated entry");

    auto_commit_entry(&store, &identity, "github", "Update").expect("auto-commit");
    let latest = repo
        .log(1)
        .expect("read commit log")
        .pop()
        .expect("latest commit");
    assert_eq!(latest.message, "Update github");
    let listed = std::process::Command::new("git")
        .args(["show", "--format=", "--name-only", "HEAD"])
        .current_dir(root.path())
        .output()
        .expect("git show");
    assert!(listed.status.success());
    let files = String::from_utf8(listed.stdout).expect("git output");
    assert!(files.lines().any(|line| line == "entries/github.age"));
    assert!(files.lines().any(|line| line == "manifest.age"));
}

#[test]
fn auto_commit_entry_is_noop_without_git_configuration() {
    let root = tempdir().expect("external synthetic vault tempdir");
    fs::write(
        root.path().join("config.yaml"),
        "vault:\n  format_version: 1\n",
    )
    .expect("config");
    fs::write(root.path().join("identity.age"), b"fixture identity marker")
        .expect("identity marker");
    fs::create_dir(root.path().join("entries")).expect("entries directory");
    let identity = generate_identity();
    let store = Store::open(root.path(), &identity).expect("open store");
    auto_commit_entry(&store, &identity, "github", "Delete").expect("no-op without git");
}
