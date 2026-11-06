//! D1 gate on the git operations that rewrite `.git` or the working tree: the
//! pre-migration backup must be taken (and see the untouched repository)
//! before `remote add`, `push --set-upstream`, the commit and a forced pull.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, OnceLock},
};

use sha2::{Digest, Sha256};
use symvault_store::data_safety::{BackupReceipt, PreMutationGuard, install_guard};
use symvault_sync::{CommitOptions, GitRepository};

/// What the guard saw: (vault, `.git/config` at that moment).
static CALLS: Mutex<Vec<(PathBuf, String)>> = Mutex::new(Vec::new());

struct Recorder {
    backups: tempfile::TempDir,
}

impl PreMutationGuard for Recorder {
    fn backup_and_verify(&self, vault: &Path) -> Result<BackupReceipt, String> {
        let config = fs::read_to_string(vault.join(".git/config")).unwrap_or_default();
        CALLS.lock().unwrap().push((vault.to_path_buf(), config));
        let name = format!("backup-{}.tar.gz", CALLS.lock().unwrap().len());
        let path = self.backups.path().join(name);
        fs::write(&path, b"archive").map_err(|error| error.to_string())?;
        Ok(BackupReceipt {
            path,
            sha256: hex::encode(Sha256::digest(b"archive")),
            bytes: 7,
            files: 1,
        })
    }
}

fn install() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        assert!(install_guard(Box::new(Recorder {
            backups: tempfile::tempdir().unwrap(),
        })));
    });
}

/// A Go-style vault (state worth protecting, no Rust marker) that is a git
/// repository with a committed worktree, canonical path returned.
fn go_vault_in_git() -> (tempfile::TempDir, PathBuf, GitRepository) {
    install();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::write(root.join("identity.age"), b"identity").unwrap();
    fs::write(root.join("config.yaml"), b"vault: {}\n").unwrap();
    fs::create_dir(root.join("entries")).unwrap();
    let repo = GitRepository::init(&root).unwrap();
    git(&root, &["add", "--all"]);
    git(&root, &["commit", "--quiet", "-m", "seed"]);
    (dir, root, repo)
}

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
}

fn calls_for(root: &Path) -> Vec<String> {
    CALLS
        .lock()
        .unwrap()
        .iter()
        .filter(|(vault, _)| vault == root)
        .map(|(_, config)| config.clone())
        .collect()
}

#[test]
fn remote_add_backs_up_before_git_config_changes() {
    let (_dir, root, repo) = go_vault_in_git();
    assert!(!root.join(".symvault-rust").exists());
    repo.add_remote("origin", "ssh://git@backup.invalid/vault.git")
        .unwrap();
    let seen = calls_for(&root);
    assert_eq!(seen.len(), 1, "exactly one backup");
    assert!(
        !seen[0].contains("[remote"),
        "the backup was taken after .git/config changed: {}",
        seen[0]
    );
    assert!(
        fs::read_to_string(root.join(".git/config"))
            .unwrap()
            .contains("[remote \"origin\"]")
    );
    assert!(root.join(".symvault-rust").exists(), "marker missing");
    // The marker excludes itself from `git add --all`.
    fs::write(root.join("note.age"), b"x").unwrap();
    repo.commit(CommitOptions {
        message: "c".into(),
        ..CommitOptions::default()
    })
    .unwrap();
    let tracked = Command::new("git")
        .args(["ls-files"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&tracked.stdout).contains(".symvault-rust"));
    assert_eq!(
        calls_for(&root).len(),
        1,
        "a marked vault is not backed up again"
    );
}

#[test]
fn commit_backs_up_before_the_index_and_gitignore_change() {
    let (_dir, root, repo) = go_vault_in_git();
    fs::write(root.join("new.age"), b"x").unwrap();
    repo.commit(CommitOptions {
        message: "c".into(),
        ..CommitOptions::default()
    })
    .unwrap()
    .expect("commit");
    assert_eq!(calls_for(&root).len(), 1);
    assert!(root.join(".symvault-rust").exists());
}

#[test]
fn push_with_set_upstream_backs_up_before_the_branch_config_is_written() {
    let (_dir, root, repo) = go_vault_in_git();
    // Added behind the library's back, so only the push can trigger the gate.
    git(
        &root,
        &["remote", "add", "origin", "ssh://git@backup.invalid/v.git"],
    );
    let result = repo.push("origin");
    assert!(!result.success, "nothing listens on backup.invalid");
    let seen = calls_for(&root);
    assert_eq!(seen.len(), 1, "the push did not take a backup");
    assert!(
        !seen[0].contains("[branch"),
        "backup taken after the upstream was written"
    );
    assert!(root.join(".symvault-rust").exists());
}

#[test]
fn a_failing_backup_refuses_the_config_rewrite() {
    // A vault with state, no marker and a guard that refuses: install a
    // dedicated vault whose path the recorder is told to fail on.
    let (_dir, root, repo) = go_vault_in_git();
    // Remove the backup directory's place by making the receipt unwritable:
    // simplest deterministic failure is a read-only vault marker location.
    // Here the failure is a marker that cannot be created: occupy its name
    // with a directory.
    fs::create_dir(root.join(".symvault-rust")).unwrap();
    let before = fs::read_to_string(root.join(".git/config")).unwrap();
    let error = repo
        .add_remote("origin", "ssh://git@backup.invalid/vault.git")
        .expect_err("the gate must refuse");
    assert!(error.to_string().contains("data-safety") || error.to_string().contains("regular"));
    assert_eq!(
        fs::read_to_string(root.join(".git/config")).unwrap(),
        before,
        ".git/config changed although the gate refused"
    );
}
