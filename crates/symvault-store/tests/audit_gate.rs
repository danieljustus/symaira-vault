//! D1 gate on the audit helpers' destructive steps: the legacy
//! `audit-hmac-key` unlink and the log rotation by rename must be preceded by
//! the verified backup of an unmarked vault. Appends stay ungated.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::SystemTime,
};

use sha2::{Digest, Sha256};
use symvault_core::session::MemoryKeyring;
use symvault_store::{
    audit::{AuditKey, LogEntry, Logger, RotationConfig, load_or_create_key_with_keyring},
    data_safety::{BackupReceipt, PreMutationGuard, install_guard},
};

/// Vaults the guard saw, with whether the legacy key / the live log existed.
static CALLS: Mutex<Vec<(PathBuf, bool, bool)>> = Mutex::new(Vec::new());

struct Recorder {
    backups: tempfile::TempDir,
}

impl PreMutationGuard for Recorder {
    fn backup_and_verify(&self, vault: &Path) -> Result<BackupReceipt, String> {
        if vault
            .file_name()
            .is_some_and(|name| name.to_string_lossy().contains("refuse"))
        {
            return Err("backup refused by the test".to_owned());
        }
        CALLS.lock().unwrap().push((
            vault.to_path_buf(),
            vault.join("audit-hmac-key").exists(),
            vault.join("audit-symvault.log").exists(),
        ));
        let path = self
            .backups
            .path()
            .join(format!("b{}.tar.gz", CALLS.lock().unwrap().len()));
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

/// A Go-style vault (identity, config, legacy audit key, no Rust marker).
fn vault(name: &str) -> (tempfile::TempDir, PathBuf) {
    install();
    let dir = tempfile::Builder::new().prefix(name).tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::write(root.join("identity.age"), b"identity").unwrap();
    fs::write(root.join("config.yaml"), b"vault: {}\n").unwrap();
    fs::write(root.join("audit-hmac-key"), [7_u8; 32]).unwrap();
    (dir, root)
}

fn calls_for(root: &Path) -> Vec<(bool, bool)> {
    CALLS
        .lock()
        .unwrap()
        .iter()
        .filter(|(vault, _, _)| vault == root)
        .map(|(_, key, log)| (*key, *log))
        .collect()
}

#[test]
fn migrating_the_legacy_key_file_backs_up_before_the_unlink() {
    let (_dir, root) = vault("audit-gate-");
    let keyring = MemoryKeyring::new();
    load_or_create_key_with_keyring(&root, &keyring).unwrap();
    assert!(!root.join("audit-hmac-key").exists(), "legacy key kept");
    assert_eq!(
        calls_for(&root),
        vec![(true, false)],
        "the backup must see the legacy key file"
    );
    assert!(root.join(".symvault-rust").exists());
}

#[test]
fn a_refused_backup_keeps_the_legacy_key_file() {
    let (_dir, root) = vault("audit-gate-refuse-");
    let keyring = MemoryKeyring::new();
    // The key still reaches the keyring; the cleanup is what is withheld.
    load_or_create_key_with_keyring(&root, &keyring).unwrap();
    assert!(root.join("audit-hmac-key").exists());
    assert!(!root.join(".symvault-rust").exists());
}

fn logger(root: &Path) -> Logger {
    Logger::open(
        root.join("audit-symvault.log"),
        AuditKey::new([9_u8; 32]).unwrap(),
        RotationConfig::default(),
    )
    .unwrap()
}

fn entry() -> LogEntry {
    LogEntry {
        timestamp: "2026-11-02T00:00:00Z".to_owned(),
        agent: "cli".to_owned(),
        action: "get".to_owned(),
        ..LogEntry::default()
    }
}

#[test]
fn rotating_the_log_backs_up_before_the_rename() {
    let (_dir, root) = vault("audit-gate-");
    let mut log = logger(&root);
    log.append(entry()).unwrap();
    assert!(calls_for(&root).is_empty(), "an append must not be gated");
    log.rotate_at(SystemTime::now()).unwrap();
    assert_eq!(
        calls_for(&root),
        vec![(true, true)],
        "the backup must see the log before it is renamed"
    );
    let rotated = fs::read_dir(&root)
        .unwrap()
        .flatten()
        .filter(|item| item.file_name().to_string_lossy().contains(".rotated."))
        .count();
    assert_eq!(rotated, 1);
}

#[test]
fn a_refused_backup_leaves_the_log_in_place_and_writable() {
    let (_dir, root) = vault("audit-gate-refuse-");
    let mut log = logger(&root);
    log.append(entry()).unwrap();
    assert!(log.rotate_at(SystemTime::now()).is_err());
    assert!(root.join("audit-symvault.log").exists());
    assert!(
        !fs::read_dir(&root)
            .unwrap()
            .flatten()
            .any(|item| item.file_name().to_string_lossy().contains(".rotated."))
    );
    log.append(entry())
        .expect("the log handle survives the refusal");
}
