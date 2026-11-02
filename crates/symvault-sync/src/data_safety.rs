//! The backup half of the Rust-cutover data-safety gate (D1, RUST-014).
//!
//! `symvault-store` decides *when* (first mutation of a vault without a Rust
//! marker, write lock held) and writes the marker; this module does the work
//! that needs the archive code: write a Go-faithful backup, restore it into a
//! scratch directory with [`crate::archive::restore`] and prove the restored
//! tree equals the live tree before the caller may write anything.
//!
//! Backups live outside the vault, in `$XDG_STATE_HOME/symvault/backups`
//! (default `~/.local/state/symvault/backups`). Go has no default backup
//! directory (the `backup` command takes an explicit archive path), and the
//! other directories the Rust CLI resolves are unusable: with a legacy
//! install the data directory *is* the vault (`~/.symvault`), so a backup
//! there would be archived into itself and, being inside a git-synced vault,
//! would be pushed to the remote. The state directory is per-user, local and
//! never synced. It is created `0700`, archives `0600`.

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use symvault_store::data_safety::{BackupReceipt, PreMutationGuard, install_guard};
use time::OffsetDateTime;

use crate::{archive, backup_writer};

/// Installs the production guard (idempotent). Every binary that can mutate a
/// vault calls this before opening one; without it the store refuses to touch
/// a vault that has no Rust marker.
pub fn install() {
    let _ = install_guard(Box::new(BackupGuard));
    // Vault `config.yaml` rewrites go through `Config::save_to`, which lives in
    // a crate below the store: route them through the same gate.
    let _ = symvault_core::config::set_pre_save_hook(|path| {
        symvault_store::data_safety::ensure_marker_for_path(path).map_err(|error| error.to_string())
    });
}

/// The production guard: default backup directory, full verification.
pub struct BackupGuard;

impl PreMutationGuard for BackupGuard {
    fn backup_and_verify(&self, vault: &Path) -> Result<BackupReceipt, String> {
        create_verified_backup(vault, &backup_dir()?)
    }
}

/// `$XDG_STATE_HOME/symvault/backups`, else `$HOME/.local/state/symvault/backups`
/// (`USERPROFILE` where `HOME` is unset).
///
/// # Errors
/// No usable base directory.
pub fn backup_dir() -> Result<PathBuf, String> {
    let env = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
    let base = if let Some(state) = env("XDG_STATE_HOME") {
        PathBuf::from(state)
    } else if let Some(home) = env("HOME").or_else(|| env("USERPROFILE")) {
        PathBuf::from(home).join(".local").join("state")
    } else {
        return Err("cannot determine the backup directory: set HOME or XDG_STATE_HOME".to_owned());
    };
    Ok(base.join("symvault").join("backups"))
}

/// Backup, restore into scratch, compare. On any failure the archive is
/// removed again and an error describes the first problem.
///
/// # Errors
/// A human-readable reason.
pub fn create_verified_backup(vault: &Path, dir: &Path) -> Result<BackupReceipt, String> {
    let archive_path = write_backup(vault, dir)?;
    match verify_backup(vault, &archive_path, dir) {
        Ok(files) => receipt(&archive_path, files),
        Err(reason) => {
            let _ = fs::remove_file(&archive_path);
            Err(format!(
                "verification of {}: {reason}",
                archive_path.display()
            ))
        }
    }
}

/// Writes the Go-faithful full backup (`.git` included, like `backup` without
/// `--exclude-git`) to a fresh name inside `dir`.
///
/// # Errors
/// A human-readable reason; a partial archive is removed.
pub fn write_backup(vault: &Path, dir: &Path) -> Result<PathBuf, String> {
    let vault_real = vault
        .canonicalize()
        .map_err(|error| format!("resolve vault {}: {error}", vault.display()))?;
    backup_writer::go_mkdir_all_private(dir)
        .map_err(|reason| format!("create backup directory {}: {reason}", dir.display()))?;
    let dir_real = dir
        .canonicalize()
        .map_err(|error| format!("resolve backup directory {}: {error}", dir.display()))?;
    if dir_real.starts_with(&vault_real) {
        return Err(format!(
            "the backup directory {} is inside the vault; set XDG_STATE_HOME elsewhere",
            dir_real.display()
        ));
    }
    let stamp = timestamp();
    let label = label(&vault_real);
    let mut candidate = dir_real.join(format!("pre-rust-{label}-{stamp}.tar.gz"));
    let mut counter = 1_u32;
    while fs::symlink_metadata(&candidate).is_ok() {
        candidate = dir_real.join(format!("pre-rust-{label}-{stamp}-{counter}.tar.gz"));
        counter += 1;
    }
    match backup_writer::create_backup(&vault_real, &candidate, false) {
        Ok(()) => Ok(candidate),
        Err(reason) => {
            let _ = fs::remove_file(&candidate);
            Err(format!("write backup: {reason}"))
        }
    }
}

/// Restores `archive_path` into a scratch directory below `scratch_parent` with
/// the production [`archive::restore`] and compares the result with the live
/// `vault`. Returns the number of regular files compared.
///
/// # Errors
/// The restore error or the first difference.
pub fn verify_backup(
    vault: &Path,
    archive_path: &Path,
    scratch_parent: &Path,
) -> Result<u64, String> {
    let scratch = tempfile::Builder::new()
        .prefix(".verify-")
        .tempdir_in(scratch_parent)
        .map_err(|error| format!("create scratch directory: {error}"))?;
    let restored = scratch.path().join("vault");
    archive::restore(archive_path, &restored, true).map_err(|error| format!("restore: {error}"))?;
    let live = snapshot(vault)?;
    let back = snapshot(&restored)?;
    compare(&live, &back)?;
    Ok(live.values().filter(|node| node.digest.is_some()).count() as u64)
}

fn receipt(archive_path: &Path, files: u64) -> Result<BackupReceipt, String> {
    let mut file = fs::File::open(archive_path)
        .map_err(|error| format!("read back {}: {error}", archive_path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut bytes = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("read back {}: {error}", archive_path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        bytes += count as u64;
    }
    Ok(BackupReceipt {
        path: archive_path.to_path_buf(),
        sha256: hex::encode(hasher.finalize()),
        bytes,
        files,
    })
}

fn timestamp() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// `<basename>-<8 hex of sha256(canonical path)>`, characters limited to
/// `[A-Za-z0-9._-]`.
fn label(vault: &Path) -> String {
    let name: String = vault
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    let digest = Sha256::digest(vault.as_os_str().as_encoded_bytes());
    let name = if name.is_empty() {
        "vault".to_owned()
    } else {
        name
    };
    format!("{name}-{}", hex::encode(&digest[..4]))
}

struct Node {
    /// `None` for directories.
    digest: Option<String>,
    size: u64,
    mode: u32,
}

/// Every non-symlink node below `root` (the backup writer skips symlinks and
/// does not follow them).
fn snapshot(root: &Path) -> Result<BTreeMap<String, Node>, String> {
    let mut nodes = BTreeMap::new();
    walk(root, root, &mut nodes)?;
    Ok(nodes)
}

fn walk(root: &Path, dir: &Path, nodes: &mut BTreeMap<String, Node>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|error| format!("read {}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read {}: {error}", dir.display()))?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|error| format!("stat {}: {error}", path.display()))?;
        if meta.file_type().is_symlink() {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        if meta.is_dir() {
            nodes.insert(
                relative,
                Node {
                    digest: None,
                    size: 0,
                    mode: mode_bits(&meta),
                },
            );
            walk(root, &path, nodes)?;
        } else if meta.is_file() {
            let mut file = fs::File::open(&path)
                .map_err(|error| format!("open {}: {error}", path.display()))?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                let count = file
                    .read(&mut buffer)
                    .map_err(|error| format!("read {}: {error}", path.display()))?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            nodes.insert(
                relative,
                Node {
                    digest: Some(hex::encode(hasher.finalize())),
                    size: meta.len(),
                    mode: mode_bits(&meta),
                },
            );
        } else {
            return Err(format!("unsupported file type: {}", path.display()));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn mode_bits(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_bits(_: &fs::Metadata) -> u32 {
    0
}

fn compare(live: &BTreeMap<String, Node>, restored: &BTreeMap<String, Node>) -> Result<(), String> {
    for (path, node) in live {
        let Some(other) = restored.get(path) else {
            return Err(format!("{path} is missing from the restored copy"));
        };
        if node.digest != other.digest || node.size != other.size {
            return Err(format!("{path} differs in the restored copy"));
        }
        // Go's restore keeps only the owner read/write bits of a file
        // (`header.Mode & 0o600`) and recreates directories 0700, so file modes
        // are compared through that mask and directory modes not at all.
        if node.digest.is_some() && (node.mode & 0o600) != other.mode {
            return Err(format!(
                "{path} has mode {:o} but the restored copy has {:o} (expected {:o})",
                node.mode,
                other.mode,
                node.mode & 0o600
            ));
        }
    }
    if let Some(path) = restored.keys().find(|path| !live.contains_key(*path)) {
        return Err(format!("{path} exists only in the restored copy"));
    }
    Ok(())
}
