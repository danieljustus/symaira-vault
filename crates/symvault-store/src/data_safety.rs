//! The Rust-cutover data-safety gate (maintainer decision D1, RUST-014).
//!
//! The first time Rust is about to *mutate* a vault that carries no Rust
//! marker, a verified backup is taken first and only then is the marker
//! written. Reads never reach this module. The gate runs inside
//! `open_root_write_lock`, i.e. with the vault's cross-process write lock held
//! for the whole sequence (backup, restore check, marker), which makes every
//! store write (entries, manifest, grants, tokens, journal recovery) and every
//! caller that takes the lock (`Store::with_write_lock`) pass through it. Writers
//! that bypass the lock (the zero-key heal, `init`) call [`ensure_marker`] or
//! [`mark_created`] explicitly.
//!
//! The backup itself (archive writer, restore into a temporary directory and
//! comparison with the live tree) lives in `symvault-sync`, which depends on
//! this crate; it plugs in through [`PreMutationGuard`]. A binary that links the
//! store but has not installed a guard refuses to touch an unmarked vault:
//! failing closed is the only safe default.
//!
//! The marker is `.symvault-rust` in the vault root: a small JSON document
//! written atomically (temporary file, fsync, rename, directory fsync) and only
//! after the backup has been verified. A vault that Rust creates itself gets
//! the marker without a backup because there is nothing to lose.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    CONFIG_FILE, ENTRIES_DIR, IDENTITY_FILE, MANIFEST_FILE, RECIPIENTS_FILE, StoreError,
    open_root_write_lock,
};

/// The marker file in the vault root.
pub const MARKER_FILE: &str = ".symvault-rust";
const MARKER_SCHEMA: u32 = 1;
/// A marker is a few hundred bytes; anything larger is not ours.
const MAX_MARKER_BYTES: u64 = 64 * 1024;

/// What a verified pre-mutation backup looks like.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupReceipt {
    /// Absolute path of the `.tar.gz` archive.
    pub path: PathBuf,
    /// Lowercase hex SHA-256 of the archive file.
    pub sha256: String,
    /// Archive size in bytes.
    pub bytes: u64,
    /// Regular files compared between the restored copy and the live vault.
    pub files: u64,
}

/// Takes a backup of `vault`, restores it into a scratch directory, proves the
/// restored tree equals the live tree and removes the scratch directory.
///
/// Implementations run with the vault write lock held by the caller. An `Err`
/// must leave no usable partial archive behind; the vault is never modified.
pub trait PreMutationGuard: Send + Sync {
    /// # Errors
    /// A human-readable reason; the mutation is refused.
    fn backup_and_verify(&self, vault: &Path) -> Result<BackupReceipt, String>;
}

static GUARD: OnceLock<Box<dyn PreMutationGuard>> = OnceLock::new();

/// Installs the process-wide guard. Returns `false` when one is already
/// installed (the first one stays).
pub fn install_guard(guard: Box<dyn PreMutationGuard>) -> bool {
    GUARD.set(guard).is_ok()
}

/// Whether a guard is installed in this process.
#[must_use]
pub fn guard_installed() -> bool {
    GUARD.get().is_some()
}

#[derive(Debug, Serialize, Deserialize)]
struct Marker {
    schema: u32,
    /// `go-vault-backup` (existing state backed up first) or `rust-created`.
    kind: String,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup: Option<BackupReceipt>,
}

fn refuse(detail: impl Into<String>) -> StoreError {
    StoreError::DataSafety(detail.into())
}

/// The vault holds state worth protecting: any of the files a Go vault has.
fn has_vault_state(root: &Path) -> bool {
    [
        IDENTITY_FILE,
        CONFIG_FILE,
        ENTRIES_DIR,
        MANIFEST_FILE,
        RECIPIENTS_FILE,
    ]
    .iter()
    .any(|name| fs::symlink_metadata(root.join(name)).is_ok())
}

/// A valid marker is a regular file holding a document of a known schema.
fn marker_present(root: &Path) -> Result<bool, StoreError> {
    let path = root.join(MARKER_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(StoreError::Read { path, source }),
    };
    if !metadata.file_type().is_file() {
        return Err(StoreError::NotRegularFile(path));
    }
    if metadata.len() > MAX_MARKER_BYTES {
        return Ok(false);
    }
    let bytes = fs::read(&path).map_err(|source| StoreError::Read {
        path: path.clone(),
        source,
    })?;
    Ok(serde_json::from_slice::<Marker>(&bytes).is_ok_and(|marker| marker.schema >= 1))
}

fn write_marker(root: &Path, marker: &Marker) -> Result<(), StoreError> {
    use std::hash::{BuildHasher, Hasher};
    let mut bytes = serde_json::to_vec_pretty(marker)
        .map_err(|error| refuse(format!("encode marker: {error}")))?;
    bytes.push(b'\n');
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let temporary = root.join(format!(
        "{MARKER_FILE}.tmp-{}-{random:016x}",
        std::process::id()
    ));
    let target = root.join(MARKER_FILE);
    let write = |error: io::Error, path: &Path| StoreError::Write {
        path: path.to_path_buf(),
        source: error,
    };
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<(), StoreError> {
        let mut file = options.open(&temporary).map_err(|e| write(e, &temporary))?;
        file.write_all(&bytes).map_err(|e| write(e, &temporary))?;
        file.sync_all().map_err(|e| write(e, &temporary))?;
        drop(file);
        fs::rename(&temporary, &target).map_err(|e| write(e, &target))?;
        #[cfg(unix)]
        if let Ok(dir) = fs::File::open(root) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

/// The gate itself. The caller holds the vault write lock.
///
/// * marker present: nothing to do;
/// * no vault state at all (a directory that is not a vault): nothing to
///   protect and nothing to mark (the vault creator calls [`mark_created`]);
/// * otherwise: backup, restore check, then the marker; any failure refuses the
///   mutation and writes no marker.
pub(crate) fn ensure_locked(root: &Path) -> Result<(), StoreError> {
    if marker_present(root)? {
        return Ok(());
    }
    if !has_vault_state(root) {
        return Ok(());
    }
    let Some(guard) = GUARD.get() else {
        return Err(refuse(
            "this vault has not been opened by the Rust build yet and the pre-migration \
             backup guard is not installed in this binary; refusing to modify it",
        ));
    };
    let receipt = guard.backup_and_verify(root).map_err(|reason| {
        refuse(format!(
            "pre-migration backup failed, the vault was not modified: {reason}"
        ))
    })?;
    write_marker(
        root,
        &Marker {
            schema: MARKER_SCHEMA,
            kind: "go-vault-backup".to_owned(),
            created_at: now(),
            backup: Some(receipt),
        },
    )
}

/// Runs the gate for a vault the caller is about to write without going
/// through the store's own lock (zero-key heal, FFI re-initialisation).
///
/// # Errors
/// [`StoreError::DataSafety`] when the backup or its verification fails.
pub fn ensure_marker(root: &Path) -> Result<(), StoreError> {
    let root = root.canonicalize().map_err(|source| StoreError::Read {
        path: root.to_path_buf(),
        source,
    })?;
    if marker_present(&root)? || !has_vault_state(&root) {
        return Ok(());
    }
    let cap = fs::File::open(&root).map_err(|source| StoreError::Read {
        path: root.clone(),
        source,
    })?;
    // Taking the lock runs the gate (open_root_write_lock calls `ensure_locked`).
    let lock = open_root_write_lock(&cap, &root)?;
    let _ = lock.unlock();
    Ok(())
}

/// Marks a vault Rust has just created: there is no earlier state to back up.
///
/// # Errors
/// Filesystem failures while writing the marker.
pub fn mark_created(root: &Path) -> Result<(), StoreError> {
    if marker_present(root)? {
        return Ok(());
    }
    write_marker(
        root,
        &Marker {
            schema: MARKER_SCHEMA,
            kind: "rust-created".to_owned(),
            created_at: now(),
            backup: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_roundtrip_and_validation() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!marker_present(dir.path()).expect("absent"));
        mark_created(dir.path()).expect("mark");
        assert!(marker_present(dir.path()).expect("present"));
        fs::write(dir.path().join(MARKER_FILE), b"not json").expect("corrupt");
        assert!(!marker_present(dir.path()).expect("corrupt is absent"));
        fs::remove_file(dir.path().join(MARKER_FILE)).expect("rm");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hosts", dir.path().join(MARKER_FILE)).expect("link");
            assert!(matches!(
                marker_present(dir.path()),
                Err(StoreError::NotRegularFile(_))
            ));
        }
    }

    #[test]
    fn empty_directory_needs_no_backup() {
        let dir = tempfile::tempdir().expect("tempdir");
        ensure_locked(dir.path()).expect("nothing to protect");
        assert!(!dir.path().join(MARKER_FILE).exists());
    }
}
