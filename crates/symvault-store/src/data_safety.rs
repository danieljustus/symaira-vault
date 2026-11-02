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
    cell::Cell,
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

thread_local! {
    /// Set while the guard runs on this thread: the backup and its scratch
    /// restore write files of their own and must not re-enter the gate.
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
}

/// The store crate's own unit tests build hundreds of throw-away vaults with
/// the store API and no marker; they run with the gate off unless a test turns
/// it on with [`enforce_in_unit_test`]. Integration tests and every other
/// crate see the real gate.
#[cfg(test)]
thread_local! {
    static ENFORCE: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn enforce_in_unit_test() {
    ENFORCE.with(|flag| flag.set(true));
}

fn bypassed() -> bool {
    #[cfg(test)]
    {
        !ENFORCE.with(Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

struct Active;

impl Active {
    fn enter() -> Self {
        ACTIVE.with(|flag| flag.set(true));
        Self
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        ACTIVE.with(|flag| flag.set(false));
    }
}

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
    // A marker that arrived through git sync from another device describes
    // that device's backup. The marker is kept out of git (see
    // `exclude_marker_from_git`), and a backup this machine does not have never
    // counts as one.
    Ok(marker_bytes_valid(&bytes))
}

/// A parseable marker of a known schema whose backup (if any) still exists.
pub(crate) fn marker_bytes_valid(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Marker>(bytes).is_ok_and(|marker| {
        marker.schema >= 1
            && marker
                .backup
                .as_ref()
                .is_none_or(|backup| fs::symlink_metadata(&backup.path).is_ok())
    })
}

/// Looks for the marker through the retained root capability, so a directory
/// swapped in under the path can neither satisfy nor receive the gate. Without
/// a marker the capability must still be the directory the path names, else
/// the root changed under us and the mutation is refused.
pub(crate) fn marker_via_capability(root_cap: &fs::File, root: &Path) -> Result<bool, StoreError> {
    #[cfg(unix)]
    {
        let name = Path::new(MARKER_FILE);
        if let Ok(bytes) = crate::rooted::read(root_cap, name, &root.join(name))
            && marker_bytes_valid(&bytes)
        {
            return Ok(true);
        }
        if crate::root_identity_from_file(root_cap)? != crate::root_identity(root)? {
            return Err(StoreError::RootChanged(root.to_path_buf()));
        }
        Ok(false)
    }
    #[cfg(not(unix))]
    {
        let _ = root_cap;
        marker_present(root)
    }
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
        exclude_marker_from_git(root);
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

/// Keeps the marker out of `git add --all`: it is per machine, and a marker
/// pushed to a peer would make that peer skip its own backup. Uses the
/// repository-local `.git/info/exclude`, so no tracked file (and no Go-created
/// `.gitignore`) is modified. Best effort: a vault without a `.git` directory
/// has nothing to exclude from, and `git init` calls this again.
pub fn exclude_marker_from_git(root: &Path) {
    let info = root.join(".git").join("info");
    if !root.join(".git").is_dir() || fs::create_dir_all(&info).is_err() {
        return;
    }
    let exclude = info.join("exclude");
    let line = format!("/{MARKER_FILE}");
    let existing = fs::read_to_string(&exclude).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == line) {
        return;
    }
    let mut text = existing;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&line);
    text.push('\n');
    let _ = fs::write(&exclude, text);
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
pub(crate) fn ensure_locked(root_cap: &fs::File, root: &Path) -> Result<(), StoreError> {
    if bypassed() || ACTIVE.with(Cell::get) || marker_via_capability(root_cap, root)? {
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
    let _active = Active::enter();
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
    if bypassed() || ACTIVE.with(Cell::get) {
        return Ok(());
    }
    let root = match root.canonicalize() {
        Ok(root) => root,
        // No directory, no vault: nothing to protect.
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(StoreError::Read {
                path: root.to_path_buf(),
                source,
            });
        }
    };
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

/// Test fixtures build vaults with the store API and never ran `init`; they
/// are Rust-created by construction. Marks `root` (errors, such as a missing
/// directory, are ignored so negative tests keep their original failure) and
/// returns it for use inside an expression.
#[doc(hidden)]
pub fn test_support_pre_marked<P: AsRef<Path>>(root: P) -> P {
    let _ = mark_created(root.as_ref());
    root
}

/// How far above a written path a vault root is looked for.
const VAULT_SEARCH_DEPTH: usize = 6;

/// Runs the gate for the vault that contains `path`, found as the nearest
/// ancestor (at most six levels up) holding an `identity.age`. A path outside
/// any vault, or a vault that is still being created, needs nothing. This is
/// the choke point for the helpers that write vault files by path
/// (`symvault_sync::safeio`): recipients, device and pairing files, policies,
/// approval queues, identity rewrites.
///
/// # Errors
/// [`StoreError::DataSafety`] when the backup or its verification fails.
pub fn ensure_marker_for_path(path: &Path) -> Result<(), StoreError> {
    if ACTIVE.with(Cell::get) {
        return Ok(());
    }
    for ancestor in path.ancestors().skip(1).take(VAULT_SEARCH_DEPTH) {
        if fs::symlink_metadata(ancestor.join(IDENTITY_FILE)).is_ok() {
            return ensure_marker(ancestor);
        }
    }
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

    thread_local! {
        static MODE: Cell<u8> = const { Cell::new(0) };
        static CALLS: Cell<u32> = const { Cell::new(0) };
    }

    struct Fake;

    impl PreMutationGuard for Fake {
        fn backup_and_verify(&self, vault: &Path) -> Result<BackupReceipt, String> {
            CALLS.with(|c| c.set(c.get() + 1));
            if MODE.with(Cell::get) == 1 {
                return Err("disk full".to_owned());
            }
            let path = vault.join("fake-backup.tar.gz");
            fs::write(&path, b"x").unwrap();
            Ok(BackupReceipt {
                path,
                sha256: "00".into(),
                bytes: 1,
                files: 1,
            })
        }
    }

    fn enforced_vault() -> tempfile::TempDir {
        enforce_in_unit_test();
        install_guard(Box::new(Fake));
        CALLS.with(|c| c.set(0));
        MODE.with(|m| m.set(0));
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("identity.age"), b"x").unwrap();
        dir
    }

    #[test]
    fn first_mutation_backs_up_then_marks_and_later_ones_skip_the_guard() {
        let dir = enforced_vault();
        let root = dir.path().canonicalize().unwrap();
        ensure_marker(&root).expect("gate");
        assert_eq!(CALLS.with(Cell::get), 1);
        let marker: Marker =
            serde_json::from_slice(&fs::read(root.join(MARKER_FILE)).unwrap()).unwrap();
        assert_eq!(marker.kind, "go-vault-backup");
        assert_eq!(marker.backup.unwrap().path, root.join("fake-backup.tar.gz"));
        ensure_marker(&root).expect("marked");
        assert_eq!(CALLS.with(Cell::get), 1);
    }

    #[test]
    fn a_failed_backup_refuses_and_writes_no_marker() {
        let dir = enforced_vault();
        MODE.with(|m| m.set(1));
        let error = ensure_marker(dir.path()).expect_err("must refuse");
        assert!(matches!(error, StoreError::DataSafety(ref m) if m.contains("disk full")));
        assert!(!dir.path().join(MARKER_FILE).exists());
    }

    #[test]
    fn a_marker_whose_backup_is_gone_does_not_count() {
        let dir = enforced_vault();
        let root = dir.path().canonicalize().unwrap();
        ensure_marker(&root).expect("gate");
        fs::remove_file(root.join("fake-backup.tar.gz")).unwrap();
        ensure_marker(&root).expect("gate again");
        assert_eq!(CALLS.with(Cell::get), 2);
    }

    #[test]
    fn path_gate_finds_the_enclosing_vault_and_ignores_other_paths() {
        let dir = enforced_vault();
        fs::create_dir(dir.path().join("sub")).unwrap();
        ensure_marker_for_path(&dir.path().join("sub/file")).expect("gate");
        assert_eq!(CALLS.with(Cell::get), 1);
        let other = tempfile::tempdir().unwrap();
        ensure_marker_for_path(&other.path().join("x")).expect("no vault");
        assert_eq!(CALLS.with(Cell::get), 1);
    }

    #[test]
    fn marker_is_excluded_from_git() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        mark_created(dir.path()).unwrap();
        mark_created(dir.path()).unwrap();
        let text = fs::read_to_string(dir.path().join(".git/info/exclude")).unwrap();
        assert_eq!(text.matches("/.symvault-rust").count(), 1);
    }

    #[test]
    fn empty_directory_needs_no_backup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cap = fs::File::open(dir.path()).unwrap();
        ensure_locked(&cap, dir.path()).expect("nothing to protect");
        assert!(!dir.path().join(MARKER_FILE).exists());
    }
}
