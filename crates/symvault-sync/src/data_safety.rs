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
//!
//! The directory is the *default*: a host that has no `$XDG_STATE_HOME`/`$HOME`
//! to offer (an iOS app through the FFI) passes an explicit directory with
//! [`set_backup_dir`]. Excluding that directory from cloud backup (iCloud) is
//! the host's responsibility: the archive holds the same encrypted vault files
//! as the vault itself.
//!
//! Durability and crash safety: the archive is written as
//! `pre-rust-<label>-<stamp>.tar.gz.<pid>.partial`, flushed to disk, verified
//! and only then renamed to its final name; the backup directory is flushed
//! before the receipt (and with it the marker) is produced. A process killed
//! halfway (SIGXFSZ, power loss) leaves a `.partial` file or a `.verify-<pid>-*`
//! scratch directory, never a final-named archive that is incomplete; the next
//! gate sweeps stale leftovers of dead processes.

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Mutex,
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

static EXPLICIT_BACKUP_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Sets the backup directory for this process, taking precedence over
/// `$XDG_STATE_HOME`/`$HOME`. For hosts without a usable home directory (the
/// iOS app through the FFI). The directory is created `0700` on first use;
/// keeping it out of cloud backup is the host's responsibility. `None` goes
/// back to the environment-derived default.
pub fn set_backup_dir(dir: Option<PathBuf>) {
    if let Ok(mut slot) = EXPLICIT_BACKUP_DIR.lock() {
        *slot = dir;
    }
}

/// The directory set by [`set_backup_dir`], else
/// `$XDG_STATE_HOME/symvault/backups`, else `$HOME/.local/state/symvault/backups`
/// (`USERPROFILE` where `HOME` is unset).
///
/// # Errors
/// No usable base directory.
pub fn backup_dir() -> Result<PathBuf, String> {
    let explicit = EXPLICIT_BACKUP_DIR
        .lock()
        .ok()
        .and_then(|slot| slot.clone());
    resolve_backup_dir(explicit, |name| {
        std::env::var_os(name).filter(|value| !value.is_empty())
    })
}

fn resolve_backup_dir(
    explicit: Option<PathBuf>,
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<PathBuf, String> {
    if let Some(dir) = explicit {
        return Ok(dir);
    }
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
    // Leftovers of an earlier, killed run (never of a live one) go first.
    sweep_stale(dir);
    let partial = write_backup_partial(vault, dir)?;
    match verify_backup(vault, &partial, dir) {
        Ok(files) => {
            let archive_path = promote(&partial, dir)?;
            receipt(&archive_path, files)
        }
        Err(reason) => {
            let _ = fs::remove_file(&partial);
            Err(format!("verification of {}: {reason}", partial.display()))
        }
    }
}

/// Writes the Go-faithful full backup (`.git` included, like `backup` without
/// `--exclude-git`) to a fresh name inside `dir`, flushed to disk, and returns
/// its final path. Nothing carries the final name until the archive is
/// complete and durable.
///
/// # Errors
/// A human-readable reason; a partial archive is removed.
pub fn write_backup(vault: &Path, dir: &Path) -> Result<PathBuf, String> {
    let partial = write_backup_partial(vault, dir)?;
    promote(&partial, dir)
}

/// Writes the archive to `<final name>.<pid>.partial` and flushes it.
fn write_backup_partial(vault: &Path, dir: &Path) -> Result<PathBuf, String> {
    let vault_real = vault
        .canonicalize()
        .map_err(|error| format!("resolve vault {}: {error}", vault.display()))?;
    ensure_private_dir(dir)
        .map_err(|error| format!("create backup directory {}: {error}", dir.display()))?;
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
    let pid = std::process::id();
    let name = |counter: u32| {
        if counter == 0 {
            format!("pre-rust-{label}-{stamp}.tar.gz")
        } else {
            format!("pre-rust-{label}-{stamp}-{counter}.tar.gz")
        }
    };
    let mut counter = 0_u32;
    let partial = loop {
        let final_name = name(counter);
        let candidate = dir_real.join(&final_name);
        let partial = dir_real.join(format!("{final_name}.{pid}.partial"));
        if fs::symlink_metadata(&candidate).is_err() && fs::symlink_metadata(&partial).is_err() {
            break partial;
        }
        counter += 1;
    };
    let written = backup_writer::create_backup(&vault_real, &partial, false)
        .map_err(|reason| format!("write backup: {reason}"))
        .and_then(|()| sync_file(&partial));
    match written {
        Ok(()) => Ok(partial),
        Err(reason) => {
            let _ = fs::remove_file(&partial);
            Err(reason)
        }
    }
}

/// Flushes a file's data to stable storage through a fresh handle.
fn sync_file(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("flush {} to disk: {error}", path.display()))
}

/// Flushes a directory entry change (create, rename) to stable storage.
fn sync_dir(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        match fs::File::open(dir).and_then(|handle| handle.sync_all()) {
            Ok(()) => Ok(()),
            // A filesystem that cannot flush directories offers nothing better.
            Err(error) if error.kind() == std::io::ErrorKind::Unsupported => Ok(()),
            Err(error) => Err(format!("flush {} to disk: {error}", dir.display())),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// `<final>.<pid>.partial` -> `<final>`, then the backup directory is flushed
/// (and its parent, which may just have been created).
fn promote(partial: &Path, dir: &Path) -> Result<PathBuf, String> {
    let file_name = partial
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "backup name is not valid UTF-8".to_owned())?;
    let stem = file_name
        .strip_suffix(".partial")
        .and_then(|rest| rest.rsplit_once('.').map(|(stem, _pid)| stem))
        .ok_or_else(|| format!("unexpected partial backup name {file_name}"))?;
    let parent = partial.parent().unwrap_or(dir);
    let target = parent.join(stem);
    if let Err(error) = fs::rename(partial, &target) {
        let _ = fs::remove_file(partial);
        return Err(format!("publish backup {}: {error}", target.display()));
    }
    sync_dir(parent)?;
    if let Some(grandparent) = parent.parent() {
        let _ = sync_dir(grandparent);
    }
    Ok(target)
}

/// Removes `*.partial` archives and `.verify-*` scratch directories that a
/// killed process left in `dir`. Ones owned by a live process (a gate running
/// right now for another vault) stay; the owning pid is part of the name.
/// Best effort: a leftover that cannot be removed is not an error.
pub fn sweep_stale(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let owner = if let Some(rest) = name.strip_prefix(".verify-") {
            rest.split('-')
                .next()
                .and_then(|pid| pid.parse::<u32>().ok())
        } else if name.starts_with("pre-rust-")
            && let Some(rest) = name.strip_suffix(".partial")
        {
            rest.rsplit_once('.')
                .and_then(|(_, pid)| pid.parse::<u32>().ok())
        } else {
            continue;
        };
        if owner.is_some_and(process_alive) {
            continue;
        }
        let path = entry.path();
        let is_dir = fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir());
        let _ = if is_dir {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
    }
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    use rustix::process::{Pid, test_kill_process};
    let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
        return false;
    };
    match test_kill_process(pid) {
        Ok(()) => true,
        Err(error) => error != rustix::io::Errno::SRCH,
    }
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    // Without a cheap liveness probe, leave other processes' files alone.
    true
}

/// Creates `dir` and its missing parents `0700`. Unlike `mkdir(2)` with a mode
/// this is immune to a restrictive umask (`0277` would otherwise leave an
/// unwritable `0500` directory and make the gate refuse for no reason).
fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    let missing: Vec<&Path> = dir
        .ancestors()
        .take_while(|path| !path.as_os_str().is_empty() && fs::symlink_metadata(path).is_err())
        .collect();
    for path in missing.into_iter().rev() {
        match fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
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
        .prefix(&format!(".verify-{}-", std::process::id()))
        .tempdir_in(scratch_parent)
        .map_err(|error| format!("create scratch directory: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("prepare scratch directory: {error}"))?;
    }
    let restored = scratch.path().join("vault");
    // The production restore creates directories with the process umask; under
    // a restrictive one (0277) it could not write into its own directories.
    // Hold an owner-writable umask for the duration of the scratch restore.
    let restored_result = {
        let _umask = OwnerWritableUmask::enter();
        archive::restore(archive_path, &restored, true)
    };
    restored_result.map_err(|error| format!("restore: {error}"))?;
    let live = snapshot(vault)?;
    let back = snapshot(&restored)?;
    compare(&live, &back)?;
    Ok(live.values().filter(|node| node.digest.is_some()).count() as u64)
}

/// Clears the owner bits of the umask (and sets group/other) while alive.
struct OwnerWritableUmask(Option<rustix::fs::Mode>);

impl OwnerWritableUmask {
    fn enter() -> Self {
        #[cfg(unix)]
        {
            use rustix::fs::Mode;
            let old = rustix::process::umask(Mode::empty());
            let wanted = (old | Mode::from_raw_mode(0o077)) & !Mode::from_raw_mode(0o700);
            rustix::process::umask(wanted);
            Self(Some(old))
        }
        #[cfg(not(unix))]
        {
            Self(None)
        }
    }
}

impl Drop for OwnerWritableUmask {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(old) = self.0 {
            rustix::process::umask(old);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("vault");
        fs::write(dir.path().join("identity.age"), b"identity").unwrap();
        fs::write(dir.path().join("config.yaml"), b"vault: {}\n").unwrap();
        fs::create_dir(dir.path().join("entries")).unwrap();
        dir
    }

    /// A pid that belonged to a process that has exited.
    #[cfg(unix)]
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("true").spawn().expect("spawn");
        let pid = child.id();
        child.wait().expect("wait");
        pid
    }

    #[test]
    fn a_verified_backup_is_published_whole_and_leaves_no_scratch() {
        let vault = vault();
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("backups");
        let receipt = create_verified_backup(vault.path(), &backups).expect("backup");
        assert!(receipt.path.to_string_lossy().ends_with(".tar.gz"));
        assert_eq!(fs::metadata(&receipt.path).unwrap().len(), receipt.bytes);
        let names: Vec<String> = fs::read_dir(&backups)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 1, "unexpected leftovers: {names:?}");
    }

    #[cfg(unix)]
    #[test]
    fn stale_partial_archives_and_scratch_dirs_of_dead_processes_are_swept() {
        let vault = vault();
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("backups");
        fs::create_dir(&backups).unwrap();
        let dead = dead_pid();
        let live = std::process::id();
        let stale_partial = backups.join(format!("pre-rust-v-1.tar.gz.{dead}.partial"));
        let stale_scratch = backups.join(format!(".verify-{dead}-abc123"));
        let live_partial = backups.join(format!("pre-rust-v-2.tar.gz.{live}.partial"));
        let live_scratch = backups.join(format!(".verify-{live}-abc123"));
        let unrelated = backups.join("pre-rust-v-3.tar.gz");
        fs::write(&stale_partial, b"half an archive").unwrap();
        fs::create_dir(&stale_scratch).unwrap();
        fs::write(stale_scratch.join("vault"), b"half a restore").unwrap();
        fs::write(&live_partial, b"in progress").unwrap();
        fs::create_dir(&live_scratch).unwrap();
        fs::write(&unrelated, b"a finished backup").unwrap();

        create_verified_backup(vault.path(), &backups).expect("backup");

        assert!(!stale_partial.exists(), "stale .partial kept");
        assert!(!stale_scratch.exists(), "stale .verify-* kept");
        assert!(live_partial.exists(), "a live process's .partial was swept");
        assert!(live_scratch.exists(), "a live process's scratch was swept");
        assert!(unrelated.exists(), "a finished backup was swept");
    }

    #[test]
    fn an_explicit_backup_dir_wins_over_the_environment_default() {
        let env = |name: &str| match name {
            "XDG_STATE_HOME" => Some("/xdg".into()),
            "HOME" => Some("/home/u".into()),
            _ => None,
        };
        assert_eq!(
            resolve_backup_dir(Some("/host/chosen".into()), env).unwrap(),
            PathBuf::from("/host/chosen")
        );
        assert_eq!(
            resolve_backup_dir(None, env).unwrap(),
            PathBuf::from("/xdg/symvault/backups")
        );
        assert_eq!(
            resolve_backup_dir(None, |name| (name == "HOME").then(|| "/home/u".into())).unwrap(),
            PathBuf::from("/home/u/.local/state/symvault/backups")
        );
        assert!(resolve_backup_dir(None, |_| None).is_err());
    }
}
