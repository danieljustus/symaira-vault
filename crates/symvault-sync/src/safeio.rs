//! Symlink-hardened file access shared by the vault-directory ports.
//!
//! These are the Rust counterparts of `internal/vault.SafeReadFile` and
//! `SafeWriteFile`: the target is refused if it is a symlink or any other
//! non-regular file rather than being followed, and a replacement is staged,
//! fsynced and renamed so an interrupted write cannot leave a truncated file
//! behind. An attacker who can plant a link inside the vault directory must not
//! be able to redirect a `0600` write onto a file of their choosing.

use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;

/// Mode vault-private directories are created with, matching Go's `0o700`.
pub const DIR_MODE: u32 = 0o700;

/// Mode vault-private files are created with, matching Go's `0o600`.
pub const FILE_MODE: u32 = 0o600;

/// Why a guarded read or write could not be completed.
#[derive(Debug)]
pub enum SafeIoError {
    /// The path exists but is a symlink or another non-regular file.
    NotRegularFile,
    /// The underlying filesystem call failed.
    Io(std::io::Error),
}

impl From<std::io::Error> for SafeIoError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl std::fmt::Display for SafeIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRegularFile => write!(f, "refusing a symlinked or non-regular target"),
            Self::Io(source) => write!(f, "{source}"),
        }
    }
}

/// Reads `path`, or reports `Ok(None)` when it does not exist.
pub fn read(path: &Path) -> Result<Option<Vec<u8>>, SafeIoError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => Err(SafeIoError::NotRegularFile),
        Ok(_) => Ok(Some(fs::read(path)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Reports whether `path` exists as a regular file.
pub fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

/// Refuses a symlinked or otherwise non-regular target before it is written to.
pub fn refuse_unsafe_target(path: &Path) -> Result<(), SafeIoError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => Err(SafeIoError::NotRegularFile),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Replaces `path` atomically: stage, fsync, rename. The staging file's name is
/// not part of any frozen contract; the resulting bytes and mode are.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<(), SafeIoError> {
    refuse_unsafe_target(path)?;
    let staged = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut file = create_file(&staged)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = fs::rename(&staged, path) {
        let _ = fs::remove_file(&staged);
        return Err(error.into());
    }
    Ok(())
}

/// Opens `path` for appending, creating it with [`FILE_MODE`] if absent, after
/// refusing a symlinked target.
pub fn open_append(path: &Path) -> Result<File, SafeIoError> {
    refuse_unsafe_target(path)?;
    Ok(append_options().open(path)?)
}

/// Creates every missing component of `path` with [`DIR_MODE`].
pub fn create_dir_all(path: &Path) -> Result<(), SafeIoError> {
    Ok(dir_builder().create(path)?)
}

#[cfg(unix)]
fn create_file(path: &Path) -> Result<File, SafeIoError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    Ok(fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(path)?)
}

/// Windows has no POSIX mode to apply; Go's `0o600` is equally inert there.
#[cfg(not(unix))]
fn create_file(path: &Path) -> Result<File, SafeIoError> {
    Ok(File::create(path)?)
}

#[cfg(unix)]
fn append_options() -> fs::OpenOptions {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true).mode(FILE_MODE);
    options
}

#[cfg(not(unix))]
fn append_options() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    options
}

#[cfg(unix)]
fn dir_builder() -> fs::DirBuilder {
    use std::os::unix::fs::DirBuilderExt as _;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(DIR_MODE);
    builder
}

#[cfg(not(unix))]
fn dir_builder() -> fs::DirBuilder {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    builder
}
