//! Symlink-hardened file access shared by the vault-directory ports.
//!
//! These are the Rust counterparts of `internal/vault.SafeReadFile` and
//! `SafeWriteFile`: the target is refused if it is a symlink or any other
//! non-regular file rather than being followed, and a replacement is staged,
//! fsynced and renamed so an interrupted write cannot leave a truncated file
//! behind. An attacker who can plant a link inside the vault directory must not
//! be able to redirect a `0600` write onto a file of their choosing.

#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
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
    read_bounded(path, u64::MAX)
}

/// Reads a regular file without following a final symlink and caps allocation.
pub fn read_bounded(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, SafeIoError> {
    let Some(file) = open_read(path)? else {
        return Ok(None);
    };
    let length = file.metadata()?.len();
    if length > limit {
        return Err(SafeIoError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("file exceeds {limit} bytes"),
        )));
    }
    let mut data = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(SafeIoError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("file exceeds {limit} bytes"),
        )));
    }
    Ok(Some(data))
}

#[cfg(unix)]
/// Opens a regular file for streaming, rejecting final symlinks.
pub fn open_read(path: &Path) -> Result<Option<File>, SafeIoError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    use rustix::io::Errno;

    let descriptor = match open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == Errno::NOENT => return Ok(None),
        Err(error) if error == Errno::LOOP => return Err(SafeIoError::NotRegularFile),
        Err(error) => return Err(SafeIoError::Io(error.into())),
    };
    let metadata = fstat(&descriptor).map_err(|error| SafeIoError::Io(error.into()))?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file() {
        return Err(SafeIoError::NotRegularFile);
    }
    Ok(Some(File::from(descriptor)))
}

#[cfg(not(unix))]
/// Opens a regular file for streaming, rejecting final symlinks.
pub fn open_read(path: &Path) -> Result<Option<File>, SafeIoError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => Err(SafeIoError::NotRegularFile),
        Ok(_) => Ok(Some(File::open(path)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Reports whether `path` exists as a regular file.
pub fn is_regular_file(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use rustix::fs::{FileType, lstat};
        lstat(path).is_ok_and(|metadata| FileType::from_raw_mode(metadata.st_mode).is_file())
    }
    #[cfg(not(unix))]
    {
        fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
    }
}

/// Refuses a symlinked or otherwise non-regular target before it is written to.
pub fn refuse_unsafe_target(path: &Path) -> Result<(), SafeIoError> {
    #[cfg(unix)]
    {
        use rustix::fs::{FileType, lstat};
        use rustix::io::Errno;
        match lstat(path) {
            Ok(metadata) if FileType::from_raw_mode(metadata.st_mode).is_file() => Ok(()),
            Ok(_) => Err(SafeIoError::NotRegularFile),
            Err(error) if error == Errno::NOENT => Ok(()),
            Err(error) => Err(SafeIoError::Io(error.into())),
        }
    }
    #[cfg(not(unix))]
    {
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_file() => Err(SafeIoError::NotRegularFile),
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Replaces `path` atomically: stage, fsync, rename. The staging file's name is
/// not part of any frozen contract; the resulting bytes and mode are.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<(), SafeIoError> {
    refuse_unsafe_target(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::Builder::new()
        .prefix(".symvault-tmp-")
        .tempfile_in(parent)
        .map_err(SafeIoError::Io)?;
    staged.write_all(data)?;
    staged.as_file().sync_all()?;
    staged
        .persist(path)
        .map_err(|error| SafeIoError::Io(error.error))?;
    Ok(())
}

/// Opens `path` for appending, creating it with [`FILE_MODE`] if absent, after
/// refusing a symlinked target.
pub fn open_append(path: &Path) -> Result<File, SafeIoError> {
    #[cfg(unix)]
    {
        use rustix::fs::{FileType, Mode, OFlags, fstat, open};
        use rustix::io::Errno;
        let descriptor = open(
            path,
            OFlags::WRONLY
                | OFlags::APPEND
                | OFlags::CREATE
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(FILE_MODE as _),
        )
        .map_err(|error| {
            if error == Errno::LOOP {
                SafeIoError::NotRegularFile
            } else {
                SafeIoError::Io(error.into())
            }
        })?;
        let metadata = fstat(&descriptor).map_err(|error| SafeIoError::Io(error.into()))?;
        if !FileType::from_raw_mode(metadata.st_mode).is_file() {
            return Err(SafeIoError::NotRegularFile);
        }
        Ok(File::from(descriptor))
    }
    #[cfg(not(unix))]
    {
        refuse_unsafe_target(path)?;
        Ok(append_options().open(path)?)
    }
}

/// Overwrites a regular file with bounded zero chunks, syncs it, then unlinks
/// the name. Unix opens use `NOFOLLOW`, so a replaced symlink is removed as a
/// link and never followed to an unrelated file.
pub fn secure_delete(path: &Path, max_bytes: u64) -> Result<(), SafeIoError> {
    #[cfg(unix)]
    let result = (|| {
        use rustix::fs::{FileType, Mode, OFlags, fstat, open};
        use rustix::io::Errno;
        let descriptor = match open(
            path,
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == Errno::LOOP => return Err(SafeIoError::NotRegularFile),
            Err(error) => return Err(SafeIoError::Io(error.into())),
        };
        let metadata = fstat(&descriptor).map_err(|error| SafeIoError::Io(error.into()))?;
        if !FileType::from_raw_mode(metadata.st_mode).is_file() {
            return Err(SafeIoError::NotRegularFile);
        }
        let mut file = File::from(descriptor);
        let mut remaining = metadata.st_size.max(0) as u64;
        file.seek(SeekFrom::Start(0))?;
        let zeros = [0u8; 4096];
        let writable = remaining.min(max_bytes);
        remaining = writable;
        while remaining > 0 {
            let chunk = remaining.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..chunk])?;
            remaining -= chunk as u64;
        }
        file.sync_all()?;
        Ok::<(), SafeIoError>(())
    })();
    #[cfg(not(unix))]
    let result = (|| {
        refuse_unsafe_target(path)?;
        let mut file = OpenOptions::new().write(true).open(path)?;
        let mut remaining = file.metadata()?.len().min(max_bytes);
        file.seek(SeekFrom::Start(0))?;
        let zeros = [0u8; 4096];
        while remaining > 0 {
            let chunk = remaining.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..chunk])?;
            remaining -= chunk as u64;
        }
        file.sync_all()?;
        Ok::<(), SafeIoError>(())
    })();
    let remove = fs::remove_file(path).map_err(SafeIoError::Io);
    result.and(remove)
}

/// Creates every missing component of `path` with [`DIR_MODE`].
pub fn create_dir_all(path: &Path) -> Result<(), SafeIoError> {
    Ok(dir_builder().create(path)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn atomic_write_replaces_existing_regular_file() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("output");
        let preplanted = path.with_extension(format!("tmp.{}", std::process::id()));
        fs::write(&preplanted, b"preplanted sentinel").expect("preplanted staging sentinel");
        fs::write(&path, b"old").expect("old output");
        write_atomic(&path, b"new").expect("atomic write");
        assert_eq!(fs::read(path).expect("new output"), b"new");
        assert_eq!(
            fs::read(preplanted).expect("preplanted sentinel remains"),
            b"preplanted sentinel"
        );
    }

    #[test]
    fn bounded_read_rejects_oversize_before_allocation() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("large");
        fs::write(&path, b"123456").expect("large fixture");
        let error = read_bounded(&path, 5).expect_err("oversize must fail");
        assert!(error.to_string().contains("file exceeds 5 bytes"));
    }

    #[cfg(unix)]
    #[test]
    fn guarded_read_and_write_refuse_symlink_targets() {
        let directory = tempfile::tempdir().expect("temp directory");
        let sentinel = directory.path().join("sentinel");
        let link = directory.path().join("link");
        fs::write(&sentinel, b"sentinel").expect("sentinel");
        std::os::unix::fs::symlink(&sentinel, &link).expect("symlink");

        assert!(matches!(read(&link), Err(SafeIoError::NotRegularFile)));
        assert!(matches!(
            write_atomic(&link, b"changed"),
            Err(SafeIoError::NotRegularFile)
        ));
        assert_eq!(fs::read(&sentinel).expect("sentinel remains"), b"sentinel");
    }

    #[cfg(unix)]
    #[test]
    fn secure_delete_removes_replaced_symlink_without_touching_target() {
        let directory = tempfile::tempdir().expect("temp directory");
        let sentinel = directory.path().join("sentinel");
        let link = directory.path().join("link");
        fs::write(&sentinel, b"sentinel").expect("sentinel");
        std::os::unix::fs::symlink(&sentinel, &link).expect("symlink");

        let _ = secure_delete(&link, 4096);
        assert!(!link.exists());
        assert_eq!(fs::read(sentinel).expect("sentinel remains"), b"sentinel");
    }

    #[cfg(unix)]
    #[test]
    fn open_append_refuses_fifo_without_blocking() {
        let directory = tempfile::tempdir().expect("temp directory");
        let fifo = directory.path().join("fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .expect("mkfifo")
                .success()
        );
        assert!(open_append(&fifo).is_err());
    }
}
