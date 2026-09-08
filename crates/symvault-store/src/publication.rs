//! Atomic replacement relative to an already acquired parent directory.
//! Unix operations retain that capability through publication and cleanup.
//! Windows retains the existing path-based implementation and needs native
//! reparse-point/ancestor-race validation before any confinement claim.

use std::{
    fs,
    io::{self, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use super::StoreError;

pub(super) fn replace(target: &Path, bytes: &[u8], parent: &fs::File) -> Result<(), StoreError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = basename(target)?;
    replace_using_names(
        target,
        bytes,
        parent,
        (0..32).map(|_| {
            format!(
                ".{name}.tmp-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            )
        }),
    )
}

fn basename(target: &Path) -> Result<&str, StoreError> {
    target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| StoreError::UnsafePath(target.display().to_string()))
}

fn write_error(target: &Path, source: impl Into<io::Error>) -> StoreError {
    StoreError::Write {
        path: target.to_path_buf(),
        source: source.into(),
    }
}

#[cfg(unix)]
fn validate_target(parent: &fs::File, target: &Path) -> Result<(), StoreError> {
    use rustix::fs::{AtFlags, FileType, statat};
    match statat(parent, basename(target)?, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => match FileType::from_raw_mode(metadata.st_mode) {
            FileType::RegularFile => Ok(()),
            FileType::Symlink => Err(StoreError::Symlink(target.to_path_buf())),
            _ => Err(StoreError::NotRegularFile(target.to_path_buf())),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(write_error(target, error)),
    }
}

#[cfg(not(unix))]
fn validate_target(_parent: &fs::File, target: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(target) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(StoreError::Symlink(target.to_path_buf()))
        }
        Ok(metadata) if !metadata.is_file() => {
            Err(StoreError::NotRegularFile(target.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(write_error(target, error)),
    }
}

fn replace_using_names(
    target: &Path,
    bytes: &[u8],
    parent: &fs::File,
    names: impl IntoIterator<Item = String>,
) -> Result<(), StoreError> {
    validate_target(parent, target)?;
    for temporary in names {
        // Never clean up a name until exclusive creation succeeds: a collision
        // belongs to another writer, including when all retries are exhausted.
        let mut file = match create_temp(parent, target, &temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(write_error(target, error)),
        };
        let result = (|| {
            super::set_private_permissions(&file).map_err(|error| write_error(target, error))?;
            file.write_all(bytes)
                .map_err(|error| write_error(target, error))?;
            file.sync_all()
                .map_err(|error| write_error(target, error))?;
            // No generic POSIX operation atomically asserts a target's type
            // while replacing it. This rejects special targets observed now,
            // but does not claim protection against a hostile final-name swap.
            validate_target(parent, target)?;
            publish(parent, target, &temporary).map_err(|error| write_error(target, error))?;
            sync_parent(parent).map_err(|error| write_error(target, error))
        })();
        drop(file);
        let cleanup = cleanup_temp(parent, target, &temporary)
            .and_then(|()| sync_parent(parent))
            .map_err(|error| write_error(target, error));
        return result.and(cleanup);
    }
    Err(write_error(
        target,
        io::Error::new(io::ErrorKind::AlreadyExists, "temporary name exhausted"),
    ))
}

#[cfg(unix)]
fn create_temp(parent: &fs::File, _target: &Path, name: &str) -> io::Result<fs::File> {
    use rustix::fs::{Mode, OFlags, openat};
    openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        Mode::from_raw_mode(0o600),
    )
    .map(fs::File::from)
    .map_err(Into::into)
}

#[cfg(not(unix))]
fn create_temp(_parent: &fs::File, target: &Path, name: &str) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target.with_file_name(name))
}

#[cfg(unix)]
fn publish(parent: &fs::File, target: &Path, temporary: &str) -> io::Result<()> {
    rustix::fs::renameat(parent, temporary, parent, target.file_name().unwrap()).map_err(Into::into)
}

#[cfg(not(unix))]
fn publish(_parent: &fs::File, target: &Path, temporary: &str) -> io::Result<()> {
    fs::rename(target.with_file_name(temporary), target)
}

#[cfg(unix)]
fn cleanup_temp(parent: &fs::File, _target: &Path, temporary: &str) -> io::Result<()> {
    use rustix::fs::{AtFlags, unlinkat};
    match unlinkat(parent, temporary, AtFlags::empty()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(unix))]
fn cleanup_temp(_parent: &fs::File, target: &Path, temporary: &str) -> io::Result<()> {
    match fs::remove_file(target.with_file_name(temporary)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn sync_parent(parent: &fs::File) -> io::Result<()> {
    rustix::fs::fsync(parent).map_err(Into::into)
}

#[cfg(not(unix))]
fn sync_parent(_parent: &fs::File) -> io::Result<()> {
    // Directory durability on Windows is an explicit unverified contract.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> tempfile::TempDir {
        // macOS exposes /var as a symlink; tests exercise a deliberately
        // symlink-free acquired root, just as Store::open does.
        tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
    }

    #[test]
    fn collisions_preserve_unowned_files_and_old_target() {
        let dir = tempdir();
        let parent = super::super::ensure_directory(dir.path()).unwrap();
        let target = dir.path().join("entry.age");
        fs::write(&target, b"old").unwrap();
        fs::write(dir.path().join("collision"), b"other writer").unwrap();
        let error =
            replace_using_names(&target, b"new", &parent, ["collision".to_owned()]).unwrap_err();
        assert!(
            matches!(error, StoreError::Write { source, .. } if source.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(
            fs::read(dir.path().join("collision")).unwrap(),
            b"other writer"
        );
        replace_using_names(
            &target,
            b"new",
            &parent,
            ["collision".to_owned(), "owned".to_owned()],
        )
        .unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(
            fs::read(dir.path().join("collision")).unwrap(),
            b"other writer"
        );
        assert!(!dir.path().join("owned").exists());
    }

    #[test]
    fn rejects_directory_target_before_creating_temp() {
        let dir = tempdir();
        let parent = super::super::ensure_directory(dir.path()).unwrap();
        let target = dir.path().join("directory.age");
        fs::create_dir(&target).unwrap();
        assert!(matches!(
            replace_using_names(&target, b"new", &parent, ["owned".to_owned()]),
            Err(StoreError::NotRegularFile(_))
        ));
        assert!(target.is_dir());
        assert!(!dir.path().join("owned").exists());
    }

    #[cfg(unix)]
    #[test]
    fn retained_parent_replaces_only_inside_original_directory() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tempdir();
        let checked = root.path().join("checked");
        let moved = root.path().join("moved");
        let outside = root.path().join("outside");
        fs::create_dir(&checked).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(checked.join("entry.age"), b"old").unwrap();
        fs::write(outside.join("entry.age"), b"outside").unwrap();
        let parent = super::super::ensure_directory(&checked).unwrap();
        fs::rename(&checked, &moved).unwrap();
        symlink(&outside, &checked).unwrap();
        replace(&checked.join("entry.age"), b"new", &parent).unwrap();
        assert_eq!(fs::read(moved.join("entry.age")).unwrap(), b"new");
        assert_eq!(fs::read(outside.join("entry.age")).unwrap(), b"outside");
        assert_eq!(
            fs::metadata(moved.join("entry.age"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_and_socket_without_opening_or_removing_them() {
        use std::os::unix::{fs::symlink, net::UnixListener};
        let dir = tempdir();
        let parent = super::super::ensure_directory(dir.path()).unwrap();
        fs::write(dir.path().join("sentinel"), b"outside").unwrap();
        let link = dir.path().join("link.age");
        symlink("sentinel", &link).unwrap();
        assert!(matches!(
            replace(&link, b"new", &parent),
            Err(StoreError::Symlink(_))
        ));
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(dir.path().join("sentinel")).unwrap(), b"outside");
        let socket = dir.path().join("socket.age");
        let _listener = UnixListener::bind(&socket).unwrap();
        assert!(matches!(
            replace(&socket, b"new", &parent),
            Err(StoreError::NotRegularFile(_))
        ));
        assert!(socket.exists());
    }
}
