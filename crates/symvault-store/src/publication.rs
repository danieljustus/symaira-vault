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
    replace_using_names_with_ops(
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
        &production_ops(),
    )
}

type CreateTemp<'a> = Box<dyn Fn(&fs::File, &Path, &str) -> io::Result<fs::File> + 'a>;
type WriteAll<'a> = Box<dyn Fn(&mut fs::File, &[u8]) -> io::Result<()> + 'a>;
type SyncFile<'a> = Box<dyn Fn(&fs::File) -> io::Result<()> + 'a>;
type ValidateTarget<'a> = Box<dyn Fn(&fs::File, &Path) -> Result<(), StoreError> + 'a>;
type Publish<'a> = Box<dyn Fn(&fs::File, &Path, &str) -> io::Result<()> + 'a>;
type CleanupTemp<'a> = Box<dyn Fn(&fs::File, &Path, &str) -> io::Result<()> + 'a>;
type SyncParent<'a> = Box<dyn Fn(&fs::File) -> io::Result<()> + 'a>;

struct PublicationOps<'a> {
    create_temp: CreateTemp<'a>,
    write_all: WriteAll<'a>,
    sync_file: SyncFile<'a>,
    validate_target: ValidateTarget<'a>,
    publish: Publish<'a>,
    cleanup_temp: CleanupTemp<'a>,
    sync_parent: SyncParent<'a>,
}

fn production_ops() -> PublicationOps<'static> {
    PublicationOps {
        create_temp: Box::new(create_temp),
        write_all: Box::new(|file, bytes| file.write_all(bytes)),
        sync_file: Box::new(|file| file.sync_all()),
        validate_target: Box::new(validate_target),
        publish: Box::new(publish),
        cleanup_temp: Box::new(cleanup_temp),
        sync_parent: Box::new(sync_parent),
    }
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

#[cfg(test)]
fn replace_using_names(
    target: &Path,
    bytes: &[u8],
    parent: &fs::File,
    names: impl IntoIterator<Item = String>,
) -> Result<(), StoreError> {
    replace_using_names_with_ops(target, bytes, parent, names, &production_ops())
}

fn replace_using_names_with_ops(
    target: &Path,
    bytes: &[u8],
    parent: &fs::File,
    names: impl IntoIterator<Item = String>,
    ops: &PublicationOps<'_>,
) -> Result<(), StoreError> {
    (ops.validate_target)(parent, target)?;
    for temporary in names {
        // Never clean up a name until exclusive creation succeeds: a collision
        // belongs to another writer, including when all retries are exhausted.
        let mut file = match (ops.create_temp)(parent, target, &temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(write_error(target, error)),
        };
        let result = (|| {
            super::set_private_permissions(&file).map_err(|error| write_error(target, error))?;
            (ops.write_all)(&mut file, bytes).map_err(|error| write_error(target, error))?;
            (ops.sync_file)(&file).map_err(|error| write_error(target, error))?;
            // No generic POSIX operation atomically asserts a target's type
            // while replacing it. This rejects special targets observed now,
            // but does not claim protection against a hostile final-name swap.
            (ops.validate_target)(parent, target)?;
            (ops.publish)(parent, target, &temporary)
                .map_err(|error| write_error(target, error))?;
            (ops.sync_parent)(parent).map_err(|error| write_error(target, error))
        })();
        drop(file);
        let cleanup = (ops.cleanup_temp)(parent, target, &temporary)
            .and_then(|()| (ops.sync_parent)(parent))
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

    fn fault_ops(
        sync_file_fail: bool,
        publish_fail: bool,
        cleanup_fail: bool,
        parent_fail_call: Option<usize>,
    ) -> PublicationOps<'static> {
        use std::{cell::Cell, rc::Rc};
        let parent_calls = Rc::new(Cell::new(0));
        let parent_calls_hook = Rc::clone(&parent_calls);
        let cleanup_state = Rc::new(Cell::new(cleanup_fail));
        let cleanup_hook = Rc::clone(&cleanup_state);
        PublicationOps {
            create_temp: Box::new(create_temp),
            write_all: Box::new(|file, bytes| file.write_all(bytes)),
            sync_file: Box::new(move |file| {
                if sync_file_fail {
                    Err(io::Error::other("injected file sync"))
                } else {
                    file.sync_all()
                }
            }),
            validate_target: Box::new(validate_target),
            publish: Box::new(move |parent, target, temporary| {
                if publish_fail {
                    Err(io::Error::other("injected publish"))
                } else {
                    publish(parent, target, temporary)
                }
            }),
            cleanup_temp: Box::new(move |parent, target, temporary| {
                if cleanup_hook.replace(false) {
                    Err(io::Error::other("injected cleanup"))
                } else {
                    cleanup_temp(parent, target, temporary)
                }
            }),
            sync_parent: Box::new(move |parent| {
                let call = parent_calls_hook.get() + 1;
                parent_calls_hook.set(call);
                if parent_fail_call == Some(call) {
                    Err(io::Error::other("injected parent sync"))
                } else {
                    sync_parent(parent)
                }
            }),
        }
    }

    #[test]
    fn injected_prepublication_failure_preserves_old_target_and_cleans_owned_temp() {
        let dir = tempdir();
        let parent = super::super::ensure_directory(dir.path()).unwrap();
        let target = dir.path().join("entry.age");
        fs::write(&target, b"old").unwrap();
        let error = replace_using_names_with_ops(
            &target,
            b"new",
            &parent,
            ["owned".to_owned()],
            &fault_ops(true, false, false, None),
        )
        .unwrap_err();
        assert!(
            matches!(error, StoreError::Write { source, .. } if source.to_string() == "injected file sync")
        );
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert!(!dir.path().join("owned").exists());
    }

    #[test]
    fn injected_post_rename_fsync_failure_returns_error_and_keeps_new_target() {
        let dir = tempdir();
        let parent = super::super::ensure_directory(dir.path()).unwrap();
        let target = dir.path().join("entry.age");
        fs::write(&target, b"old").unwrap();
        let error = replace_using_names_with_ops(
            &target,
            b"new",
            &parent,
            ["owned".to_owned()],
            &fault_ops(false, false, false, Some(1)),
        )
        .unwrap_err();
        assert!(
            matches!(error, StoreError::Write { source, .. } if source.to_string() == "injected parent sync")
        );
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(!dir.path().join("owned").exists());
    }

    #[test]
    fn injected_cleanup_failure_does_not_erase_primary_error() {
        let dir = tempdir();
        let parent = super::super::ensure_directory(dir.path()).unwrap();
        let target = dir.path().join("entry.age");
        fs::write(&target, b"old").unwrap();
        let error = replace_using_names_with_ops(
            &target,
            b"new",
            &parent,
            ["owned".to_owned()],
            &fault_ops(false, true, true, None),
        )
        .unwrap_err();
        assert!(
            matches!(error, StoreError::Write { source, .. } if source.to_string() == "injected publish")
        );
        assert_eq!(fs::read(&target).unwrap(), b"old");
        // An unlink failure cannot promise cleanup: retain the owned temporary
        // bytes while preserving the original publication error.
        assert_eq!(fs::read(dir.path().join("owned")).unwrap(), b"new");
    }

    #[test]
    fn injected_final_sync_failure_returns_error_after_successful_cleanup() {
        let dir = tempdir();
        let parent = super::super::ensure_directory(dir.path()).unwrap();
        let target = dir.path().join("entry.age");
        fs::write(&target, b"old").unwrap();
        let error = replace_using_names_with_ops(
            &target,
            b"new",
            &parent,
            ["owned".to_owned()],
            &fault_ops(false, false, false, Some(2)),
        )
        .unwrap_err();
        assert!(
            matches!(error, StoreError::Write { source, .. } if source.to_string() == "injected parent sync")
        );
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(!dir.path().join("owned").exists());
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
