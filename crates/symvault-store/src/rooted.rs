//! Unix root-relative traversal for mutation operations. Display paths are
//! diagnostic only; they are never used for Unix filesystem access here.

use std::{
    ffi::OsString,
    fs, io,
    path::{Component, Path},
};

use super::StoreError;

#[derive(Clone, Debug)]
pub(super) struct RootedEntry {
    pub relative: std::path::PathBuf,
    pub regular: bool,
}

fn validate_relative(path: &Path) -> Result<(), StoreError> {
    if path
        .components()
        .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return Err(StoreError::UnsafePath(path.display().to_string()));
    }
    Ok(())
}

pub(super) fn directory(
    root: &fs::File,
    relative: &Path,
    display: &Path,
    create: bool,
) -> Result<fs::File, StoreError> {
    use rustix::fs::{Mode, OFlags, fsync, mkdirat, openat};
    validate_relative(relative)?;
    let mut dir = root.try_clone().map_err(|source| StoreError::Read {
        path: display.to_path_buf(),
        source,
    })?;
    for part in relative.components() {
        let Component::Normal(name) = part else {
            continue;
        };
        let open = |parent: &fs::File| {
            openat(
                parent,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                Mode::empty(),
            )
        };
        let next = match open(&dir) {
            Ok(next) => next,
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                match mkdirat(&dir, name, Mode::from_raw_mode(0o700)) {
                    Ok(()) => fsync(&dir).map_err(|source| StoreError::Write {
                        path: display.to_path_buf(),
                        source: source.into(),
                    })?,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(source) => {
                        return Err(StoreError::Write {
                            path: display.to_path_buf(),
                            source: source.into(),
                        });
                    }
                }
                open(&dir).map_err(|source| StoreError::Read {
                    path: display.to_path_buf(),
                    source: source.into(),
                })?
            }
            Err(source) => {
                return Err(StoreError::Read {
                    path: display.to_path_buf(),
                    source: source.into(),
                });
            }
        };
        dir = fs::File::from(next);
    }
    Ok(dir)
}

pub(super) fn open_lock(root: &fs::File, display: &Path) -> Result<fs::File, StoreError> {
    use rustix::fs::{Mode, OFlags, openat};
    let file = openat(
        root,
        ".lock",
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|source| StoreError::Write {
        path: display.to_path_buf(),
        source: source.into(),
    })?;
    Ok(fs::File::from(file))
}

pub(super) fn walk_from(
    root: &fs::File,
    relative: &Path,
    display: &Path,
    max_depth: Option<usize>,
) -> Result<Vec<RootedEntry>, StoreError> {
    let directory = directory(root, relative, display, false)?;
    let mut entries = Vec::new();
    walk_directory(
        &directory,
        relative,
        display,
        &mut entries,
        relative.components().count(),
        max_depth,
    )?;
    Ok(entries)
}

pub(super) fn walk(root: &fs::File, display: &Path) -> Result<Vec<RootedEntry>, StoreError> {
    walk_with_max_depth(root, display, None)
}

pub(super) fn walk_with_max_depth(
    root: &fs::File,
    display: &Path,
    max_depth: Option<usize>,
) -> Result<Vec<RootedEntry>, StoreError> {
    let mut entries = Vec::new();
    walk_directory(root, Path::new(""), display, &mut entries, 0, max_depth)?;
    Ok(entries)
}

fn walk_directory(
    directory: &fs::File,
    prefix: &Path,
    display: &Path,
    entries: &mut Vec<RootedEntry>,
    depth: usize,
    max_depth: Option<usize>,
) -> Result<(), StoreError> {
    if max_depth.is_some_and(|limit| depth >= limit) {
        return Ok(());
    }
    for name in read_directory_names(directory, display)? {
        let relative = prefix.join(&name);
        let entry_display = display.join(&relative);
        use rustix::fs::{AtFlags, FileType, statat};
        let metadata = statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
            StoreError::Read {
                path: entry_display.clone(),
                source: source.into(),
            }
        })?;
        match FileType::from_raw_mode(metadata.st_mode) {
            FileType::Directory => {
                entries.push(RootedEntry {
                    relative: relative.clone(),
                    regular: false,
                });
                if max_depth.is_some_and(|limit| depth + 1 >= limit) {
                    continue;
                }
                let child = rustix::fs::openat(
                    directory,
                    &name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|source| StoreError::Read {
                    path: entry_display,
                    source: source.into(),
                })?;
                walk_directory(
                    &fs::File::from(child),
                    &relative,
                    display,
                    entries,
                    depth + 1,
                    max_depth,
                )?;
            }
            FileType::RegularFile => entries.push(RootedEntry {
                relative,
                regular: true,
            }),
            FileType::Symlink => return Err(StoreError::Symlink(entry_display)),
            _ => entries.push(RootedEntry {
                relative,
                regular: false,
            }),
        }
    }
    Ok(())
}

fn read_directory_names(directory: &fs::File, display: &Path) -> Result<Vec<OsString>, StoreError> {
    use rustix::fs::Dir;
    use std::os::unix::ffi::OsStringExt;

    let mut stream = Dir::read_from(directory).map_err(|source| StoreError::Read {
        path: display.to_path_buf(),
        source: source.into(),
    })?;
    let mut names = Vec::new();
    while let Some(entry) = stream.read() {
        let entry = entry.map_err(|source| StoreError::Read {
            path: display.to_path_buf(),
            source: source.into(),
        })?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.push(OsString::from_vec(name.to_vec()));
    }
    Ok(names)
}

pub(super) fn metadata(
    root: &fs::File,
    relative: &Path,
    display: &Path,
) -> Result<fs::Metadata, StoreError> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, statat};
    validate_relative(relative)?;
    let parent = directory(
        root,
        relative.parent().unwrap_or(Path::new("")),
        display,
        false,
    )?;
    let name = relative
        .file_name()
        .ok_or_else(|| StoreError::UnsafePath(display.display().to_string()))?;
    let stat =
        statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| StoreError::Read {
            path: display.to_path_buf(),
            source: source.into(),
        })?;
    let file_type = FileType::from_raw_mode(stat.st_mode);
    if file_type == FileType::Symlink {
        return Err(StoreError::Symlink(display.to_path_buf()));
    }
    if !matches!(file_type, FileType::RegularFile | FileType::Directory) {
        return Err(StoreError::NotRegularFile(display.to_path_buf()));
    }
    let flags = if file_type == FileType::Directory {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW
    } else {
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK
    };
    let file = rustix::fs::openat(&parent, name, flags, Mode::empty()).map_err(|source| {
        StoreError::Read {
            path: display.to_path_buf(),
            source: source.into(),
        }
    })?;
    fs::File::from(file)
        .metadata()
        .map_err(|source| StoreError::Read {
            path: display.to_path_buf(),
            source,
        })
}

pub(super) fn regular_exists(parent: &fs::File, target: &Path) -> Result<bool, StoreError> {
    use rustix::fs::{AtFlags, FileType, statat};
    let name = target
        .file_name()
        .ok_or_else(|| StoreError::UnsafePath(target.display().to_string()))?;
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => match FileType::from_raw_mode(metadata.st_mode) {
            FileType::RegularFile => Ok(true),
            FileType::Symlink => Err(StoreError::Symlink(target.to_path_buf())),
            _ => Err(StoreError::NotRegularFile(target.to_path_buf())),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(StoreError::Read {
            path: target.to_path_buf(),
            source: source.into(),
        }),
    }
}

pub(super) fn regular_exists_at(
    root: &fs::File,
    relative: &Path,
    display: &Path,
) -> Result<bool, StoreError> {
    validate_relative(relative)?;
    let parent = match directory(
        root,
        relative.parent().unwrap_or(Path::new("")),
        display,
        false,
    ) {
        Ok(parent) => parent,
        Err(StoreError::Read { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    regular_exists(&parent, display)
}

/// Missing candidates are skipped; other failures must not enable fallback.
/// Unlink operates on the directory entry, never on a swapped symlink referent.
pub(super) fn remove(root: &fs::File, relative: &Path, display: &Path) -> Result<bool, StoreError> {
    use rustix::fs::{AtFlags, fsync, unlinkat};
    validate_relative(relative)?;
    let parent = match directory(
        root,
        relative.parent().unwrap_or(Path::new("")),
        display,
        false,
    ) {
        Ok(parent) => parent,
        Err(StoreError::Read { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    if !regular_exists(&parent, display)? {
        return Ok(false);
    }
    let name = relative
        .file_name()
        .ok_or_else(|| StoreError::UnsafePath(display.display().to_string()))?;
    unlinkat(&parent, name, AtFlags::empty()).map_err(|source| StoreError::Write {
        path: display.to_path_buf(),
        source: source.into(),
    })?;
    fsync(&parent).map_err(|source| StoreError::Write {
        path: display.to_path_buf(),
        source: source.into(),
    })?;
    Ok(true)
}

pub(super) fn rename(
    root: &fs::File,
    source: &Path,
    destination: &Path,
    display: &Path,
) -> Result<(), StoreError> {
    use rustix::fs::{fsync, renameat};
    validate_relative(source)?;
    validate_relative(destination)?;
    let source_parent = directory(
        root,
        source.parent().unwrap_or(Path::new("")),
        display,
        false,
    )?;
    let destination_parent = directory(
        root,
        destination.parent().unwrap_or(Path::new("")),
        display,
        true,
    )?;
    let source_name = source
        .file_name()
        .ok_or_else(|| StoreError::UnsafePath(display.display().to_string()))?;
    let destination_name = destination
        .file_name()
        .ok_or_else(|| StoreError::UnsafePath(display.display().to_string()))?;
    renameat(
        &source_parent,
        source_name,
        &destination_parent,
        destination_name,
    )
    .map_err(|source| StoreError::Write {
        path: display.to_path_buf(),
        source: source.into(),
    })?;
    fsync(&source_parent).map_err(|source| StoreError::Write {
        path: display.to_path_buf(),
        source: source.into(),
    })?;
    fsync(&destination_parent).map_err(|source| StoreError::Write {
        path: display.to_path_buf(),
        source: source.into(),
    })?;
    Ok(())
}

pub(super) fn read(
    root: &fs::File,
    relative: &Path,
    display: &Path,
) -> Result<Vec<u8>, StoreError> {
    read_with_metadata(root, relative, display).map(|(bytes, _)| bytes)
}

pub(super) fn read_with_metadata(
    root: &fs::File,
    relative: &Path,
    display: &Path,
) -> Result<(Vec<u8>, fs::Metadata), StoreError> {
    use rustix::fs::{Mode, OFlags, openat};
    validate_relative(relative)?;
    let name = relative
        .file_name()
        .ok_or_else(|| StoreError::UnsafePath(display.display().to_string()))?;
    let parent = directory(
        root,
        relative.parent().unwrap_or(Path::new("")),
        display,
        false,
    )?;
    let file = openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| StoreError::Read {
        path: display.to_path_buf(),
        source: source.into(),
    })?;
    super::read_open_regular_with_metadata(fs::File::from(file), display)
}
