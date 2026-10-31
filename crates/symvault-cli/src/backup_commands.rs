//! CLI backup/restore orchestration.
//!
//! `backup` is a port of Go's `admin.CreateBackup` (`cmd/admin/backup.go`),
//! including its observable side effects: the archive is created in place
//! (`O_CREATE|O_WRONLY|O_TRUNC`, 0600 only for a new file), missing parent
//! directories are made with mode 0700, and a walk or read failure leaves the
//! members written so far in the archive. `restore` goes through the shared
//! `symvault_sync::archive::restore`, which already follows `RestoreBackup`.
use flate2::{Compression, write::GzEncoder};
use std::{
    cell::{Cell, RefCell},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    rc::Rc,
};
use symvault_sync::archive;
use tar::{Builder, EntryType, Header};

pub fn backup(root: &Path, destination: &Path, exclude_git: bool) -> Result<PathBuf, String> {
    let mut destination = destination.as_os_str().to_owned();
    if !destination.as_encoded_bytes().ends_with(b".tar.gz") {
        destination.push(".tar.gz");
    }
    let destination = PathBuf::from(destination);
    create_backup(root, &destination, exclude_git)
        .map_err(|error| format!("backup failed: {error}"))?;
    Ok(destination)
}

/// The writer under the tar builder. After `closed` is set, writes are
/// swallowed: Go's deferred `tar.Writer.Close` refuses to write the footer when
/// an entry is unfinished, while the Rust builder would append it on drop.
struct Gate {
    gzip: Rc<RefCell<Option<GzEncoder<fs::File>>>>,
    closed: Rc<Cell<bool>>,
}

impl Write for Gate {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.closed.get() {
            return Ok(bytes.len());
        }
        match self.gzip.borrow_mut().as_mut() {
            Some(gzip) => gzip.write(bytes),
            None => Ok(bytes.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.gzip.borrow_mut().as_mut() {
            Some(gzip) if !self.closed.get() => gzip.flush(),
            _ => Ok(()),
        }
    }
}

/// `filepath.Dir` for a Unix path.
fn go_dir(path: &Path) -> PathBuf {
    let bytes = path.as_os_str().as_encoded_bytes();
    let end = bytes
        .iter()
        .rposition(|byte| *byte == b'/')
        .map_or(0, |index| index + 1);
    PathBuf::from(unix_os_string(archive::go_path_clean(&bytes[..end])))
}

#[cfg(unix)]
fn unix_os_string(bytes: Vec<u8>) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(bytes)
}

#[cfg(not(unix))]
fn unix_os_string(bytes: Vec<u8>) -> std::ffi::OsString {
    String::from_utf8_lossy(&bytes).into_owned().into()
}

/// `os.MkdirAll(path, 0700)`; on failure the offending path and Go's reason.
fn go_mkdir_all(path: &Path) -> Result<(), (PathBuf, String)> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => return Err((path.to_path_buf(), "not a directory".to_owned())),
        Err(_) => {}
    }
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b'/' {
        end -= 1;
    }
    while end > 0 && bytes[end - 1] != b'/' {
        end -= 1;
    }
    let parent = end.saturating_sub(1);
    if parent > 0 {
        go_mkdir_all(Path::new(&unix_os_string(bytes[..parent].to_vec())))?;
    }
    match make_private_dir(path) {
        Ok(()) => Ok(()),
        Err(error) => match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() => Ok(()),
            _ => Err((path.to_path_buf(), archive::go_reason(&error))),
        },
    }
}

fn make_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn create_backup(vault: &Path, archive_path: &Path, exclude_git: bool) -> Result<(), String> {
    go_mkdir_all(&go_dir(archive_path)).map_err(|(path, reason)| {
        format!(
            "create backup directory: mkdir {}: {reason}",
            path.display()
        )
    })?;
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .create(true)
        .truncate(true)
        .write(true)
        .open(archive_path)
        .map_err(|error| {
            format!(
                "create archive: open {}: {}",
                archive_path.display(),
                archive::go_reason(&error)
            )
        })?;
    let gzip = Rc::new(RefCell::new(Some(GzEncoder::new(
        file,
        Compression::default(),
    ))));
    let closed = Rc::new(Cell::new(false));
    let mut builder = Builder::new(Gate {
        gzip: Rc::clone(&gzip),
        closed: Rc::clone(&closed),
    });
    // filepath.Walk reports a symlinked root as a symlink, which the callback
    // skips: the archive is then empty. A missing root fails the initial lstat.
    let walked = match fs::symlink_metadata(vault) {
        Err(error) => Err(format!(
            "lstat {}: {}",
            vault.display(),
            archive::go_reason(&error)
        )),
        Ok(meta) if meta.file_type().is_symlink() => Ok(()),
        Ok(_) => walk(vault, vault, exclude_git, &mut builder),
    };
    // Go's deferred closers: the footer only when no entry is left unfinished,
    // then the gzip trailer; their errors are not reported.
    if walked.is_err() {
        closed.set(true);
    }
    let _ = builder.finish();
    drop(builder);
    if let Some(gzip) = gzip.borrow_mut().take() {
        let _ = gzip.finish();
    }
    walked
}

/// `filepath.Walk` over `dir`: sorted names, pre-order, symlinks neither
/// archived nor followed. Excluded `.git*` entries are skipped but, as in Go
/// (the callback returns nil, not `SkipDir`), their directories are still read.
fn walk(
    root: &Path,
    dir: &Path,
    exclude_git: bool,
    builder: &mut Builder<Gate>,
) -> Result<(), String> {
    let open_error =
        |error: &io::Error| format!("open {}: {}", dir.display(), archive::go_reason(error));
    let mut names = fs::read_dir(dir)
        .map_err(|error| open_error(&error))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| open_error(&error))?;
    names.sort_by(|a, b| a.as_encoded_bytes().cmp(b.as_encoded_bytes()));
    for name in names {
        let path = dir.join(&name);
        let meta = fs::symlink_metadata(&path)
            .map_err(|error| format!("lstat {}: {}", path.display(), archive::go_reason(&error)))?;
        if meta.file_type().is_symlink() {
            continue;
        }
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let excluded = exclude_git && relative.as_os_str().as_encoded_bytes().starts_with(b".git");
        if !excluded {
            append_member(builder, &path, relative, &meta)?;
        }
        if meta.is_dir() {
            walk(root, &path, exclude_git, builder)?;
        }
    }
    Ok(())
}

fn append_member(
    builder: &mut Builder<Gate>,
    path: &Path,
    relative: &Path,
    meta: &fs::Metadata,
) -> Result<(), String> {
    let mut header = Header::new_gnu();
    header.set_metadata(meta);
    // Go's FileInfoHeader keeps the permission bits plus setuid/setgid/sticky;
    // the file-type bits live in the type flag only.
    header.set_mode(permission_bits(meta));
    if meta.is_dir() {
        header.set_entry_type(EntryType::Directory);
        header.set_size(0);
        return builder
            .append_data(&mut header, relative, io::empty())
            .map_err(|error| archive::go_reason(&error));
    }
    if !meta.is_file() {
        return Err(if is_socket(meta) {
            "archive/tar: sockets not supported".to_owned()
        } else {
            format!("archive/tar: unsupported file type for {}", path.display())
        });
    }
    header.set_entry_type(EntryType::Regular);
    header.set_size(meta.len());
    match fs::File::open(path) {
        Ok(file) => builder
            .append_data(&mut header, relative, file)
            .map_err(|error| archive::go_reason(&error)),
        Err(error) => {
            // Go writes the header first and only then opens the file, so the
            // failed member's header stays in the archive.
            let _ = builder.append_data(&mut header, relative, io::empty());
            Err(format!(
                "open {}: {}",
                path.display(),
                archive::go_reason(&error)
            ))
        }
    }
}

#[cfg(unix)]
fn permission_bits(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn permission_bits(meta: &fs::Metadata) -> u32 {
    if meta.permissions().readonly() {
        0o444
    } else {
        0o666
    }
}

#[cfg(unix)]
fn is_socket(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    meta.file_type().is_socket()
}

#[cfg(not(unix))]
fn is_socket(_: &fs::Metadata) -> bool {
    false
}

/// The operation name in the `*PathError` Go's `os.Stat` returns. Unix reports
/// `stat`; on Windows (`os/stat_windows.go`) a missing path fails in
/// `GetFileAttributesEx` and any other failure falls through to `CreateFile`.
fn go_stat_op(error: &std::io::Error) -> &'static str {
    if !cfg!(windows) {
        "stat"
    } else if error.kind() == std::io::ErrorKind::NotFound {
        "GetFileAttributesEx"
    } else {
        "CreateFile"
    }
}

pub fn restore(root: &Path, source: &Path) -> Result<(), String> {
    fs::metadata(source).map_err(|error| {
        format!(
            "archive not found: {} {}: {}",
            go_stat_op(&error),
            source.display(),
            archive::go_reason(&error)
        )
    })?;
    archive::restore(source, root, true).map_err(|error| format!("restore failed: {error}"))?;
    for required in ["identity.age", "config.yaml"] {
        fs::metadata(root.join(required))
            .map_err(|_| format!("restore failed: missing required file: {required}"))?;
    }
    fs::metadata(root.join("entries"))
        .map_err(|_| "restore failed: missing entries directory".to_owned())?;
    Ok(())
}
