use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Seek, Write},
    path::{Component, Path, PathBuf},
};
use tar::{Archive, Builder, EntryType, Header};
use thiserror::Error;

const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_ARCHIVE_FILE: u64 = 1 << 30;
const MAX_ARCHIVE_TOTAL: u64 = 16 * (1 << 30);

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("archive I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("unsafe archive path: {0}")]
    UnsafePath(String),
    #[error("archive entry is not a regular file or directory: {0}")]
    UnsupportedEntry(String),
    #[error("archive exceeds safety limits")]
    Limit,
    #[error("archive destination already exists: {0}")]
    Exists(PathBuf),
    #[error("archive path is not a directory: {0}")]
    NotDirectory(PathBuf),
    /// A restore failure carrying production Go's exact error text.
    #[error("{0}")]
    Restore(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub path: String,
    pub directory: bool,
    pub mode: u32,
    pub size: u64,
    pub sha256: String,
}

fn safe_relative(path: &Path) -> Result<PathBuf, ArchiveError> {
    if path.is_absolute() {
        return Err(ArchiveError::UnsafePath(path.display().to_string()));
    }
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(v) => out.push(v),
            Component::CurDir => {}
            _ => return Err(ArchiveError::UnsafePath(path.display().to_string())),
        }
    }
    if out.as_os_str().is_empty() {
        return Err(ArchiveError::UnsafePath(path.display().to_string()));
    }
    Ok(out)
}

fn mode(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}
fn copy_and_hash(mut input: impl Read, mut output: impl Write) -> io::Result<(u64, String)> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 32 * 1024];
    let mut size = 0u64;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
        size += count as u64;
    }
    Ok((size, hex::encode(digest.finalize())))
}

/// Creates a private gzip tar backup. Source symlinks are skipped, as in Go;
/// special files and unsafe output targets are rejected.
pub fn backup(
    root: impl AsRef<Path>,
    output: impl AsRef<Path>,
    exclude_git: bool,
) -> Result<Vec<ArchiveEntry>, ArchiveError> {
    let root = root.as_ref();
    let root_metadata = fs::symlink_metadata(root)?;
    let symlink_root = root_metadata.file_type().is_symlink();
    if !symlink_root && !root_metadata.is_dir() {
        return Err(ArchiveError::NotDirectory(root.to_path_buf()));
    }
    // Go's filepath.Walk reports a symlink root as a symlink and CreateBackup
    // skips it. Do not canonicalize this path: that would follow the link and
    // archive the target's contents instead of producing an empty backup.
    let root = if symlink_root {
        root.to_path_buf()
    } else {
        root.canonicalize()?
    };
    let output = output.as_ref();
    crate::safeio::refuse_unsafe_target(output)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    crate::safeio::create_dir_all(parent).map_err(|error| io::Error::other(error.to_string()))?;
    let output = parent.canonicalize()?.join(
        output
            .file_name()
            .ok_or_else(|| ArchiveError::UnsafePath(output.display().to_string()))?,
    );
    let mut staged =
        tempfile::NamedTempFile::new_in(output.parent().expect("canonical output has parent"))?;
    let staged_path = staged.path().to_path_buf();
    let encoder = GzEncoder::new(staged.as_file_mut(), Compression::default());
    let mut builder = Builder::new(encoder);
    let mut manifest = Vec::new();
    let mut paths: Vec<_> = if symlink_root {
        Vec::new()
    } else {
        walkdir(&root)?.into_iter().collect()
    };
    paths.sort();
    for path in paths {
        if path == staged_path || path == output {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .map_err(|_| ArchiveError::UnsafePath(path.display().to_string()))?;
        let rel = safe_relative(rel)?;
        if exclude_git && rel.to_string_lossy().starts_with(".git") {
            continue;
        }
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if !meta.is_dir() && !meta.is_file() {
            return Err(ArchiveError::UnsupportedEntry(rel.display().to_string()));
        }
        let slash = rel
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        if meta.is_dir() {
            builder.append_dir(&rel, &path)?;
            manifest.push(ArchiveEntry {
                path: slash,
                directory: true,
                mode: mode(&meta),
                size: 0,
                sha256: String::new(),
            });
        } else {
            if meta.len() > MAX_ARCHIVE_FILE {
                return Err(ArchiveError::Limit);
            }
            let mut file = fs::File::open(&path)?;
            let (size, hash) = copy_and_hash((&mut file).take(MAX_ARCHIVE_FILE + 1), io::sink())?;
            if size > MAX_ARCHIVE_FILE {
                return Err(ArchiveError::Limit);
            }
            file.rewind()?;
            let mut h = Header::new_gnu();
            h.set_metadata(&meta);
            h.set_mode(mode(&meta));
            h.set_size(size);
            h.set_cksum();
            builder.append_data(&mut h, &rel, &mut file)?;
            manifest.push(ArchiveEntry {
                path: slash,
                directory: false,
                mode: mode(&meta),
                size,
                sha256: hash,
            });
        }
        if manifest.len() > MAX_ARCHIVE_ENTRIES {
            return Err(ArchiveError::Limit);
        }
    }
    builder.into_inner()?.finish()?;
    staged.as_file().sync_all()?;
    staged
        .persist(output)
        .map_err(|error| ArchiveError::Io(error.error))?;
    Ok(manifest)
}
fn walkdir(root: &Path) -> Result<Vec<PathBuf>, ArchiveError> {
    fn visit(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), ArchiveError> {
        let mut children: Vec<_> = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        children.sort_by_key(|e| e.file_name());
        for e in children {
            let p = e.path();
            out.push(p.clone());
            if fs::symlink_metadata(&p)?.is_dir() {
                visit(&p, out)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    visit(root, &mut out)?;
    Ok(out)
}

/// Archive restore failures that production Go reports with fixed text.
/// The message is the whole Go error (the CLI adds `restore failed: `).
fn restore_error(message: impl Into<String>) -> ArchiveError {
    ArchiveError::Restore(message.into())
}

/// Go's `syscall.Errno` text for an OS error: strerror lowered on Unix, the
/// system message elsewhere. `(os error N)` is Rust-only decoration.
pub fn go_reason(error: &io::Error) -> String {
    #[cfg(unix)]
    if let Some(code) = error.raw_os_error() {
        let text = io::Error::from_raw_os_error(code).to_string();
        let text = text
            .rsplit_once(" (os error ")
            .map_or(text.as_str(), |(head, _)| head);
        let mut chars = text.chars();
        return chars
            .next()
            .map(|first| first.to_lowercase().chain(chars).collect())
            .unwrap_or_default();
    }
    let text = error.to_string();
    text.rsplit_once(" (os error ")
        .map_or(text.as_str(), |(head, _)| head)
        .to_owned()
}

/// Lexical `filepath.Clean`, used so messages show the path Go's
/// `filepath.Join` would have produced.
fn lexical_clean(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    let mut rooted = false;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                rooted = true;
                out.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                let last_normal =
                    matches!(out.components().next_back(), Some(Component::Normal(_)));
                if last_normal {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            Component::Normal(name) => out.push(name),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// Go's `path.Clean` over slash-separated names.
fn go_path_clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let rooted = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if stack.last().is_some_and(|last| *last != "..") {
                    stack.pop();
                } else if !rooted {
                    stack.push("..");
                }
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".to_owned(),
        (false, false) => joined,
    }
}

/// `cleanBackupMemberName` from cmd/admin/backup.go, including its error text.
fn go_clean_member_name(name: &str) -> Result<String, String> {
    if name.is_empty() || name == "." || name.contains('\\') {
        return Err(format!("archive contains unsafe path: {name}"));
    }
    let bytes = name.as_bytes();
    if name.starts_with('/') || (bytes.len() >= 2 && bytes[1] == b':') {
        return Err(format!("archive contains absolute path: {name}"));
    }
    let name = name.strip_suffix('/').unwrap_or(name);
    let clean = go_path_clean(name);
    if clean == "." || clean != name || clean == ".." || clean.starts_with("../") {
        return Err(format!("archive contains path traversal: {name}"));
    }
    Ok(clean)
}

/// `fsutil.SafeMkdirAll`: walks each component, trusts only root-owned
/// symlinks, and creates missing components with `mode`. On failure returns
/// the offending path and Go's reason text.
fn go_safe_mkdir_all(path: &Path, mode: u32) -> Result<(), (PathBuf, String)> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| (path.to_path_buf(), go_reason(&error)))?
            .join(path)
    };
    let absolute = lexical_clean(&absolute);
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                current.push(component.as_os_str());
                continue;
            }
            Component::Normal(name) => current.push(name),
            _ => continue,
        }
        match fs::symlink_metadata(&current) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                make_dir(&current, mode).map_err(|error| (current.clone(), go_reason(&error)))?;
            }
            Err(error) => return Err((current, go_reason(&error))),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if metadata.uid() == 0 {
                        current = fs::canonicalize(&current)
                            .map_err(|error| (current.clone(), go_reason(&error)))?;
                        continue;
                    }
                }
                return Err((current, "too many levels of symbolic links".to_owned()));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err((current, "not a directory".to_owned()));
            }
            Ok(_) => {}
        }
    }
    Ok(())
}

fn make_dir(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new().mode(mode).create(path)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        fs::create_dir(path)
    }
}

/// Reads the tar mode field like Go's `parseNumeric`: octal, or base-256
/// where the sign bit makes the value negative (which Go then rejects).
fn go_header_mode(header: &Header) -> Result<i64, ()> {
    let field = &header.as_bytes()[100..108];
    if field[0] & 0x80 != 0 {
        let inverted: u8 = if field[0] & 0x40 != 0 { 0xff } else { 0x00 };
        let mut value: u64 = 0;
        for (index, byte) in field.iter().enumerate() {
            let mut byte = byte ^ inverted;
            if index == 0 {
                byte &= 0x7f;
            }
            if value >> 56 > 0 {
                return Err(());
            }
            value = (value << 8) | u64::from(byte);
        }
        if value >> 63 > 0 {
            return Err(());
        }
        return Ok(if inverted == 0xff {
            !(value as i64)
        } else {
            value as i64
        });
    }
    let trimmed: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|byte| *byte == b' ' || *byte == 0)
        .collect();
    let end = trimmed
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != 0)
        .map_or(0, |index| index + 1);
    let digits = &trimmed[..end];
    if digits.is_empty() {
        return Ok(0);
    }
    std::str::from_utf8(digits)
        .ok()
        .and_then(|text| i64::from_str_radix(text, 8).ok())
        .ok_or(())
}

type Failure = std::rc::Rc<std::cell::RefCell<Option<(io::ErrorKind, String)>>>;

/// Remembers the first failure of the gzip layer so a tar-level error can be
/// told apart from a decompression error, as Go's two readers report them.
struct Tracked<R> {
    inner: R,
    failure: Failure,
}

impl<R: Read> Read for Tracked<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buffer) {
            Err(error) => {
                self.failure
                    .borrow_mut()
                    .get_or_insert((error.kind(), error.to_string()));
                Err(error)
            }
            other => other,
        }
    }
}

/// Go's text for a failed read of the (gzip-wrapped) tar stream.
fn go_stream_error(error: &io::Error, failure: &Failure) -> String {
    if let Some((kind, message)) = failure.borrow().as_ref() {
        if *kind == io::ErrorKind::UnexpectedEof || message.contains("incomplete") {
            return "unexpected EOF".to_owned();
        }
        // Go appends "before offset N", a decoder-internal position that
        // flate2 does not expose.
        return "flate: corrupt input".to_owned();
    }
    if error.raw_os_error().is_some() {
        return go_reason(error);
    }
    // The tar crate reports truncation and malformed headers as plain
    // io errors without an OS code; Go names them ErrUnexpectedEOF/ErrHeader.
    if error.kind() == io::ErrorKind::UnexpectedEof
        || error.to_string().contains("failed to read entire block")
    {
        "unexpected EOF".to_owned()
    } else {
        "archive/tar: invalid tar header".to_owned()
    }
}

/// `gzip.NewReader` reads and validates the header eagerly; flate2 is lazy.
fn check_gzip_header(path: &Path) -> Result<(), ArchiveError> {
    let open_error = |error: io::Error| {
        restore_error(format!(
            "open archive: open {}: {}",
            path.display(),
            go_reason(&error)
        ))
    };
    let mut file = fs::File::open(path).map_err(open_error)?;
    let mut header = [0u8; 10];
    let mut filled = 0;
    while filled < header.len() {
        match file.read(&mut header[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(restore_error(format!(
                    "read gzip: read {}: {}",
                    path.display(),
                    go_reason(&error)
                )));
            }
        }
    }
    if filled == 0 {
        return Err(restore_error("read gzip: EOF"));
    }
    if filled < header.len() {
        return Err(restore_error("read gzip: unexpected EOF"));
    }
    if header[0] != 0x1f || header[1] != 0x8b || header[2] != 8 {
        return Err(restore_error("read gzip: gzip: invalid header"));
    }
    Ok(())
}

/// Restores a gzip tar backup into an existing or newly created directory.
///
/// Error text and extraction order follow `cmd/admin.RestoreBackup` (see
/// `testdata/port/sync/restore-errors.json`). One deliberate difference: a
/// member is staged and renamed into place, so a truncated member never leaves
/// the partial file Go's in-place `O_TRUNC` write does.
pub fn restore(
    input: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    overwrite: bool,
) -> Result<Vec<ArchiveEntry>, ArchiveError> {
    let dest = destination.as_ref();
    go_safe_mkdir_all(dest, 0o700).map_err(|(path, reason)| {
        restore_error(format!(
            "create vault directory: mkdir {}: {reason}",
            path.display()
        ))
    })?;
    if !dest.is_dir() {
        return Err(ArchiveError::NotDirectory(dest.to_path_buf()));
    }
    let input = input.as_ref();
    check_gzip_header(input)?;
    let file = fs::File::open(input).map_err(|error| {
        restore_error(format!(
            "open archive: open {}: {}",
            input.display(),
            go_reason(&error)
        ))
    })?;
    let failure = Failure::default();
    let decoder = Tracked {
        inner: GzDecoder::new(file),
        failure: failure.clone(),
    };
    let mut archive = Archive::new(decoder);
    let read_error = |error: &io::Error| {
        restore_error(format!(
            "read archive: {}",
            go_stream_error(error, &failure)
        ))
    };
    let mut result = Vec::new();
    let mut total = 0u64;
    let entries = archive.entries().map_err(|error| read_error(&error))?;
    for (index, item) in entries.enumerate() {
        if index >= MAX_ARCHIVE_ENTRIES {
            return Err(ArchiveError::Limit);
        }
        let mut entry = item.map_err(|error| read_error(&error))?;
        let raw_name = entry.path_bytes().into_owned();
        let name = String::from_utf8_lossy(&raw_name).into_owned();
        let clean = go_clean_member_name(&name).map_err(restore_error)?;
        let rel = PathBuf::from(&clean);
        let target = dest.join(&rel);
        let shown = lexical_clean(&target);
        if fs::symlink_metadata(&target).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(restore_error(format!(
                "target path is a symlink: {}",
                shown.display()
            )));
        }
        let kind = entry.header().entry_type();
        let header_mode = go_header_mode(entry.header())
            .map_err(|()| restore_error("read archive: archive/tar: invalid tar header"))?;
        if kind == EntryType::Directory {
            if header_mode < 0 {
                return Err(restore_error(format!(
                    "invalid negative mode in archive: {name}"
                )));
            }
            let dir_mode = (header_mode as u32) & 0o700;
            go_safe_mkdir_all(&target, dir_mode).map_err(|(path, reason)| {
                restore_error(format!(
                    "create directory: mkdir {}: {reason}",
                    path.display()
                ))
            })?;
            result.push(ArchiveEntry {
                path: clean.clone(),
                directory: true,
                mode: dir_mode,
                size: 0,
                sha256: String::new(),
            });
            continue;
        }
        if kind != EntryType::Regular {
            return Err(restore_error(format!(
                "unsupported archive entry type: {name}"
            )));
        }
        let size = entry.size();
        if size > MAX_ARCHIVE_FILE {
            return Err(restore_error(format!(
                "archive entry {name} exceeds maximum file size of {MAX_ARCHIVE_FILE} bytes"
            )));
        }
        if total > MAX_ARCHIVE_TOTAL - size {
            return Err(restore_error(format!(
                "archive exceeds maximum extraction size of {MAX_ARCHIVE_TOTAL} bytes"
            )));
        }
        total += size;
        if let Some(parent) = target.parent() {
            go_safe_mkdir_all(parent, 0o700).map_err(|(path, reason)| {
                restore_error(format!(
                    "create parent directory: mkdir {}: {reason}",
                    path.display()
                ))
            })?;
        }
        if header_mode < 0 {
            return Err(restore_error(format!(
                "invalid negative mode in archive: {name}"
            )));
        }
        if target.exists() && !overwrite {
            return Err(ArchiveError::Exists(target));
        }
        let create_error = |error: io::Error| {
            restore_error(format!(
                "create file: open {}: {}",
                shown.display(),
                go_reason(&error)
            ))
        };
        let m = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.is_file() => {
                // Go opens existing restore targets for writing before
                // truncating them. Preserve its permission failure instead
                // of replacing a read-only file through the parent directory.
                fs::OpenOptions::new()
                    .write(true)
                    .open(&target)
                    .map_err(create_error)?;
                mode(&metadata)
            }
            Ok(metadata) if metadata.is_dir() => {
                return Err(restore_error(format!(
                    "create file: open {}: is a directory",
                    shown.display()
                )));
            }
            Ok(_) => (header_mode as u32) & 0o600,
            Err(error) if error.kind() == io::ErrorKind::NotFound => (header_mode as u32) & 0o600,
            Err(error) => return Err(create_error(error)),
        };
        let mut tmp = tempfile::NamedTempFile::new_in(target.parent().unwrap_or(dest))
            .map_err(create_error)?;
        let (copied, hash) = copy_and_hash((&mut entry).take(size), &mut tmp).map_err(|error| {
            restore_error(format!("write file: {}", go_stream_error(&error, &failure)))
        })?;
        if copied != size {
            return Err(restore_error("write file: unexpected EOF"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp.as_file()
                .set_permissions(fs::Permissions::from_mode(m))
                .map_err(create_error)?;
        }
        let published = if overwrite {
            tmp.persist(&target)
        } else {
            tmp.persist_noclobber(&target)
        };
        published.map_err(|error| {
            if !overwrite && error.error.kind() == io::ErrorKind::AlreadyExists {
                ArchiveError::Exists(target.clone())
            } else {
                create_error(error.error)
            }
        })?;
        result.push(ArchiveEntry {
            path: clean,
            directory: false,
            mode: m,
            size,
            sha256: hash,
        });
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}
