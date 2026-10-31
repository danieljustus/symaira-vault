use crate::gzip_multistream::GoGzip;
use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Seek, Write},
    path::{Component, Path, PathBuf},
};
use tar::{Archive, Builder, EntryType, Header};
use thiserror::Error;

/// Deliberate safety limit with no production-Go equivalent (Go restores any
/// number of members). It is enforced by a header-only pre-pass in `restore`
/// before the first member is written, so an over-limit archive leaves no
/// partial tree. Recorded as an unapproved divergence in the IO-002 row.
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
pub fn go_path_clean(path: &[u8]) -> Vec<u8> {
    if path.is_empty() {
        return b".".to_vec();
    }
    let rooted = path.starts_with(b"/");
    let mut stack: Vec<&[u8]> = Vec::new();
    for part in path.split(|byte| *byte == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                if stack.last().is_some_and(|last| *last != b"..") {
                    stack.pop();
                } else if !rooted {
                    stack.push(b"..");
                }
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join(&b'/');
    match (rooted, joined.is_empty()) {
        (true, _) => [b"/".as_slice(), &joined].concat(),
        (false, true) => b".".to_vec(),
        (false, false) => joined,
    }
}

/// `cleanBackupMemberName` from cmd/admin/backup.go, including its error text.
/// Works on the raw header bytes so a non-UTF-8 name reaches the OS unchanged
/// (Go passes the bytes through; macOS then answers `illegal byte sequence`).
fn go_clean_member_name(name: &[u8]) -> Result<Vec<u8>, String> {
    let shown = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    if name.is_empty() || name == b"." || name.contains(&b'\\') {
        return Err(format!("archive contains unsafe path: {}", shown(name)));
    }
    if name.starts_with(b"/") || (name.len() >= 2 && name[1] == b':') {
        return Err(format!("archive contains absolute path: {}", shown(name)));
    }
    let name = name.strip_suffix(b"/").unwrap_or(name);
    let clean = go_path_clean(name);
    if clean == b"." || clean != name || clean == b".." || clean.starts_with(b"../") {
        return Err(format!("archive contains path traversal: {}", shown(name)));
    }
    Ok(clean)
}

/// The path a cleaned member name denotes. Unix keeps the raw bytes so the
/// operating system, not a lossy conversion, decides whether the name is legal.
fn member_path(clean: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        PathBuf::from(std::ffi::OsStr::from_bytes(clean))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(clean).into_owned())
    }
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
                return Err((current, not_a_directory_reason().to_owned()));
            }
            Ok(_) => {}
        }
    }
    Ok(())
}

/// Go's reason when a path component exists but is not a directory. Unix
/// reports `syscall.ENOTDIR`; the Windows `SafeMkdirAll` (corekit
/// `fsutil/safewrite_windows.go`) returns `errUnsafePath` instead.
const fn not_a_directory_reason() -> &'static str {
    if cfg!(windows) {
        "path is not a regular file"
    } else {
        "not a directory"
    }
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

/// What Go's `Reader.readHeader` derives from one header block beyond what
/// the tar crate exposes.
struct GoHeader {
    mode: i64,
    /// USTAR prefix Go prepends to a GNU header whose atime/ctime does not
    /// parse (the format is demoted and the prefix field, which overlaps
    /// those GNU fields, is read). Empty otherwise.
    gnu_demoted_prefix: Vec<u8>,
}

/// Go's `Reader.readHeader` numeric parsing: size, mode, uid, gid and mtime
/// always; devmajor/devminor from USTAR on; STAR atime/ctime. Any failure is
/// the one sticky `ErrHeader`. A bad GNU atime/ctime is not an error: Go
/// drops the times, demotes the format and joins the ASCII USTAR prefix.
fn go_header(header: &Header) -> Result<GoHeader, ()> {
    let block = header.as_bytes();
    let field = |start: usize, len: usize| &block[start..start + len];
    let magic = field(257, 6);
    let star = magic == b"ustar\0" && field(508, 4) == b"tar\0";
    let ustar = magic == b"ustar\0";
    let gnu = magic == b"ustar " && field(263, 2) == b" \0";
    let mut numeric = vec![(124, 12), (100, 8), (108, 8), (116, 8), (136, 12)];
    if ustar || gnu {
        numeric.extend([(329, 8), (337, 8)]);
    }
    if star {
        numeric.extend([(476, 12), (488, 12)]);
    }
    for (start, len) in numeric {
        go_parse_numeric(field(start, len))?;
    }
    let mut gnu_demoted_prefix = Vec::new();
    if gnu && !star {
        let demoted = [345, 357].into_iter().any(|start| {
            let time = field(start, 12);
            time[0] != 0 && go_parse_numeric(time).is_err()
        });
        if demoted {
            let prefix = field(345, 155);
            let prefix = prefix
                .iter()
                .position(|byte| *byte == 0)
                .map_or(prefix, |nul| &prefix[..nul]);
            if prefix.is_ascii() {
                gnu_demoted_prefix = prefix.to_vec();
            }
        }
    }
    Ok(GoHeader {
        mode: go_parse_numeric(field(100, 8))?,
        gnu_demoted_prefix,
    })
}

/// Go's `parser.parseNumeric`: base-256 when the high bit is set (the sign
/// bit makes the value negative), otherwise `parseOctal`.
fn go_parse_numeric(field: &[u8]) -> Result<i64, ()> {
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
    go_parse_octal(field)
}

/// Go's `parser.parseOctal`: trim spaces and NULs at both ends, then
/// `strconv.ParseUint(parseString(b), 8, 64)`, where `parseString` cuts at the
/// first remaining NUL. Only unsigned base-8 digits are accepted (no sign,
/// prefix or separators), and the unsigned result is reinterpreted as `int64`.
fn go_parse_octal(field: &[u8]) -> Result<i64, ()> {
    let is_padding = |byte: &u8| *byte == b' ' || *byte == 0;
    let start = field.iter().position(|byte| !is_padding(byte));
    let Some(start) = start else {
        return Ok(0);
    };
    let end = field
        .iter()
        .rposition(|byte| !is_padding(byte))
        .map_or(0, |index| index + 1);
    let trimmed = &field[start..end];
    let digits = trimmed
        .iter()
        .position(|byte| *byte == 0)
        .map_or(trimmed, |nul| &trimmed[..nul]);
    let mut value: u64 = 0;
    for byte in digits {
        if !(b'0'..=b'7').contains(byte) {
            return Err(());
        }
        value = value
            .checked_mul(8)
            .and_then(|shifted| shifted.checked_add(u64::from(byte - b'0')))
            .ok_or(())?;
    }
    Ok(value as i64)
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
        // Framing errors raised by the multistream reader carry Go's text.
        if message == "gzip: invalid header" || message == "gzip: invalid checksum" {
            return message.clone();
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

/// Opens an existing restore target for writing without following a symlink.
fn open_existing_for_write(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    options.open(path)
}

/// Creates an exclusive (`O_EXCL`, mode 0600) staging file next to the target.
/// Opened directly rather than through `tempfile::NamedTempFile`, which wraps
/// the `io::Error` and drops the errno Go's lowercase reason text derives from.
fn create_staging(dir: &Path) -> io::Result<(fs::File, tempfile::TempPath)> {
    let mut last = io::Error::from(io::ErrorKind::AlreadyExists);
    for _ in 0..32 {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let path = dir.join(format!(".symvault-restore-{}", hex::encode(random)));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                return match tempfile::TempPath::try_from_path(&path) {
                    Ok(guard) => Ok((file, guard)),
                    Err(error) => {
                        let _ = fs::remove_file(&path);
                        Err(error)
                    }
                };
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last = error,
            Err(error) => return Err(error),
        }
    }
    Err(last)
}

/// True when the first header block of `entry` carries the legacy `\0`
/// typeflag (Go's `TypeRegA`).
fn is_legacy_regular<R: Read>(entry: &tar::Entry<'_, R>) -> bool {
    entry.header().as_bytes()[156] == 0
}

/// Fails with [`ArchiveError::Limit`] before any member is written when the
/// archive holds more than `MAX_ARCHIVE_ENTRIES` members. Only headers are
/// counted; a read error ends the count so the extraction pass reports it with
/// Go's wording and ordering.
fn check_entry_limit(input: &Path) -> Result<(), ArchiveError> {
    let Ok(file) = fs::File::open(input) else {
        return Ok(());
    };
    scan_entry_limit(GoGzip::new(file), MAX_ARCHIVE_FILE, MAX_ARCHIVE_TOTAL)
}

/// Counts tar headers in `reader` (an already-inflated tar stream).
///
/// Skipping a member body means inflating it, so the scan stops with `Ok(())`
/// at the first regular member whose declared size exceeds `max_file`, or
/// whose size pushes the declared total past `max_total`. The extraction pass
/// rejects that very header (as Go does) before reading its body, so nothing
/// beyond it can be written and the oversized body is never inflated here.
fn scan_entry_limit<R: Read>(reader: R, max_file: u64, max_total: u64) -> Result<(), ArchiveError> {
    let mut archive = Archive::new(reader);
    let Ok(entries) = archive.entries() else {
        return Ok(());
    };
    let mut total = 0u64;
    for (index, item) in entries.enumerate() {
        let Ok(entry) = item else {
            return Ok(());
        };
        if index >= MAX_ARCHIVE_ENTRIES {
            return Err(ArchiveError::Limit);
        }
        // Mirrors the extraction pass: only regular files carry a size check.
        let is_dir = entry.header().entry_type() == EntryType::Directory
            || (is_legacy_regular(&entry) && entry.path_bytes().ends_with(b"/"));
        if is_dir || entry.header().entry_type() != EntryType::Regular {
            continue;
        }
        let size = entry.size();
        if size > max_file || size > max_total || total > max_total - size {
            return Ok(());
        }
        total += size;
    }
    Ok(())
}

/// Restores a gzip tar backup into an existing or newly created directory.
///
/// The gzip layer is multistream like Go's `gzip.Reader` (see
/// `gzip_multistream`): concatenated members are one tar stream.
///
/// Error text and extraction order follow `cmd/admin.RestoreBackup` (see
/// `testdata/port/sync/restore-errors.json`). Deliberate differences, all
/// recorded in the IO-002 contract row: a member is staged and renamed into
/// place, so a truncated member never leaves the partial file Go's in-place
/// `O_TRUNC` write does (when the directory is not writable, an existing
/// writable regular file is rewritten in place instead, as Go does); and an
/// archive with more than `MAX_ARCHIVE_ENTRIES` members is rejected up front
/// (the header-only pre-pass never inflates a member that extraction rejects).
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
    check_entry_limit(input)?;
    let file = fs::File::open(input).map_err(|error| {
        restore_error(format!(
            "open archive: open {}: {}",
            input.display(),
            go_reason(&error)
        ))
    })?;
    let failure = Failure::default();
    // Go's gzip.Reader is multistream and validates the first header eagerly.
    let mut gzip = GoGzip::new(file);
    gzip.read_first_header()
        .map_err(|reason| restore_error(format!("read gzip: {reason}")))?;
    let decoder = Tracked {
        inner: gzip,
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
    for item in entries {
        let mut entry = item.map_err(|error| read_error(&error))?;
        // Go parses the numeric header fields while reading the header, so a
        // malformed mode wins over any name error.
        let go_header = go_header(entry.header())
            .map_err(|()| restore_error("read archive: archive/tar: invalid tar header"))?;
        let header_mode = go_header.mode;
        let mut raw_name = entry.path_bytes().into_owned();
        // ponytail: a GNU long name or PAX path replaces the header name in
        // Go, prefix included; treat "differs from the header's own name" as
        // that override (a long name equal to the header name is misread).
        if !go_header.gnu_demoted_prefix.is_empty()
            && raw_name.as_slice() == entry.header().path_bytes().as_ref()
        {
            let mut joined = go_header.gnu_demoted_prefix;
            joined.push(b'/');
            joined.extend_from_slice(&raw_name);
            raw_name = joined;
        }
        let name = String::from_utf8_lossy(&raw_name).into_owned();
        let clean_bytes = go_clean_member_name(&raw_name).map_err(restore_error)?;
        let clean = String::from_utf8_lossy(&clean_bytes).into_owned();
        let rel = member_path(&clean_bytes);
        let target = dest.join(&rel);
        let shown = lexical_clean(&target);
        if fs::symlink_metadata(&target).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(restore_error(format!(
                "target path is a symlink: {}",
                shown.display()
            )));
        }
        let kind = entry.header().entry_type();
        // Go's reader maps a legacy `\0` typeflag to a directory when the
        // (final) name ends in a slash, and to a regular file otherwise.
        let is_dir = kind == EntryType::Directory
            || (kind == EntryType::Regular
                && is_legacy_regular(&entry)
                && raw_name.ends_with(b"/"));
        if is_dir {
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
        // Existing regular file: Go opens it for writing before truncating, so
        // a permission failure is reported (and nothing is replaced through the
        // parent directory). The handle is kept for the in-place fallback.
        let (m, existing) = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.is_file() => {
                let handle = open_existing_for_write(&target).map_err(create_error)?;
                (mode(&metadata), Some((metadata, handle)))
            }
            Ok(metadata) if metadata.is_dir() => {
                return Err(restore_error(format!(
                    "create file: open {}: is a directory",
                    shown.display()
                )));
            }
            Ok(_) => ((header_mode as u32) & 0o600, None),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                ((header_mode as u32) & 0o600, None)
            }
            Err(error) => return Err(create_error(error)),
        };
        let parent = target.parent().unwrap_or(dest);
        let (_, hash) = match create_staging(parent) {
            Ok((mut staged, staged_path)) => {
                drop(existing);
                let outcome =
                    copy_and_hash((&mut entry).take(size), &mut staged).map_err(|error| {
                        restore_error(format!("write file: {}", go_stream_error(&error, &failure)))
                    })?;
                if outcome.0 != size {
                    return Err(restore_error("write file: unexpected EOF"));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    staged
                        .set_permissions(fs::Permissions::from_mode(m))
                        .map_err(create_error)?;
                }
                // Close before the rename so it also works where an open
                // file cannot be replaced.
                drop(staged);
                let published = if overwrite {
                    staged_path.persist(&target)
                } else {
                    staged_path.persist_noclobber(&target)
                };
                published.map_err(|error| {
                    if !overwrite && error.error.kind() == io::ErrorKind::AlreadyExists {
                        ArchiveError::Exists(target.clone())
                    } else {
                        create_error(error.error)
                    }
                })?;
                outcome
            }
            // A directory that cannot be written still lets Go rewrite a
            // writable file in place. Same target, same checks: the handle was
            // opened with NOFOLLOW and must still be that regular file.
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied && existing.is_some() => {
                let (metadata, mut handle) = existing.expect("checked above");
                if !same_regular_file(&metadata, &handle) {
                    return Err(create_error(error));
                }
                handle.set_len(0).map_err(create_error)?;
                let outcome =
                    copy_and_hash((&mut entry).take(size), &mut handle).map_err(|error| {
                        restore_error(format!("write file: {}", go_stream_error(&error, &failure)))
                    })?;
                if outcome.0 != size {
                    return Err(restore_error("write file: unexpected EOF"));
                }
                outcome
            }
            Err(error) => return Err(create_error(error)),
        };
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

/// The opened handle is still the regular file `lstat` saw (not swapped for a
/// symlink target or another inode between the two calls).
fn same_regular_file(before: &fs::Metadata, handle: &fs::File) -> bool {
    let Ok(after) = handle.metadata() else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        after.is_file() && before.dev() == after.dev() && before.ino() == after.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = before;
        after.is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::go_parse_octal;

    #[test]
    fn octal_mode_follows_go_parse_octal() {
        // Accepted: padding, NUL tail cut, 8 unterminated digits.
        assert_eq!(go_parse_octal(b"0000644\x00"), Ok(0o644));
        assert_eq!(go_parse_octal(b"\x00\x00\x00644\x00\x00"), Ok(0o644));
        assert_eq!(go_parse_octal(b"  644   "), Ok(0o644));
        assert_eq!(go_parse_octal(b"644\x00777\x00"), Ok(0o644));
        assert_eq!(go_parse_octal(b"644\x00zz\x00\x00"), Ok(0o644));
        assert_eq!(go_parse_octal(b"77777777"), Ok(0o7777_7777));
        assert_eq!(go_parse_octal(b"        "), Ok(0));
        assert_eq!(go_parse_octal(b"\x00\x00\x00\x00\x00\x00\x00\x00"), Ok(0));
        // Rejected: signs (even zero), embedded spaces, prefixes,
        // separators, non-octal digits, bad head before a NUL.
        for field in [
            &b"+000644\x00"[..],
            b"+0\x00\x00\x00\x00\x00\x00",
            b"-000001\x00",
            b"-0\x00\x00\x00\x00\x00\x00",
            b" 6 4 4  ",
            b"0o644\x00\x00\x00",
            b"6_44\x00\x00\x00\x00",
            b"0000888\x00",
            b"6z4\x00644\x00",
        ] {
            assert_eq!(go_parse_octal(field), Err(()), "{field:?}");
        }
    }
}

#[cfg(test)]
#[path = "archive_entry_limit_tests.rs"]
mod entry_limit_scan_tests;
