//! Native file attachment add/get operations over the shared encrypted store.

use std::{
    fs,
    io::{Read, Write as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

#[cfg(not(windows))]
use std::io::{Seek, SeekFrom};

#[cfg(windows)]
use symvault_platform::windows_attachment as windows_file;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use symvault_crypto::Identity;
use symvault_store::{AttachmentInfo, Entry, StoreError};
use symvault_sync::{GoTime, safeio};

/// Go's `DefaultMaxAttachmentSize` (an `int64`: `--max-size` accepts negative values).
pub const DEFAULT_MAX_ATTACHMENT_SIZE: i64 = 1 << 20;

#[derive(Debug)]
pub struct AddOptions {
    pub path: String,
    pub field: String,
    pub source: PathBuf,
    pub secret_type: String,
    pub shred: bool,
}

/// A source file `file add` already read and size-checked.
#[derive(Debug)]
pub struct SourceFile {
    content: Vec<u8>,
    filename: String,
}

/// What Go's `runFileAdd` decides before it opens the vault, in its order: `--field` and
/// `--from` must be non-empty (invalid input, 9), the source must be stat-able (general
/// error, 1), its size must not exceed the signed `--max-size` (invalid input, 9; a
/// negative limit rejects every file) and it must be readable (1). The error is the exit
/// status and the message Go prints.
pub fn read_source(field: &str, source: &Path, max_size: i64) -> Result<SourceFile, (u8, String)> {
    if field.is_empty() {
        return Err((9, "--field is required".to_owned()));
    }
    if source.as_os_str().is_empty() {
        return Err((9, "--from is required".to_owned()));
    }
    let reason = |error: &std::io::Error| {
        crate::config::go_errno_text(error).map_or_else(|| error.to_string(), str::to_owned)
    };
    let metadata = fs::metadata(source).map_err(|error| {
        (
            1,
            format!(
                "cannot stat source file: stat {}: {}",
                source.display(),
                reason(&error)
            ),
        )
    })?;
    let exceeds = |size: u64| {
        (
            9,
            format!(
                "source file is {size} bytes, exceeds the {max_size} byte limit (override with --max-size)"
            ),
        )
    };
    if i128::from(metadata.len()) > i128::from(max_size) {
        return Err(exceeds(metadata.len()));
    }
    let read_failed = |error: &std::io::Error| {
        let text =
            crate::config::go_path_error(source, error, true).unwrap_or_else(|| error.to_string());
        (1, format!("cannot read source file: {text}"))
    };
    let source_file = fs::File::open(source).map_err(|error| read_failed(&error))?;
    let limit = u64::try_from(max_size).unwrap_or(0);
    let mut content = Vec::new();
    source_file
        .take(limit.saturating_add(1))
        .read_to_end(&mut content)
        .map_err(|error| read_failed(&error))?;
    if content.len() as u64 > limit {
        return Err(exceeds(content.len() as u64));
    }
    let filename = source
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| (1, "source path has no file name".to_owned()))?;
    Ok(SourceFile { content, filename })
}

#[derive(Debug, Eq, PartialEq)]
pub struct AddResult {
    pub filename: String,
    pub source: PathBuf,
    pub path: String,
    pub field: String,
    pub size: usize,
    pub sha256: String,
    pub shredded: bool,
}

#[derive(Debug)]
pub struct GetOptions {
    pub query: String,
    pub field: String,
    pub output: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
pub struct GetResult {
    pub path: String,
    pub field: String,
    pub output: PathBuf,
    pub size: usize,
}

pub struct AttachmentRead {
    pub path: String,
    pub field: String,
    pub content: Vec<u8>,
    pub attachment: Option<AttachmentInfo>,
}

#[derive(Debug)]
pub struct UseOptions {
    pub query: String,
    pub field: String,
    pub as_name: String,
    pub timeout: Option<Duration>,
    pub command: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct UseResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub timed_out: bool,
}

struct MaterializedFile {
    directory: PathBuf,
    path: PathBuf,
    handle: fs::File,
    length: u64,
}

pub fn add(
    root: &Path,
    identity: &Identity,
    options: &AddOptions,
    file: SourceFile,
) -> Result<AddResult, String> {
    let SourceFile { content, filename } = file;
    let sha256 = digest(&content);
    let encoded = STANDARD.encode(&content);
    let source = options.source.clone();

    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| error.to_string())?;
    let mut entry = match store.get(&options.path, identity) {
        Ok(entry) => entry,
        Err(StoreError::EntryNotFound(_)) => Entry::default(),
        Err(error) => return Err(format!("cannot read entry: {error}")),
    };
    entry
        .data
        .insert(options.field.clone(), Value::String(encoded));
    entry.secret_metadata.attachments.insert(
        options.field.clone(),
        AttachmentInfo {
            filename: filename.clone(),
            size: content.len() as i64,
            sha256: sha256.clone(),
        },
    );
    if entry.secret_metadata.secret_type.is_empty() {
        entry.secret_metadata.secret_type = options.secret_type.clone();
    }
    // Go's file add mutates Version before WriteEntry, whose preparation
    // increments it again. Preserve that observable two-step update.
    entry.metadata.version = entry.metadata.version.wrapping_add(1);
    // Go's file command calls WriteEntry directly, so it does not add a
    // pending write-history record here.
    store
        .write_entry_with_recipients_at(
            &options.path,
            &entry,
            identity,
            &GoTime::now().to_rfc3339_nano(),
            None,
        )
        .map_err(|error| format!("cannot write attachment: {error}"))?;
    crate::write_commands::auto_commit(
        &store,
        identity,
        &options.path,
        &format!("Attach {} to", filename),
    );

    let shredded = if options.shred {
        shred_source(&options.source)
    } else {
        false
    };
    Ok(AddResult {
        filename,
        source,
        path: options.path.clone(),
        field: options.field.clone(),
        size: content.len(),
        sha256,
        shredded,
    })
}

pub fn get(root: &Path, identity: &Identity, options: &GetOptions) -> Result<GetResult, String> {
    let read = read_attachment(root, identity, &options.query, &options.field)?;
    if let Some(attachment) = &read.attachment {
        let actual = digest(&read.content);
        if actual != attachment.sha256 {
            eprintln!(
                "Warning: sha256 mismatch for {}#{} (expected {}, got {actual})",
                read.path, read.field, attachment.sha256
            );
        }
    }
    safeio::write_atomic(&options.output, &read.content)
        .map_err(|error| format!("cannot write output file: {error}"))?;
    Ok(GetResult {
        path: read.path,
        field: read.field,
        output: options.output.clone(),
        size: read.content.len(),
    })
}

pub fn read_attachment(
    root: &Path,
    identity: &Identity,
    query: &str,
    requested_field: &str,
) -> Result<AttachmentRead, String> {
    let (path, explicit_field) = split_path_field(query);
    // A field embedded in PATH#FIELD is the Go command's primary selector;
    // --field is only used when the query has no embedded field.
    let field = if explicit_field.is_empty() {
        requested_field.to_owned()
    } else {
        explicit_field
    };
    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| error.to_string())?;
    let entry = store
        .get(&path, identity)
        .map_err(|error| format!("cannot read entry: {error}"))?;
    let (field, attachment) = resolve_attachment_field(&entry, &field)?;
    let content = decode_attachment_content(&entry, &field)?;
    Ok(AttachmentRead {
        path,
        field,
        content,
        attachment,
    })
}

pub fn use_attachment(
    root: &Path,
    identity: &Identity,
    options: &UseOptions,
) -> Result<UseResult, String> {
    if options.command.is_empty() {
        return Err("command must contain at least one element".to_owned());
    }
    let read = read_attachment(root, identity, &options.query, &options.field)?;
    let name = if options.as_name.is_empty() {
        read.field.to_uppercase()
    } else {
        options.as_name.clone()
    };
    if !is_safe_file_name(&name) {
        return Err(format!(
            "invalid file name {name:?}: must match [A-Za-z0-9_]+"
        ));
    }
    let materialized = materialize_file(&name, &read.content)?;
    let result = run_file_command(
        &options.command,
        &materialized.path,
        &name,
        &read.content,
        options.timeout,
    );
    let cleanup = cleanup_file(materialized);
    match result {
        Ok(result) if result.exit_code != 0 => {
            if let Err(cleanup_error) = cleanup {
                eprintln!("Warning: {cleanup_error}");
            }
            Ok(result)
        }
        Ok(result) => cleanup.map(|()| result),
        Err(error) => {
            if let Err(cleanup_error) = cleanup {
                eprintln!("Warning: {cleanup_error}");
            }
            Err(error)
        }
    }
}

fn is_safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

static FILE_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn materialize_file(name: &str, content: &[u8]) -> Result<MaterializedFile, String> {
    let base = std::env::temp_dir();
    let mut directory = None;
    for _ in 0..64 {
        let sequence = FILE_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = base.join(format!("symvault-file-{}-{sequence}", std::process::id()));
        match create_private_directory(&candidate) {
            Ok(()) => {
                directory = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("create ephemeral file directory: {error}")),
        }
    }
    let directory = directory.ok_or_else(|| {
        "create ephemeral file directory: temporary name space exhausted".to_owned()
    })?;
    let file = directory.join(name);
    let handle = match write_private_file(&file, content) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = fs::remove_file(&file);
            let _ = fs::remove_dir(&directory);
            return Err(format!("materialize file {name:?}: {error}"));
        }
    };
    Ok(MaterializedFile {
        directory,
        path: file,
        handle,
        length: content.len() as u64,
    })
}

#[cfg(not(windows))]
fn cleanup_file(materialized: MaterializedFile) -> Result<(), String> {
    let MaterializedFile {
        directory,
        path,
        mut handle,
        length,
    } = materialized;
    // Write through the descriptor opened before the child ran. The child may
    // replace the pathname with a symlink or another file, but cannot redirect
    // this handle. The zero buffer and original length keep cleanup bounded.
    let zeros = [0u8; 8192];
    let _ = handle.seek(SeekFrom::Start(0));
    let mut remaining = length;
    while remaining > 0 {
        let count = remaining.min(zeros.len() as u64) as usize;
        if handle.write_all(&zeros[..count]).is_err() {
            break;
        }
        remaining -= count as u64;
    }
    let _ = handle.sync_all();
    drop(handle);
    // remove_file unlinks a child-created symlink; it never follows it. If the
    // child installed a directory at this path, leave it rather than recurse.
    let _ = fs::remove_file(path);
    let _ = fs::remove_dir(directory);
    Ok(())
}

#[cfg(windows)]
fn cleanup_file(materialized: MaterializedFile) -> Result<(), String> {
    let MaterializedFile {
        directory,
        handle,
        length,
        ..
    } = materialized;
    // Delete the retained object itself; never resolve the child-controlled
    // file pathname again, even if its parent was replaced with a junction.
    windows_file::shred_and_delete(handle, length)
        .map_err(|error| format!("secure attachment cleanup failed: {error}"))?;
    let _ = fs::remove_dir(directory);
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn write_private_file(path: &Path, content: &[u8]) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(file)
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, content: &[u8]) -> std::io::Result<fs::File> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    #[cfg(windows)]
    return windows_file::shareable_guard(file);
    #[cfg(not(windows))]
    Ok(file)
}

fn run_file_command(
    command: &[String],
    file: &Path,
    name: &str,
    content: &[u8],
    timeout: Option<Duration>,
) -> Result<UseResult, String> {
    const FILE_ENV_WHITELIST: &[&str] = &[
        "PATH",
        "HOME",
        "USERPROFILE",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "SystemRoot",
    ];
    let environment = std::collections::BTreeMap::new();
    let extra_environment = [(
        std::ffi::OsString::from(format!("SYMVAULT_FILE_{name}")),
        file.as_os_str().to_os_string(),
    )];
    let redactions = vec![content.to_vec(), STANDARD.encode(content).into_bytes()];
    let result = crate::run_commands::run_process(crate::run_commands::ProcessOptions {
        command,
        environment: &environment,
        files: &std::collections::BTreeMap::new(),
        extra_environment: &extra_environment,
        passthrough: &[],
        working_directory: None,
        timeout,
        redactions: &redactions,
        generic_redaction: false,
        whitelist: FILE_ENV_WHITELIST,
    })?;
    if result.timed_out {
        return Err(format!(
            "command timed out after {}",
            crate::run_commands::format_timeout(timeout.unwrap_or_default())
        ));
    }
    Ok(UseResult {
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
        timed_out: result.timed_out,
    })
}

fn split_path_field(query: &str) -> (String, String) {
    query
        .rfind('#')
        .filter(|index| *index > 0)
        .map(|index| (query[..index].to_owned(), query[index + 1..].to_owned()))
        .unwrap_or_else(|| (query.to_owned(), String::new()))
}

fn resolve_attachment_field(
    entry: &Entry,
    explicit: &str,
) -> Result<(String, Option<AttachmentInfo>), String> {
    if !explicit.is_empty() {
        return Ok((
            explicit.to_owned(),
            entry.secret_metadata.attachments.get(explicit).cloned(),
        ));
    }
    match entry.secret_metadata.attachments.len() {
        0 => Err("entry has no recorded attachment fields; specify --field".to_owned()),
        1 => entry
            .secret_metadata
            .attachments
            .iter()
            .next()
            .map(|(field, info)| (field.clone(), Some(info.clone())))
            .ok_or_else(|| "entry has no recorded attachment fields; specify --field".to_owned()),
        _ => {
            let mut fields: Vec<_> = entry.secret_metadata.attachments.keys().cloned().collect();
            fields.sort();
            Err(format!(
                "entry has multiple attachment fields ({}); specify --field",
                fields.join(", ")
            ))
        }
    }
}

fn decode_attachment_content(entry: &Entry, field: &str) -> Result<Vec<u8>, String> {
    let raw = entry
        .data
        .get(field)
        .ok_or_else(|| format!("field {field:?} not found in entry"))?;
    let encoded = raw
        .as_str()
        .ok_or_else(|| format!("field {field:?} is not string-encoded content"))?;
    let encoded = if let Some(manifest) = encoded.strip_prefix("chunked-v1:") {
        if manifest.is_empty() {
            return Err(format!(
                "invalid chunk manifest in field {field:?}: no chunks specified"
            ));
        }
        let mut combined = String::new();
        let chunk_names: Vec<_> = manifest.split(',').collect();
        for count_key in [format!("{field}_chunk_count"), "chunk_count".to_owned()] {
            if let Some(value) = entry.data.get(&count_key) {
                let expected = value
                    .as_i64()
                    .or_else(|| value.as_u64().map(|value| value as i64))
                    .or_else(|| value.as_f64().map(|value| value as i64))
                    .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                    .unwrap_or_default();
                if expected > 0 && expected as usize != chunk_names.len() {
                    return Err(format!(
                        "chunk count mismatch for field {field:?}: manifest lists {} chunks, entry specifies {expected}",
                        chunk_names.len()
                    ));
                }
            }
        }
        for chunk in chunk_names {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                return Err(format!(
                    "invalid chunk manifest in field {field:?}: empty chunk name"
                ));
            }
            let raw = entry
                .data
                .get(chunk)
                .ok_or_else(|| format!("chunk field {chunk:?} not found in entry"))?;
            let value = raw
                .as_str()
                .ok_or_else(|| format!("chunk field {chunk:?} is not string-encoded content"))?;
            combined.push_str(value);
        }
        combined
    } else {
        encoded.to_owned()
    };
    // Go's StdEncoding ignores CR/LF inserted into a base64 stream.
    let encoded: String = encoded
        .bytes()
        .filter(|byte| !matches!(byte, b'\r' | b'\n'))
        .map(char::from)
        .collect();
    STANDARD
        .decode(encoded)
        .map_err(|error| format!("decode attachment content: {error}"))
}

fn digest(content: &[u8]) -> String {
    Sha256::digest(content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn shred_source(path: &Path) -> bool {
    if let Ok(length) = fs::metadata(path).map(|metadata| metadata.len() as usize)
        && let Ok(file) = fs::OpenOptions::new().write(true).open(path)
    {
        let _ = file.set_len(length as u64);
        let _ = (&file).write_all(&vec![0u8; length]);
        let _ = file.sync_all();
    }
    fs::remove_file(path).is_ok()
}
