//! Native file attachment add/get operations over the shared encrypted store.

use std::{
    fs,
    io::{Read, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use symvault_crypto::Identity;
use symvault_store::{AttachmentInfo, Entry, Store, StoreError};
use symvault_sync::{GoTime, safeio};

pub const DEFAULT_MAX_ATTACHMENT_SIZE: u64 = 1 << 20;

#[derive(Debug)]
pub struct AddOptions {
    pub path: String,
    pub field: String,
    pub source: PathBuf,
    pub secret_type: String,
    pub max_size: u64,
    pub shred: bool,
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

pub fn add(root: &Path, identity: &Identity, options: &AddOptions) -> Result<AddResult, String> {
    if options.field.is_empty() {
        return Err("--field is required".to_owned());
    }
    let metadata = fs::metadata(&options.source)
        .map_err(|error| format!("cannot stat source file: {error}"))?;
    if metadata.len() > options.max_size {
        return Err(format!(
            "source file is {} bytes, exceeds the {} byte limit (override with --max-size)",
            metadata.len(),
            options.max_size
        ));
    }
    let source_file = fs::File::open(&options.source)
        .map_err(|error| format!("cannot read source file: {error}"))?;
    let mut content = Vec::new();
    source_file
        .take(options.max_size.saturating_add(1))
        .read_to_end(&mut content)
        .map_err(|error| format!("cannot read source file: {error}"))?;
    if content.len() as u64 > options.max_size {
        return Err(format!(
            "source file is {} bytes, exceeds the {} byte limit (override with --max-size)",
            content.len(),
            options.max_size
        ));
    }
    let filename = options
        .source
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| "source path has no file name".to_owned())?;
    let sha256 = digest(&content);
    let encoded = STANDARD.encode(&content);
    let source = options.source.clone();

    let store = Store::open(root, identity).map_err(|error| error.to_string())?;
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
    let store = Store::open(root, identity).map_err(|error| error.to_string())?;
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
    let (directory, file) = materialize_file(&name, &read.content)?;
    let result = run_file_command(
        &options.command,
        &file,
        &name,
        &read.content,
        options.timeout,
    );
    cleanup_file(&directory, &file);
    result
}

fn is_safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

static FILE_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn materialize_file(name: &str, content: &[u8]) -> Result<(PathBuf, PathBuf), String> {
    let base = std::env::temp_dir();
    let mut directory = None;
    for _ in 0..64 {
        let sequence = FILE_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = base.join(format!("symvault-file-{}-{sequence}", std::process::id()));
        match fs::create_dir(&candidate) {
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
    if let Err(error) = set_private_directory(&directory) {
        let _ = fs::remove_dir(&directory);
        return Err(format!("secure ephemeral file directory: {error}"));
    }
    let file = directory.join(name);
    if let Err(error) = write_private_file(&file, content) {
        let _ = fs::remove_dir(&directory);
        return Err(format!("materialize file {name:?}: {error}"));
    }
    Ok((directory, file))
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_private_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(content)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(content)?;
    file.sync_all()
}

fn cleanup_file(directory: &Path, file: &Path) {
    if let Ok(length) = fs::metadata(file).map(|metadata| metadata.len() as usize)
        && let Ok(handle) = fs::OpenOptions::new().write(true).open(file)
    {
        let _ = (&handle).write_all(&vec![0u8; length]);
        let _ = handle.sync_all();
    }
    let _ = fs::remove_file(file);
    let _ = fs::remove_dir(directory);
}

fn run_file_command(
    command: &[String],
    file: &Path,
    name: &str,
    content: &[u8],
    timeout: Option<Duration>,
) -> Result<UseResult, String> {
    let mut child_command = Command::new(&command[0]);
    child_command.args(&command[1..]);
    child_command.env_clear();
    for key in [
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
    ] {
        if let Some(value) = std::env::var_os(key) {
            child_command.env(key, value);
        }
    }
    child_command.env(format!("SYMVAULT_FILE_{name}"), file);
    child_command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = child_command
        .spawn()
        .map_err(|error| format!("failed to run command: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture command stdout".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture command stderr".to_owned())?;
    let stdout_reader = thread::spawn(|| read_output(stdout));
    let stderr_reader = thread::spawn(|| read_output(stderr));
    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if timeout.is_some_and(|limit| started.elapsed() >= limit) {
                    timed_out = true;
                    let _ = child.kill();
                    break child
                        .wait()
                        .map_err(|error| format!("wait for timed out command: {error}"))?;
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(format!("wait for command: {error}")),
        }
    };
    let (stdout, _) = stdout_reader
        .join()
        .map_err(|_| "command stdout reader failed".to_owned())?;
    let (stderr, _) = stderr_reader
        .join()
        .map_err(|_| "command stderr reader failed".to_owned())?;
    if timed_out {
        return Err(format!(
            "command timed out after {}",
            format_timeout(timeout.unwrap_or_default())
        ));
    }
    let stdout = redact_output(&stdout, content);
    let stderr = redact_output(&stderr, content);
    Ok(UseResult {
        stdout,
        stderr,
        exit_code: status.code().unwrap_or(-1),
        timed_out,
    })
}

fn read_output(mut reader: impl Read) -> (Vec<u8>, bool) {
    const MAX_OUTPUT: usize = 100 * 1024;
    let mut captured = Vec::with_capacity(MAX_OUTPUT);
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let remaining = MAX_OUTPUT.saturating_sub(captured.len());
                captured.extend_from_slice(&buffer[..count.min(remaining)]);
                truncated |= count > remaining;
            }
            Err(_) => break,
        }
    }
    (captured, truncated)
}

fn redact_output(output: &[u8], content: &[u8]) -> String {
    let mut output = replace_bytes(output, content, b"***");
    let encoded = STANDARD.encode(content);
    output = replace_bytes(&output, encoded.as_bytes(), b"***");
    String::from_utf8_lossy(&output).into_owned()
}

fn replace_bytes(input: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return input.to_vec();
    }
    let mut result = Vec::with_capacity(input.len());
    let mut cursor = 0;
    while cursor < input.len() {
        if input[cursor..].starts_with(needle) {
            result.extend_from_slice(replacement);
            cursor += needle.len();
        } else {
            result.push(input[cursor]);
            cursor += 1;
        }
    }
    result
}

fn format_timeout(timeout: Duration) -> String {
    if timeout.as_secs() > 0 {
        format!("{}s", timeout.as_secs())
    } else {
        format!("{}ms", timeout.as_millis())
    }
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
