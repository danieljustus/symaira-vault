//! Non-interactive entry editing through a temporary JSON document.
//!
//! The Go command delegates the actual editing to an external editor. This
//! module keeps that boundary explicit: the editor receives one private file,
//! and the resulting JSON is validated before the encrypted entry is written.

use std::{
    env, fs,
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use symvault_crypto::Identity;
use symvault_store::{Entry, StoreError};
use symvault_sync::{GoTime, safeio};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
const MAX_EDIT_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct EditOptions {
    pub path: String,
    pub editor: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct EditResult {
    pub path: String,
}

/// Edits an existing entry with an external editor and persists the result.
pub fn edit(root: &Path, identity: &Identity, options: &EditOptions) -> Result<EditResult, String> {
    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| error.to_string())?;
    let entry = store
        .get(&options.path, identity)
        .map_err(|error| match error {
            StoreError::EntryNotFound(_) => format!("entry not found: {}", options.path),
            error => format!("cannot read entry {}: {error}", options.path),
        })?;

    let initial =
        serde_json::to_vec_pretty(&entry).map_err(|error| format!("encode entry: {error}"))?;
    let mut initial = initial;
    initial.push(b'\n');
    let (temp_path, temp_file) = create_temp_file(&initial)?;
    drop(temp_file);

    let result = (|| {
        let editor = resolve_editor(&options.editor)?;
        let status = editor_command(&editor, &temp_path)
            .status()
            .map_err(|error| format!("editor failed: {error}"))?;
        if !status.success() {
            return Err(format!("editor failed: {status}"));
        }

        let data = safeio::read_bounded(&temp_path, MAX_EDIT_FILE_BYTES)
            .map_err(|error| format!("read edited file: {error}"))?
            .ok_or_else(|| "read edited file: file not found".to_owned())?;
        let data = trim_ascii_whitespace(&data);
        if data.is_empty() {
            return Err("empty file, changes discarded".to_owned());
        }
        let mut edited: Entry =
            serde_json::from_slice(data).map_err(|error| format!("invalid JSON: {error}"))?;
        // Entry's deserializer already supplies an empty map for omitted/null
        // data. Keep this assignment explicit as the Go editor does.
        if edited.data.is_empty() {
            edited.data = Default::default();
        }
        store
            .write_entry_with_recipients_at(
                &options.path,
                &edited,
                identity,
                &GoTime::now().to_rfc3339_nano(),
                None,
            )
            .map_err(|error| format!("cannot save entry: {error}"))?;
        crate::write_commands::auto_commit(&store, identity, &options.path, "Edit");
        Ok(EditResult {
            path: options.path.clone(),
        })
    })();

    // Match secureedit's deferred cleanup contract. Cleanup errors are not
    // allowed to replace the editor, parse, or store result.
    let _ = safeio::secure_delete(&temp_path, MAX_EDIT_FILE_BYTES);
    result
}

fn trim_ascii_whitespace(data: &[u8]) -> &[u8] {
    let start = data
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(data.len());
    let end = data[..]
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &data[start..end]
}

pub(crate) fn create_temp_file(data: &[u8]) -> Result<(PathBuf, fs::File), String> {
    let temp_dir = env::temp_dir();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("create temp file: {error}"))?
        .as_nanos();
    for _ in 0..100 {
        let suffix = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = temp_dir.join(format!("symvault-edit-{stamp}-{suffix}.json"));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                if let Err(error) = file.write_all(data).and_then(|()| file.sync_all()) {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(format!("write temp file: {error}"));
                }
                return Ok((path, file));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("create temp file: {error}")),
        }
    }
    Err("create temp file: could not allocate a unique path".to_owned())
}

pub(crate) fn resolve_editor(preferred: &str) -> Result<String, String> {
    if !preferred.is_empty() {
        return command_path(preferred)
            .map(|path| path.to_string_lossy().into_owned())
            .ok_or_else(|| format!("editor {preferred:?} not found in PATH"));
    }
    if let Some(editor) = env::var_os("EDITOR").filter(|value| !value.is_empty()) {
        let editor = editor
            .into_string()
            .map_err(|_| "EDITOR must be valid UTF-8".to_owned())?;
        return command_path(&editor)
            .map(|path| path.to_string_lossy().into_owned())
            .ok_or_else(|| format!("editor {editor:?} not found in PATH"));
    }
    for candidate in ["vim", "nano", "vi"] {
        if command_path(candidate).is_some() {
            return Ok(candidate.to_owned());
        }
    }
    Err("no editor found on PATH (tried [\"vim\", \"nano\", \"vi\"]); set $EDITOR to a valid editor".to_owned())
}

fn command_path(command: &str) -> Option<PathBuf> {
    let path = Path::new(command);
    if path.components().count() > 1 {
        return executable_candidate(path);
    }
    let path_var = env::var_os("PATH")?;
    for directory in env::split_paths(&path_var) {
        let candidate = directory.join(command);
        if let Some(candidate) = executable_candidate(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn executable_candidate(path: &Path) -> Option<PathBuf> {
    if is_executable(path) {
        return Some(path.to_path_buf());
    }
    #[cfg(windows)]
    if path.extension().is_none() {
        let extensions = env::var_os("PATHEXT")
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_owned());
        for extension in extensions
            .split(';')
            .filter(|extension| !extension.is_empty())
        {
            let candidate = path.with_extension(extension.trim_start_matches('.'));
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_file()
        && fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

pub(crate) fn editor_command(editor: &str, path: &Path) -> Command {
    let mut command = Command::new(editor);
    command.arg(path);
    // The Go command prepares the child environment instead of forwarding
    // vault credentials. Preserve only ordinary process/UI variables needed
    // by shell scripts and terminal editors.
    command.env_clear();
    for (key, value) in env::vars_os().filter(|(key, _)| safe_environment_key(key)) {
        command.env(key, value);
    }
    command
}

fn safe_environment_key(key: &std::ffi::OsStr) -> bool {
    match key.to_str() {
        Some(
            "PATH" | "HOME" | "TMPDIR" | "TMP" | "TEMP" | "USER" | "LOGNAME" | "LANG" | "LC_ALL"
            | "SHELL" | "TERM" | "COLORTERM" | "DISPLAY" | "XAUTHORITY" | "GIT_ASKPASS" | "GIT_SSH"
            | "GIT_SSH_COMMAND" | "SSH_AUTH_SOCK" | "SSH_AGENT_LAUNCHER" | "GNUPGHOME",
        ) => true,
        #[cfg(windows)]
        Some("SystemRoot" | "USERPROFILE") => true,
        _ => false,
    }
}
