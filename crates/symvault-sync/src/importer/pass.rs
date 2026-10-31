// `pass` directory adapter parity.
//
// Decryption is deliberately kept behind the small `gpg` process adapter.
// The command receives a Go-compatible allowlisted environment and no
// caller environment is inherited implicitly.

use super::{ImportError, ImportedEntry, go_string_from_bytes, normalize_path};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const GPG_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "SHELL",
    "TERM",
    "COLORTERM",
    "DISPLAY",
    "XAUTHORITY",
    "GIT_ASKPASS",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_LAUNCHER",
    "GNUPGHOME",
];

/// Import a password-store directory using the host `gpg` executable.
pub fn import_pass(dir: &Path) -> Result<Vec<ImportedEntry>, ImportError> {
    import_pass_with_gpg(dir, Path::new("gpg"))
}

/// Import a password-store directory with an explicit executable.
///
/// The explicit path is used by tests and by tightly scoped callers that own
/// their process adapter. It still goes through the same argument and
/// environment filtering as the production entry point.
pub fn import_pass_with_gpg(dir: &Path, gpg: &Path) -> Result<Vec<ImportedEntry>, ImportError> {
    let metadata = fs::metadata(dir).map_err(|error| {
        ImportError::Parse(format!(
            "open pass store: stat {}: {}",
            dir.display(),
            super::go_io_reason(&error)
        ))
    })?;
    if !metadata.is_dir() {
        return Err(ImportError::Parse(format!(
            "pass store is not a directory: {}",
            dir.display()
        )));
    }
    // Go's filepath.WalkDir lstat()s the root: a symlinked root is a single
    // non-directory entry (so it is never descended into) unless the OS
    // resolves it, as it does for a trailing slash.
    let root = fs::symlink_metadata(dir).map_err(|error| {
        ImportError::Parse(format!(
            "walk pass store: lstat {}: {}",
            dir.display(),
            super::go_io_reason(&error)
        ))
    })?;
    let mut entries = Vec::new();
    let walk = Walk { gpg };
    if root.is_dir() {
        walk.directory(dir, Path::new(""), &mut entries)?;
    } else if root_name(dir).ends_with(".gpg") {
        walk.file(dir, Path::new("."), &mut entries)?;
    }
    Ok(entries)
}

/// `os.Lstat(root).Name()`: the last element, ignoring trailing slashes.
fn root_name(dir: &Path) -> String {
    let text = dir.to_string_lossy();
    let trimmed = text.trim_end_matches('/');
    if trimmed.is_empty() {
        return if text.is_empty() {
            ".".into()
        } else {
            "/".into()
        };
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed).to_owned()
}

/// Lexical `filepath.Clean`.
fn go_clean(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut cleaned = PathBuf::new();
    let mut rooted = false;
    let mut depth = 0usize;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                rooted = true;
                cleaned.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if depth > 0 {
                    cleaned.pop();
                    depth -= 1;
                } else if !rooted {
                    cleaned.push("..");
                }
            }
            Component::Normal(name) => {
                cleaned.push(name);
                depth += 1;
            }
        }
    }
    if cleaned.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        cleaned
    }
}

/// One `filepath.WalkDir` over the store: the callback of Go's importer
/// decrypts each `*.gpg` as the walk reaches it, so a decrypt failure ahead of
/// an unreadable directory wins, exactly as in Go.
struct Walk<'a> {
    gpg: &'a Path,
}

impl Walk<'_> {
    fn directory(
        &self,
        path: &Path,
        relative: &Path,
        entries: &mut Vec<ImportedEntry>,
    ) -> Result<(), ImportError> {
        let walk_error = |detail: String| ImportError::Parse(format!("walk pass store: {detail}"));
        let mut children = fs::read_dir(path)
            .map_err(|error| {
                walk_error(format!(
                    "open {}: {}",
                    path.display(),
                    super::go_io_reason(&error)
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                walk_error(format!(
                    "readdirent {}: {}",
                    path.display(),
                    super::go_io_reason(&error)
                ))
            })?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let name = child.file_name();
            // Go joins with path.Join, which cleans the result.
            let child_path = go_clean(&path.join(&name));
            let child_relative = relative.join(&name);
            let file_type = child
                .file_type()
                .map_err(|error| walk_error(super::go_io_reason(&error)))?;
            if file_type.is_dir() {
                self.directory(&child_path, &child_relative, entries)?;
            } else if name.to_string_lossy().ends_with(".gpg") {
                self.file(&child_path, &child_relative, entries)?;
            }
        }
        Ok(())
    }

    fn file(
        &self,
        path: &Path,
        relative: &Path,
        entries: &mut Vec<ImportedEntry>,
    ) -> Result<(), ImportError> {
        let content = decrypt_pass_file(self.gpg, path)?;
        entries.push(parse_pass_entry_bytes(relative, &content));
        Ok(())
    }
}

fn decrypt_pass_file(gpg: &Path, path: &Path) -> Result<Vec<u8>, ImportError> {
    let mut command = Command::new(gpg);
    command.args(["--decrypt", "--batch", "--yes"]);
    command.arg(path);
    prepare_gpg_command(&mut command);
    let output = command.output().map_err(|error| {
        // Go's os/exec reports a bare program name that is not on PATH with
        // its own text; any other spawn failure carries the OS reason.
        let reason =
            if error.kind() == std::io::ErrorKind::NotFound && gpg.components().count() == 1 {
                format!(
                    "exec: {:?}: executable file not found in $PATH",
                    gpg.display().to_string()
                )
            } else {
                super::go_io_reason(&error)
            };
        ImportError::Parse(format!("decrypt pass entry {}: {reason}", path.display()))
    })?;
    if !output.status.success() {
        let message = go_trim_space(&output.stderr);
        let message = if message.is_empty() {
            go_exit_text(&output.status)
        } else {
            go_string_from_bytes(message)
        };
        return Err(ImportError::Parse(format!(
            "decrypt pass entry {}: {message}",
            path.display()
        )));
    }
    Ok(output.stdout)
}

/// `(*os.ProcessState).String()` for a child that failed with empty stderr:
/// Go reports `exit status N` / `signal: NAME`, not Rust's `exit status: N`.
fn go_exit_text(status: &std::process::ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            let name = match signal {
                1 => "hangup",
                2 => "interrupt",
                3 => "quit",
                9 => "killed",
                11 => "segmentation fault",
                13 => "broken pipe",
                14 => "alarm clock",
                15 => "terminated",
                other => return format!("signal: {other}"),
            };
            let core = if status.core_dumped() {
                " (core dumped)"
            } else {
                ""
            };
            return format!("signal: {name}{core}");
        }
    }
    match status.code() {
        Some(code) => format!("exit status {code}"),
        None => status.to_string(),
    }
}

fn prepare_gpg_command(command: &mut Command) {
    command.env_clear();
    for name in GPG_ENV {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
}

/// `strings.TrimSpace` on a Go string that may hold invalid UTF-8: an invalid
/// byte is never a space.
pub(super) fn go_trim_space(mut bytes: &[u8]) -> &[u8] {
    while let Some((character, width)) = first_char(bytes) {
        if !character.is_whitespace() {
            break;
        }
        bytes = &bytes[width..];
    }
    while let Some((character, width)) = last_char(bytes) {
        if !character.is_whitespace() {
            break;
        }
        bytes = &bytes[..bytes.len() - width];
    }
    bytes
}

fn first_char(bytes: &[u8]) -> Option<(char, usize)> {
    let window = &bytes[..bytes.len().min(4)];
    let valid = match std::str::from_utf8(window) {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&window[..error.valid_up_to()]).ok()?,
    };
    valid.chars().next().map(|c| (c, c.len_utf8()))
}

fn last_char(bytes: &[u8]) -> Option<(char, usize)> {
    (1..=bytes.len().min(4)).find_map(|width| {
        let text = std::str::from_utf8(&bytes[bytes.len() - width..]).ok()?;
        let mut chars = text.chars();
        let character = chars.next()?;
        chars.next().is_none().then_some((character, width))
    })
}

/// Parse one decrypted pass entry. The first line is the password; recognized
/// metadata lines match Go's exact `url: ` and `username: ` prefixes.
pub fn parse_pass_entry(path: &Path, content: &str) -> ImportedEntry {
    parse_pass_entry_bytes(path, content.as_bytes())
}

/// [`parse_pass_entry`] over the raw decrypted bytes. Go keeps the plaintext as
/// a byte string until JSON marshaling, so error text built from a line (for
/// example a rejected `otpauth://` URI) quotes invalid bytes as `\xNN`; the
/// lossy conversion to `String` therefore happens per field, last.
pub fn parse_pass_entry_bytes(path: &Path, content: &[u8]) -> ImportedEntry {
    let normalized = replace_all(&replace_all(content, b"\r\n", b"\n"), b"\r", b"\n");
    let normalized = normalized.strip_suffix(b"\n").unwrap_or(&normalized);
    let mut lines = normalized.split(|byte| *byte == b'\n');
    let password = lines.next().unwrap_or_default();
    let mut data = BTreeMap::new();
    data.insert(
        "password".into(),
        Value::String(go_string_from_bytes(password)),
    );
    let mut notes: Vec<&[u8]> = Vec::new();
    let mut warnings = None;
    for line in lines {
        if let Some(value) = line.strip_prefix(b"url: ") {
            data.insert(
                "url".into(),
                Value::String(go_string_from_bytes(go_trim_space(value))),
            );
        } else if let Some(value) = line.strip_prefix(b"username: ") {
            data.insert(
                "username".into(),
                Value::String(go_string_from_bytes(go_trim_space(value))),
            );
        } else if line.starts_with(b"otpauth://") {
            match super::totp::parse_totp_bytes(line) {
                Ok(totp) => {
                    data.insert("totp".into(), totp);
                }
                Err(error) => warnings
                    .get_or_insert_with(Vec::new)
                    .push(format!("totp: {error}")),
            }
        } else {
            notes.push(line);
        }
    }
    if !notes.is_empty() {
        data.insert(
            "notes".into(),
            Value::String(go_string_from_bytes(&notes.join(&b'\n'))),
        );
    }
    let raw_path = path.to_string_lossy();
    let raw_path = raw_path.strip_suffix(".gpg").unwrap_or(&raw_path);
    let raw_path = to_slash(raw_path);
    ImportedEntry {
        path: normalize_path(&raw_path),
        data,
        warnings,
        secret_type: None,
    }
}

fn replace_all(input: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index..].starts_with(from) {
            out.extend_from_slice(to);
            index += from.len();
        } else {
            out.push(input[index]);
            index += 1;
        }
    }
    out
}

fn to_slash(path: &str) -> String {
    #[cfg(windows)]
    {
        path.replace('\\', "/")
    }
    #[cfg(not(windows))]
    {
        path.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::Write;

    #[test]
    fn parser_matches_pass_metadata_and_line_rules() {
        let entry = parse_pass_entry(
            Path::new("work/example.gpg"),
            "secret\r\nurl:  https://example.test  \r\nusername: user \r\ncomment\r\nsecond\n",
        );
        assert_eq!(entry.path, "work/example");
        assert_eq!(entry.data["password"], "secret");
        assert_eq!(entry.data["url"], "https://example.test");
        assert_eq!(entry.data["username"], "user");
        assert_eq!(entry.data["notes"], "comment\nsecond");
    }

    #[test]
    fn parser_preserves_one_warning_for_invalid_totp() {
        let entry = parse_pass_entry(Path::new("x.gpg"), "pw\notpauth://totp/x?secret=bad\n");
        assert!(!entry.data.contains_key("totp"));
        assert_eq!(entry.warnings.as_deref().unwrap().len(), 1);
    }

    #[test]
    fn gpg_environment_is_reduced_to_the_go_allowlist() {
        let mut command = Command::new("gpg");
        command.env("SYMVAULT_TEST_SECRET", "must-not-pass");
        prepare_gpg_command(&mut command);
        assert!(
            command
                .get_envs()
                .all(|(name, _)| name != std::ffi::OsStr::new("SYMVAULT_TEST_SECRET"))
        );
    }

    #[test]
    fn go_clean_matches_filepath_clean() {
        for (input, want) in [
            ("a//b", "a/b"),
            ("./a", "a"),
            ("a/../b", "b"),
            ("../a", "../a"),
            ("../../a/..", "../.."),
            ("/..", "/"),
            ("a/b/..", "a"),
            ("a/b/", "a/b"),
            (".", "."),
            ("", "."),
            ("a/./b/.", "a/b"),
            ("/a//b/../c", "/a/c"),
        ] {
            assert_eq!(go_clean(Path::new(input)), Path::new(want), "{input:?}");
        }
    }

    #[test]
    fn root_name_matches_os_lstat_name() {
        for (input, want) in [
            ("/a/b", "b"),
            ("/a/b///", "b"),
            ("store.gpg", "store.gpg"),
            (".", "."),
            ("/", "/"),
            ("./x/", "x"),
        ] {
            assert_eq!(root_name(Path::new(input)), want, "{input:?}");
        }
    }

    #[test]
    fn trim_space_never_treats_an_invalid_byte_as_space() {
        assert_eq!(go_trim_space(b"\xe2\x80\x83 a \xc2\x85"), b"a");
        assert_eq!(go_trim_space(b" \xff "), b"\xff");
        assert_eq!(
            go_trim_space(b"\xe2\x80 x \xe2\x80"),
            b"\xe2\x80 x \xe2\x80"
        );
        assert_eq!(go_trim_space(b"  \t\n"), b"");
    }

    #[cfg(unix)]
    #[test]
    fn failure_without_stderr_uses_go_process_state_text() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("store");
        fs::create_dir_all(&store).unwrap();
        fs::write(store.join("a.gpg"), b"x").unwrap();
        for (script, want) in [
            ("exit 3", "exit status 3"),
            ("kill -9 $$", "signal: killed"),
            ("kill -15 $$", "signal: terminated"),
        ] {
            let gpg = temp.path().join("gpg");
            fs::write(&gpg, format!("#!/bin/sh\n{script}\n")).unwrap();
            fs::set_permissions(&gpg, fs::Permissions::from_mode(0o700)).unwrap();
            let error = import_pass_with_gpg(&store, &gpg).unwrap_err().to_string();
            assert_eq!(
                error,
                format!(
                    "import parse failed: decrypt pass entry {}: {want}",
                    store.join("a.gpg").display()
                )
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn adapter_runs_isolated_fake_gpg_process() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::create_dir_all(root.join("nested/deeper")).unwrap();
        fs::write(root.join("nested/example.gpg"), b"ciphertext").unwrap();
        fs::write(root.join("nested/deeper/second.gpg"), b"ciphertext").unwrap();
        let gpg = root.join("gpg");
        let mut script = fs::File::create(&gpg).unwrap();
        script.write_all(b"#!/bin/sh\ncase \"$4\" in\n*failure.gpg) printf 'decrypt failed\\n' >&2; exit 7 ;;\nesac\nprintf 'secret\\nusername: test\\nurl: https://example.test\\n'\n").unwrap();
        drop(script);
        let mut permissions = fs::metadata(&gpg).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o700);
        fs::set_permissions(&gpg, permissions).unwrap();

        std::os::unix::fs::symlink(root.join("nested"), root.join("linked")).unwrap();
        std::os::unix::fs::symlink(
            root.join("nested/example.gpg"),
            root.join("linked-entry.gpg"),
        )
        .unwrap();

        let entries = import_pass_with_gpg(root, &gpg).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().any(|entry| entry.path == "nested/example"));
        assert!(
            entries
                .iter()
                .any(|entry| entry.path == "nested/deeper/second")
        );
        assert!(entries.iter().any(|entry| entry.path == "linked-entry"));
        assert!(
            entries
                .iter()
                .all(|entry| entry.data["password"] == "secret")
        );

        fs::write(root.join("nested/failure.gpg"), b"ciphertext").unwrap();
        let error = import_pass_with_gpg(root, &gpg).unwrap_err();
        assert!(error.to_string().contains("decrypt failed"));
    }
}
