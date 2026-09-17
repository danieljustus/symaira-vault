// `pass` directory adapter parity.
//
// Decryption is deliberately kept behind the small `gpg` process adapter.
// The command receives a Go-compatible allowlisted environment and no
// caller environment is inherited implicitly.

use super::{ImportError, ImportedEntry, normalize_path, parse_totp};
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
    let metadata = fs::metadata(dir)
        .map_err(|error| ImportError::Parse(format!("open pass store: {error}")))?;
    if !metadata.is_dir() {
        return Err(ImportError::Parse(format!(
            "pass store is not a directory: {}",
            dir.display()
        )));
    }
    let mut paths = Vec::new();
    collect_entries(dir, dir, &mut paths)?;
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let content = decrypt_pass_file(gpg, &path)?;
        let relative = path
            .strip_prefix(dir)
            .map_err(|error| ImportError::Parse(format!("resolve pass entry path: {error}")))?;
        entries.push(parse_pass_entry(relative, &content));
    }
    Ok(entries)
}

fn collect_entries(
    root: &Path,
    current: &Path,
    paths: &mut Vec<PathBuf>,
) -> Result<(), ImportError> {
    let mut children = fs::read_dir(current)
        .map_err(|error| ImportError::Parse(format!("walk pass store: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ImportError::Parse(format!("walk pass store: {error}")))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        let file_type = child
            .file_type()
            .map_err(|error| ImportError::Parse(format!("walk pass store: {error}")))?;
        if file_type.is_dir() {
            collect_entries(root, &path, paths)?;
        } else if child.file_name().to_string_lossy().ends_with(".gpg") {
            // `root` is kept in the signature to make the traversal contract
            // explicit and to guard against accidental path escapes in future
            // changes. WalkDir in Go also emits only descendants of root.
            if path.strip_prefix(root).is_ok() {
                paths.push(path);
            }
        }
    }
    Ok(())
}

fn decrypt_pass_file(gpg: &Path, path: &Path) -> Result<String, ImportError> {
    let mut command = Command::new(gpg);
    command.args(["--decrypt", "--batch", "--yes"]);
    command.arg(path);
    command.env_clear();
    for name in GPG_ENV {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    let output = command.output().map_err(|error| {
        ImportError::Parse(format!("decrypt pass entry {}: {error}", path.display()))
    })?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let message = if message.is_empty() {
            output.status.to_string()
        } else {
            message
        };
        return Err(ImportError::Parse(format!(
            "decrypt pass entry {}: {message}",
            path.display()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parse one decrypted pass entry. The first line is the password; recognized
/// metadata lines match Go's exact `url: ` and `username: ` prefixes.
pub fn parse_pass_entry(path: &Path, content: &str) -> ImportedEntry {
    let normalized = content.replace("\r\n", "\n").replace('\r', "\n");
    let normalized = normalized.strip_suffix('\n').unwrap_or(&normalized);
    let mut lines = normalized.split('\n');
    let password = lines.next().unwrap_or_default();
    let mut data = BTreeMap::new();
    data.insert("password".into(), Value::String(password.into()));
    let mut notes = Vec::new();
    let mut warnings = None;
    for line in lines {
        if let Some(value) = line.strip_prefix("url: ") {
            data.insert("url".into(), Value::String(value.trim().into()));
        } else if let Some(value) = line.strip_prefix("username: ") {
            data.insert("username".into(), Value::String(value.trim().into()));
        } else if line.starts_with("otpauth://") {
            match parse_totp(line) {
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
        data.insert("notes".into(), Value::String(notes.join("\n")));
    }
    let raw_path = path.to_string_lossy();
    let raw_path = raw_path.strip_suffix(".gpg").unwrap_or(&raw_path);
    let raw_path = raw_path.replace('\\', "/");
    ImportedEntry {
        path: normalize_path(&raw_path),
        data,
        warnings,
        secret_type: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        time::{SystemTime, UNIX_EPOCH},
    };

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
        assert!(entry.data.get("totp").is_none());
        assert_eq!(entry.warnings.as_deref().unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn adapter_runs_isolated_fake_gpg_process() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            env::temp_dir().join(format!("symvault-pass-test-{}-{nonce}", std::process::id()));
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/example.gpg"), b"ciphertext").unwrap();
        let gpg = root.join("gpg");
        let mut script = fs::File::create(&gpg).unwrap();
        script
            .write_all(
                b"#!/bin/sh\nprintf 'secret\\nusername: test\\nurl: https://example.test\\n'\n",
            )
            .unwrap();
        drop(script);
        let mut permissions = fs::metadata(&gpg).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o700);
        fs::set_permissions(&gpg, permissions).unwrap();

        let entries = import_pass_with_gpg(&root, &gpg).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "nested/example");
        assert_eq!(entries[0].data["password"], "secret");
        assert_eq!(entries[0].data["username"], "test");
        let _ = fs::remove_dir_all(root);
    }
}
