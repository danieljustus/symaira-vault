//! `recipients.txt` management (`PAIRING-001`).
//!
//! The Go oracle is `internal/vault.RecipientsManager` at the frozen baseline
//! commit. `device accept` adds the joining device's public key here and
//! `device revoke` removes it, so this file is the other half of "a revoked
//! device no longer decrypts" — the cryptographic half is `CRYPTO-004`.
//!
//! Two behaviours are faithfully preserved rather than improved, because the
//! register's rule is that Rust replaces observable behaviour, not that it
//! corrects it. Both are frozen as vectors:
//!
//! - **Appending never inserts a missing separator.** Go means to write a
//!   newline when the existing file does not end in one, but it opens the file
//!   `O_WRONLY|O_APPEND` and then tries to `ReadAt` the last byte through that
//!   same write-only descriptor. That read always fails, so the branch is dead
//!   and the new recipient is concatenated onto the previous line. This is a
//!   real defect in the Go production code — see
//!   `recipients/add-after-file-without-trailing-newline`, where the result is
//!   one corrupt 124-character line. It is reproduced here deliberately; fixing
//!   it is a change to the Go oracle, not to this port.
//! - **An uppercase recipient is rejected as malformed.** `ValidateRecipient`
//!   checks `strings.HasPrefix(s, "age1")` case-sensitively before parsing, so
//!   `AGE1…` never reaches the bech32 decoder that would have accepted it.
//!
//! Neither `LoadRecipientStrings` nor the removal scan validates the lines it
//! keeps: a junk line stays in the file and is reported by a load.

use crate::safeio::{self, SafeIoError};
use std::path::PathBuf;

/// Filename inside the vault directory, matching Go's `recipientsFileName`.
pub const RECIPIENTS_FILE: &str = "recipients.txt";

/// Failures the recipients file can report.
#[derive(Debug)]
pub enum RecipientsError {
    /// The recipient string is empty, lacks the lowercase `age1` prefix, or is
    /// not a valid age X25519 recipient.
    Invalid,
    /// The recipient is already listed.
    AlreadyExists,
    /// The recipient, or the file itself, is not there.
    NotFound,
    /// The file could not be read or written.
    Io(SafeIoError),
}

impl From<SafeIoError> for RecipientsError {
    fn from(source: SafeIoError) -> Self {
        Self::Io(source)
    }
}

impl std::fmt::Display for RecipientsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => write!(f, "invalid recipient"),
            Self::AlreadyExists => write!(f, "recipient already exists"),
            Self::NotFound => write!(f, "recipient not found"),
            Self::Io(source) => write!(f, "recipients file: {source}"),
        }
    }
}

impl std::error::Error for RecipientsError {}

/// The `recipients.txt` of one vault directory.
#[derive(Debug, Clone)]
pub struct RecipientsFile {
    vault_dir: PathBuf,
}

impl RecipientsFile {
    /// Binds to `vault_dir`; nothing is touched until a read or write happens.
    pub fn new(vault_dir: impl Into<PathBuf>) -> Self {
        Self {
            vault_dir: vault_dir.into(),
        }
    }

    /// Path of the recipients file.
    pub fn path(&self) -> PathBuf {
        self.vault_dir.join(RECIPIENTS_FILE)
    }

    /// Whether the file is present, matching `RecipientsFileExists`.
    pub fn exists(&self) -> bool {
        safeio::is_regular_file(&self.path())
    }

    /// Every non-empty, non-comment line, trimmed.
    ///
    /// The `Option` preserves a distinction Go's callers can observe: a missing
    /// file yields an empty non-nil slice (`[]`), while a file that exists but
    /// contributes no lines yields Go's nil slice (`null`). Lines are not
    /// validated, so a junk line is reported like any other.
    pub fn load_strings(&self) -> Result<Option<Vec<String>>, RecipientsError> {
        let Some(data) = safeio::read(&self.path())? else {
            return Ok(Some(Vec::new()));
        };
        let text = String::from_utf8_lossy(&data);
        let mut lines: Option<Vec<String>> = None;
        for line in text.split('\n') {
            // Go reads this with a bufio.Scanner, whose ScanLines drops a
            // trailing carriage return before TrimSpace runs. Trimming alone
            // reproduces that: a carriage return is whitespace, so a CRLF file
            // and an LF file load identically either way. Frozen by
            // `recipients/crlf-file-loads-without-carriage-returns`.
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            lines.get_or_insert_with(Vec::new).push(trimmed.to_owned());
        }
        Ok(lines)
    }

    /// Appends `recipient` in its canonical form.
    ///
    /// See the module documentation: no separator is inserted when the file
    /// does not end in a newline, because Go's separator branch cannot run.
    pub fn add(&self, recipient: &str) -> Result<(), RecipientsError> {
        use std::io::Write as _;

        let canonical = canonicalize(recipient)?;
        let existing = self.load_strings()?.unwrap_or_default();
        if existing.contains(&canonical) {
            return Err(RecipientsError::AlreadyExists);
        }
        let mut file = safeio::open_append(&self.path())?;
        file.write_all(canonical.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|source| RecipientsError::Io(SafeIoError::Io(source)))
    }

    /// Removes every line naming `recipient`, keeping comments, blank lines and
    /// lines that do not parse as recipients exactly where they are.
    pub fn remove(&self, recipient: &str) -> Result<(), RecipientsError> {
        let canonical = canonicalize(recipient)?;
        let path = self.path();
        let Some(data) = safeio::read(&path)? else {
            return Err(RecipientsError::NotFound);
        };
        let text = String::from_utf8_lossy(&data).into_owned();

        let mut kept: Vec<&str> = Vec::new();
        let mut found = false;
        for line in text.split('\n') {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                kept.push(line);
                continue;
            }
            match canonicalize(trimmed) {
                Ok(parsed) if parsed == canonical => found = true,
                // A line that is not a recipient at all is left untouched; it
                // may be metadata this port knows nothing about.
                _ => kept.push(line),
            }
        }
        if !found {
            return Err(RecipientsError::NotFound);
        }
        safeio::write_atomic(&path, kept.join("\n").as_bytes())?;
        Ok(())
    }
}

/// Validates and normalizes a recipient exactly as `crypto.ValidateRecipient`
/// followed by `(*age.X25519Recipient).String()` does.
///
/// The `age1` prefix test is case-sensitive in Go and therefore here too, even
/// though bech32 itself is not: an uppercase recipient is rejected as malformed
/// rather than normalized.
fn canonicalize(recipient: &str) -> Result<String, RecipientsError> {
    if recipient.is_empty() || !recipient.starts_with("age1") {
        return Err(RecipientsError::Invalid);
    }
    symvault_crypto::parse_recipient(recipient)
        .map(|parsed| parsed.to_string())
        .map_err(|_| RecipientsError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const RECIPIENT: &str = "age1mdwavk4nralsx6te8ucvdenyxjaepgdqpk8zh6m4glsnu064eczskcng9y";

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("symvault-recipients-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A symlinked recipients file must be refused for both reading and
    /// writing: following it would let anyone who can plant a link in the vault
    /// directory read an arbitrary file or redirect a `0600` write.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_recipients_file_is_refused() {
        let dir = scratch("symlink");
        let file = RecipientsFile::new(&dir);
        let target = dir.join("elsewhere.txt");
        fs::write(&target, format!("{RECIPIENT}\n")).unwrap();
        std::os::unix::fs::symlink(&target, file.path()).unwrap();

        assert!(matches!(
            file.load_strings(),
            Err(RecipientsError::Io(SafeIoError::NotRegularFile))
        ));
        assert!(matches!(
            file.add(RECIPIENT),
            Err(RecipientsError::Io(SafeIoError::NotRegularFile))
        ));
        assert!(!file.exists(), "a symlink must not count as the file");
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            format!("{RECIPIENT}\n"),
            "the link target was written through"
        );
        let _ = fs::remove_dir_all(dir);
    }

    /// The Go oracle's dead separator branch, reproduced deliberately. If this
    /// ever starts inserting a newline, the port has diverged from the frozen
    /// behaviour even though the result would look more correct.
    #[test]
    fn appending_to_a_file_without_a_trailing_newline_concatenates() {
        let dir = scratch("concat");
        let file = RecipientsFile::new(&dir);
        fs::write(file.path(), RECIPIENT).unwrap();
        let second = "age1wxknyar29luhmltc320wnllzxd7n0cjvldxqjunyh9u3l4gpd3kq9r4lgr";
        file.add(second).unwrap();
        assert_eq!(
            fs::read_to_string(file.path()).unwrap(),
            format!("{RECIPIENT}{second}\n")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn an_uppercase_recipient_is_malformed_not_normalized() {
        let dir = scratch("uppercase");
        let file = RecipientsFile::new(&dir);
        assert!(matches!(
            file.add(&RECIPIENT.to_uppercase()),
            Err(RecipientsError::Invalid)
        ));
        assert!(!file.exists());
        let _ = fs::remove_dir_all(dir);
    }
}
