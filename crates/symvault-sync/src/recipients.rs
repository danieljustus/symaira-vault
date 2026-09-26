//! `recipients.txt` management (`PAIRING-001`).
//!
//! The Go oracle is `internal/vault.RecipientsManager` at the frozen baseline
//! commit. `device accept` adds the joining device's public key here and
//! `device revoke` removes it, so this file is the other half of "a revoked
//! device no longer decrypts" — the cryptographic half is `CRYPTO-004`.
//!
//! One behaviour is faithfully preserved because Rust replaces observable
//! behavior, not that it corrects it; another has been fixed in the Go oracle
//! and ported here:
//!
//! - **An uppercase recipient is rejected as malformed.** `ValidateRecipient`
//!   checks `strings.HasPrefix(s, "age1")` case-sensitively before parsing, so
//!   `AGE1…` never reaches the bech32 decoder that would have accepted it.
//!
//! Neither `LoadRecipientStrings` nor the removal scan validates the lines it
//! keeps: a junk line stays in the file and is reported by a load. Appending
//! now reads the last byte through the same symlink-safe read/write descriptor
//! used for the append, matching the corrected Go implementation.

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
    /// Inserts a separator when existing non-empty content does not end in a
    /// newline, matching the Go `RecipientsManager` contract.
    pub fn add(&self, recipient: &str) -> Result<(), RecipientsError> {
        use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

        let canonical = canonicalize(recipient)?;
        let existing = self.load_strings()?.unwrap_or_default();
        if existing.contains(&canonical) {
            return Err(RecipientsError::AlreadyExists);
        }
        let mut file = safeio::open_append(&self.path())?;
        let length = file
            .metadata()
            .map_err(|source| RecipientsError::Io(SafeIoError::Io(source)))?
            .len();
        if length > 0 {
            file.seek(SeekFrom::End(-1))
                .map_err(|source| RecipientsError::Io(SafeIoError::Io(source)))?;
            let mut last = [0_u8; 1];
            file.read_exact(&mut last)
                .map_err(|source| RecipientsError::Io(SafeIoError::Io(source)))?;
            if last[0] != b'\n' {
                file.write_all(b"\n")
                    .map_err(|source| RecipientsError::Io(SafeIoError::Io(source)))?;
            }
        }
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

    #[test]
    fn appending_to_a_file_without_a_trailing_newline_separates_records() {
        let dir = scratch("concat");
        let file = RecipientsFile::new(&dir);
        fs::write(file.path(), RECIPIENT).unwrap();
        let second = "age1wxknyar29luhmltc320wnllzxd7n0cjvldxqjunyh9u3l4gpd3kq9r4lgr";
        file.add(second).unwrap();
        assert_eq!(
            fs::read_to_string(file.path()).unwrap(),
            format!("{RECIPIENT}\n{second}\n")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn appending_after_comment_only_or_malformed_content_keeps_records_separate() {
        for (tag, initial, expected) in [
            (
                "comment",
                "# vault recipients".to_owned(),
                format!("# vault recipients\n{RECIPIENT}\n"),
            ),
            (
                "malformed",
                "not-a-recipient".to_owned(),
                format!("not-a-recipient\n{RECIPIENT}\n"),
            ),
        ] {
            let dir = scratch(tag);
            let file = RecipientsFile::new(&dir);
            fs::write(file.path(), initial).unwrap();
            file.add(RECIPIENT).unwrap();
            assert_eq!(fs::read_to_string(file.path()).unwrap(), expected);
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn appending_to_an_existing_empty_file_does_not_add_a_blank_record() {
        let dir = scratch("empty-existing");
        let file = RecipientsFile::new(&dir);
        fs::write(file.path(), []).unwrap();
        file.add(RECIPIENT).unwrap();
        assert_eq!(
            fs::read_to_string(file.path()).unwrap(),
            format!("{RECIPIENT}\n")
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
