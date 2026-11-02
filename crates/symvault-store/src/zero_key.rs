//! Go's `vault.tryHealZeroKeyIdentity`: recovery of an `identity.age` written
//! under the pre-#476 zero-key bug, shared by the CLI and the C ABI.
//!
//! The Argon2id wrap key of such a file depends only on the passphrase byte
//! length. When the real passphrase fails to unwrap an Argon2id identity (and the
//! failure is not a resource-policy refusal), Go reads `recipients.txt` as the
//! local trust anchor, recovers the identity with a zero key of the passphrase
//! length, requires its public key to be listed there, re-checks that the file
//! has not changed and re-wraps `identity.age` under the real passphrase,
//! keeping the old bytes as `identity.age.bak`.
//!
//! The returned messages are what follows `load identity: ` in Go's error.

use std::{
    fs,
    io::{self, Write},
    path::Path,
};

use symvault_crypto::{
    Argon2idParams, CryptoError, Identity, SecretBytes, ZeroKeyAuthority, decrypt_identity,
    encrypt_identity_argon2id, parse_recipient, recover_zero_key_identity_with_authorities,
};

const TRUSTED: &str = "zero-key recovery requires a trusted recipients.txt";
const VALID_AUTHORITY: &str = "zero-key recovery requires valid recipients.txt authority";
const MAX_SCAN_TOKEN: usize = 64 * 1024;

/// The lower-case `strerror` wording Go's `syscall.Errno` prints.
#[must_use]
pub fn errno_text(error: &io::Error) -> String {
    let known = match error.raw_os_error() {
        Some(1) => Some("operation not permitted"),
        Some(2) => Some("no such file or directory"),
        Some(5) => Some("input/output error"),
        Some(13) => Some("permission denied"),
        Some(17) => Some("file exists"),
        Some(20) => Some("not a directory"),
        Some(21) => Some("is a directory"),
        Some(22) => Some("invalid argument"),
        Some(28) => Some("no space left on device"),
        Some(30) => Some("read-only file system"),
        Some(36 | 63) => Some("file name too long"),
        Some(39 | 66) => Some("directory not empty"),
        Some(40 | 62) => Some("too many levels of symbolic links"),
        _ => None,
    };
    if let Some(text) = known {
        return text.to_owned();
    }
    match error.kind() {
        io::ErrorKind::NotFound => "no such file or directory".to_owned(),
        io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
        io::ErrorKind::AlreadyExists => "file exists".to_owned(),
        io::ErrorKind::NotADirectory => "not a directory".to_owned(),
        io::ErrorKind::IsADirectory => "is a directory".to_owned(),
        _ => error.to_string().to_lowercase(),
    }
}

/// Whether `error` is one of Go's `IsArgon2ResourceError` errors, which are
/// returned as they are and never start a zero-key recovery.
#[must_use]
pub fn is_argon2_resource_error(error: CryptoError) -> bool {
    use symvault_crypto::FailureClass;
    matches!(
        error.class(),
        FailureClass::ResourcePolicy | FailureClass::ResourceBusy | FailureClass::ParameterBounds
    ) || error.to_string() == "malformed argon2id stanza"
}

/// `trustedZeroKeyAuthorities`: `recipients.txt` must be a regular, readable
/// file (`SafeReadFile` refuses a symlink) listing at least one valid
/// recipient, with every other line blank or a comment. Returns the distinct
/// canonical recipients and the exact bytes they were read from.
///
/// # Errors
/// Go's two refusal texts.
pub fn trusted_zero_key_authorities(vault: &Path) -> Result<(Vec<String>, Vec<u8>), &'static str> {
    let snapshot = safe_read(&vault.join("recipients.txt")).ok_or(TRUSTED)?;
    let mut recipients: Vec<String> = Vec::new();
    let mut rest = snapshot.as_slice();
    while !rest.is_empty() {
        let (line, terminated, next) = match rest.iter().position(|&byte| byte == b'\n') {
            Some(end) => (&rest[..end], true, &rest[end + 1..]),
            None => (rest, false, &rest[rest.len()..]),
        };
        // bufio.Scanner gives up on a line that fills its 64 KiB buffer.
        let held = line.len() + usize::from(terminated);
        if held > MAX_SCAN_TOKEN || (!terminated && held >= MAX_SCAN_TOKEN) {
            return Err(VALID_AUTHORITY);
        }
        rest = next;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let text = String::from_utf8_lossy(line);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if !text.starts_with("age1") {
            return Err(VALID_AUTHORITY);
        }
        let Ok(recipient) = parse_recipient(text) else {
            return Err(VALID_AUTHORITY);
        };
        let canonical = recipient.to_string();
        if !recipients.contains(&canonical) {
            recipients.push(canonical);
        }
    }
    if recipients.is_empty() {
        return Err(VALID_AUTHORITY);
    }
    Ok((recipients, snapshot))
}

/// `SafeReadFile`: a regular file, never a symlink.
fn safe_read(path: &Path) -> Option<Vec<u8>> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    fs::read(path).ok()
}

/// `fsutil.AtomicWriteFile`: a private temporary file next to the target,
/// fsync, rename.
fn atomic_write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let suffix = format!(
        "{}-{}-{random:016x}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let temporary = parent.join(format!(".{name}.tmp-{suffix}"));
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// `tryHealZeroKeyIdentity` for an Argon2id identity `raw` (the bytes read from
/// `vault/identity.age`) that `passphrase` failed to unwrap.
///
/// # Errors
/// Go's error text without its `load identity: ` prefix.
pub fn heal_zero_key_identity(
    vault: &Path,
    raw: &[u8],
    passphrase: &[u8],
) -> Result<Identity, String> {
    // The envelope never chooses its own expected identity: the trust file is
    // read, validated and snapshotted before any zero-key KDF runs.
    let (recipients, snapshot) = trusted_zero_key_authorities(vault).map_err(str::to_owned)?;
    let authorities: Vec<ZeroKeyAuthority<'_>> = recipients
        .iter()
        .map(|recipient| ZeroKeyAuthority::recipient(recipient))
        .collect();
    let recovered = recover_zero_key_identity_with_authorities(raw, passphrase.len(), &authorities)
        .map_err(|error| error.to_string())?;

    // Do not heal if the trust file changed while the recovery KDF was running.
    if safe_read(&vault.join("recipients.txt")).as_deref() != Some(snapshot.as_slice()) {
        return Err("zero-key recovery authority changed; refusing to re-key the vault".to_owned());
    }
    rewrite_identity(vault, raw, &recovered, passphrase)
        .map_err(|reason| format!("atomic rewrite of healed identity: {reason}"))?;
    Ok(recovered)
}

/// `rewriteIdentityAtomicExpected`: back the old file up, write the new wrap,
/// verify it opens with the passphrase, otherwise put the old bytes back.
fn rewrite_identity(
    vault: &Path,
    expected: &[u8],
    identity: &Identity,
    passphrase: &[u8],
) -> Result<(), String> {
    let path = vault.join("identity.age");
    let backup = vault.join("identity.age.bak");
    let original = fs::read(&path).map_err(|error| {
        let stage = if fs::File::open(&path).is_ok() {
            "read"
        } else {
            "open"
        };
        format!(
            "read original identity: {stage} {}: {}",
            path.display(),
            errno_text(&error)
        )
    })?;
    if original != expected {
        return Err(
            "identity changed during zero-key recovery; refusing to re-key the vault".to_owned(),
        );
    }
    atomic_write(&backup, &original, 0o600)
        .map_err(|error| format!("write backup: {}", errno_text(&error)))?;
    let restore = || {
        if atomic_write(&path, &original, 0o600).is_ok() {
            let _ = fs::remove_file(&backup);
        }
    };
    let secret = SecretBytes::new(passphrase);
    let sealed = encrypt_identity_argon2id(identity, &secret, Argon2idParams::default()).map_err(
        |error| {
            restore();
            format!("save new identity: create encryptor: {error}")
        },
    )?;
    atomic_write(&path, &sealed, 0o600).map_err(|error| {
        restore();
        format!("save new identity: write file: {}", errno_text(&error))
    })?;
    let verified = fs::read(&path)
        .map_err(|error| format!("read file: {}", errno_text(&error)))
        .and_then(|written| {
            decrypt_identity(&written, &secret).map_err(|error| format!("{error}"))
        });
    if let Err(reason) = verified {
        restore();
        return Err(format!("verify new identity: {reason}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use symvault_crypto::{EnvelopeFormat, decrypt_identity, detect_envelope, recipient_string};

    /// The Go-made `historical_zero_key_length_23` envelope of
    /// `testdata/port/crypto/age-kdf.json` and its recipient.
    fn go_fixture() -> (Vec<u8>, String) {
        let document: serde_json::Value =
            serde_json::from_str(include_str!("../../../testdata/port/crypto/age-kdf.json"))
                .unwrap();
        let case = document["zero_key_cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "historical_zero_key_length_23")
            .unwrap();
        (
            base64::engine::general_purpose::STANDARD
                .decode(case["ciphertext"].as_str().unwrap())
                .unwrap(),
            case["expected_recipient"].as_str().unwrap().to_owned(),
        )
    }

    const PASSPHRASE: &[u8] = b"abcdefghijklmnopqrstuvw";

    fn vault(recipients: Option<&str>) -> (tempfile::TempDir, Vec<u8>, String) {
        let (raw, recipient) = go_fixture();
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("identity.age"), &raw).unwrap();
        if let Some(text) = recipients {
            fs::write(
                dir.path().join("recipients.txt"),
                text.replace("{R}", &recipient),
            )
            .unwrap();
        }
        (dir, raw, recipient)
    }

    #[test]
    fn heals_a_go_made_zero_key_identity_and_keeps_the_old_bytes() {
        let (dir, raw, recipient) = vault(Some("# trust\n{R}\n"));
        let identity = heal_zero_key_identity(dir.path(), &raw, PASSPHRASE).unwrap();
        assert_eq!(recipient_string(&identity), recipient);

        let rewritten = fs::read(dir.path().join("identity.age")).unwrap();
        assert_ne!(rewritten, raw);
        assert_eq!(detect_envelope(&rewritten), EnvelopeFormat::Argon2id);
        // The real passphrase opens it now, with the same identity.
        let opened = decrypt_identity(&rewritten, &SecretBytes::new(PASSPHRASE)).unwrap();
        assert_eq!(recipient_string(&opened), recipient);
        assert_eq!(fs::read(dir.path().join("identity.age.bak")).unwrap(), raw);
        for name in ["identity.age", "identity.age.bak"] {
            let mode = fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
        // No temporary file is left behind.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn refusals_use_go_text_and_leave_the_vault_untouched() {
        let long = vec![b'p'; 1025];
        let cases: Vec<(&str, Option<&str>, &[u8], &str)> = vec![
            (
                "missing",
                None,
                PASSPHRASE,
                "zero-key recovery requires a trusted recipients.txt",
            ),
            (
                "garbled",
                Some("nope\n"),
                PASSPHRASE,
                "zero-key recovery requires valid recipients.txt authority",
            ),
            (
                "empty",
                Some(""),
                PASSPHRASE,
                "zero-key recovery requires valid recipients.txt authority",
            ),
            (
                "comments",
                Some("# x\n"),
                PASSPHRASE,
                "zero-key recovery requires valid recipients.txt authority",
            ),
            (
                "valid then garbled",
                Some("{R}\nnope\n"),
                PASSPHRASE,
                "zero-key recovery requires valid recipients.txt authority",
            ),
            (
                "wrong key",
                Some("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n"),
                PASSPHRASE,
                "zero-key recovery failed",
            ),
            (
                "wrong length",
                Some("{R}\n"),
                b"abcdefghijklmnopqrstuv",
                "zero-key recovery failed: decryption failed",
            ),
            (
                "too long",
                Some("{R}\n"),
                &long,
                "zero-key length is invalid",
            ),
        ];
        for (name, recipients, passphrase, expected) in cases {
            let (dir, raw, _) = vault(recipients);
            let error = heal_zero_key_identity(dir.path(), &raw, passphrase).unwrap_err();
            assert_eq!(error, expected, "{name}");
            assert_eq!(
                fs::read(dir.path().join("identity.age")).unwrap(),
                raw,
                "{name}"
            );
            assert!(!dir.path().join("identity.age.bak").exists(), "{name}");
        }
    }

    #[test]
    fn a_symlinked_or_non_regular_recipients_file_is_not_a_trust_anchor() {
        let (dir, raw, recipient) = vault(None);
        fs::write(dir.path().join("real.txt"), format!("{recipient}\n")).unwrap();
        symlink(
            dir.path().join("real.txt"),
            dir.path().join("recipients.txt"),
        )
        .unwrap();
        assert_eq!(
            heal_zero_key_identity(dir.path(), &raw, PASSPHRASE).unwrap_err(),
            "zero-key recovery requires a trusted recipients.txt"
        );
        fs::remove_file(dir.path().join("recipients.txt")).unwrap();
        fs::create_dir(dir.path().join("recipients.txt")).unwrap();
        assert_eq!(
            heal_zero_key_identity(dir.path(), &raw, PASSPHRASE).unwrap_err(),
            "zero-key recovery requires a trusted recipients.txt"
        );
    }

    #[test]
    fn authorities_follow_bufio_scanner_rules() {
        let (dir, _, recipient) = vault(None);
        let write = |bytes: &[u8]| fs::write(dir.path().join("recipients.txt"), bytes).unwrap();
        // CRLF, padding, comments and duplicates fold to one canonical key.
        write(format!("# c\r\n  {recipient}  \r\n\r\n{recipient}").as_bytes());
        let (list, snapshot) = trusted_zero_key_authorities(dir.path()).unwrap();
        assert_eq!(list, vec![recipient.clone()]);
        assert!(snapshot.ends_with(recipient.as_bytes()));
        // A non-UTF-8 comment is still a comment (Go never decodes it).
        write(&[b"# ".as_slice(), &[0xff, 0xfe], b"\n", recipient.as_bytes()].concat());
        assert!(trusted_zero_key_authorities(dir.path()).is_ok());
        // A line that fills the scanner's 64 KiB buffer is an error, even a comment.
        write(format!("{recipient}\n# {}\n", "x".repeat(70_000)).as_bytes());
        assert_eq!(
            trusted_zero_key_authorities(dir.path()).unwrap_err(),
            "zero-key recovery requires valid recipients.txt authority"
        );
        // Upper case is not an `age1` key.
        write(recipient.to_uppercase().as_bytes());
        assert!(trusted_zero_key_authorities(dir.path()).is_err());
    }
}
