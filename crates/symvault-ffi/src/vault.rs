//! The six vault-level bridge functions, orchestrated over `symvault-store`
//! and `symvault-crypto`, with Go's checks performed in Go's order so the
//! first failure (and its text) is the same.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use symvault_core::config::Config;
use symvault_crypto::{
    Argon2idParams, EnvelopeFormat, FailureClass, Identity, SecretBytes, ZeroKeyAuthority, decrypt,
    decrypt_identity, detect_envelope, encrypt_identity_argon2id, generate_identity,
    identity_string, recover_zero_key_identity,
};
use symvault_store::{Entry, Store, StoreError};
use zeroize::Zeroizing;

use crate::gotext::agehdr::{self, Identity as AgeIdentity};
use crate::gotext::bech32::{validate_identity, validate_recipient};
use crate::gotext::entryjson::decode_entry;
use crate::gotext::timefmt::now_rfc3339_nano;
use crate::gotext::{errno_text, path_error, trim_space};
use crate::marshal::marshal_entry;

pub(crate) type R<T> = Result<T, String>;

const DIR_EMPTY: &str = "vault directory is empty";
const DIR_ESCAPES: &str = "vault directory path escapes intended directory";
const RESOURCE_LIMIT: &str = "vault resource limit exceeded";
const BOUNDED_PAYLOAD: &str = "read decrypted entry";
const MAX_ENTRY_PATH_DEPTH: usize = 64;

fn has_traversal(path: &str) -> bool {
    path.split('/').any(|segment| segment == "..")
}

// ---------------------------------------------------------------------------
// Filesystem helpers with Go's error spelling.
// ---------------------------------------------------------------------------

/// `os.MkdirAll`, including which path its error names.
fn go_mkdir_all(path: &Path, mode: u32) -> Result<(), String> {
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(format!("mkdir {}: not a directory", path.display()));
        }
        Err(_) => {}
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && parent != path
    {
        go_mkdir_all(parent, mode)?;
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) => match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() => Ok(()),
            _ => Err(path_error("mkdir", &path.display().to_string(), &error)),
        },
    }
}

/// `fsutil.AtomicWriteFile`: temporary file next to the target, fsync, rename.
fn atomic_write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let temporary = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
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

/// `os.ReadFile`.
fn go_read_file(path: &Path) -> Result<Vec<u8>, String> {
    let shown = path.display().to_string();
    let mut file = fs::File::open(path).map_err(|error| path_error("open", &shown, &error))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|error| path_error("read", &shown, &error))?;
    Ok(data)
}

fn config_path(dir: &str) -> PathBuf {
    Path::new(dir).join("config.yaml")
}

// ---------------------------------------------------------------------------
// InitVault
// ---------------------------------------------------------------------------

pub(crate) fn init_vault(dir: &str, passphrase: &[u8]) -> R<()> {
    if dir.is_empty() {
        return Err("vaultDir is empty".to_owned());
    }
    if passphrase.is_empty() {
        return Err("passphrase is empty".to_owned());
    }
    let identity = generate_identity();
    let entries = Path::new(dir).join("entries");
    go_mkdir_all(&entries, 0o700).map_err(|reason| format!("create vault dir: {reason}"))?;
    let config = symvault_gojson::yaml::to_string(&symvault_gojson::yaml::Node::Map(vec![
        (
            "vault".to_owned(),
            symvault_gojson::yaml::Node::Map(vec![(
                "format_version".to_owned(),
                symvault_gojson::yaml::Node::Int(2),
            )]),
        ),
        (
            "vaultDir".to_owned(),
            symvault_gojson::yaml::Node::Str(dir.to_owned()),
        ),
    ]));
    atomic_write(&config_path(dir), config.as_bytes(), 0o600)
        .map_err(|error| format!("write config: {}", errno_text(&error)))?;
    let sealed = encrypt_identity_argon2id(
        &identity,
        &SecretBytes::new(passphrase),
        Argon2idParams::default(),
    )
    .map_err(|error| format!("save identity with argon2id: {error}"))?;
    atomic_write(&Path::new(dir).join("identity.age"), &sealed, 0o600)
        .map_err(|error| format!("save identity with argon2id: {}", errno_text(&error)))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// OpenVaultWithPassphrase
// ---------------------------------------------------------------------------

/// `trustedZeroKeyAuthorities`: recipients.txt is the only trust anchor.
fn zero_key_authorities(dir: &str) -> R<(Vec<String>, Vec<u8>)> {
    let path = Path::new(dir).join("recipients.txt");
    let snapshot = match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => fs::read(&path).ok(),
        _ => None,
    }
    .ok_or_else(|| "zero-key recovery requires a trusted recipients.txt".to_owned())?;
    let invalid = || "zero-key recovery requires valid recipients.txt authority".to_owned();
    let text = std::str::from_utf8(&snapshot).map_err(|_| invalid())?;
    let mut recipients = Vec::new();
    for line in text.lines() {
        let line = trim_space(line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        validate_recipient(line).map_err(|_| invalid())?;
        if !recipients.iter().any(|seen| seen == line) {
            recipients.push(line.to_owned());
        }
    }
    if recipients.is_empty() {
        return Err(invalid());
    }
    Ok((recipients, snapshot))
}

/// `tryHealZeroKeyIdentity`.
fn heal_zero_key(dir: &str, raw: &[u8], passphrase: &[u8]) -> R<Identity> {
    let (recipients, snapshot) = zero_key_authorities(dir)?;
    let mut recovered = None;
    for recipient in &recipients {
        if let Ok(identity) = recover_zero_key_identity(
            raw,
            passphrase.len(),
            ZeroKeyAuthority::recipient(recipient),
        ) {
            recovered = Some(identity);
            break;
        }
    }
    let Some(identity) = recovered else {
        return Err("zero-key recovery failed: decryption failed".to_owned());
    };
    let recipients_path = Path::new(dir).join("recipients.txt");
    if fs::read(&recipients_path).ok().as_deref() != Some(snapshot.as_slice()) {
        return Err("zero-key recovery authority changed; refusing to re-key the vault".to_owned());
    }
    let identity_path = Path::new(dir).join("identity.age");
    let backup = Path::new(dir).join("identity.age.bak");
    let original = fs::read(&identity_path).map_err(|error| {
        format!(
            "atomic rewrite of healed identity: read original identity: {}",
            errno_text(&error)
        )
    })?;
    if original != raw {
        return Err("atomic rewrite of healed identity: identity changed during zero-key recovery; refusing to re-key the vault".to_owned());
    }
    atomic_write(&backup, &original, 0o600).map_err(|error| {
        format!(
            "atomic rewrite of healed identity: write backup: {}",
            errno_text(&error)
        )
    })?;
    let sealed = encrypt_identity_argon2id(
        &identity,
        &SecretBytes::new(passphrase),
        Argon2idParams::default(),
    )
    .map_err(|error| format!("atomic rewrite of healed identity: save new identity: {error}"))?;
    atomic_write(&identity_path, &sealed, 0o600).map_err(|error| {
        format!(
            "atomic rewrite of healed identity: save new identity: {}",
            errno_text(&error)
        )
    })?;
    Ok(identity)
}

pub(crate) fn open_with_passphrase(dir: &str, passphrase: &[u8]) -> R<Zeroizing<String>> {
    if dir.is_empty() {
        return Err("vaultDir is empty".to_owned());
    }
    if passphrase.is_empty() {
        return Err("passphrase is empty".to_owned());
    }
    if has_traversal(dir) {
        return Err(DIR_ESCAPES.to_owned());
    }
    let identity_path = Path::new(dir).join("identity.age");
    let raw =
        go_read_file(&identity_path).map_err(|reason| format!("read identity file: {reason}"))?;
    let secret = SecretBytes::new(passphrase);
    let identity = match decrypt_identity(&raw, &secret) {
        Ok(identity) => identity,
        Err(error) => {
            let reason = if detect_envelope(&raw) == EnvelopeFormat::Argon2id {
                match error.class() {
                    FailureClass::ResourceBusy | FailureClass::ResourcePolicy => error.to_string(),
                    _ => match heal_zero_key(dir, &raw, passphrase) {
                        Ok(identity) => return finish_open(dir, identity),
                        Err(reason) => reason,
                    },
                }
            } else {
                scrypt_identity_error(&raw, passphrase)
            };
            return Err(format!("load identity: {reason}"));
        }
    };
    finish_open(dir, identity)
}

/// What `vaultcrypto.LoadIdentity` returns for a non-Argon2id identity file.
fn scrypt_identity_error(raw: &[u8], passphrase: &[u8]) -> String {
    agehdr::explain(
        raw,
        &AgeIdentity::Passphrase(passphrase),
        "read decrypted data",
    )
}

fn finish_open(dir: &str, identity: Identity) -> R<Zeroizing<String>> {
    open_store(dir, &identity)?;
    Ok(secret_text(&identity))
}

pub(crate) fn secret_text(identity: &Identity) -> Zeroizing<String> {
    let bytes = identity_string(identity);
    Zeroizing::new(String::from_utf8_lossy(bytes.as_bytes()).into_owned())
}

// ---------------------------------------------------------------------------
// vault.Open
// ---------------------------------------------------------------------------

fn map_store_error(error: &StoreError) -> String {
    match error {
        StoreError::MissingFile(path) => {
            format!("open {}: no such file or directory", path.display())
        }
        StoreError::ResourceLimit => RESOURCE_LIMIT.to_owned(),
        other => other.to_string(),
    }
}

/// The part of Go `vault.Open` that decides success or the error text.
fn open_store(dir: &str, identity: &Identity) -> R<Store> {
    if dir.is_empty() {
        return Err(DIR_EMPTY.to_owned());
    }
    if has_traversal(dir) {
        return Err(DIR_ESCAPES.to_owned());
    }
    // recoverReencryptJournal takes the write lock, which creates the directory.
    let absolute = std::path::absolute(dir).unwrap_or_else(|_| PathBuf::from(dir));
    go_mkdir_all(&absolute, 0o700).map_err(|reason| {
        format!("recover re-encryption: create vault directory for lock: {reason}")
    })?;
    let path = config_path(dir);
    let bytes = go_read_file(&path).map_err(|reason| format!("load config: {reason}"))?;
    Config::load_from_bytes(&bytes).map_err(|error| format!("load config: {error}"))?;
    let store = Store::open_with_legacy_migration(dir, identity)
        .map_err(|error| map_store_error(&error))?;
    if !Path::new(dir).join("manifest.age").exists() {
        let _ = store.rebuild_manifest(identity);
    }
    Ok(store)
}

// ---------------------------------------------------------------------------
// Entry paths
// ---------------------------------------------------------------------------

/// `validateRawEntryPath` plus the depth limit of `validateEntryPath`.
fn validate_entry_path(path: &str) -> R<()> {
    let trimmed = trim_space(path);
    let invalid = |reason: &str| {
        format!(
            "entry path {}: invalid path: {reason}",
            crate::gotext::quote(trimmed)
        )
    };
    if trimmed.is_empty() {
        return Err(invalid("path is empty"));
    }
    if trimmed.contains('\0') {
        return Err(invalid("path contains null byte"));
    }
    if let Some(control) = trimmed.chars().find(|c| (*c as u32) < 0x20) {
        return Err(invalid(&format!(
            "path contains control character 0x{:02x}",
            control as u32
        )));
    }
    let normalized = trimmed.replace('\\', "/");
    if normalized.starts_with('/') {
        return Err(invalid("path must be relative"));
    }
    let segments: Vec<&str> = normalized.split('/').collect();
    if segments.contains(&"..") {
        return Err(invalid("path contains '..' segment"));
    }
    if segments.len() > 1 && segments.contains(&"") {
        return Err(invalid("path contains empty segment (double slash)"));
    }
    if segments.contains(&".") {
        return Err(format!(
            "entry path {} contains invalid path segment \".\"",
            crate::gotext::quote(trimmed)
        ));
    }
    if path.replace('\\', "/").split('/').count() > MAX_ENTRY_PATH_DEPTH {
        return Err(RESOURCE_LIMIT.to_owned());
    }
    Ok(())
}

/// The text of Go's legacy-layout `statat` failure for a missing entry: the
/// first component of `<path>.age` that does not exist below the vault root.
fn statat_message(dir: &str, path: &str) -> String {
    let relative = format!("{path}.age");
    let parts: Vec<&str> = relative.split('/').collect();
    let mut walked = PathBuf::from(dir);
    let mut shown = String::new();
    for (index, part) in parts.iter().enumerate() {
        walked.push(part);
        if !shown.is_empty() {
            shown.push('/');
        }
        shown.push_str(part);
        match fs::symlink_metadata(&walked) {
            Ok(_) => {}
            Err(error) => {
                let _ = index;
                return format!("statat {shown}: {}", errno_text(&error));
            }
        }
    }
    format!("statat {shown}: no such file or directory")
}

fn entry_ciphertext(store: &Store, identity: &Identity, path: &str) -> Option<Vec<u8>> {
    let target = store.configured_entry_path(path, identity).ok()?;
    fs::read(target).ok()
}

fn describe_entry_error(
    store: &Store,
    identity: &Identity,
    id_text: &str,
    dir: &str,
    path: &str,
    error: &StoreError,
) -> String {
    match error {
        StoreError::EntryNotFound(_) => statat_message(dir, path),
        StoreError::ResourceLimit => RESOURCE_LIMIT.to_owned(),
        StoreError::Decryption(_) => {
            let Some(bytes) = entry_ciphertext(store, identity, path) else {
                return error.to_string();
            };
            if bytes.is_empty() {
                return "ciphertext is empty".to_owned();
            }
            match trim_space(id_text).parse::<age::x25519::Identity>() {
                Ok(key) => agehdr::explain(&bytes, &AgeIdentity::X25519(&key), BOUNDED_PAYLOAD),
                Err(_) => error.to_string(),
            }
        }
        other => map_store_error(other),
    }
}

// ---------------------------------------------------------------------------
// ReadEntryJSON / WriteEntryJSON / ListEntriesJSON
// ---------------------------------------------------------------------------

pub(crate) fn read_entry_json(dir: &str, path: &str, id_text: &str) -> R<Zeroizing<String>> {
    let identity =
        validate_identity(id_text).map_err(|reason| format!("validate identity: {reason}"))?;
    let store = open_store(dir, &identity).map_err(|reason| format!("open vault: {reason}"))?;
    validate_entry_path(path).map_err(|reason| format!("read entry: {reason}"))?;
    let entry = store.get(path, &identity).map_err(|error| {
        format!(
            "read entry: {}",
            describe_entry_error(&store, &identity, id_text, dir, path, &error)
        )
    })?;
    marshal_entry(&entry)
        .map(Zeroizing::new)
        .map_err(|reason| format!("marshal entry: {reason}"))
}

pub(crate) fn write_entry_json(dir: &str, path: &str, json: &str, id_text: &str) -> R<()> {
    let identity =
        validate_identity(id_text).map_err(|reason| format!("validate identity: {reason}"))?;
    let mut entry: Entry =
        decode_entry(json).map_err(|reason| format!("unmarshal entry: {reason}"))?;
    // Go's `cloneEntry` does not copy `Path`; only a pseudonymized vault sets
    // it again (the store does that in `prepare_entry`).
    entry.path.clear();
    validate_entry_path(path)?;
    if dir.is_empty() {
        return Err(
            "create vault directory for lock: mkdir : no such file or directory".to_owned(),
        );
    }
    let cfg = config_path(dir);
    match fs::read(&cfg) {
        Ok(bytes) => {
            Config::load_from_bytes(&bytes)
                .map_err(|error| format!("load vault config: {error}"))?;
        }
        Err(error) => {
            // Go falls back to default settings for a missing config; the Rust
            // store needs an initialized vault, so surface the cause.
            return Err(format!(
                "load vault config: {}",
                path_error("open", &cfg.display().to_string(), &error)
            ));
        }
    }
    let store = Store::open(dir, &identity).map_err(|error| map_store_error(&error))?;
    store
        .write_entry_at(path, &entry, &identity, &now_rfc3339_nano(), false, None)
        .map_err(|error| map_store_error(&error))
}

pub(crate) fn list_entries_json(dir: &str, prefix: &str, id_text: &str) -> R<String> {
    let identity =
        validate_identity(id_text).map_err(|reason| format!("validate identity: {reason}"))?;
    let cfg = config_path(dir);
    let prefix_filter = |paths: Vec<String>| -> R<String> {
        let selected: Vec<String> = paths
            .into_iter()
            .filter(|path| path.starts_with(prefix))
            .collect();
        symvault_gojson::to_string(&selected).map_err(|error| format!("marshal list: {error}"))
    };
    let pseudonymized;
    match fs::read(&cfg) {
        Ok(bytes) => {
            let config = Config::load_from_bytes(&bytes)
                .map_err(|error| format!("list entries: load vault config: {error}"))?;
            pseudonymized = config
                .vault
                .as_ref()
                .is_some_and(|vault| vault.pseudonymize_paths);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Go treats a missing config as defaults and walks the directory.
            let root = Path::new(dir);
            if let Err(error) = fs::read_dir(root) {
                return Err(format!("list entries: {}", path_error("open", dir, &error)));
            }
            return prefix_filter(Vec::new());
        }
        Err(error) => {
            return Err(format!(
                "list entries: load vault config: {}",
                path_error("open", &cfg.display().to_string(), &error)
            ));
        }
    }
    let store = Store::open(dir, &identity)
        .map_err(|error| format!("list entries: {}", map_store_error(&error)))?;
    if prefix.is_empty() && !pseudonymized {
        // Go's manifest fast path: a readable manifest with entries answers
        // the listing on its own, even if it disagrees with the directory.
        if let Ok(manifest) = store.load_manifest(&identity)
            && !manifest.entries.is_empty()
        {
            return prefix_filter(manifest.entries.into_keys().collect());
        }
    }
    let paths = store
        .list(&identity)
        .map_err(|error| format!("list entries: {}", map_store_error(&error)))?;
    prefix_filter(paths)
}

// ---------------------------------------------------------------------------
// VerifyManifestIntegrity
// ---------------------------------------------------------------------------

pub(crate) fn verify_manifest(dir: &str, id_text: &str) -> R<bool> {
    let identity =
        validate_identity(id_text).map_err(|reason| format!("validate identity: {reason}"))?;
    let manifest = Path::new(dir).join("manifest.age");
    if let Err(error) = fs::metadata(&manifest) {
        return Err(format!(
            "manifest not found: {}",
            path_error("stat", &manifest.display().to_string(), &error)
        ));
    }
    let shown = manifest.display().to_string();
    let bytes = match fs::metadata(&manifest) {
        Ok(meta) if meta.is_dir() => {
            return Err(format!("verify manifest: open {shown}: not a directory"));
        }
        _ => fs::read(&manifest)
            .map_err(|error| format!("verify manifest: {}", path_error("open", &shown, &error)))?,
    };
    if bytes.is_empty() {
        return Err("verify manifest: decrypt manifest: ciphertext is empty".to_owned());
    }
    if decrypt(&bytes, &identity).is_err() {
        let key = trim_space(id_text)
            .parse::<age::x25519::Identity>()
            .map_err(|_| "verify manifest: decrypt manifest: decryption failed".to_owned())?;
        return Err(format!(
            "verify manifest: decrypt manifest: {}",
            agehdr::explain(&bytes, &AgeIdentity::X25519(&key), BOUNDED_PAYLOAD)
        ));
    }
    let cfg = config_path(dir);
    match fs::read(&cfg) {
        Ok(config) => {
            Config::load_from_bytes(&config)
                .map_err(|error| format!("verify manifest: load vault config: {error}"))?;
        }
        Err(error) => {
            return Err(format!(
                "verify manifest: load vault config: {}",
                path_error("open", &cfg.display().to_string(), &error)
            ));
        }
    }
    let store = Store::open(dir, &identity)
        .map_err(|error| format!("verify manifest: {}", map_store_error(&error)))?;
    let result = store
        .verify_manifest(&identity)
        .map_err(|error| format!("verify manifest: {}", map_store_error(&error)))?;
    Ok(result.tampered.is_empty() && result.missing.is_empty())
}
