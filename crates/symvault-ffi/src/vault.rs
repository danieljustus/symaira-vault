//! The six vault-level bridge functions, orchestrated over `symvault-store`
//! and `symvault-crypto`, with Go's checks performed in Go's order so the
//! first failure (and its text) is the same.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use symvault_core::config::{Config, VaultConfig};
use symvault_crypto::{
    Argon2idParams, EnvelopeFormat, Identity, SecretBytes, decrypt, decrypt_identity,
    detect_envelope, encrypt_identity_argon2id, generate_identity, identity_string,
};
use symvault_store::zero_key::{heal_zero_key_identity, is_argon2_resource_error};
use symvault_store::{Store, StoreError};
use zeroize::Zeroizing;

use crate::gotext::agehdr::{self, Identity as AgeIdentity};
use crate::gotext::bech32::validate_identity;
use crate::gotext::entryjson::{ScrubbedEntry, decode_entry};
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

/// A temporary file name no other call can pick: process id, a per-process
/// counter and a random component, so concurrent calls on one vault (in this
/// process or another) never share a temporary file.
fn unique_suffix() -> String {
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    format!(
        "{}-{}-{random:016x}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// `fsutil.AtomicWriteFile`: temporary file next to the target, fsync, rename.
fn atomic_write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let mut options = fs::OpenOptions::new();
    // `create_new` makes a (practically impossible) name collision an error
    // instead of two writers sharing one file.
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let temporary = parent.join(format!(".{name}.tmp-{}", unique_suffix()));
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

/// `loadVaultConfig`: a config file that does not exist means default settings
/// (`None`); any other failure is returned with Go's text. Used by the
/// package-level functions Go runs without `vault.Open`.
fn load_vault_config(dir: &str) -> R<Option<Config>> {
    let path = config_path(dir);
    match fs::read(&path) {
        Ok(bytes) => Config::load_from_bytes(&bytes)
            .map(Some)
            .map_err(|error| error.to_string()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(go_read_error(&path, &error)),
    }
}

/// `os.ReadFile`'s error: `open` when the path cannot be opened, `read` when it
/// opens (a directory) but cannot be read.
fn go_read_error(path: &Path, error: &io::Error) -> String {
    let shown = path.display().to_string();
    let stage = if fs::File::open(path).is_ok() {
        "read"
    } else {
        "open"
    };
    path_error(stage, &shown, error)
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
    symvault_sync::data_safety::install();
    // InitVault overwrites identity.age and config.yaml of an existing Go vault:
    // that is a mutation, so such a vault is backed up (and marked) first.
    if Path::new(dir).join("identity.age").exists() || config_path(dir).exists() {
        symvault_store::data_safety::ensure_marker(Path::new(dir))
            .map_err(|error| error.to_string())?;
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
    symvault_store::data_safety::mark_created(Path::new(dir))
        .map_err(|error| format!("write rust marker: {error}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// OpenVaultWithPassphrase
// ---------------------------------------------------------------------------

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
                if is_argon2_resource_error(error) {
                    error.to_string()
                } else {
                    match heal_zero_key_identity(Path::new(dir), &raw, passphrase) {
                        Ok(identity) => return finish_open(dir, identity),
                        Err(reason) => reason,
                    }
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
        // Go reports every limit (entry nesting, string/array/field budgets,
        // enumeration caps) with one text that names neither path nor value.
        StoreError::ResourceLimit | StoreError::Limit { .. } | StoreError::ValueLimit(_) => {
            RESOURCE_LIMIT.to_owned()
        }
        other => other.to_string(),
    }
}

/// `detectLegacyMode`: a config that does not record `legacy_mode` gets it
/// written, which makes Go rewrite `config.yaml` as the full merged config on
/// the first open.
fn detect_legacy_mode(dir: &str, mut config: Config) -> R<()> {
    if config
        .vault
        .as_ref()
        .is_some_and(|vault| vault.legacy_mode.is_some())
    {
        return Ok(());
    }
    // A symlinked config.yaml is refused by the store open that follows
    // (D-SYMLINK); rewriting first would replace the link with a regular file
    // and turn that refusal into a success, so leave it untouched.
    if fs::symlink_metadata(config_path(dir)).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Ok(());
    }
    let legacy = has_legacy_top_level_age_files(dir)
        .map_err(|reason| format!("detect legacy mode: {reason}"))?;
    match config.vault.as_mut() {
        Some(vault) => vault.legacy_mode = Some(legacy),
        None => {
            config.vault = Some(VaultConfig {
                legacy_mode: Some(legacy),
                ..VaultConfig::default()
            });
        }
    }
    config
        .save_to(config_path(dir))
        .map_err(|error| format!("detect legacy mode: {error}"))
}

/// `hasLegacyTopLevelAgeFiles`: any non-directory `*.age` besides the identity.
fn has_legacy_top_level_age_files(dir: &str) -> R<bool> {
    let entries = fs::read_dir(dir).map_err(|error| path_error("open", dir, &error))?;
    for (visited, entry) in entries.enumerate() {
        let entry = entry.map_err(|error| path_error("readdirent", dir, &error))?;
        if visited + 1 > symvault_store::MAX_VAULT_ENTRY_COUNT {
            return Err(RESOURCE_LIMIT.to_owned());
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
        if !is_dir && name.ends_with(".age") && name != "identity.age" {
            return Ok(true);
        }
    }
    Ok(false)
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
    let config =
        Config::load_from_bytes(&bytes).map_err(|error| format!("load config: {error}"))?;
    detect_legacy_mode(dir, config)?;
    symvault_sync::data_safety::install();
    let store = Store::open_lenient_with_legacy_migration(dir, identity)
        .map_err(|error| map_store_error(&error))?;
    // mobilebind opens through `vault.Open`, whose manifest consistency block
    // rebuilds a missing, stale or incomplete manifest (best effort).
    store.reconcile_manifest_on_open(identity);
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
    // Scrubbed on drop, so every early return below leaves no plaintext.
    let mut entry =
        ScrubbedEntry(decode_entry(json).map_err(|reason| format!("unmarshal entry: {reason}"))?);
    // Go's `cloneEntry` does not copy `Path`; only a pseudonymized vault sets
    // it again (the store does that in `prepare_entry`).
    entry.0.path.clear();
    validate_entry_path(path)?;
    if dir.is_empty() {
        return Err(
            "create vault directory for lock: mkdir : no such file or directory".to_owned(),
        );
    }
    load_vault_config(dir).map_err(|reason| format!("load vault config: {reason}"))?;
    // AcquireWriteLock creates the vault directory, so a write into a path that
    // does not exist yet succeeds in Go.
    let absolute = std::path::absolute(dir).unwrap_or_else(|_| PathBuf::from(dir));
    go_mkdir_all(&absolute, 0o700)
        .map_err(|reason| format!("create vault directory for lock: {reason}"))?;
    symvault_sync::data_safety::install();
    let store = Store::open_lenient(dir, &identity).map_err(|error| map_store_error(&error))?;
    store
        .write_entry_at(path, &entry.0, &identity, &now_rfc3339_nano(), false, None)
        .map_err(|error| map_store_error(&error))
}

pub(crate) fn list_entries_json(dir: &str, prefix: &str, id_text: &str) -> R<String> {
    let identity =
        validate_identity(id_text).map_err(|reason| format!("validate identity: {reason}"))?;
    let prefix_filter = |paths: Vec<String>| -> R<String> {
        let selected: Vec<String> = paths
            .into_iter()
            .filter(|path| path.starts_with(prefix))
            .collect();
        symvault_gojson::to_string(&selected).map_err(|error| format!("marshal list: {error}"))
    };
    let config = load_vault_config(dir)
        .map_err(|reason| format!("list entries: load vault config: {reason}"))?;
    let pseudonymized = config
        .as_ref()
        .and_then(|config| config.vault.as_ref())
        .is_some_and(|vault| vault.pseudonymize_paths);
    if config.is_none() {
        // Default settings: Go walks the directory, whose open fails first.
        if let Err(error) = fs::read_dir(dir) {
            return Err(format!("list entries: {}", path_error("open", dir, &error)));
        }
    }
    symvault_sync::data_safety::install();
    let store = Store::open_lenient(dir, &identity)
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
    load_vault_config(dir)
        .map_err(|reason| format!("verify manifest: load vault config: {reason}"))?;
    symvault_sync::data_safety::install();
    let store = Store::open_lenient(dir, &identity)
        .map_err(|error| format!("verify manifest: {}", map_store_error(&error)))?;
    let result = store
        .verify_manifest(&identity)
        .map_err(|error| format!("verify manifest: {}", map_store_error(&error)))?;
    Ok(result.tampered.is_empty() && result.missing.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Many threads replacing one file at once: every call succeeds, the file
    /// always holds exactly one writer's complete payload, and no temporary file
    /// is left behind. A temporary name keyed by process id alone makes the
    /// writers share one file, so renames fail and payloads interleave.
    #[test]
    fn concurrent_atomic_writes_to_one_target_do_not_collide() {
        const THREADS: u8 = 16;
        const ROUNDS: usize = 40;
        let directory = tempfile::tempdir().expect("tempdir");
        let target = directory.path().join("config.yaml");
        std::thread::scope(|scope| {
            for thread in 0..THREADS {
                let target = &target;
                scope.spawn(move || {
                    let payload = vec![b'a' + thread; 64 * 1024];
                    for _ in 0..ROUNDS {
                        atomic_write(target, &payload, 0o600).expect("atomic write");
                        let seen = fs::read(target).expect("read back");
                        assert_eq!(seen.len(), payload.len(), "a torn write was observed");
                        assert!(
                            seen.iter().all(|byte| *byte == seen[0]),
                            "two writers' bytes were mixed in one file"
                        );
                    }
                });
            }
        });
        let leftovers: Vec<_> = fs::read_dir(directory.path())
            .expect("read_dir")
            .flatten()
            .map(|entry| entry.file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("config.yaml")]);
    }

    /// `vault.Open` (and so every mobilebind call) rebuilds a manifest that does
    /// not list an `.age` file dropped into `entries/` out of band, and one that
    /// is missing; it used to be only the missing case here.
    #[test]
    fn every_open_reconciles_the_manifest_like_go() {
        let directory = tempfile::tempdir().expect("tempdir");
        let dir = directory.path().to_str().expect("utf-8 path");
        init_vault(dir, b"correct horse battery staple").expect("init");
        let id_text = open_with_passphrase(dir, b"correct horse battery staple").expect("open");
        write_entry_json(dir, "one", r#"{"data":{"k":"v"}}"#, &id_text).expect("write");
        let identity = validate_identity(&id_text).expect("identity");
        let listed = |dir: &str| -> Vec<String> {
            let store = Store::open(dir, &identity).expect("store");
            store
                .load_manifest(&identity)
                .expect("manifest")
                .entries
                .into_keys()
                .collect()
        };
        assert_eq!(listed(dir), vec!["one".to_owned()]);

        // A git pull / rsync drops a second entry in; the manifest is stale.
        fs::copy(
            directory.path().join("entries/one.age"),
            directory.path().join("entries/two.age"),
        )
        .expect("copy");
        read_entry_json(dir, "one", &id_text).expect("read");
        assert_eq!(listed(dir), vec!["one".to_owned(), "two".to_owned()]);

        // A missing manifest is rebuilt too.
        fs::remove_file(directory.path().join("manifest.age")).expect("remove");
        read_entry_json(dir, "one", &id_text).expect("read");
        assert_eq!(listed(dir), vec!["one".to_owned(), "two".to_owned()]);
    }

    #[test]
    fn temporary_names_are_unique() {
        let names: std::collections::HashSet<String> = (0..1000).map(|_| unique_suffix()).collect();
        assert_eq!(names.len(), 1000);
    }
}
