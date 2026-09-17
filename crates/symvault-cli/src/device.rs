//! PAIRING-001 CLI implementation: device pair, join, accept, list, add, revoke.

use crate::session_input as input;
use input::read_passphrase;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use symvault_core::config::{Config, GitConfig};
#[cfg(test)]
use symvault_crypto::encrypt;
use symvault_crypto::{
    Identity, Recipient, SecretBytes, decrypt_identity, encrypt_identity_scrypt, fingerprint,
    generate_identity, identity_string, parse_identity, parse_recipient, recipient_string,
    reencrypt,
};
use symvault_sync::{
    CommitOptions, DeviceRegistry, GitRepository, GoTime, JoinResponse, PairingFile,
    RecipientsFile, generate_token, marshal_join_response, marshal_pairing_file,
    parse_join_response, parse_pairing_file, response_filenames, safeio, validate_pairing_token,
};

#[derive(Serialize)]
struct ListedDevice<'a> {
    name: &'a str,
    public_key: &'a str,
    added_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen: Option<String>,
}

#[derive(Serialize)]
struct Listing<'a> {
    // Go's outer map is sorted, while the inner structs retain field order.
    count: usize,
    devices: Vec<ListedDevice<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unmanaged_recipients: Vec<String>,
}

fn seconds(time: GoTime) -> String {
    let mut value = time.to_rfc3339_nano();
    if let Some(start) = value.find('.') {
        let end = value[start..]
            .find(['Z', '+', '-'])
            .map(|offset| start + offset)
            .unwrap_or(value.len());
        value.replace_range(start..end, "");
    }
    value
}

fn short_key(key: &str) -> Vec<u8> {
    // Go slices bytes, not Unicode scalars. Write bytes, without lossy decoding.
    if key.len() > 16 {
        [key.as_bytes()[..16].to_vec(), b"...".to_vec()].concat()
    } else {
        key.as_bytes().to_vec()
    }
}

fn truncate_pubkey(pubkey: &str) -> String {
    String::from_utf8_lossy(&short_key(pubkey)).into_owned()
}

fn is_initialized(vault: &Path) -> bool {
    vault.join("identity.age").is_file() && vault.join("config.yaml").is_file()
}

fn joined_config(vault: &Path) -> Result<Vec<u8>, String> {
    let config = Config {
        vault_dir: vault.to_str().ok_or("vault path must be UTF-8")?.to_owned(),
        git: Some(GitConfig::default()),
        ..Config::default()
    };
    config
        .to_yaml_bytes()
        .map_err(|e| format!("serialize config: {e}"))
}

pub(crate) fn unlock_vault(vault: &Path) -> Result<Identity, String> {
    if !is_initialized(vault) {
        return Err("vault is not initialized (run 'symvault init' first)".to_owned());
    }
    let runtime = crate::runtime_session_manager();
    unlock_vault_with_runtime(vault, &runtime)
}

fn unlock_vault_with_runtime(
    vault: &Path,
    runtime: &crate::RuntimeSession,
) -> Result<Identity, String> {
    let vault_string = vault
        .to_str()
        .ok_or_else(|| "vault path is not valid UTF-8".to_owned())?;
    let config_path = vault.join("config.yaml");
    let config = Config::load(&config_path).map_err(|error| format!("load config: {error}"))?;
    let config_bytes = safeio::read(&config_path)
        .map_err(|e| format!("read config: {e}"))?
        .ok_or_else(|| "configuration is missing".to_owned())?;

    // A cached private identity is the fastest path and deliberately avoids
    // reading or decrypting the on-disk envelope. SessionManager renews the
    // idle timestamp when `refresh` is true, matching Go's vault reads.
    if let Ok(cached) = runtime
        .manager
        .load_identity(vault_string, true)
        .map(zeroize::Zeroizing::new)
        && let Ok(text) = std::str::from_utf8(&cached)
        && let Ok(identity) = parse_identity(text.trim())
    {
        return Ok(identity);
    }

    let id_path = vault.join("identity.age");
    let data = safeio::read(&id_path)
        .map_err(|e| format!("read identity: {e}"))?
        .ok_or_else(|| "vault is not initialized (run 'symvault init' first)".to_owned())?;

    // Prefer the encrypted session passphrase before invoking Touch ID or a
    // prompt. A bad/expired cache is recoverable and falls through to the
    // normal authentication path.
    if let Ok(cached) = runtime
        .manager
        .load_passphrase(vault_string)
        .map(zeroize::Zeroizing::new)
        && let Ok(identity) = decrypt_identity(&data, &SecretBytes::new(&cached))
    {
        save_unlocked_session(runtime, vault_string, &config, &cached, &identity)?;
        return Ok(identity);
    }

    let passphrase = crate::unlock_passphrase(&config_bytes, &config, vault, runtime)?;
    let sec_pass = SecretBytes::new(passphrase.as_bytes());
    let identity = decrypt_identity(&data, &sec_pass).map_err(|e| format!("unlock vault: {e}"))?;
    if !input::env_passphrase_selected(&config_bytes) {
        save_unlocked_session(
            runtime,
            vault_string,
            &config,
            passphrase.as_bytes(),
            &identity,
        )?;
    }
    Ok(identity)
}

fn save_unlocked_session(
    runtime: &crate::RuntimeSession,
    vault: &str,
    config: &Config,
    passphrase: &[u8],
    identity: &Identity,
) -> Result<(), String> {
    let ttl = if config.session_timeout.is_zero() {
        Duration::from_secs(15 * 60)
    } else {
        config.session_timeout
    };
    let max_lifetime = if config.session_max_lifetime.is_zero() {
        Duration::from_secs(8 * 60 * 60)
    } else {
        config.session_max_lifetime
    };
    runtime
        .manager
        .save_passphrase(vault, passphrase, ttl, max_lifetime)
        .map_err(|error| format!("save session: {error}"))?;
    let cached_identity = identity_string(identity);
    runtime
        .manager
        .save_identity(vault, cached_identity.as_bytes(), ttl, max_lifetime)
        .map_err(|error| format!("save identity session: {error}"))
}

pub(crate) fn get_all_recipients_for_encryption(
    vault: &Path,
    identity: &Identity,
) -> Result<Vec<Recipient>, String> {
    let own_pubkey = recipient_string(identity);
    let mut seen = HashSet::new();
    seen.insert(own_pubkey.clone());

    let mut result = Vec::new();
    let own_recip =
        parse_recipient(&own_pubkey).map_err(|e| format!("parse identity recipient: {e}"))?;
    result.push(own_recip);

    let rm = RecipientsFile::new(vault);
    let additional = rm
        .load_strings()
        .map_err(|e| format!("load recipients: {e}"))?
        .unwrap_or_default();

    for r_str in additional {
        if seen.insert(r_str.clone()) {
            let recip =
                parse_recipient(&r_str).map_err(|e| format!("parse recipient {r_str}: {e}"))?;
            result.push(recip);
        }
    }
    Ok(result)
}

pub(crate) fn reencrypt_all_entries(
    vault: &Path,
    identity: &Identity,
    recipients: &[Recipient],
) -> Result<(), String> {
    let vault = fs::canonicalize(vault).map_err(|e| format!("resolve vault directory: {e}"))?;
    let Some(entries_dir) = validate_reencrypt_entries_root(&vault)? else {
        return Ok(());
    };
    let store = symvault_store::Store::open(&vault, identity)
        .map_err(|e| format!("open store for re-encryption: {e}"))?;

    store
        .with_write_lock(|store| {
            let result: Result<(), String> = (|| {
                let manifest = snapshot_file(&vault.join("manifest.age"))?;
                let files = collect_reencrypt_files(&entries_dir, identity, recipients)?;
                if files.is_empty() {
                    return Ok(());
                }

                let mut journal = ReencryptJournal::new(&vault, &files)?;
                persist_reencrypt_journal(&vault, &journal)?;
                if let Err(error) = stage_and_install_reencrypted(&vault, &files, &mut journal) {
                    let recovery = store
                        .recover_reencrypt_journal_locked(identity)
                        .map_err(|error| error.to_string());
                    return match recovery {
                        Ok(_) => Err(error),
                        Err(recovery_error) => Err(format!(
                            "{error} (journal recovery failed: {recovery_error})"
                        )),
                    };
                }

                if let Err(error) = store.rebuild_manifest_locked(identity) {
                    let rollback = rollback_reencrypt_journal_locked(&vault);
                    let restore_manifest = Some(match manifest.as_ref() {
                        Some(snapshot) => {
                            restore_file(&snapshot.path, &snapshot.bytes, &snapshot.metadata)
                        }
                        None => remove_file_if_exists(&vault.join("manifest.age")),
                    });
                    let cleanup = if rollback.is_ok()
                        && restore_manifest.as_ref().is_some_and(Result::is_ok)
                    {
                        remove_reencrypt_journal(&vault)
                    } else {
                        Ok(())
                    };
                    return Err(format_manifest_failure(
                        error.to_string(),
                        rollback,
                        restore_manifest,
                        cleanup,
                    ));
                }
                let current = load_reencrypt_journal(&vault)?;
                verify_installed_targets(&current)?;
                cleanup_reencrypt_artifacts(&vault, &current)?;
                remove_reencrypt_journal(&vault)
            })();
            result.map_err(symvault_store::StoreError::Config)
        })
        .map_err(|e| format!("re-encrypt entries: {e}"))
}

struct ReencryptFile {
    path: PathBuf,
    replacement: Vec<u8>,
    metadata: FileMetadata,
}

fn validate_reencrypt_entries_root(vault: &Path) -> Result<Option<PathBuf>, String> {
    let entries_dir = vault.join("entries");
    match fs::symlink_metadata(&entries_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "unsafe symlink entries root {:?}",
            entries_dir.display()
        )),
        Ok(metadata) if !metadata.file_type().is_dir() => Err(format!(
            "vault entries root is not a directory: {}",
            entries_dir.display()
        )),
        Ok(_) => Ok(Some(entries_dir)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("stat {}: {error}", entries_dir.display())),
    }
}

const REENCRYPT_JOURNAL_VERSION: u32 = 1;
const REENCRYPT_JOURNAL_NAME: &str = ".reencrypt.journal";

#[derive(Debug, Deserialize, Serialize)]
struct ReencryptJournal {
    version: u32,
    entries: Vec<ReencryptJournalEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReencryptJournalEntry {
    path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    temp: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    backup: String,
    #[serde(default)]
    digest: String,
    #[serde(default)]
    installed: bool,
}

impl ReencryptJournal {
    fn new(root: &Path, files: &[ReencryptFile]) -> Result<Self, String> {
        let entries = files
            .iter()
            .map(|file| {
                Ok(ReencryptJournalEntry {
                    path: journal_string(root, &file.path)?,
                    temp: String::new(),
                    backup: String::new(),
                    digest: String::new(),
                    installed: false,
                })
            })
            .collect::<Result<_, String>>()?;
        Ok(Self {
            version: REENCRYPT_JOURNAL_VERSION,
            entries,
        })
    }
}

struct FileMetadata {
    permissions: fs::Permissions,
    accessed: SystemTime,
    modified: SystemTime,
}

struct FileSnapshot {
    path: PathBuf,
    bytes: Vec<u8>,
    metadata: FileMetadata,
}

fn collect_reencrypt_files(
    dir: &Path,
    identity: &Identity,
    recipients: &[Recipient],
) -> Result<Vec<ReencryptFile>, String> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("read dir {}: {e}", dir.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("read dir {}: {e}", dir.display()))?;
    entries.sort_by_key(|entry| entry.path());

    let mut files = Vec::new();
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("stat {}: {e}", path.display()))?;
        if file_type.is_symlink() {
            return Err(format!("unsafe symlink entry {:?}", path.display()));
        }
        if file_type.is_dir() {
            files.extend(collect_reencrypt_files(&path, identity, recipients)?);
        } else if file_type.is_file()
            && path.extension().and_then(|ext| ext.to_str()) == Some("age")
        {
            let metadata =
                fs::symlink_metadata(&path).map_err(|e| format!("stat {}: {e}", path.display()))?;
            let raw = safeio::read(&path)
                .map_err(|e| format!("read {}: {e}", path.display()))?
                .ok_or_else(|| format!("file not found: {}", path.display()))?;
            let replacement = reencrypt(&raw, identity, recipients)
                .map_err(|e| format!("re-encrypt {}: {e}", path.display()))?;
            let metadata = file_metadata(&metadata, &path)?;
            files.push(ReencryptFile {
                path,
                replacement,
                metadata,
            });
        }
    }
    Ok(files)
}

fn file_metadata(metadata: &fs::Metadata, path: &Path) -> Result<FileMetadata, String> {
    Ok(FileMetadata {
        permissions: metadata.permissions(),
        accessed: metadata
            .accessed()
            .map_err(|e| format!("read access time for {}: {e}", path.display()))?,
        modified: metadata
            .modified()
            .map_err(|e| format!("read modification time for {}: {e}", path.display()))?,
    })
}

fn snapshot_file(path: &Path) -> Result<Option<FileSnapshot>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("stat {}: {error}", path.display())),
    };
    if !metadata.file_type().is_file() {
        return Err(format!(
            "manifest is not a regular file: {}",
            path.display()
        ));
    }
    let bytes = safeio::read(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?
        .ok_or_else(|| format!("file not found: {}", path.display()))?;
    Ok(Some(FileSnapshot {
        path: path.to_owned(),
        bytes,
        metadata: file_metadata(&metadata, path)?,
    }))
}

fn restore_metadata(path: &Path, metadata: &FileMetadata) -> Result<(), String> {
    let file = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.set_times(
        fs::FileTimes::new()
            .set_accessed(metadata.accessed)
            .set_modified(metadata.modified),
    )
    .map_err(|e| e.to_string())?;
    drop(file);
    fs::set_permissions(path, metadata.permissions.clone()).map_err(|e| e.to_string())
}

fn restore_file(path: &Path, bytes: &[u8], metadata: &FileMetadata) -> Result<(), String> {
    safeio::write_atomic(path, bytes).map_err(|e| e.to_string())?;
    restore_metadata(path, metadata)
}

fn remove_file_if_exists(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {}: {error}", path.display())),
    }
}

fn journal_path(root: &Path) -> PathBuf {
    root.join(REENCRYPT_JOURNAL_NAME)
}

fn journal_string(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| format!("journal path escapes vault: {}", path.display()))?;
    if relative
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!("journal path escapes vault: {}", path.display()));
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("journal path is not valid UTF-8: {}", path.display()))
}

fn journal_target(root: &Path, value: &str) -> Result<PathBuf, String> {
    let canonical_root = canonical_journal_root(root)?;
    let path = normalize_journal_path(&canonical_root, Path::new(value))?;
    let relative = path
        .strip_prefix(&canonical_root)
        .map_err(|_| format!("journal path escapes vault: {value}"))?;
    if !path.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        || relative.components().next()
            != Some(std::path::Component::Normal(std::ffi::OsStr::new(
                "entries",
            )))
        || path.extension().and_then(|ext| ext.to_str()) != Some("age")
    {
        return Err(format!("journal path escapes vault: {value}"));
    }
    validate_journal_parents(&canonical_root, relative, &path)?;
    Ok(path)
}

fn validate_journal_parents(root: &Path, relative: &Path, display: &Path) -> Result<(), String> {
    let mut current = root.to_owned();
    for component in relative.parent().into_iter().flat_map(Path::components) {
        let std::path::Component::Normal(name) = component else {
            return Err(format!("journal path escapes vault: {}", display.display()));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "journal path uses symlinked parent: {}",
                    current.display()
                ));
            }
            Ok(_) => {
                return Err(format!(
                    "journal path parent is not a directory: {}",
                    current.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(format!(
                    "journal path parent is missing: {}",
                    current.display()
                ));
            }
            Err(error) => return Err(format!("stat journal path parent: {error}")),
        }
    }
    Ok(())
}

fn journal_artifact(
    root: &Path,
    value: &str,
    target: &Path,
    suffix: &str,
) -> Result<PathBuf, String> {
    let canonical_root = canonical_journal_root(root)?;
    let path = normalize_journal_path(&canonical_root, Path::new(value))?;
    let relative = path
        .strip_prefix(&canonical_root)
        .map_err(|_| format!("journal artifact escapes vault: {value}"))?;
    if !path.is_absolute()
        || path == target
        || path.parent() != target.parent()
        || relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "journal artifact escapes target directory: {value}"
        ));
    }
    let target_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("journal target is not valid UTF-8: {}", target.display()))?;
    let artifact_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("journal artifact is not valid UTF-8: {value}"))?;
    if !valid_reencrypt_artifact_name(artifact_name, target_name, suffix) {
        return Err(format!("journal artifact has invalid name: {value}"));
    }
    validate_journal_parents(&canonical_root, relative, &path)?;
    Ok(path)
}

fn valid_reencrypt_artifact_name(name: &str, target: &str, suffix: &str) -> bool {
    let rust_prefix = format!(".{target}.reencrypt-");
    let rust_name = name
        .strip_prefix(&rust_prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .is_some_and(|value| !value.is_empty() && !value.contains('/'));
    match suffix {
        ".tmp" => {
            let go_unix_prefix = format!(".{target}.reencrypt-");
            let go_unix_name = name
                .strip_prefix(&go_unix_prefix)
                .is_some_and(|random| is_hex(random, 24));
            let go_windows_name = name.strip_prefix(".reencrypt-").is_some_and(|random| {
                !random.is_empty() && random.chars().all(|c| c.is_ascii_alphanumeric())
            });
            rust_name || go_unix_name || go_windows_name
        }
        ".backup" => {
            let go_unix_prefix = format!(".{target}.backup.reencrypt-");
            let go_unix_name = name
                .strip_prefix(&go_unix_prefix)
                .is_some_and(|random| is_hex(random, 24));
            let go_windows_prefix = format!("{target}.reencrypt-backup");
            let go_windows_name = name.strip_prefix(&go_windows_prefix).is_some_and(|suffix| {
                suffix.is_empty()
                    || suffix[1..].chars().all(|c| c.is_ascii_digit()) && suffix.starts_with('.')
            });
            rust_name || go_unix_name || go_windows_name
        }
        _ => false,
    }
}

// Go and Rust persist absolute journal paths, but macOS can expose the same
// directory through /var and /private/var. Canonicalize only the existing
// parent so an untrusted final component is never followed. Mutations still
// pass through the existing regular-file checks and rooted operations.
fn canonical_journal_root(root: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(root)
        .map_err(|error| format!("resolve journal root {}: {error}", root.display()))
}

fn normalize_journal_path(root: &Path, path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(format!("journal path escapes vault: {}", path.display()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("journal path has no parent: {}", path.display()))?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| format!("resolve journal parent {}: {error}", parent.display()))?;
    validate_journal_ancestors(root, parent, path)?;
    if !canonical_parent.starts_with(root) {
        return Err(format!("journal path escapes vault: {}", path.display()));
    }
    let name = path
        .file_name()
        .ok_or_else(|| format!("journal path has no file name: {}", path.display()))?;
    Ok(canonical_parent.join(name))
}

fn validate_journal_ancestors(root: &Path, parent: &Path, display: &Path) -> Result<(), String> {
    let mut current = parent;
    loop {
        let metadata = fs::symlink_metadata(current)
            .map_err(|error| format!("stat journal parent {}: {error}", current.display()))?;
        let canonical = fs::canonicalize(current)
            .map_err(|error| format!("resolve journal parent {}: {error}", current.display()))?;
        if canonical == root {
            return Ok(());
        }
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "journal path uses symlinked parent: {}",
                current.display()
            ));
        }
        if !canonical.starts_with(root) {
            return Err(format!("journal path escapes vault: {}", display.display()));
        }
        if !metadata.file_type().is_dir() {
            return Err(format!(
                "journal path parent is not a directory: {}",
                current.display()
            ));
        }
        current = current
            .parent()
            .ok_or_else(|| format!("journal path escapes vault: {}", display.display()))?;
    }
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn persist_reencrypt_journal(root: &Path, journal: &ReencryptJournal) -> Result<(), String> {
    let encoded =
        serde_json::to_vec(journal).map_err(|e| format!("encode re-encryption journal: {e}"))?;
    safeio::write_atomic(&journal_path(root), &encoded)
        .map_err(|e| format!("write re-encryption journal: {e}"))?;
    sync_directory(root)
}

fn load_reencrypt_journal(root: &Path) -> Result<ReencryptJournal, String> {
    let bytes = safeio::read(&journal_path(root))
        .map_err(|e| format!("read re-encryption journal: {e}"))?
        .ok_or_else(|| "re-encryption journal is missing".to_owned())?;
    let journal: ReencryptJournal =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse re-encryption journal: {e}"))?;
    if journal.version != REENCRYPT_JOURNAL_VERSION {
        return Err(format!(
            "unsupported re-encryption journal version {}",
            journal.version
        ));
    }
    for entry in &journal.entries {
        let target = journal_target(root, &entry.path)?;
        if !entry.temp.is_empty() {
            journal_artifact(root, &entry.temp, &target, ".tmp")?;
        }
        if !entry.backup.is_empty() {
            journal_artifact(root, &entry.backup, &target, ".backup")?;
        }
        if entry.digest.is_empty() && (!entry.temp.is_empty() || !entry.backup.is_empty()) {
            return Err("journal artifact has no ciphertext digest".to_owned());
        }
    }
    Ok(journal)
}

fn remove_reencrypt_journal(root: &Path) -> Result<(), String> {
    match fs::remove_file(journal_path(root)) {
        Ok(()) => sync_directory(root),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove re-encryption journal: {error}")),
    }
}

fn artifact_path(path: &Path, suffix: &str, seed: u128, index: usize) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("entry path is not valid UTF-8: {}", path.display()))?;
    for attempt in 0..100u32 {
        let candidate = path.with_file_name(format!(
            ".{name}.reencrypt-{seed}-{index}-{attempt}.{suffix}"
        ));
        match fs::symlink_metadata(&candidate) {
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Err(error) => return Err(format!("check re-encryption artifact: {error}")),
        }
    }
    Err(format!("could not allocate re-encryption {suffix} file"))
}

fn stage_reencrypted_file(file: &ReencryptFile, temp: &Path) -> Result<(), String> {
    safeio::refuse_unsafe_target(&file.path).map_err(|e| format!("check target: {e}"))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut staged = options
        .open(temp)
        .map_err(|e| format!("create staged ciphertext: {e}"))?;
    staged
        .write_all(&file.replacement)
        .map_err(|e| format!("write staged ciphertext: {e}"))?;
    staged
        .sync_all()
        .map_err(|e| format!("sync staged ciphertext: {e}"))?;
    drop(staged);
    restore_metadata(temp, &file.metadata)
}

fn digest(bytes: &[u8]) -> String {
    symvault_store::sha256_hex(bytes)
}

fn target_matches(path: &Path, expected: &str) -> Result<bool, String> {
    let Some(bytes) = safeio::read(path).map_err(|e| format!("read recovery target: {e}"))? else {
        return Ok(false);
    };
    Ok(digest(&bytes).eq_ignore_ascii_case(expected))
}

fn regular_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(format!(
            "re-encryption artifact is not a regular file: {}",
            path.display()
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("stat re-encryption artifact: {error}")),
    }
}

fn remove_artifact(path: &Path) -> Result<(), String> {
    if !regular_exists(path)? {
        return Ok(());
    }
    fs::remove_file(path).map_err(|e| format!("remove re-encryption artifact: {e}"))
}

fn cleanup_reencrypt_artifacts(root: &Path, journal: &ReencryptJournal) -> Result<(), String> {
    let mut artifacts = Vec::new();
    for entry in &journal.entries {
        let target = journal_target(root, &entry.path)?;
        if !entry.temp.is_empty() {
            artifacts.push(journal_artifact(root, &entry.temp, &target, ".tmp")?);
        }
        if !entry.backup.is_empty() {
            artifacts.push(journal_artifact(root, &entry.backup, &target, ".backup")?);
        }
    }
    for artifact in artifacts {
        remove_artifact(&artifact)?;
    }
    Ok(())
}

fn rollback_reencrypt_journal_locked(root: &Path) -> Result<(), String> {
    let journal = load_reencrypt_journal(root)?;
    for entry in journal.entries.iter().rev() {
        let target = journal_target(root, &entry.path)?;
        let backup = if entry.backup.is_empty() {
            None
        } else {
            Some(journal_artifact(root, &entry.backup, &target, ".backup")?)
        };
        let temp = if entry.temp.is_empty() {
            None
        } else {
            Some(journal_artifact(root, &entry.temp, &target, ".tmp")?)
        };
        if let Some(temp) = temp {
            remove_artifact(&temp)?;
        }
        let Some(backup) = backup else {
            continue;
        };
        if !regular_exists(&backup)? {
            continue;
        }
        if regular_exists(&target)? {
            if !entry.digest.is_empty() && !target_matches(&target, &entry.digest)? {
                return Err(format!(
                    "refusing to overwrite changed rollback target: {}",
                    target.display()
                ));
            }
            fs::remove_file(&target).map_err(|e| format!("remove replacement ciphertext: {e}"))?;
        }
        fs::rename(&backup, &target).map_err(|e| format!("restore original ciphertext: {e}"))?;
        sync_directory(target.parent().unwrap_or(root))?;
    }
    Ok(())
}

fn format_manifest_failure(
    manifest_error: String,
    rollback: Result<(), String>,
    restore_manifest: Option<Result<(), String>>,
    cleanup: Result<(), String>,
) -> String {
    let mut details = vec![format!("rebuild manifest: {manifest_error}")];
    if let Err(error) = rollback {
        details.push(format!("rollback failed: {error}"));
    }
    if let Some(Err(error)) = restore_manifest {
        details.push(format!("restore manifest failed: {error}"));
    }
    if let Err(error) = cleanup {
        details.push(format!("remove re-encryption journal failed: {error}"));
    }
    details.join("; ")
}

fn stage_and_install_reencrypted(
    root: &Path,
    files: &[ReencryptFile],
    journal: &mut ReencryptJournal,
) -> Result<(), String> {
    let seed = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock before Unix epoch: {e}"))?
        .as_nanos();
    for (index, file) in files.iter().enumerate() {
        let temp = artifact_path(&file.path, "tmp", seed, index)?;
        let backup = artifact_path(&file.path, "backup", seed, index)?;
        // Go rejects journals that name artifacts before recording the
        // replacement digest. The replacement is already held in memory, so
        // make every artifact-bearing journal state recoverable by Go.
        journal.entries[index].digest = digest(&file.replacement);
        journal.entries[index].temp = journal_string(root, &temp)?;
        journal.entries[index].backup = journal_string(root, &backup)?;
        persist_reencrypt_journal(root, journal)?;
        stage_reencrypted_file(file, &temp)?;
        persist_reencrypt_journal(root, journal)?;
    }

    for (index, file) in files.iter().enumerate() {
        let entry = &mut journal.entries[index];
        let temp = journal_artifact(root, &entry.temp, &file.path, ".tmp")?;
        let backup = journal_artifact(root, &entry.backup, &file.path, ".backup")?;
        fs::rename(&file.path, &backup).map_err(|e| format!("move original to backup: {e}"))?;
        sync_directory(file.path.parent().unwrap_or(root))?;
        if let Err(error) = fs::rename(&temp, &file.path) {
            let _ = fs::rename(&backup, &file.path);
            return Err(format!("install staged ciphertext: {error}"));
        }
        sync_directory(file.path.parent().unwrap_or(root))?;
        entry.temp.clear();
        entry.installed = true;
        persist_reencrypt_journal(root, journal)?;
    }
    Ok(())
}

fn verify_installed_targets(journal: &ReencryptJournal) -> Result<(), String> {
    for entry in &journal.entries {
        if !entry.installed {
            return Err(format!(
                "re-encryption journal entry is not installed: {}",
                entry.path
            ));
        }
        let path = Path::new(&entry.path);
        if !target_matches(path, &entry.digest)? {
            return Err(format!("installed target changed: {}", path.display()));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| format!("sync directory {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn auto_commit_and_push(vault: &Path, message: &str) {
    if let Ok(repo) = GitRepository::open(vault) {
        if let Err(e) = repo.commit(CommitOptions {
            message: message.to_owned(),
            ..Default::default()
        }) {
            eprintln!("Warning: could not auto-commit/push: {e}");
        } else if Config::load(vault.join("config.yaml"))
            .ok()
            .and_then(|config| config.git)
            .is_some_and(|git| git.auto_push)
        {
            let result = repo.push("origin");
            if !result.success && !result.skipped {
                eprintln!("Warning: could not auto-push: {:?}", result.error);
            }
        }
    }
}

pub(super) fn pair(vault: &Path, quiet: bool) -> Result<(), String> {
    let identity = unlock_vault(vault)?;
    let token = generate_token().map_err(|e| format!("generate token: {e}"))?;
    let public_key = recipient_string(&identity);

    let pairing_data = PairingFile {
        token: token.clone(),
        public_key: public_key.clone(),
        created_at: GoTime::now(),
    };

    let pairing_dir = vault.join(".symvault").join("pairing");
    safeio::create_dir_all(&pairing_dir).map_err(|e| format!("create pairing dir: {e}"))?;
    let encoded =
        marshal_pairing_file(&pairing_data).map_err(|e| format!("save pairing file: {e}"))?;
    safeio::write_atomic(&pairing_dir.join(format!("{token}.json")), &encoded)
        .map_err(|e| format!("save pairing file: {e}"))?;

    auto_commit_and_push(vault, &format!("Pairing token {token}"));

    if !quiet {
        let fp = fingerprint(&public_key);
        let pairing_rel = Path::new(".symvault")
            .join("pairing")
            .join(format!("{token}.json"));
        print!("\n=== Pairing Token ===\n");
        println!("Token: {token}\n");
        println!("This device's public key: {public_key}");
        println!("Key fingerprint:          {fp} (SHA-256)");
        print!("\nOn the joining device, run:\n");
        println!("  symvault device join <remote-url> {token}\n");
        println!(
            "Without a git remote, share {} by any channel and run:",
            pairing_rel.display()
        );
        println!("  symvault device join --pairing-file <path-to-token.json> {token}\n");
        println!("After the joining device has submitted its key, run:");
        println!("  symvault device accept {token}\n");
    }
    Ok(())
}

pub(super) fn join(
    vault: &Path,
    args: &[String],
    name: Option<String>,
    pairing_file: Option<PathBuf>,
    quiet: bool,
) -> Result<(), String> {
    let (token, pairing_pf, is_file_transport) = if let Some(ref pf_path) = pairing_file {
        if args.len() != 1 {
            return Err("with --pairing-file, pass only the pairing token: 'device join --pairing-file <path> <token>'".to_owned());
        }
        let token = args[0].trim().to_owned();
        validate_pairing_token(&token).map_err(|e| format!("invalid pairing token: {e}"))?;
        let pf_data = std::fs::read(pf_path).map_err(|e| format!("read pairing file: {e}"))?;
        let pf = parse_pairing_file(&pf_data).map_err(|e| format!("{e}"))?;
        if !pf.token.is_empty() && pf.token != token {
            return Err(format!(
                "pairing file token {:?} does not match the given token {:?}",
                pf.token, token
            ));
        }
        if pf.public_key.is_empty() || !pf.public_key.starts_with("age1") {
            return Err("invalid pairing file: missing or malformed public_key".to_owned());
        }
        (token, pf, true)
    } else {
        if args.len() != 2 {
            return Err(format!(
                "accepts between 1 and 2 arg(s), received {} — either '<remote-url> <token>' or '--pairing-file <path> <token>'",
                args.len()
            ));
        }
        let remote_url = args[0].trim();
        let token = args[1].trim().to_owned();
        validate_pairing_token(&token).map_err(|e| format!("invalid pairing token: {e}"))?;

        if is_initialized(vault) {
            return Err(format!(
                "vault already initialized at {}. Use a different --vault or remove the existing vault first",
                vault.display()
            ));
        }

        eprintln!("Cloning vault from {remote_url} ...");
        safeio::create_dir_all(vault).map_err(|e| format!("create vault dir: {e}"))?;
        let status = std::process::Command::new("git")
            .env_remove("SYMVAULT_PASSPHRASE")
            .arg("clone")
            .arg("--")
            .arg(remote_url)
            .arg(vault)
            .status()
            .map_err(|e| format!("clone vault: {e}"))?;
        if !status.success() {
            return Err(format!("clone vault: git clone failed with {status}"));
        }

        let pairing_path = vault
            .join(".symvault")
            .join("pairing")
            .join(format!("{token}.json"));
        let pf_data = safeio::read(&pairing_path)
            .map_err(|e| format!("invalid or expired pairing token: could not read pairing file. Ensure the token is correct and the pairing device has pushed the token file: {e}"))?
            .ok_or_else(|| "invalid or expired pairing token: could not read pairing file. Ensure the token is correct and the pairing device has pushed the token file: file not found".to_owned())?;
        let pf = parse_pairing_file(&pf_data).map_err(|e| format!("invalid pairing file: {e}"))?;
        (token, pf, false)
    };

    if is_file_transport && is_initialized(vault) {
        return Err(format!(
            "vault already initialized at {}. Use a different --vault or remove the existing vault first",
            vault.display()
        ));
    }

    if is_file_transport {
        eprintln!(
            "Pairing without git transport using {}",
            pairing_file.as_ref().unwrap().display()
        );
    }
    eprintln!(
        "Pairing with device (public key: {})",
        truncate_pubkey(&pairing_pf.public_key)
    );

    let passphrase = read_passphrase("Enter passphrase for this device (minimum 12 characters): ")?;
    if passphrase.len() < 12 {
        return Err("passphrase must be at least 12 characters".to_owned());
    }

    let identity = generate_identity();
    let my_pubkey = recipient_string(&identity);

    safeio::create_dir_all(&vault.join("entries"))
        .map_err(|e| format!("create entries dir: {e}"))?;
    safeio::create_dir_all(&vault.join(".symvault").join("pairing"))
        .map_err(|e| format!("create pairing dir: {e}"))?;

    let config_content = joined_config(vault)?;
    safeio::write_atomic(&vault.join("config.yaml"), &config_content)
        .map_err(|e| format!("write config: {e}"))?;

    let sec_pass = SecretBytes::new(passphrase.as_bytes());
    let enc_id = encrypt_identity_scrypt(&identity, &sec_pass, 18)
        .map_err(|e| format!("save identity: {e}"))?;
    safeio::write_atomic(&vault.join("identity.age"), &enc_id)
        .map_err(|e| format!("save identity: {e}"))?;

    let recipients_content = format!(
        "# Symaira Vault vault recipients\n# Added by device join\n{}\n",
        pairing_pf.public_key
    );
    safeio::write_atomic(&vault.join("recipients.txt"), recipients_content.as_bytes())
        .map_err(|e| format!("write recipients: {e}"))?;

    let device_name = name.unwrap_or_else(|| format!("device-{token}"));
    let joined_data = JoinResponse {
        token: token.clone(),
        name: device_name.clone(),
        public_key: my_pubkey.clone(),
        created_at: GoTime::now(),
    };

    let response_filename = if is_file_transport {
        format!("{token}-response.json")
    } else {
        format!("{token}-joined.json")
    };

    let response_encoded =
        marshal_join_response(&joined_data).map_err(|e| format!("save joined file: {e}"))?;
    let response_path = vault
        .join(".symvault")
        .join("pairing")
        .join(&response_filename);
    safeio::write_atomic(&response_path, &response_encoded)
        .map_err(|e| format!("save joined file: {e}"))?;

    if is_file_transport {
        println!(
            "\nResponse artifact written to: {}\n",
            response_path.display()
        );
    }

    let cleanup_pairing = vault
        .join(".symvault")
        .join("pairing")
        .join(format!("{token}.json"));
    let _ = std::fs::remove_file(cleanup_pairing);

    if let Ok(repo) = GitRepository::open(vault) {
        let _ = repo.commit(CommitOptions {
            message: format!("Device join: {device_name} (token {token})"),
            ..Default::default()
        });
    }

    eprintln!("=== Join Successful ===");
    if !quiet {
        let fp = fingerprint(&my_pubkey);
        println!("\nDevice name:     {device_name}");
        println!("Key type:        age X25519");
        println!("Your public key: {my_pubkey}");
        println!("Key fingerprint: {fp} (SHA-256)\n");
        println!("IMPORTANT: Entries cannot be decrypted yet.");
        println!("On the existing device, run:");
        println!("  symvault device accept {token}\n");
    }

    if !is_file_transport && let Ok(repo) = GitRepository::open(vault) {
        let res = repo.push("origin");
        if !res.success && !res.skipped {
            eprintln!("Warning: Could not push joined file: {:?}", res.error);
            eprintln!("Push manually with: symvault git push");
        }
    }

    Ok(())
}

pub(super) fn accept(vault: &Path, token: &str, quiet: bool) -> Result<(), String> {
    validate_pairing_token(token).map_err(|e| format!("invalid pairing token: {e}"))?;
    let identity = unlock_vault(vault)?;
    let _ = validate_reencrypt_entries_root(vault)?;

    let mut jf_data = None;
    let mut found_name = String::new();
    for name in response_filenames(token) {
        let candidate_path = vault.join(".symvault").join("pairing").join(&name);
        if let Ok(Some(data)) = safeio::read(&candidate_path) {
            jf_data = Some(data);
            found_name = name;
            break;
        }
    }

    let jf_data = jf_data.ok_or_else(|| {
        format!(
            "no join request found for token {token}. Ensure the joining device has completed 'symvault device join' and the response artifact ({token}-joined.json or {token}-response.json) is present in the vault"
        )
    })?;

    let jf = parse_join_response(&jf_data)
        .map_err(|e| format!("parse joined file {found_name}: {e}"))?;

    let fp = fingerprint(&jf.public_key);
    if !quiet {
        print!("\n=== Joining Device Request ===\n");
        println!("Device name:     {}", jf.name);
        println!("Key type:        age X25519");
        println!("Public key:      {}", jf.public_key);
        println!("Key fingerprint: {fp} (SHA-256)\n");
    }

    eprintln!(
        "Accepting join from device: {} (public key: {})",
        jf.name,
        truncate_pubkey(&jf.public_key)
    );

    let rm = RecipientsFile::new(vault);
    rm.add(&jf.public_key)
        .map_err(|e| format!("add recipient: {e}"))?;

    let all_recipients = get_all_recipients_for_encryption(vault, &identity)?;
    eprintln!(
        "Re-encrypting all entries for {} recipient(s)...",
        all_recipients.len()
    );

    reencrypt_all_entries(vault, &identity, &all_recipients)?;

    let _ = std::fs::remove_file(vault.join(".symvault").join("pairing").join(&found_name));

    auto_commit_and_push(vault, &format!("Accept device join: {}", jf.name));

    if !quiet {
        print!("\n=== Pairing Complete ===\n");
        println!("Device {:?} can now access all vault entries.\n", jf.name);
        println!(
            "On the joining device, run 'symvault git pull' to fetch the re-encrypted entries."
        );
    }

    Ok(())
}

pub(super) fn add(
    vault: &Path,
    pair: bool,
    args: &[String],
    name: Option<String>,
) -> Result<(), String> {
    if !pair {
        return Err(
            "use 'symvault device add --pair <token:publickey>' to pair a device".to_owned(),
        );
    }
    if args.is_empty() {
        return Err(
            "missing pairing data. Usage: symvault device add --pair <token> or <token:publickey>"
                .to_owned(),
        );
    }

    let raw = args[0].trim();
    let (token, existing_pubkey) = if let Some(idx) = raw.find(':') {
        (&raw[..idx], &raw[idx + 1..])
    } else {
        (raw, "")
    };

    validate_pairing_token(token).map_err(|e| format!("invalid pairing token: {e}"))?;
    if !existing_pubkey.starts_with("age1") || existing_pubkey.len() < 50 {
        return Err("invalid public key in pairing data: expected age1... format".to_owned());
    }

    if is_initialized(vault) {
        return Err(format!(
            "vault already initialized at {}. Use a different --vault or remove the existing vault first",
            vault.display()
        ));
    }

    let passphrase = read_passphrase("Enter passphrase for this device (minimum 12 characters): ")?;
    if passphrase.len() < 12 {
        return Err("passphrase must be at least 12 characters".to_owned());
    }

    let identity = generate_identity();
    let my_pubkey = recipient_string(&identity);

    safeio::create_dir_all(&vault.join("entries"))
        .map_err(|e| format!("create entries dir: {e}"))?;
    safeio::create_dir_all(&vault.join(".symvault").join("pairing"))
        .map_err(|e| format!("create pairing dir: {e}"))?;

    let config_content = joined_config(vault)?;
    safeio::write_atomic(&vault.join("config.yaml"), &config_content)
        .map_err(|e| format!("write config: {e}"))?;

    let sec_pass = SecretBytes::new(passphrase.as_bytes());
    let enc_id = encrypt_identity_scrypt(&identity, &sec_pass, 18)
        .map_err(|e| format!("save identity: {e}"))?;
    safeio::write_atomic(&vault.join("identity.age"), &enc_id)
        .map_err(|e| format!("save identity: {e}"))?;

    let recipients_content = format!(
        "# Symaira Vault vault recipients\n# Added by device add --pair\n{}\n",
        existing_pubkey
    );
    safeio::write_atomic(&vault.join("recipients.txt"), recipients_content.as_bytes())
        .map_err(|e| format!("write recipients: {e}"))?;

    let device_name = name.unwrap_or_else(|| format!("device-{token}"));
    let joined_data = JoinResponse {
        token: token.to_owned(),
        name: device_name.clone(),
        public_key: my_pubkey.clone(),
        created_at: GoTime::now(),
    };

    let response_encoded =
        marshal_join_response(&joined_data).map_err(|e| format!("save joined file: {e}"))?;
    safeio::write_atomic(
        &vault
            .join(".symvault")
            .join("pairing")
            .join(format!("{token}-joined.json")),
        &response_encoded,
    )
    .map_err(|e| format!("save joined file: {e}"))?;

    let fp = fingerprint(&my_pubkey);
    eprintln!("=== Pairing Setup Complete ===");
    eprintln!("Device name:     {device_name}");
    eprintln!("Key type:        age X25519");
    eprintln!("Your public key: {my_pubkey}");
    eprintln!("Key fingerprint: {fp} (SHA-256)\n");
    eprintln!("IMPORTANT: Entries cannot be decrypted yet.");
    eprintln!("On the original device, run:");
    eprintln!("  symvault device accept {token}\n");
    eprintln!("After accepting, pull the re-encrypted entries:");
    eprintln!("  symvault git pull");

    Ok(())
}

pub(super) fn revoke(vault: &Path, name: &str, yes: bool, quiet: bool) -> Result<(), String> {
    if !is_initialized(vault) {
        return Err("vault is not initialized (run 'symvault init' first)".to_owned());
    }
    let identity = unlock_vault(vault)?;

    let dm = DeviceRegistry::new(vault);
    let device = dm
        .get(name)
        .map_err(|e| format!("cannot look up device: {e}"))?
        .ok_or_else(|| format!("device {name:?} not found in device registry"))?;

    let current_pubkey = recipient_string(&identity);
    if device.public_key == current_pubkey {
        return Err(format!(
            "cannot revoke the current device {name:?} (this device's identity would be lost)"
        ));
    }

    if !yes {
        eprint!("This will revoke device {name:?} and re-encrypt all entries.\nContinue? [y/N]: ");
        let mut answer = String::new();
        let stdin = io::stdin();
        stdin
            .lock()
            .read_line(&mut answer)
            .map_err(|e| format!("read confirmation: {e}"))?;
        if answer.trim().to_lowercase() != "y" {
            eprintln!("Canceled");
            return Ok(());
        }
    }

    dm.remove(name)
        .map_err(|e| format!("remove device from registry: {e}"))?;

    let rm = RecipientsFile::new(vault);
    let _ = rm.remove(&device.public_key);

    let all_recipients = get_all_recipients_for_encryption(vault, &identity)?;
    eprintln!(
        "Re-encrypting all entries for {} recipient(s)...",
        all_recipients.len()
    );

    reencrypt_all_entries(vault, &identity, &all_recipients)?;

    auto_commit_and_push(vault, &format!("Revoke device: {name}"));

    if !quiet {
        print!("\nDevice {name:?} has been revoked and all entries re-encrypted.\n");
    }

    Ok(())
}

pub(super) fn list(vault: &Path, format: &str, json: bool, quiet: bool) -> Result<(), String> {
    let devices = DeviceRegistry::new(vault)
        .list()
        .map_err(|e| format!("list devices: {e}"))?;
    let keys: HashSet<&str> = devices
        .devices()
        .iter()
        .map(|d| d.public_key.as_str())
        .collect();
    // Go intentionally suppresses recipients-file errors for this read-only view.
    let unmanaged: Vec<String> = RecipientsFile::new(vault)
        .load_strings()
        .unwrap_or_default()
        .unwrap_or_default()
        .into_iter()
        .filter(|key| !keys.contains(key.as_str()))
        .collect();
    if format == "yaml" && !json {
        return Err("device list YAML output is not yet ported".to_owned());
    }
    if quiet {
        return Ok(());
    }
    let mut out = Vec::new();
    if json || format == "json" {
        let listing = Listing {
            count: devices.devices().len(),
            devices: devices
                .devices()
                .iter()
                .map(|d| ListedDevice {
                    name: &d.name,
                    public_key: &d.public_key,
                    added_at: seconds(d.added_at),
                    last_seen: d.last_seen.map(seconds),
                })
                .collect(),
            unmanaged_recipients: unmanaged,
        };
        // Go's encoder disables HTML escaping but always escapes these separators.
        let encoded = serde_json::to_string(&listing)
            .map_err(|e| e.to_string())?
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029");
        out.extend_from_slice(encoded.as_bytes());
        out.push(b'\n');
    } else {
        if devices.devices().is_empty() {
            out.extend_from_slice(b"No devices registered.\n");
            if !unmanaged.is_empty() {
                out.push(b'\n');
            }
        } else {
            write!(out, "Devices ({}):\n\n", devices.devices().len()).map_err(|e| e.to_string())?;
            for d in devices.devices() {
                write!(out, "  {}\n    Public Key: ", d.name).map_err(|e| e.to_string())?;
                out.extend_from_slice(&short_key(&d.public_key));
                write!(
                    out,
                    "\n    Added:      {}\n    Last Seen:  {}\n\n",
                    seconds(d.added_at),
                    d.last_seen
                        .map(seconds)
                        .unwrap_or_else(|| "never".to_owned())
                )
                .map_err(|e| e.to_string())?;
            }
        }
        if !unmanaged.is_empty() {
            out.extend_from_slice(b"Unmanaged recipients in recipients.txt:\n");
            for key in unmanaged {
                out.extend_from_slice(b"  ");
                out.extend_from_slice(&short_key(&key));
                out.push(b'\n');
            }
            if !devices.devices().is_empty() {
                out.push(b'\n');
            }
        }
    }
    std::io::stdout()
        .lock()
        .write_all(&out)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        thread,
    };
    use symvault_core::session::{MemoryKeyring, SessionManager};
    use symvault_platform::FallbackKeyring;

    fn fixture_runtime() -> crate::RuntimeSession {
        let keyring = FallbackKeyring::new(Arc::new(MemoryKeyring::new()), true);
        crate::RuntimeSession {
            manager: SessionManager::with_system_clock(keyring.clone()),
            keyring: Some(keyring),
            memory_only: false,
        }
    }

    fn encrypted_fixture() -> (PathBuf, Identity, String) {
        static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "symvault-device-unlock-{}-{}-{}",
            std::process::id(),
            GoTime::now().to_rfc3339_nano().replace([':', '.', '-'], ""),
            FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("create fixture vault");
        let identity = generate_identity();
        let passphrase = "fixture-device-passphrase".to_owned();
        let config = Config {
            vault_dir: root.to_string_lossy().into_owned(),
            ..Config::default()
        };
        fs::write(root.join("config.yaml"), config.to_yaml_bytes().unwrap()).unwrap();
        let encrypted =
            encrypt_identity_scrypt(&identity, &SecretBytes::new(passphrase.as_bytes()), 10)
                .unwrap();
        fs::write(root.join("identity.age"), encrypted).unwrap();
        (root, identity, passphrase)
    }

    #[cfg(unix)]
    fn ancestor_alias(root: &Path) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::symlink;

        static ALIAS_COUNTER: AtomicU64 = AtomicU64::new(0);
        let parent = root.parent().expect("fixture has a parent");
        let alias_parent = parent.join(format!(
            "symvault-device-alias-{}-{}",
            std::process::id(),
            ALIAS_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        symlink(parent, &alias_parent).expect("create ancestor alias");
        let alias_root = alias_parent.join(root.file_name().expect("fixture has a name"));
        (alias_parent, alias_root)
    }

    #[test]
    fn cached_identity_and_passphrase_open_the_same_encrypted_fixture() {
        let (root, expected, passphrase) = encrypted_fixture();
        let vault = root.to_str().unwrap().to_owned();

        let identity_runtime = fixture_runtime();
        let identity_bytes = identity_string(&expected);
        identity_runtime
            .manager
            .save_identity(
                &vault,
                identity_bytes.as_bytes(),
                Duration::from_secs(60),
                Duration::from_secs(600),
            )
            .unwrap();
        let cached = unlock_vault_with_runtime(&root, &identity_runtime).unwrap();
        assert_eq!(recipient_string(&cached), recipient_string(&expected));

        let passphrase_runtime = fixture_runtime();
        passphrase_runtime
            .manager
            .save_passphrase(
                &vault,
                passphrase.as_bytes(),
                Duration::from_secs(60),
                Duration::from_secs(600),
            )
            .unwrap();
        let cached_passphrase = unlock_vault_with_runtime(&root, &passphrase_runtime).unwrap();
        assert_eq!(
            recipient_string(&cached_passphrase),
            recipient_string(&expected)
        );
        assert!(!passphrase_runtime.manager.is_identity_expired(&vault));
        let _ = fs::remove_dir_all(root);
    }

    fn recovery_fixture(after_install: bool) {
        let (root, identity, _passphrase) = encrypted_fixture();
        let entries = root.join("entries");
        fs::create_dir_all(&entries).unwrap();
        let target = entries.join("a.age");
        let backup = entries.join(".a.age.reencrypt-1-0-0.backup");
        let original = b"original ciphertext";
        let replacement = b"replacement ciphertext";
        let store = symvault_store::Store::open(&root, &identity).unwrap();
        fs::write(&backup, original).unwrap();
        if after_install {
            fs::write(&target, replacement).unwrap();
        }
        assert!(
            backup.is_file(),
            "backup fixture missing: {}",
            backup.display()
        );
        let journal = ReencryptJournal {
            version: REENCRYPT_JOURNAL_VERSION,
            entries: vec![ReencryptJournalEntry {
                path: journal_string(&root, &target).unwrap(),
                temp: String::new(),
                backup: journal_string(&root, &backup).unwrap(),
                digest: digest(replacement),
                installed: after_install,
            }],
        };
        persist_reencrypt_journal(&root, &journal).unwrap();
        assert!(
            backup.is_file(),
            "backup removed while persisting: {}",
            backup.display()
        );
        store
            .with_write_lock(|store| store.recover_reencrypt_journal_locked(&identity))
            .unwrap();
        let expected: &[u8] = if after_install { replacement } else { original };
        assert_eq!(fs::read(&target).unwrap(), expected);
        assert!(!backup.exists());
        assert!(!journal_path(&root).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reencrypt_journal_recovers_after_backup_before_install() {
        recovery_fixture(false);
    }

    #[test]
    fn reencrypt_journal_recovers_after_install() {
        recovery_fixture(true);
    }

    #[test]
    fn store_open_recovers_journal_before_normal_reads() {
        let (root, identity, _passphrase) = encrypted_fixture();
        let entries = root.join("entries");
        fs::create_dir_all(&entries).unwrap();
        let target = entries.join("a.age");
        let backup = entries.join(".a.age.reencrypt-1-0-0.backup");
        let original = b"original ciphertext";
        let replacement = b"replacement ciphertext";
        fs::write(root.join("manifest.age"), b"old manifest").unwrap();
        fs::write(&target, replacement).unwrap();
        fs::write(&backup, original).unwrap();
        let journal = ReencryptJournal {
            version: REENCRYPT_JOURNAL_VERSION,
            entries: vec![ReencryptJournalEntry {
                path: journal_string(&root, &target).unwrap(),
                temp: String::new(),
                backup: journal_string(&root, &backup).unwrap(),
                digest: digest(replacement),
                installed: true,
            }],
        };
        persist_reencrypt_journal(&root, &journal).unwrap();
        let _store = symvault_store::Store::open(&root, &identity).unwrap();
        assert_eq!(fs::read(&target).unwrap(), replacement);
        assert!(!backup.exists());
        assert!(!journal_path(&root).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn store_open_recovers_go_journal_artifact_names() {
        // These names are emitted by the Go Unix and Windows re-encryption
        // implementations, respectively. Keep the fixture journal-shaped so
        // Rust can recover a vault after a Go process crashes mid-rotation.
        let fixtures = [
            (
                ".a.age.reencrypt-0123456789abcdef01234567",
                ".a.age.backup.reencrypt-0123456789abcdef01234567",
            ),
            (".reencrypt-ABC123", "a.age.reencrypt-backup.1"),
        ];
        for (temp_name, backup_name) in fixtures {
            let (root, identity, _passphrase) = encrypted_fixture();
            let entries = root.join("entries");
            fs::create_dir_all(&entries).unwrap();
            let target = entries.join("a.age");
            let temp = entries.join(temp_name);
            let backup = entries.join(backup_name);
            let original = b"original ciphertext";
            let replacement = b"replacement ciphertext";
            fs::write(&temp, replacement).unwrap();
            fs::write(&backup, original).unwrap();
            let journal = ReencryptJournal {
                version: REENCRYPT_JOURNAL_VERSION,
                entries: vec![ReencryptJournalEntry {
                    path: journal_string(&root, &target).unwrap(),
                    temp: journal_string(&root, &temp).unwrap(),
                    backup: journal_string(&root, &backup).unwrap(),
                    digest: digest(replacement),
                    installed: false,
                }],
            };
            persist_reencrypt_journal(&root, &journal).unwrap();

            symvault_store::Store::open(&root, &identity).unwrap();
            assert_eq!(fs::read(&target).unwrap(), original);
            assert!(!temp.exists());
            assert!(!backup.exists());
            assert!(!journal_path(&root).exists());
            assert!(root.join("manifest.age").is_file());
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn successful_reencrypt_cleanup_removes_all_artifacts() {
        let (root, _identity, _passphrase) = encrypted_fixture();
        let entries = root.join("entries").join("nested");
        fs::create_dir_all(&entries).unwrap();
        let target = entries.join("a.age");
        let temp = entries.join(".a.age.reencrypt-1-0-0.tmp");
        let backup = entries.join(".a.age.reencrypt-1-0-0.backup");
        fs::write(&target, b"replacement ciphertext").unwrap();
        fs::write(&temp, b"staged ciphertext").unwrap();
        fs::write(&backup, b"original ciphertext").unwrap();
        let journal = ReencryptJournal {
            version: REENCRYPT_JOURNAL_VERSION,
            entries: vec![ReencryptJournalEntry {
                path: journal_string(&root, &target).unwrap(),
                temp: journal_string(&root, &temp).unwrap(),
                backup: journal_string(&root, &backup).unwrap(),
                digest: digest(b"replacement ciphertext"),
                installed: true,
            }],
        };

        cleanup_reencrypt_artifacts(&root, &journal).unwrap();
        assert!(target.exists());
        assert!(!temp.exists());
        assert!(!backup.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn digestless_artifact_journal_is_rejected_without_cleanup() {
        let (root, identity, _passphrase) = encrypted_fixture();
        let entries = root.join("entries");
        fs::create_dir_all(&entries).unwrap();
        let target = entries.join("a.age");
        let backup = entries.join(".a.age.reencrypt-1-0-0.backup");
        fs::write(&target, b"original ciphertext").unwrap();
        fs::write(&backup, b"backup ciphertext").unwrap();
        let journal = ReencryptJournal {
            version: REENCRYPT_JOURNAL_VERSION,
            entries: vec![ReencryptJournalEntry {
                path: journal_string(&root, &target).unwrap(),
                temp: String::new(),
                backup: journal_string(&root, &backup).unwrap(),
                digest: String::new(),
                installed: false,
            }],
        };
        persist_reencrypt_journal(&root, &journal).unwrap();

        let error = symvault_store::Store::open(&root, &identity).unwrap_err();
        assert!(error.to_string().contains("no ciphertext digest"));
        assert!(target.is_file());
        assert!(backup.is_file());
        assert!(journal_path(&root).is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn journal_path_validation_precedes_mutation() {
        let (root, identity, _passphrase) = encrypted_fixture();
        let entries = root.join("entries");
        fs::create_dir_all(&entries).unwrap();
        let outside = root.join("outside.age");
        fs::write(&outside, b"outside original").unwrap();
        let traversal = root.join("entries/../outside.age");
        let journal = ReencryptJournal {
            version: REENCRYPT_JOURNAL_VERSION,
            entries: vec![ReencryptJournalEntry {
                path: traversal.to_string_lossy().into_owned(),
                temp: String::new(),
                backup: String::new(),
                digest: digest(b"replacement"),
                installed: true,
            }],
        };
        persist_reencrypt_journal(&root, &journal).unwrap();
        let error = symvault_store::Store::open(&root, &identity).unwrap_err();
        assert!(error.to_string().contains("unsafe"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside original");
        let _ = fs::remove_dir_all(root);

        let (root, identity, _passphrase) = encrypted_fixture();
        let entries = root.join("entries");
        fs::create_dir_all(&entries).unwrap();
        let target = entries.join("a.age");
        fs::write(&target, b"original").unwrap();
        let journal = ReencryptJournal {
            version: REENCRYPT_JOURNAL_VERSION,
            entries: vec![ReencryptJournalEntry {
                path: journal_string(&root, &target).unwrap(),
                temp: String::new(),
                backup: journal_string(&root, &target).unwrap(),
                digest: digest(b"replacement"),
                installed: true,
            }],
        };
        persist_reencrypt_journal(&root, &journal).unwrap();
        let error = symvault_store::Store::open(&root, &identity).unwrap_err();
        assert!(error.to_string().contains("unsafe"));
        assert_eq!(fs::read(&target).unwrap(), b"original");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn journal_parent_symlink_is_rejected_before_mutation() {
        use std::os::unix::fs::symlink;

        let (root, identity, _passphrase) = encrypted_fixture();
        let entries = root.join("entries");
        let outside_dir = root.join("outside-dir");
        fs::create_dir_all(&entries).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();
        symlink(&outside_dir, entries.join("linked")).unwrap();
        let outside = outside_dir.join("a.age");
        fs::write(&outside, b"outside original").unwrap();
        let target = entries.join("linked/a.age");
        let journal = ReencryptJournal {
            version: REENCRYPT_JOURNAL_VERSION,
            entries: vec![ReencryptJournalEntry {
                path: target.to_string_lossy().into_owned(),
                temp: String::new(),
                backup: String::new(),
                digest: digest(b"replacement"),
                installed: true,
            }],
        };
        persist_reencrypt_journal(&root, &journal).unwrap();
        let error = symvault_store::Store::open(&root, &identity).unwrap_err();
        assert!(error.to_string().contains("symlink"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside original");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn manifest_failure_rollback_restores_entries_and_manifest() {
        let (root, identity, _passphrase) = encrypted_fixture();
        let entries = root.join("entries");
        fs::create_dir_all(&entries).unwrap();
        let target = entries.join("a.age");
        let backup = entries.join(".a.age.reencrypt-1-0-0.backup");
        let original = b"original ciphertext";
        let replacement = b"replacement ciphertext";
        let manifest = root.join("manifest.age");
        let old_manifest = b"old manifest";
        let store = symvault_store::Store::open(&root, &identity).unwrap();
        fs::write(&target, replacement).unwrap();
        fs::write(&backup, original).unwrap();
        fs::write(&manifest, old_manifest).unwrap();
        let journal = ReencryptJournal {
            version: REENCRYPT_JOURNAL_VERSION,
            entries: vec![ReencryptJournalEntry {
                path: journal_string(&root, &target).unwrap(),
                temp: String::new(),
                backup: journal_string(&root, &backup).unwrap(),
                digest: digest(replacement),
                installed: true,
            }],
        };
        persist_reencrypt_journal(&root, &journal).unwrap();
        let snapshot = snapshot_file(&manifest).unwrap().unwrap();
        store
            .with_write_lock(|_| {
                rollback_reencrypt_journal_locked(&root).unwrap();
                restore_file(&snapshot.path, &snapshot.bytes, &snapshot.metadata).unwrap();
                remove_reencrypt_journal(&root).unwrap();
                Ok::<_, symvault_store::StoreError>(())
            })
            .unwrap();
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(fs::read(&manifest).unwrap(), old_manifest);
        assert!(!backup.exists());
        assert!(!journal_path(&root).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn store_write_lock_blocks_concurrent_writer() {
        let (root, identity, _passphrase) = encrypted_fixture();
        let store = Arc::new(symvault_store::Store::open(&root, &identity).unwrap());
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let holder_store = Arc::clone(&store);
        let holder = thread::spawn(move || {
            holder_store.with_write_lock(|_| {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok::<_, symvault_store::StoreError>(())
            })
        });
        held_rx.recv().unwrap();

        let (contender_tx, contender_rx) = mpsc::channel();
        let contender_store = Arc::clone(&store);
        let contender = thread::spawn(move || {
            let result =
                contender_store.with_write_lock(|_| Ok::<_, symvault_store::StoreError>(()));
            contender_tx.send(result.is_ok()).unwrap();
        });
        assert!(
            contender_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        release_tx.send(()).unwrap();
        holder.join().unwrap().unwrap();
        assert!(contender_rx.recv_timeout(Duration::from_secs(2)).unwrap());
        contender.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reencrypt_preflights_all_entries_before_replacing_any_file() {
        let (root, identity, _passphrase) = encrypted_fixture();
        let entries = root.join("entries");
        fs::create_dir_all(&entries).unwrap();
        let own_recipient = parse_recipient(&recipient_string(&identity)).unwrap();
        let first = encrypt(b"first-entry", &[own_recipient]).unwrap();
        fs::write(entries.join("a.age"), &first).unwrap();
        fs::write(entries.join("b.age"), b"corrupt age envelope").unwrap();

        let new_identity = generate_identity();
        let new_recipient = parse_recipient(&recipient_string(&new_identity)).unwrap();
        let error = reencrypt_all_entries(&root, &identity, &[new_recipient]).unwrap_err();

        assert!(error.contains("b.age"), "unexpected error: {error}");
        assert_eq!(fs::read(entries.join("a.age")).unwrap(), first);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn reencrypt_through_ancestor_alias_covers_success_and_preflight_failure() {
        let (root, identity, _passphrase) = encrypted_fixture();
        let entries = root.join("entries");
        fs::create_dir_all(&entries).unwrap();
        let (alias_parent, alias_root) = ancestor_alias(&root);

        let source_recipient = parse_recipient(&recipient_string(&identity)).unwrap();
        let original = encrypt(b"alias-success", std::slice::from_ref(&source_recipient)).unwrap();
        let target = entries.join("a.age");
        fs::write(&target, &original).unwrap();

        let new_identity = generate_identity();
        let new_recipient = parse_recipient(&recipient_string(&new_identity)).unwrap();
        reencrypt_all_entries(&alias_root, &identity, std::slice::from_ref(&new_recipient))
            .unwrap();
        assert_eq!(
            symvault_crypto::decrypt(&fs::read(&target).unwrap(), &new_identity).unwrap(),
            b"alias-success"
        );
        assert!(!journal_path(&root).exists());

        let original_before_failure =
            encrypt(b"alias-preserved", std::slice::from_ref(&source_recipient)).unwrap();
        fs::write(&target, &original_before_failure).unwrap();
        fs::write(entries.join("b.age"), b"corrupt age envelope").unwrap();
        let error =
            reencrypt_all_entries(&alias_root, &identity, std::slice::from_ref(&new_recipient))
                .unwrap_err();
        assert!(error.contains("b.age"), "unexpected error: {error}");
        assert_eq!(fs::read(&target).unwrap(), original_before_failure);
        assert!(!journal_path(&root).exists());

        fs::remove_file(alias_parent).unwrap();
        let _ = fs::remove_dir_all(root);
    }
}
