#![deny(unsafe_code)]

//! Read-only access to the Symaira Vault filesystem format.
//!
//! This slice intentionally has no mutation API. It can open both the current
//! `entries/` layout and pre-migration top-level `.age` entries, list logical
//! names, and decrypt individual JSON entries using `symvault-crypto`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use symvault_crypto::{Identity, decrypt, parse_recipient};
use thiserror::Error;
use walkdir::WalkDir;
use zeroize::Zeroize;

const ENTRIES_DIR: &str = "entries";
const CONFIG_FILE: &str = "config.yaml";
const IDENTITY_FILE: &str = "identity.age";
const RECIPIENTS_FILE: &str = "recipients.txt";
const MANIFEST_FILE: &str = "manifest.age";
const ENTRY_EXTENSION: &str = ".age";

/// Errors returned by the read-only store.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("vault root is not a directory: {0}")]
    RootNotDirectory(PathBuf),
    #[error("required vault file is missing: {0}")]
    MissingFile(PathBuf),
    #[error("vault path is unsafe: {0}")]
    UnsafePath(String),
    #[error("vault path is a symlink: {0}")]
    Symlink(PathBuf),
    #[error("vault path is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error("failed to read {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("invalid vault config: {0}")]
    Config(String),
    #[error("invalid entry {path}: {detail}")]
    Entry { path: String, detail: String },
    #[error("entry not found: {0}")]
    EntryNotFound(String),
    #[error("entry path {0:?} is not valid")]
    InvalidEntryPath(String),
    #[error("entry ciphertext is invalid: {0}")]
    Decryption(String),
}

/// Which on-disk entry namespace was observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// Entries are stored below `entries/`.
    Fresh,
    /// Entries are stored as top-level `<path>.age` files.
    Legacy,
    /// Both namespaces are present; fresh entries take precedence on get.
    Mixed,
}

/// The subset of vault configuration needed by read-only storage.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultConfig {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub legacy_mode: Option<bool>,
    #[serde(default)]
    pub pseudonymize_paths: bool,
    #[serde(default)]
    pub format_version: u32,
    #[serde(default)]
    pub manifest_generation: u64,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct RawConfig {
    #[serde(rename = "vaultDir", default)]
    vault_dir: String,
    #[serde(default)]
    vault: Option<VaultConfig>,
}

/// Metadata for the three vault-level files.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Presence {
    pub config: bool,
    pub identity: bool,
    pub recipients: bool,
}

/// A filesystem item exposed by [`Store::files`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub kind: FileKind,
    pub mode: u32,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Directory,
    Regular,
}

/// A decrypted vault entry. Its JSON field names match the Go model.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default)]
    pub data: BTreeMap<String, serde_json::Value>,
    #[serde(rename = "meta", default)]
    pub metadata: EntryMetadata,
    #[serde(rename = "secret_meta", default)]
    pub secret_metadata: SecretMetadata,
    #[serde(default)]
    pub classification: i32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub canary: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntryMetadata {
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub version: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_history: Vec<WriteRecord>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct WriteRecord {
    #[serde(default)]
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub field: String,
    #[serde(default)]
    pub action: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretMetadata {
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub secret_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub usage_hint: String,
    #[serde(default)]
    pub auto_rotate: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attachments: BTreeMap<String, AttachmentInfo>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttachmentInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub filename: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub sha256: String,
}

/// A read-only vault handle.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
    layout: Layout,
    config: VaultConfig,
    presence: Presence,
}

impl Store {
    /// Opens an existing vault without changing any filesystem state.
    pub fn open(root: impl AsRef<Path>, _identity: &Identity) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        ensure_directory(&root)?;
        reject_symlink(&root)?;
        let config_path = root.join(CONFIG_FILE);
        let identity_path = root.join(IDENTITY_FILE);
        ensure_regular_file(&config_path, true)?;
        ensure_regular_file(&identity_path, true)?;
        let config_bytes = read_regular(&config_path)?;
        let config = parse_config(&config_bytes)?;
        let presence = Presence {
            config: true,
            identity: true,
            recipients: regular_exists(&root.join(RECIPIENTS_FILE))?,
        };
        let layout = detect_layout(&root)?;
        Ok(Self {
            root,
            layout,
            config,
            presence,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub const fn layout(&self) -> Layout {
        self.layout
    }

    #[must_use]
    pub const fn config(&self) -> &VaultConfig {
        &self.config
    }

    #[must_use]
    pub const fn presence(&self) -> &Presence {
        &self.presence
    }

    /// Returns normalized public recipients, preserving file order.
    pub fn recipients(&self) -> Result<Vec<String>, StoreError> {
        let path = self.root.join(RECIPIENTS_FILE);
        if !self.presence.recipients {
            return Ok(Vec::new());
        }
        let text = String::from_utf8(read_regular(&path)?)
            .map_err(|_| StoreError::Config("recipients.txt is not UTF-8".into()))?;
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                parse_recipient(line)
                    .map(|recipient| recipient.to_string())
                    .map_err(|error| StoreError::Config(error.to_string()))
            })
            .collect()
    }

    /// Lists logical entry paths in deterministic lexical order.
    pub fn list(&self, identity: &Identity) -> Result<Vec<String>, StoreError> {
        let mut paths = BTreeSet::new();
        for candidate in entry_candidates(&self.root)? {
            let logical = candidate.logical_path(&self.root);
            if self.config.pseudonymize_paths {
                let entry = self.read_candidate(&candidate, identity)?;
                if !entry.path.is_empty() {
                    paths.insert(entry.path);
                }
            } else {
                paths.insert(logical);
            }
        }
        Ok(paths.into_iter().collect())
    }

    /// Decrypts and parses one entry. This method never writes or migrates files.
    pub fn get(&self, path: &str, identity: &Identity) -> Result<Entry, StoreError> {
        validate_entry_path(path)?;
        let candidates = self.candidates_for(path, identity)?;
        for candidate in candidates {
            if regular_exists(&candidate.path)? {
                return self.read_candidate(&candidate, identity);
            }
        }
        Err(StoreError::EntryNotFound(path.to_owned()))
    }

    /// Returns only the metadata portion of an entry after decryption.
    pub fn get_metadata(
        &self,
        path: &str,
        identity: &Identity,
    ) -> Result<EntryMetadata, StoreError> {
        Ok(self.get(path, identity)?.metadata)
    }

    /// Returns a sorted recursive manifest of the vault tree.
    pub fn files(&self) -> Result<Vec<FileInfo>, StoreError> {
        let mut result = Vec::new();
        for item in WalkDir::new(&self.root).follow_links(false) {
            let item = item.map_err(|error| StoreError::Read {
                path: self.root.clone(),
                source: io::Error::other(error.to_string()),
            })?;
            if item.path() == self.root {
                continue;
            }
            let rel = item
                .path()
                .strip_prefix(&self.root)
                .map_err(|_| StoreError::UnsafePath(item.path().display().to_string()))?;
            let rel = rel
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            let metadata =
                fs::symlink_metadata(item.path()).map_err(|source| StoreError::Read {
                    path: item.path().to_path_buf(),
                    source,
                })?;
            if metadata.file_type().is_symlink() {
                return Err(StoreError::Symlink(item.path().to_path_buf()));
            }
            let kind = if metadata.is_dir() {
                FileKind::Directory
            } else if metadata.is_file() {
                FileKind::Regular
            } else {
                return Err(StoreError::NotRegularFile(item.path().to_path_buf()));
            };
            let bytes = if kind == FileKind::Regular {
                read_regular(item.path())?
            } else {
                Vec::new()
            };
            result.push(FileInfo {
                path: rel,
                kind,
                mode: mode_bits(&metadata),
                size: metadata.len(),
                sha256: sha256_hex(&bytes),
            });
        }
        result.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(result)
    }

    fn candidates_for(
        &self,
        path: &str,
        identity: &Identity,
    ) -> Result<Vec<Candidate>, StoreError> {
        let mut result = Vec::new();
        if self.config.pseudonymize_paths {
            let name = symvault_crypto::pseudonymize_path(identity, path);
            result.push(Candidate {
                path: self
                    .root
                    .join(ENTRIES_DIR)
                    .join(&name[..2])
                    .join(format!("{name}{ENTRY_EXTENSION}")),
                logical: path.to_owned(),
            });
        } else {
            result.push(Candidate {
                path: self.root.join(ENTRIES_DIR).join(path).with_extension("age"),
                logical: path.to_owned(),
            });
        }
        if can_use_legacy_path(path) {
            result.push(Candidate {
                path: self.root.join(format!("{path}{ENTRY_EXTENSION}")),
                logical: path.to_owned(),
            });
        }
        Ok(result)
    }

    fn read_candidate(
        &self,
        candidate: &Candidate,
        identity: &Identity,
    ) -> Result<Entry, StoreError> {
        let mut raw = read_regular(&candidate.path)?;
        let mut plaintext =
            decrypt(&raw, identity).map_err(|error| StoreError::Decryption(error.to_string()))?;
        raw.zeroize();
        let result = serde_json::from_slice(&plaintext).map_err(|error| StoreError::Entry {
            path: candidate.logical.clone(),
            detail: error.to_string(),
        });
        plaintext.zeroize();
        result
    }
}

#[derive(Clone, Debug)]
struct Candidate {
    path: PathBuf,
    logical: String,
}

impl Candidate {
    fn logical_path(&self, root: &Path) -> String {
        let rel = self.path.strip_prefix(root).unwrap_or(&self.path);
        let value = rel
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        value
            .strip_prefix("entries/")
            .unwrap_or(&value)
            .trim_end_matches(ENTRY_EXTENSION)
            .to_owned()
    }
}

fn parse_config(bytes: &[u8]) -> Result<VaultConfig, StoreError> {
    let raw: RawConfig =
        serde_yaml::from_slice(bytes).map_err(|error| StoreError::Config(error.to_string()))?;
    let mut config = raw.vault.unwrap_or_default();
    if config.path.is_empty() {
        config.path = raw.vault_dir;
    }
    Ok(config)
}

fn detect_layout(root: &Path) -> Result<Layout, StoreError> {
    let fresh = root.join(ENTRIES_DIR).is_dir()
        && entry_candidates(root)?
            .iter()
            .any(|candidate| candidate.path.starts_with(root.join(ENTRIES_DIR)));
    let legacy = entry_candidates(root)?
        .iter()
        .any(|candidate| !candidate.path.starts_with(root.join(ENTRIES_DIR)));
    Ok(match (fresh, legacy) {
        (true, true) => Layout::Mixed,
        (true, false) => Layout::Fresh,
        (false, true) => Layout::Legacy,
        (false, false) => Layout::Fresh,
    })
}

fn entry_candidates(root: &Path) -> Result<Vec<Candidate>, StoreError> {
    let mut result = Vec::new();
    let entries_root = root.join(ENTRIES_DIR);
    if entries_root.is_dir() {
        for item in WalkDir::new(&entries_root).follow_links(false) {
            let item = item.map_err(|error| StoreError::Read {
                path: entries_root.clone(),
                source: io::Error::other(error.to_string()),
            })?;
            if item.file_type().is_symlink() {
                return Err(StoreError::Symlink(item.path().to_path_buf()));
            }
            if item.file_type().is_file()
                && item
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "age")
            {
                let rel = item
                    .path()
                    .strip_prefix(&entries_root)
                    .map_err(|_| StoreError::UnsafePath(item.path().display().to_string()))?;
                let logical = rel
                    .to_string_lossy()
                    .replace(std::path::MAIN_SEPARATOR, "/")
                    .trim_end_matches(ENTRY_EXTENSION)
                    .to_owned();
                result.push(Candidate {
                    path: item.path().to_path_buf(),
                    logical,
                });
            }
        }
    }
    for item in WalkDir::new(root).max_depth(64).follow_links(false) {
        let item = item.map_err(|error| StoreError::Read {
            path: root.to_path_buf(),
            source: io::Error::other(error.to_string()),
        })?;
        if item.path() == root || item.path().starts_with(&entries_root) {
            continue;
        }
        if item.file_type().is_symlink() {
            return Err(StoreError::Symlink(item.path().to_path_buf()));
        }
        let name = item.file_name().to_string_lossy();
        if item.file_type().is_file()
            && name.ends_with(ENTRY_EXTENSION)
            && name != IDENTITY_FILE
            && name != MANIFEST_FILE
        {
            let rel = item
                .path()
                .strip_prefix(root)
                .map_err(|_| StoreError::UnsafePath(item.path().display().to_string()))?;
            let logical = rel
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/")
                .trim_end_matches(ENTRY_EXTENSION)
                .to_owned();
            result.push(Candidate {
                path: item.path().to_path_buf(),
                logical,
            });
        }
    }
    result.sort_by(|a, b| a.logical.cmp(&b.logical).then_with(|| a.path.cmp(&b.path)));
    Ok(result)
}

fn validate_entry_path(path: &str) -> Result<(), StoreError> {
    if path.trim().is_empty()
        || path.contains('\0')
        || path.chars().any(char::is_control)
        || Path::new(path).is_absolute()
    {
        return Err(StoreError::InvalidEntryPath(path.to_owned()));
    }
    let normalized = path.replace('\\', "/");
    for component in normalized.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(StoreError::InvalidEntryPath(path.to_owned()));
        }
    }
    if Path::new(path).components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(StoreError::InvalidEntryPath(path.to_owned()));
    }
    Ok(())
}

fn can_use_legacy_path(path: &str) -> bool {
    path != "identity" && path != ENTRIES_DIR && !path.starts_with("entries/")
}

fn ensure_directory(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::metadata(path).map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(StoreError::RootNotDirectory(path.to_path_buf()));
    }
    Ok(())
}

fn ensure_regular_file(path: &Path, required: bool) -> Result<bool, StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(StoreError::Symlink(path.to_path_buf()));
            }
            if !metadata.is_file() {
                return Err(StoreError::NotRegularFile(path.to_path_buf()));
            }
            Ok(true)
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound && !required => Ok(false),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            Err(StoreError::MissingFile(path.to_path_buf()))
        }
        Err(source) => Err(StoreError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn regular_exists(path: &Path) -> Result<bool, StoreError> {
    ensure_regular_file(path, false)
}

fn reject_symlink(path: &Path) -> Result<(), StoreError> {
    if fs::symlink_metadata(path)
        .map_err(|source| StoreError::Read {
            path: path.to_path_buf(),
            source,
        })?
        .file_type()
        .is_symlink()
    {
        return Err(StoreError::Symlink(path.to_path_buf()));
    }
    Ok(())
}

fn read_regular(path: &Path) -> Result<Vec<u8>, StoreError> {
    ensure_regular_file(path, true)?;
    fs::read(path).map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn mode_bits(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_bits(_metadata: &fs::Metadata) -> u32 {
    0
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Supported semantic secret types from the Go entry model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretType {
    ApiKey,
    BearerToken,
    BasicAuth,
    SshKey,
    Password,
    Certificate,
    DatabaseUrl,
    TotpSeed,
}

/// Infers a type using the Go precedence: explicit, value, path, field, password.
#[must_use]
pub fn infer_secret_type(
    path: &str,
    field: &str,
    value: &str,
    explicit: Option<&str>,
) -> SecretType {
    if let Some(explicit) = explicit.filter(|value| !value.is_empty()) {
        return parse_secret_type(explicit);
    }
    let value = value.trim();
    if value.starts_with("-----BEGIN RSA PRIVATE KEY-----")
        || value.starts_with("-----BEGIN EC PRIVATE KEY-----")
        || value.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        || value.starts_with("-----BEGIN DSA PRIVATE KEY-----")
    {
        return SecretType::SshKey;
    }
    if value
        .to_ascii_uppercase()
        .starts_with("-----BEGIN CERTIFICATE-----")
    {
        return SecretType::Certificate;
    }
    if [
        "postgres://",
        "postgresql://",
        "mysql://",
        "mongodb://",
        "mongodb+srv://",
        "redis://",
        "sqlite://",
        "mariadb://",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
    {
        return SecretType::DatabaseUrl;
    }
    if value.starts_with("ghp_")
        || value.starts_with("gho_")
        || value.starts_with("ghs_")
        || value.starts_with("ghr_")
        || value.starts_with("github_pat_")
        || value.split('.').count() == 3
    {
        return SecretType::BearerToken;
    }
    if value.starts_with("AKIA") && value.len() == 20 {
        return SecretType::ApiKey;
    }
    if value.len() >= 16
        && value
            .chars()
            .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
        && value
            .chars()
            .all(|character| !matches!(character, '0' | '1' | '8' | '9'))
    {
        return SecretType::TotpSeed;
    }
    if value.contains(':') && !value.contains("//") {
        return SecretType::BasicAuth;
    }
    let path_or_field = format!(
        "{} {}",
        path.to_ascii_lowercase(),
        field.to_ascii_lowercase()
    );
    if path_or_field.contains("api-key")
        || path_or_field.contains("apikey")
        || field.eq_ignore_ascii_case("api_key")
    {
        return SecretType::ApiKey;
    }
    if path_or_field.contains("token") || field.eq_ignore_ascii_case("access_token") {
        return SecretType::BearerToken;
    }
    if path_or_field.contains("ssh") || field.eq_ignore_ascii_case("private_key") {
        return SecretType::SshKey;
    }
    if path_or_field.contains("database")
        || path_or_field.contains("/db")
        || field.eq_ignore_ascii_case("database_url")
    {
        return SecretType::DatabaseUrl;
    }
    SecretType::Password
}

fn parse_secret_type(value: &str) -> SecretType {
    match value.to_ascii_lowercase().as_str() {
        "api_key" => SecretType::ApiKey,
        "bearer_token" => SecretType::BearerToken,
        "basic_auth" => SecretType::BasicAuth,
        "ssh_key" => SecretType::SshKey,
        "certificate" => SecretType::Certificate,
        "database_url" => SecretType::DatabaseUrl,
        "totp_seed" => SecretType::TotpSeed,
        _ => SecretType::Password,
    }
}

#[cfg(test)]
mod tests;
