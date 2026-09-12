#![deny(unsafe_code)]

//! Access to the Symaira Vault filesystem format.
//!
//! The store opens current, legacy, and mixed vault layouts, lists logical
//! names, decrypts JSON entries, and performs safe atomic writes, migration,
//! manifest verification, and encrypted search-index persistence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use fs4::fs_std::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use symvault_crypto::{Identity, decrypt, encrypt, parse_recipient, recipient_string};
use thiserror::Error;
#[cfg(not(unix))]
use walkdir::WalkDir;
use zeroize::{Zeroize, Zeroizing};

/// Keyed JSONL audit logging, verification, rotation, and export.
pub mod audit;

/// Pure fixed-clock write metadata preparation.
pub mod metadata;

mod publication;

#[cfg(unix)]
mod rooted;

const ENTRIES_DIR: &str = "entries";
const CONFIG_FILE: &str = "config.yaml";
const IDENTITY_FILE: &str = "identity.age";
const RECIPIENTS_FILE: &str = "recipients.txt";
const MANIFEST_FILE: &str = "manifest.age";
const ENTRY_EXTENSION: &str = ".age";
const LOCK_FILE: &str = ".lock";

/// Read and parse limits are deliberately explicit. They cap allocation before
/// decryption and reject pathological JSON structures after parsing.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ENTRY_FIELDS: usize = 1024;
pub const MAX_ENTRY_DEPTH: usize = 32;
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;
pub const MAX_ARRAY_ITEMS: usize = 1024;

/// Errors returned by the read-only store.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("vault root is not a directory: {0}")]
    RootNotDirectory(PathBuf),
    #[error("vault root changed while it was being acquired: {0}")]
    RootChanged(PathBuf),
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
    #[error("failed to write {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
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
    #[error("search index build produced no entries")]
    SearchIndexBuildEmpty,
    #[error("vault resource exceeds {limit} bytes: {path}")]
    Limit { path: PathBuf, limit: u64 },
    #[error("entry value exceeds the supported structure limits: {0}")]
    ValueLimit(String),
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

/// A decrypted vault entry. Its JSON field names and omission rules match the Go model.
#[derive(Clone, Default, Deserialize, Eq, PartialEq)]
pub struct Entry {
    #[serde(default)]
    pub path: String,
    #[serde(default, deserialize_with = "deserialize_null_map")]
    pub data: BTreeMap<String, serde_json::Value>,
    #[serde(
        rename = "meta",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub metadata: EntryMetadata,
    #[serde(
        rename = "secret_meta",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub secret_metadata: SecretMetadata,
    #[serde(default, deserialize_with = "deserialize_null_i32")]
    pub classification: i32,
    #[serde(default, deserialize_with = "deserialize_null_bool")]
    pub canary: bool,
}

impl fmt::Debug for Entry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Entry")
            .field("path", &self.path)
            .field("fields", &self.data.keys().collect::<Vec<_>>())
            .field("metadata", &self.metadata)
            .field("secret_type", &self.secret_metadata.secret_type)
            .field("auto_rotate", &self.secret_metadata.auto_rotate)
            .field("has_expiration", &self.secret_metadata.expires_at.is_some())
            .field("classification", &self.classification)
            .field("canary", &self.canary)
            .finish()
    }
}

impl Serialize for Entry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut fields = 3;
        if !self.path.is_empty() {
            fields += 1;
        }
        if self.classification != 0 {
            fields += 1;
        }
        if self.canary {
            fields += 1;
        }
        let mut state = serializer.serialize_struct("Entry", fields)?;
        if !self.path.is_empty() {
            state.serialize_field("path", &self.path)?;
        }
        state.serialize_field("data", &self.data)?;
        state.serialize_field("meta", &self.metadata)?;
        // Go's encoding/json does not omit a non-pointer struct, even with
        // `omitempty`, so secret_meta is present for every Entry.
        state.serialize_field("secret_meta", &self.secret_metadata)?;
        if self.classification != 0 {
            state.serialize_field("classification", &self.classification)?;
        }
        if self.canary {
            state.serialize_field("canary", &self.canary)?;
        }
        state.end()
    }
}

fn deserialize_null_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(
        Option::<BTreeMap<String, serde_json::Value>>::deserialize(deserializer)?
            .unwrap_or_default(),
    )
}
fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}
fn deserialize_null_i32<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<i32>::deserialize(deserializer)?.unwrap_or_default())
}
fn deserialize_null_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<bool>::deserialize(deserializer)?.unwrap_or_default())
}

fn go_zero_time() -> String {
    "0001-01-01T00:00:00Z".into()
}

fn utc_now_string(path: &Path) -> Result<String, StoreError> {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|source| StoreError::Read {
            path: path.to_path_buf(),
            source: io::Error::other(source.to_string()),
        })
}

fn system_time_string(path: &Path, value: std::time::SystemTime) -> Result<String, StoreError> {
    let value = time::OffsetDateTime::from(value);
    value
        .to_offset(time::UtcOffset::UTC)
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|source| StoreError::Read {
            path: path.to_path_buf(),
            source: io::Error::other(source.to_string()),
        })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntryMetadata {
    #[serde(default = "go_zero_time")]
    pub created: String,
    #[serde(default = "go_zero_time")]
    pub updated: String,
    #[serde(default)]
    pub version: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_history: Vec<WriteRecord>,
}

impl Default for EntryMetadata {
    fn default() -> Self {
        Self {
            created: "0001-01-01T00:00:00Z".into(),
            updated: "0001-01-01T00:00:00Z".into(),
            version: 0,
            tags: Vec::new(),
            write_history: Vec::new(),
        }
    }
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
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
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
    root_cap: std::sync::Arc<fs::File>,
    layout: Layout,
    config: VaultConfig,
    presence: Presence,
}

impl Store {
    /// Opens an existing vault without changing any filesystem state.
    pub fn open(root: impl AsRef<Path>, _identity: &Identity) -> Result<Self, StoreError> {
        Self::open_with_root_acquisition(root, |_: &Path| {})
    }

    fn open_with_root_acquisition(
        root: impl AsRef<Path>,
        acquire_hook: impl FnOnce(&Path),
    ) -> Result<Self, StoreError> {
        let requested_root = root.as_ref();
        reject_symlink(requested_root)?;
        #[cfg(unix)]
        let root_snapshot = root_identity(requested_root)?;
        let root = requested_root
            .canonicalize()
            .map_err(|source| StoreError::Read {
                path: requested_root.to_path_buf(),
                source,
            })?;
        acquire_hook(&root);
        let root_cap = std::sync::Arc::new(ensure_directory(&root)?);
        #[cfg(unix)]
        if root_identity_from_file(&root_cap)? != root_snapshot {
            return Err(StoreError::RootChanged(requested_root.to_path_buf()));
        }
        reject_symlink(&root)?;
        let config_path = root.join(CONFIG_FILE);
        let identity_path = root.join(IDENTITY_FILE);
        #[cfg(unix)]
        let config_exists =
            rooted::regular_exists_at(&root_cap, Path::new(CONFIG_FILE), &config_path)?;
        #[cfg(not(unix))]
        let config_exists = ensure_regular_file(&config_path, false)?;
        if !config_exists {
            return Err(StoreError::MissingFile(config_path));
        }

        #[cfg(unix)]
        let identity_exists =
            rooted::regular_exists_at(&root_cap, Path::new(IDENTITY_FILE), &identity_path)?;
        #[cfg(not(unix))]
        let identity_exists = ensure_regular_file(&identity_path, false)?;
        if !identity_exists {
            return Err(StoreError::MissingFile(identity_path));
        }

        #[cfg(unix)]
        let config_bytes = rooted::read(&root_cap, Path::new(CONFIG_FILE), &config_path)?;
        #[cfg(not(unix))]
        let config_bytes = read_regular(&config_path)?;
        let config = parse_config(&config_bytes)?;

        #[cfg(unix)]
        let recipients = rooted::regular_exists_at(
            &root_cap,
            Path::new(RECIPIENTS_FILE),
            &root.join(RECIPIENTS_FILE),
        )?;
        #[cfg(not(unix))]
        let recipients = regular_exists(&root.join(RECIPIENTS_FILE))?;
        let presence = Presence {
            config: true,
            identity: true,
            recipients,
        };
        #[cfg(unix)]
        let layout = detect_layout_rooted(&root_cap, &root)?;
        #[cfg(not(unix))]
        let layout = detect_layout(&root)?;
        Ok(Self {
            root,
            root_cap,
            layout,
            config,
            presence,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn read_root_file(&self, name: &str) -> Result<Vec<u8>, StoreError> {
        #[cfg(unix)]
        {
            rooted::read(&self.root_cap, Path::new(name), &self.root.join(name))
        }
        #[cfg(not(unix))]
        {
            read_regular(&self.root.join(name))
        }
    }

    fn relative_path(&self, target: &Path) -> Result<PathBuf, StoreError> {
        target
            .strip_prefix(&self.root)
            .map(Path::to_path_buf)
            .map_err(|_| StoreError::UnsafePath(target.display().to_string()))
    }

    fn regular_exists_path(&self, target: &Path) -> Result<bool, StoreError> {
        #[cfg(unix)]
        {
            let relative = self.relative_path(target)?;
            let parent = rooted::directory(
                &self.root_cap,
                relative.parent().unwrap_or(Path::new("")),
                target,
                false,
            );
            match parent {
                Ok(parent) => rooted::regular_exists(&parent, target),
                Err(StoreError::Read { source, .. })
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    Ok(false)
                }
                Err(error) => Err(error),
            }
        }
        #[cfg(not(unix))]
        {
            regular_exists(target)
        }
    }

    fn read_path(&self, target: &Path) -> Result<Vec<u8>, StoreError> {
        #[cfg(unix)]
        {
            let relative = self.relative_path(target)?;
            self.read_relative_path(&relative, target)
        }
        #[cfg(not(unix))]
        {
            read_regular(target)
        }
    }

    #[cfg(unix)]
    fn read_relative_path(&self, relative: &Path, display: &Path) -> Result<Vec<u8>, StoreError> {
        #[cfg(unix)]
        {
            rooted::read(&self.root_cap, relative, display)
        }
        #[cfg(not(unix))]
        {
            let _ = relative;
            read_regular(display)
        }
    }

    fn remove_path(&self, target: &Path) -> Result<bool, StoreError> {
        let relative = self.relative_path(target)?;
        #[cfg(unix)]
        {
            rooted::remove(&self.root_cap, &relative, target)
        }
        #[cfg(not(unix))]
        {
            let _ = relative;
            match fs::remove_file(target) {
                Ok(()) => Ok(true),
                Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(source) => Err(StoreError::Write {
                    path: target.to_path_buf(),
                    source,
                }),
            }
        }
    }

    fn acquire_write_lock(&self) -> Result<fs::File, StoreError> {
        let path = self.root.join(LOCK_FILE);
        #[cfg(unix)]
        let file = rooted::open_lock(&self.root_cap, &path)?;
        #[cfg(not(unix))]
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| StoreError::Write {
                path: path.clone(),
                source,
            })?;
        set_private_permissions(&file).map_err(|source| StoreError::Write {
            path: path.clone(),
            source,
        })?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match file.try_lock_exclusive() {
                Ok(true) => return Ok(file),
                Ok(false) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Ok(false) => {
                    return Err(StoreError::Write {
                        path,
                        source: io::Error::new(
                            io::ErrorKind::TimedOut,
                            "vault is currently locked by another process, try again in a moment",
                        ),
                    });
                }
                Err(source)
                    if source.kind() == io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                    return Err(StoreError::Write {
                        path,
                        source: io::Error::new(
                            io::ErrorKind::TimedOut,
                            "vault is currently locked by another process, try again in a moment",
                        ),
                    });
                }
                Err(source) => return Err(StoreError::Write { path, source }),
            }
        }
    }

    fn with_write_lock<T>(
        &self,
        operation: impl FnOnce(&Self) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let lock = self.acquire_write_lock()?;
        let result = operation(self);
        let unlock = lock.unlock();
        match (result, unlock) {
            (Err(error), _) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(source)) => Err(StoreError::Write {
                path: self.root.join(LOCK_FILE),
                source,
            }),
        }
    }

    fn entry_candidates(&self) -> Result<Vec<Candidate>, StoreError> {
        #[cfg(unix)]
        {
            let mut result = Vec::new();
            let fresh_entries = match rooted::walk_from(
                &self.root_cap,
                Path::new(ENTRIES_DIR),
                &self.root.join(ENTRIES_DIR),
                None,
            ) {
                Ok(entries) => entries,
                Err(StoreError::Read { source, .. })
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    Vec::new()
                }
                Err(error) => return Err(error),
            };
            let legacy_entries = rooted::walk_with_max_depth(&self.root_cap, &self.root, Some(64))?;
            for (entries, fresh) in [(fresh_entries, true), (legacy_entries, false)] {
                for item in entries {
                    if !item.regular {
                        continue;
                    }
                    let relative = item.relative;
                    let name = relative
                        .file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or_default();
                    if !name.ends_with(ENTRY_EXTENSION) {
                        continue;
                    }
                    if !fresh && matches!(name, IDENTITY_FILE | MANIFEST_FILE) {
                        continue;
                    }
                    if fresh != relative.starts_with(Path::new(ENTRIES_DIR)) {
                        continue;
                    }
                    let logical = if fresh {
                        relative
                            .strip_prefix(ENTRIES_DIR)
                            .map_err(|_| StoreError::UnsafePath(relative.display().to_string()))?
                            .to_string_lossy()
                            .replace(std::path::MAIN_SEPARATOR, "/")
                    } else {
                        relative
                            .to_string_lossy()
                            .replace(std::path::MAIN_SEPARATOR, "/")
                    };
                    result.push(Candidate {
                        path: self.root.join(&relative),
                        relative,
                        logical: logical.trim_end_matches(ENTRY_EXTENSION).to_owned(),
                        fresh,
                    });
                }
            }
            result.sort_by(|a, b| a.logical.cmp(&b.logical).then_with(|| a.path.cmp(&b.path)));
            Ok(result)
        }
        #[cfg(not(unix))]
        {
            entry_candidates(&self.root)
        }
    }

    fn entry_parent_cap(&self, target: &Path) -> Result<fs::File, StoreError> {
        let relative = target
            .strip_prefix(&self.root)
            .map_err(|_| StoreError::UnsafePath(target.display().to_string()))?;
        let parent = relative
            .parent()
            .ok_or_else(|| StoreError::UnsafePath(target.display().to_string()))?;
        #[cfg(unix)]
        {
            rooted::directory(&self.root_cap, parent, target, true)
        }
        #[cfg(not(unix))]
        {
            ensure_directory_recursive(&self.root.join(parent))
        }
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
        let bytes = match self.read_root_file(RECIPIENTS_FILE) {
            Ok(bytes) => bytes,
            Err(StoreError::Read { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error),
        };
        let text = String::from_utf8(bytes)
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
        for candidate in self.entry_candidates()? {
            let logical = candidate.logical.clone();
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
            if self.regular_exists_path(&candidate.path)? {
                return self.read_candidate(&candidate, identity);
            }
        }
        Err(StoreError::EntryNotFound(path.to_owned()))
    }

    /// Writes a new encrypted entry to the current `entries/` layout.
    ///
    /// This first write slice intentionally refuses replacement, path
    /// pseudonymization, and implicit directory creation. Those operations
    /// remain separate STORE-003 work so this method cannot silently claim
    /// parity for unimplemented atomic-update semantics.
    pub fn write_new_entry(
        &self,
        path: &str,
        entry: &Entry,
        identity: &Identity,
    ) -> Result<(), StoreError> {
        validate_entry_path(path)?;
        let entries_root = self.root.join(ENTRIES_DIR);
        // Resolve and prepare all potentially fallible content before creating
        // directories, so invalid configuration has no filesystem side effect.
        let target = if self.config.pseudonymize_paths {
            let name = symvault_crypto::pseudonymize_path(identity, path);
            entries_root
                .join(&name[..2])
                .join(format!("{name}{ENTRY_EXTENSION}"))
        } else {
            let relative = Path::new(path);
            let parent = relative.parent().unwrap_or_else(|| Path::new(""));
            let parent_path = entries_root.join(parent);
            let file_name = relative
                .file_name()
                .ok_or_else(|| StoreError::InvalidEntryPath(path.to_owned()))?;
            parent_path.join(format!(
                "{}{}",
                file_name.to_string_lossy(),
                ENTRY_EXTENSION
            ))
        };
        let mut stored = entry.clone();
        if self.config.pseudonymize_paths {
            stored.path = path.to_owned();
        }
        let plaintext =
            Zeroizing::new(
                serde_json::to_vec(&stored).map_err(|error| StoreError::Entry {
                    path: path.to_owned(),
                    detail: error.to_string(),
                })?,
            );
        let mut recipient_strings = self.recipients()?;
        recipient_strings.insert(0, recipient_string(identity));
        let mut seen = BTreeSet::new();
        let recipients = recipient_strings
            .into_iter()
            .filter(|value| seen.insert(value.clone()))
            .map(|value| {
                parse_recipient(&value).map_err(|error| StoreError::Config(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ciphertext = encrypt(&plaintext, &recipients)
            .map_err(|error| StoreError::Decryption(error.to_string()))?;

        #[cfg(unix)]
        let _entries_cap =
            rooted::directory(&self.root_cap, Path::new(ENTRIES_DIR), &entries_root, false)?;
        #[cfg(not(unix))]
        let _entries_cap = ensure_directory(&entries_root)?;
        let parent_cap = self.entry_parent_cap(&target)?;
        #[cfg(unix)]
        let exists = rooted::regular_exists(&parent_cap, &target)?;
        #[cfg(not(unix))]
        let exists = regular_exists(&target)?;
        if exists {
            return Err(StoreError::Config(
                "entry replacement is not part of the new-entry slice".into(),
            ));
        }
        atomic_create(&target, &ciphertext, &parent_cap)
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
        #[cfg(unix)]
        for item in rooted::walk(&self.root_cap, &self.root)? {
            let metadata = rooted::metadata(
                &self.root_cap,
                &item.relative,
                &self.root.join(&item.relative),
            )?;
            result.push(self.file_info(&item.relative, metadata)?);
        }
        #[cfg(not(unix))]
        for item in WalkDir::new(&self.root).follow_links(false) {
            let item = item.map_err(|error| StoreError::Read {
                path: self.root.clone(),
                source: io::Error::other(error.to_string()),
            })?;
            if item.path() == self.root {
                continue;
            }
            let relative = item
                .path()
                .strip_prefix(&self.root)
                .map_err(|_| StoreError::UnsafePath(item.path().display().to_string()))?;
            let metadata =
                fs::symlink_metadata(item.path()).map_err(|source| StoreError::Read {
                    path: self.root.join(relative),
                    source,
                })?;
            result.push(self.file_info(relative, metadata)?);
        }
        result.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(result)
    }

    fn file_info(
        &self,
        relative: &Path,
        mut metadata: fs::Metadata,
    ) -> Result<FileInfo, StoreError> {
        let display = self.root.join(relative);
        if metadata.file_type().is_symlink() {
            return Err(StoreError::Symlink(display));
        }
        let kind = if metadata.is_dir() {
            FileKind::Directory
        } else if metadata.is_file() {
            FileKind::Regular
        } else {
            return Err(StoreError::NotRegularFile(display));
        };
        let bytes = if kind == FileKind::Regular {
            // The path may have been replaced since traversal. Publish the
            // metadata of the same opened regular file that supplied the bytes.
            #[cfg(unix)]
            let (bytes, opened_metadata) =
                rooted::read_with_metadata(&self.root_cap, relative, &display)?;
            #[cfg(not(unix))]
            let (bytes, opened_metadata) = read_regular_with_metadata(&display)?;
            metadata = opened_metadata;
            bytes
        } else {
            Vec::new()
        };
        Ok(FileInfo {
            path: relative
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/"),
            kind,
            mode: mode_bits(&metadata),
            size: metadata.len(),
            sha256: sha256_hex(&bytes),
        })
    }

    fn candidates_for(
        &self,
        path: &str,
        identity: &Identity,
    ) -> Result<Vec<Candidate>, StoreError> {
        let mut result = Vec::new();
        if self.config.pseudonymize_paths {
            let name = symvault_crypto::pseudonymize_path(identity, path);
            let relative = PathBuf::from(ENTRIES_DIR)
                .join(&name[..2])
                .join(format!("{name}{ENTRY_EXTENSION}"));
            result.push(Candidate {
                path: self.root.join(&relative),
                relative,
                logical: path.to_owned(),
                fresh: true,
            });
        } else {
            let relative = PathBuf::from(ENTRIES_DIR).join(format!("{path}{ENTRY_EXTENSION}"));
            result.push(Candidate {
                path: self.root.join(&relative),
                relative,
                logical: path.to_owned(),
                fresh: true,
            });
        }
        if can_use_legacy_path(path) {
            let relative = PathBuf::from(format!("{path}{ENTRY_EXTENSION}"));
            result.push(Candidate {
                path: self.root.join(&relative),
                relative,
                logical: path.to_owned(),
                fresh: false,
            });
        }
        Ok(result)
    }

    fn read_candidate(
        &self,
        candidate: &Candidate,
        identity: &Identity,
    ) -> Result<Entry, StoreError> {
        let mut raw = self.read_candidate_bytes(candidate)?;
        let mut plaintext =
            decrypt(&raw, identity).map_err(|error| StoreError::Decryption(error.to_string()))?;
        raw.zeroize();
        let result = serde_json::from_slice(&plaintext)
            .map_err(|error| StoreError::Entry {
                path: candidate.logical.clone(),
                detail: error.to_string(),
            })
            .and_then(|entry: Entry| validate_entry_values(&entry).map(|()| entry));
        plaintext.zeroize();
        result
    }

    fn read_candidate_bytes(&self, candidate: &Candidate) -> Result<Vec<u8>, StoreError> {
        #[cfg(unix)]
        {
            rooted::read(&self.root_cap, &candidate.relative, &candidate.path)
        }
        #[cfg(not(unix))]
        {
            read_regular(&candidate.path)
        }
    }
}

fn validate_entry_values(entry: &Entry) -> Result<(), StoreError> {
    if entry.data.len() > MAX_ENTRY_FIELDS {
        return Err(StoreError::ValueLimit("too many top-level fields".into()));
    }
    let mut fields = 0usize;
    for (key, value) in &entry.data {
        if key.len() > MAX_VALUE_BYTES {
            return Err(StoreError::ValueLimit("field name too large".into()));
        }
        validate_json_value(value, 1, &mut fields)?;
    }
    Ok(())
}

// These numeric values are the wire values of Go's taint.Classification.
fn classify_secret_type(secret_type: SecretType) -> i32 {
    match secret_type {
        SecretType::SshKey | SecretType::Certificate | SecretType::TotpSeed => 4,
        SecretType::ApiKey
        | SecretType::BearerToken
        | SecretType::BasicAuth
        | SecretType::DatabaseUrl => 3,
        SecretType::Password | SecretType::Payment | SecretType::Custom => 2,
    }
}

fn infer_classification(entry: &Entry) -> i32 {
    entry
        .data
        .values()
        .fold(entry.classification, |current, value| {
            let serde_json::Value::String(value) = value else {
                return current;
            };
            current.max(classify_secret_type(detect_secret_type(value)))
        })
}

fn validate_json_value(
    value: &serde_json::Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), StoreError> {
    if depth > MAX_ENTRY_DEPTH {
        return Err(StoreError::ValueLimit(
            "maximum nesting depth exceeded".into(),
        ));
    }
    match value {
        serde_json::Value::String(value) if value.len() > MAX_VALUE_BYTES => {
            Err(StoreError::ValueLimit("string value too large".into()))
        }
        serde_json::Value::Array(values) => {
            if values.len() > MAX_ARRAY_ITEMS {
                return Err(StoreError::ValueLimit("array has too many items".into()));
            }
            for value in values {
                validate_json_value(value, depth + 1, fields)?;
            }
            Ok(())
        }
        serde_json::Value::Object(values) => {
            *fields = fields.saturating_add(values.len());
            if *fields > MAX_ENTRY_FIELDS {
                return Err(StoreError::ValueLimit("too many fields".into()));
            }
            for (key, value) in values {
                if key.len() > MAX_VALUE_BYTES {
                    return Err(StoreError::ValueLimit("field name too large".into()));
                }
                validate_json_value(value, depth + 1, fields)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Clone, Debug)]
struct Candidate {
    path: PathBuf,
    relative: PathBuf,
    logical: String,
    fresh: bool,
}

fn parse_config(bytes: &[u8]) -> Result<VaultConfig, StoreError> {
    let raw: RawConfig =
        serde_yaml_ng::from_slice(bytes).map_err(|error| StoreError::Config(error.to_string()))?;
    let mut config = raw.vault.unwrap_or_default();
    if config.path.is_empty() {
        config.path = raw.vault_dir;
    }
    Ok(config)
}

#[cfg(unix)]
fn detect_layout_rooted(root_cap: &fs::File, root: &Path) -> Result<Layout, StoreError> {
    let fresh_entries = match rooted::walk_from(
        root_cap,
        Path::new(ENTRIES_DIR),
        &root.join(ENTRIES_DIR),
        None,
    ) {
        Ok(entries) => entries,
        Err(StoreError::Read { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            Vec::new()
        }
        Err(error) => return Err(error),
    };
    let legacy_entries = rooted::walk_with_max_depth(root_cap, root, Some(64))?;
    let fresh = fresh_entries.iter().any(|item| {
        item.regular
            && item.relative.starts_with(Path::new(ENTRIES_DIR))
            && item
                .relative
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(ENTRY_EXTENSION))
    });
    let legacy = legacy_entries.iter().any(|item| {
        item.regular
            && !item.relative.starts_with(Path::new(ENTRIES_DIR))
            && item.relative.file_name().is_some_and(|name| {
                let name = name.to_string_lossy();
                name.ends_with(ENTRY_EXTENSION) && name != IDENTITY_FILE && name != MANIFEST_FILE
            })
    });
    Ok(match (fresh, legacy) {
        (true, true) => Layout::Mixed,
        (true, false) => Layout::Fresh,
        (false, true) => Layout::Legacy,
        (false, false) => Layout::Fresh,
    })
}

#[cfg(not(unix))]
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

#[cfg(not(unix))]
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
                    relative: PathBuf::from(ENTRIES_DIR).join(rel),
                    logical,
                    fresh: true,
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
                relative: rel.to_path_buf(),
                logical,
                fresh: false,
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

fn set_private_permissions(_file: &fs::File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        _file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn atomic_create(target: &Path, bytes: &[u8], parent: &fs::File) -> Result<(), StoreError> {
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| StoreError::Write {
            path: target.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "entry filename is not UTF-8"),
        })?;

    #[cfg(unix)]
    {
        use rustix::fs::{AtFlags, Mode, OFlags, fsync, linkat, openat, unlinkat};
        for _ in 0..32 {
            let temporary = format!(
                ".{name}.tmp-{}-{}",
                std::process::id(),
                TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let mut file = match openat(
                parent,
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(file) => fs::File::from(file),
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(StoreError::Write {
                        path: target.to_path_buf(),
                        source: source.into(),
                    });
                }
            };
            let result = (|| {
                file.write_all(bytes).map_err(|source| StoreError::Write {
                    path: target.to_path_buf(),
                    source,
                })?;
                fsync(&file).map_err(|source| StoreError::Write {
                    path: target.to_path_buf(),
                    source: source.into(),
                })?;
                linkat(parent, temporary.as_str(), parent, name, AtFlags::empty()).map_err(
                    |source| {
                        if source.kind() == io::ErrorKind::AlreadyExists {
                            StoreError::Config(
                                "entry replacement is not part of the new-entry slice".into(),
                            )
                        } else {
                            StoreError::Write {
                                path: target.to_path_buf(),
                                source: source.into(),
                            }
                        }
                    },
                )?;
                fsync(parent).map_err(|source| StoreError::Write {
                    path: target.to_path_buf(),
                    source: source.into(),
                })?;
                Ok(())
            })();
            drop(file);
            let _ = unlinkat(parent, temporary.as_str(), AtFlags::empty());
            let cleanup = fsync(parent).map_err(|source| StoreError::Write {
                path: target.to_path_buf(),
                source: source.into(),
            });
            return result.and(cleanup.map(|_| ()));
        }
        Err(StoreError::Write {
            path: target.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique temporary entry path",
            ),
        })
    }

    #[cfg(not(unix))]
    {
        let _ = parent;
        // Windows publication remains explicitly unproven; retain the path-based
        // implementation and its old retry/error taxonomy until native tests exist.
        let parent_path = target.parent().ok_or_else(|| StoreError::Write {
            path: target.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "entry has no parent directory"),
        })?;
        for _ in 0..32 {
            let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let temporary =
                parent_path.join(format!(".{name}.tmp-{}-{sequence}", std::process::id()));
            let mut file = match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
            {
                Ok(file) => file,
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(StoreError::Write {
                        path: target.to_path_buf(),
                        source,
                    });
                }
            };
            let result = (|| {
                set_private_permissions(&file).map_err(|source| StoreError::Write {
                    path: target.to_path_buf(),
                    source,
                })?;
                file.write_all(bytes).map_err(|source| StoreError::Write {
                    path: target.to_path_buf(),
                    source,
                })?;
                file.sync_all().map_err(|source| StoreError::Write {
                    path: target.to_path_buf(),
                    source,
                })?;
                drop(file);
                fs::hard_link(&temporary, target).map_err(|source| {
                    if source.kind() == io::ErrorKind::AlreadyExists {
                        StoreError::Config(
                            "entry replacement is not part of the new-entry slice".into(),
                        )
                    } else {
                        StoreError::Write {
                            path: target.to_path_buf(),
                            source,
                        }
                    }
                })
            })();
            let _ = fs::remove_file(&temporary);
            return result;
        }
        Err(StoreError::Write {
            path: target.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique temporary entry path",
            ),
        })
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn root_identity(path: &Path) -> Result<RootIdentity, StoreError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path).map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(StoreError::Symlink(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(StoreError::RootNotDirectory(path.to_path_buf()));
    }
    Ok(RootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn root_identity_from_file(file: &fs::File) -> Result<RootIdentity, StoreError> {
    use std::os::unix::fs::MetadataExt;
    file.metadata()
        .map(|metadata| RootIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
        .map_err(|source| StoreError::Read {
            path: PathBuf::from("<acquired vault root>"),
            source,
        })
}

fn ensure_directory(path: &Path) -> Result<fs::File, StoreError> {
    let file = open_directory_nofollow(path).map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(StoreError::RootNotDirectory(path.to_path_buf()));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn ensure_regular_file(path: &Path, required: bool) -> Result<bool, StoreError> {
    let file = match open_nofollow(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound && !required => return Ok(false),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(StoreError::MissingFile(path.to_path_buf()));
        }
        Err(source) => {
            return Err(StoreError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let metadata = file.metadata().map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(StoreError::NotRegularFile(path.to_path_buf()));
    }
    Ok(true)
}

#[cfg(not(unix))]
fn regular_exists(path: &Path) -> Result<bool, StoreError> {
    ensure_regular_file(path, false)
}

fn reject_symlink(path: &Path) -> Result<(), StoreError> {
    // Kept as a cheap diagnostic for callers; all actual reads use the same
    // descriptor-based no-follow open below, so there is no check/use split.
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(StoreError::Symlink(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(source) => Err(StoreError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(not(unix))]
fn read_regular(path: &Path) -> Result<Vec<u8>, StoreError> {
    read_regular_with_metadata(path).map(|(bytes, _)| bytes)
}

#[cfg(not(unix))]
fn read_regular_with_metadata(path: &Path) -> Result<(Vec<u8>, fs::Metadata), StoreError> {
    let file = open_nofollow(path).map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    read_open_regular_with_metadata(file, path)
}

fn read_open_regular_with_metadata(
    file: fs::File,
    path: &Path,
) -> Result<(Vec<u8>, fs::Metadata), StoreError> {
    let metadata = file.metadata().map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(StoreError::NotRegularFile(path.to_path_buf()));
    }
    let size = metadata.len();
    if size > MAX_FILE_BYTES {
        return Err(StoreError::Limit {
            path: path.to_path_buf(),
            limit: MAX_FILE_BYTES,
        });
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| StoreError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(StoreError::Limit {
            path: path.to_path_buf(),
            limit: MAX_FILE_BYTES,
        });
    }
    Ok((bytes, metadata))
}

#[cfg(unix)]
fn open_directory_nofollow(path: &Path) -> io::Result<fs::File> {
    open_nofollow_kind(path, true)
}

#[cfg(unix)]
fn open_nofollow_kind(path: &Path, final_directory: bool) -> io::Result<fs::File> {
    use rustix::fs::{CWD, Mode, OFlags, openat};
    let mut components = path.components().peekable();
    let mut dir = if path.is_absolute() {
        openat(
            CWD,
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )?
    } else {
        openat(
            CWD,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )?
    };
    let mut last = None;
    while let Some(component) = components.next() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe path"));
            }
        };
        let is_last = components.peek().is_none();
        let flags = if is_last && final_directory {
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW
        } else if is_last {
            OFlags::RDONLY | OFlags::NOFOLLOW
        } else {
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW
        };
        let opened = openat(&dir, name, flags, Mode::empty())?;
        if is_last {
            last = Some(opened);
        } else {
            dir = opened;
        }
    }
    last.map(fs::File::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty path"))
}

#[cfg(windows)]
fn open_nofollow(path: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

#[cfg(windows)]
fn open_directory_nofollow(path: &Path) -> io::Result<fs::File> {
    open_nofollow(path)
}

#[cfg(not(any(unix, windows)))]
fn open_nofollow(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new().read(true).open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_directory_nofollow(path: &Path) -> io::Result<fs::File> {
    open_nofollow(path)
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
    Payment,
    Custom,
}

impl SecretType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::BearerToken => "bearer_token",
            Self::BasicAuth => "basic_auth",
            Self::SshKey => "ssh_key",
            Self::Password => "password",
            Self::Certificate => "certificate",
            Self::DatabaseUrl => "database_url",
            Self::TotpSeed => "totp_seed",
            Self::Payment => "payment",
            Self::Custom => "custom",
        }
    }
}

fn ascii_alnum(value: &str) -> bool {
    value
        .chars()
        .all(|character| character.is_ascii_alphanumeric())
}

#[must_use]
pub fn detect_secret_type(value: &str) -> SecretType {
    let value = value.trim();
    if value.is_empty() {
        return SecretType::Password;
    }
    let upper = value.to_ascii_uppercase();
    if [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
    ]
    .iter()
    .any(|prefix| upper.starts_with(prefix))
    {
        return SecretType::SshKey;
    }
    if upper.starts_with("-----BEGIN CERTIFICATE-----") {
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
    let github = ["ghp_", "gho_", "ghs_", "ghr_"].iter().any(|prefix| {
        value
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.len() == 36 && ascii_alnum(suffix))
    }) || value
        .strip_prefix("github_pat_")
        .and_then(|suffix| suffix.split_once('_'))
        .is_some_and(|(first, second)| {
            first.len() == 22 && second.len() == 59 && ascii_alnum(first) && ascii_alnum(second)
        });
    if github {
        return SecretType::BearerToken;
    }
    if value.starts_with("AKIA")
        && value.len() == 20
        && value[4..]
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return SecretType::ApiKey;
    }
    if value.len() >= 16
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        && value.chars().all(|c| !matches!(c, '0' | '1' | '8' | '9'))
    {
        return SecretType::TotpSeed;
    }
    let jwt_parts: Vec<_> = value.split('.').collect();
    if jwt_parts.len() == 3
        && jwt_parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
    {
        return SecretType::BearerToken;
    }
    let basic_parts: Vec<_> = value.split(':').collect();
    if basic_parts.len() == 2 && basic_parts.iter().all(|part| !part.is_empty()) {
        return SecretType::BasicAuth;
    }
    if value.len() >= 32
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return SecretType::ApiKey;
    }
    SecretType::Password
}

#[must_use]
pub fn detect_type_from_path(path: &str) -> Option<SecretType> {
    for part in path.to_ascii_lowercase().split('/') {
        if matches!(part, "api-key" | "apikey") {
            return Some(SecretType::ApiKey);
        }
        for segment in part.split('-') {
            let kind = match segment {
                "apikey" => Some(SecretType::ApiKey),
                "token" => Some(SecretType::BearerToken),
                "ssh" => Some(SecretType::SshKey),
                "seed" | "mnemonic" => Some(SecretType::TotpSeed),
                "database" | "db" => Some(SecretType::DatabaseUrl),
                "password" | "pass" => Some(SecretType::Password),
                _ => None,
            };
            if kind.is_some() {
                return kind;
            }
        }
    }
    None
}

#[must_use]
pub fn detect_type_from_field_name(field: &str) -> Option<SecretType> {
    Some(match field.trim().to_ascii_lowercase().as_str() {
        "api_key" | "apikey" => SecretType::ApiKey,
        "token" | "access_token" | "bearer_token" => SecretType::BearerToken,
        "seed_phrase" | "mnemonic" => SecretType::TotpSeed,
        "private_key" | "ssh_key" => SecretType::SshKey,
        "database_url" | "connection_string" => SecretType::DatabaseUrl,
        "cert_pem" | "certificate" => SecretType::Certificate,
        _ => return None,
    })
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
    let detected = detect_secret_type(value);
    if detected != SecretType::Password {
        return detected;
    }
    if let Some(detected) = detect_type_from_path(path) {
        return detected;
    }
    detect_type_from_field_name(field).unwrap_or(SecretType::Password)
}

fn parse_secret_type(value: &str) -> SecretType {
    match value.to_ascii_lowercase().as_str() {
        "api_key" => SecretType::ApiKey,
        "bearer_token" => SecretType::BearerToken,
        "basic_auth" => SecretType::BasicAuth,
        "ssh_key" => SecretType::SshKey,
        "password" => SecretType::Password,
        "certificate" => SecretType::Certificate,
        "database_url" => SecretType::DatabaseUrl,
        "totp_seed" => SecretType::TotpSeed,
        "payment" => SecretType::Payment,
        "custom" => SecretType::Custom,
        _ => SecretType::Custom,
    }
}

/// Integrity metadata for one encrypted entry in `manifest.age`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub sha256: String,
    pub size: i64,
    pub mtime: String,
}

/// The encrypted manifest format used by the Go vault.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: i64,
    pub generation: i64,
    pub created: String,
    pub updated: String,
    pub entries: BTreeMap<String, ManifestEntry>,
}

/// The four independent outcomes of manifest verification.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManifestVerifyResult {
    pub missing: Vec<String>,
    pub tampered: Vec<String>,
    pub unknown: Vec<String>,
    pub ok: usize,
}

impl Store {
    /// Moves legacy top-level `.age` entries into `entries/` without changing
    /// their ciphertext. Existing fresh files win; a marker makes the operation
    /// idempotent. No plaintext is ever loaded during migration.
    pub fn migrate_legacy(&self) -> Result<(), StoreError> {
        let entries = self.entry_candidates()?;
        let fresh_root = self.root.join(ENTRIES_DIR);
        #[cfg(unix)]
        rooted::directory(&self.root_cap, Path::new(ENTRIES_DIR), &fresh_root, true)?;
        #[cfg(not(unix))]
        ensure_directory_recursive(&fresh_root)?;
        for candidate in entries {
            if candidate.fresh {
                continue;
            }
            let destination_relative = PathBuf::from(ENTRIES_DIR)
                .join(format!("{}{}", candidate.logical, ENTRY_EXTENSION));
            let destination = self.root.join(&destination_relative);
            if self.regular_exists_path(&destination)? {
                continue;
            }
            #[cfg(unix)]
            {
                if !rooted::regular_exists_at(&self.root_cap, &candidate.relative, &candidate.path)?
                {
                    continue;
                }
                rooted::rename(
                    &self.root_cap,
                    &candidate.relative,
                    &destination_relative,
                    &destination,
                )?;
            }
            #[cfg(not(unix))]
            {
                reject_symlink(&candidate.path)?;
                let parent = destination
                    .parent()
                    .ok_or_else(|| StoreError::UnsafePath(candidate.logical.clone()))?;
                ensure_directory_recursive(parent)?;
                fs::rename(&candidate.path, &destination).map_err(|source| StoreError::Write {
                    path: destination.clone(),
                    source,
                })?;
            }
        }
        let marker = self.root.join(".symvault-migrated");
        if !self.regular_exists_path(&marker)? {
            publication::replace(&marker, &[], &self.root_cap)?;
        }
        Ok(())
    }

    /// Replaces or creates an entry using a same-directory temporary file and
    /// rename. The old ciphertext remains intact if encryption or writing fails.
    pub fn write_entry(
        &self,
        path: &str,
        entry: &Entry,
        identity: &Identity,
    ) -> Result<(), StoreError> {
        // Preserve the historical writer contract: write_entry did not stamp
        // wall-clock metadata. Callers that need Go-compatible stamping use
        // write_entry_at with an explicit clock.
        self.write_entry_at(path, entry, identity, "0001-01-01T00:00:00Z", false, None)
    }

    /// Writes an entry after applying metadata with an explicit clock seam.
    pub fn write_entry_at(
        &self,
        path: &str,
        entry: &Entry,
        identity: &Identity,
        now: &str,
        pseudonymize: bool,
        pending: Option<&WriteRecord>,
    ) -> Result<(), StoreError> {
        validate_entry_path(path)?;
        let stored = metadata::prepare_entry(
            entry,
            now,
            path,
            pseudonymize || self.config.pseudonymize_paths,
            pending,
        )
        .map_err(|detail| StoreError::Entry {
            path: path.to_owned(),
            detail,
        })?;
        let mut stored = stored;
        stored.classification = infer_classification(&stored);
        // Keep the single-recipient entry seam distinct from Go's
        // WriteEntryWithRecipients. Manifests use all configured recipients.
        let recipient = parse_recipient(&recipient_string(identity))
            .map_err(|error| StoreError::Decryption(error.to_string()))?;
        self.publish_prepared_entry(path, &stored, identity, &[recipient])
    }

    /// Applies Go metadata preparation and encrypts for every configured
    /// recipient, corresponding to `WriteEntryWithRecipients` with a clock seam.
    /// Entry publication and manifest update remain separate operations.
    pub fn write_entry_with_recipients_at(
        &self,
        path: &str,
        entry: &Entry,
        identity: &Identity,
        now: &str,
        pending: Option<&WriteRecord>,
    ) -> Result<(), StoreError> {
        validate_entry_path(path)?;
        let recipients = self.encryption_recipients(identity)?;
        let stored =
            metadata::prepare_entry(entry, now, path, self.config.pseudonymize_paths, pending)
                .map_err(|detail| StoreError::Entry {
                    path: path.to_owned(),
                    detail,
                })?;
        self.publish_prepared_entry(path, &stored, identity, &recipients)
    }

    fn publish_prepared_entry(
        &self,
        path: &str,
        entry: &Entry,
        identity: &Identity,
        recipients: &[symvault_crypto::Recipient],
    ) -> Result<(), StoreError> {
        validate_entry_values(entry)?;
        let plaintext =
            Zeroizing::new(
                serde_json::to_vec(entry).map_err(|error| StoreError::Entry {
                    path: path.to_owned(),
                    detail: error.to_string(),
                })?,
            );
        let encrypted = encrypt(&plaintext, recipients)
            .map_err(|error| StoreError::Decryption(error.to_string()))?;
        let target = self.configured_entry_path(path, identity)?;
        let parent_cap = self.entry_parent_cap(&target)?;
        publication::replace(&target, &encrypted, &parent_cap)?;
        // Go publishes the primary entry first and intentionally discards
        // queued manifest failures from this high-level mutation.
        let _ = self.update_manifest_entry(path, &encrypted, identity);
        Ok(())
    }

    /// Deletes a fresh entry. Missing entries are reported as `EntryNotFound`;
    /// symlinks and non-regular targets are never followed.
    pub fn delete_entry(&self, path: &str) -> Result<(), StoreError> {
        self.delete_entry_at(path, None)
    }

    /// Deletes the configured entry path, including pseudonymized layouts.
    /// Manifest bookkeeping is best-effort after the primary unlink, matching
    /// the high-level Go mutation contract.
    pub fn delete_entry_with_identity(
        &self,
        path: &str,
        identity: &Identity,
    ) -> Result<(), StoreError> {
        self.delete_entry_at(path, Some(identity))
    }

    /// Reports whether the configured identity-derived entry exists.
    pub fn entry_exists(&self, path: &str, identity: &Identity) -> Result<bool, StoreError> {
        let target = self.configured_entry_path(path, identity)?;
        #[cfg(unix)]
        {
            let relative = target
                .strip_prefix(&self.root)
                .map_err(|_| StoreError::UnsafePath(target.display().to_string()))?;
            let parent = rooted::directory(
                &self.root_cap,
                relative.parent().unwrap_or(Path::new("")),
                &target,
                false,
            );
            match parent {
                Ok(parent) => rooted::regular_exists(&parent, &target),
                Err(StoreError::Read { source, .. })
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    Ok(false)
                }
                Err(error) => Err(error),
            }
        }
        #[cfg(not(unix))]
        {
            regular_exists(&target)
        }
    }

    fn delete_entry_at(&self, path: &str, identity: Option<&Identity>) -> Result<(), StoreError> {
        validate_entry_path(path)?;
        let configured = identity.map(|identity| self.configured_entry_path(path, identity));
        #[cfg(unix)]
        {
            let fresh_path = match configured {
                Some(path) => path?,
                None => self
                    .root
                    .join(ENTRIES_DIR)
                    .join(format!("{path}{ENTRY_EXTENSION}")),
            };
            let fresh = fresh_path
                .strip_prefix(&self.root)
                .map_err(|_| StoreError::UnsafePath(fresh_path.display().to_string()))?;
            if rooted::remove(&self.root_cap, fresh, &self.root.join(fresh))? {
                if let Some(identity) = identity {
                    let _ = self.remove_manifest_entry(path, identity);
                }
                return Ok(());
            }
            if can_use_legacy_path(path) {
                let legacy = PathBuf::from(format!("{path}{ENTRY_EXTENSION}"));
                if rooted::remove(&self.root_cap, &legacy, &self.root.join(&legacy))? {
                    if let Some(identity) = identity {
                        let _ = self.remove_manifest_entry(path, identity);
                    }
                    return Ok(());
                }
            }
            Err(StoreError::EntryNotFound(path.to_owned()))
        }
        #[cfg(not(unix))]
        {
            let fresh = match configured {
                Some(path) => path?,
                None => self.fresh_entry_path(path)?,
            };
            let target = if regular_exists(&fresh)? {
                fresh
            } else if can_use_legacy_path(path) {
                let legacy = self.root.join(format!("{path}{ENTRY_EXTENSION}"));
                if regular_exists(&legacy)? {
                    legacy
                } else {
                    return Err(StoreError::EntryNotFound(path.to_owned()));
                }
            } else {
                return Err(StoreError::EntryNotFound(path.to_owned()));
            };
            fs::remove_file(&target).map_err(|source| StoreError::Write {
                path: target,
                source,
            })?;
            if let Some(identity) = identity {
                let _ = self.remove_manifest_entry(path, identity);
            }
            Ok(())
        }
    }

    fn fresh_entry_path(&self, path: &str) -> Result<PathBuf, StoreError> {
        validate_entry_path(path)?;
        Ok(self
            .root
            .join(ENTRIES_DIR)
            .join(format!("{path}{ENTRY_EXTENSION}")))
    }

    fn configured_entry_path(
        &self,
        path: &str,
        identity: &Identity,
    ) -> Result<PathBuf, StoreError> {
        validate_entry_path(path)?;
        if self.config.pseudonymize_paths {
            let name = symvault_crypto::pseudonymize_path(identity, path);
            Ok(self
                .root
                .join(ENTRIES_DIR)
                .join(&name[..2])
                .join(format!("{name}{ENTRY_EXTENSION}")))
        } else {
            self.fresh_entry_path(path)
        }
    }

    fn encryption_recipients(
        &self,
        identity: &Identity,
    ) -> Result<Vec<symvault_crypto::Recipient>, StoreError> {
        let mut values = self.recipients()?;
        values.insert(0, recipient_string(identity));
        let mut seen = BTreeSet::new();
        values
            .into_iter()
            .filter(|value| seen.insert(value.clone()))
            .map(|value| {
                parse_recipient(&value).map_err(|error| StoreError::Config(error.to_string()))
            })
            .collect()
    }

    /// Loads and decrypts the manifest. A missing manifest is distinguished
    /// from malformed or unauthentic ciphertext.
    pub fn load_manifest(&self, identity: &Identity) -> Result<Manifest, StoreError> {
        let mut raw = self.read_root_file(MANIFEST_FILE)?;
        let mut plaintext =
            decrypt(&raw, identity).map_err(|error| StoreError::Decryption(error.to_string()))?;
        raw.zeroize();
        let result = serde_json::from_slice::<Manifest>(&plaintext)
            .map_err(|error| StoreError::Config(error.to_string()));
        plaintext.zeroize();
        let mut manifest: Manifest = result?;
        if manifest.entries.is_empty() {
            manifest.entries = BTreeMap::new();
        }
        Ok(manifest)
    }

    /// Verifies manifest entries and reports missing, tampered, and unknown
    /// files separately, matching the Go diagnostic shape.
    pub fn verify_manifest(&self, identity: &Identity) -> Result<ManifestVerifyResult, StoreError> {
        let manifest = self.load_manifest(identity)?;
        let mut result = ManifestVerifyResult::default();
        let mut expected = BTreeSet::new();
        for (logical, metadata) in &manifest.entries {
            let target = self.configured_entry_path(logical, identity)?;
            let target_relative = self.relative_path(&target)?;
            expected.insert(
                target_relative
                    .strip_prefix(ENTRIES_DIR)
                    .unwrap_or(&target_relative)
                    .to_string_lossy()
                    .into_owned(),
            );
            match self.read_path(&target) {
                Ok(bytes) => {
                    if sha256_hex(&bytes) == metadata.sha256 {
                        result.ok += 1;
                    } else {
                        result.tampered.push(logical.clone());
                    }
                }
                Err(StoreError::Read { source, .. })
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    result.missing.push(logical.clone());
                }
                Err(error) => return Err(error),
            }
        }
        for candidate in self.entry_candidates()? {
            if !candidate.fresh {
                continue;
            }
            let storage = candidate
                .relative
                .strip_prefix(ENTRIES_DIR)
                .unwrap_or(&candidate.relative)
                .to_string_lossy()
                .into_owned();
            if !expected.contains(&storage) {
                result.unknown.push(storage);
            }
        }
        result.missing.sort();
        result.tampered.sort();
        result.unknown.sort();
        Ok(result)
    }

    /// Rebuilds the manifest from regular fresh-layout entry files.
    pub fn rebuild_manifest(&self, identity: &Identity) -> Result<Manifest, StoreError> {
        self.with_write_lock(|store| store.rebuild_manifest_unlocked(identity))
    }

    fn rebuild_manifest_unlocked(&self, identity: &Identity) -> Result<Manifest, StoreError> {
        let mut manifest = Manifest {
            version: 1,
            generation: 0,
            created: go_zero_time(),
            updated: go_zero_time(),
            entries: BTreeMap::new(),
        };
        for candidate in self.entry_candidates()? {
            if !candidate.fresh {
                continue;
            }
            let bytes = self.read_candidate_bytes(&candidate)?;
            #[cfg(unix)]
            let metadata = rooted::metadata(&self.root_cap, &candidate.relative, &candidate.path)?;
            #[cfg(not(unix))]
            let metadata = fs::metadata(&candidate.path).map_err(|source| StoreError::Read {
                path: candidate.path.clone(),
                source,
            })?;
            manifest.entries.insert(
                candidate.logical.clone(),
                ManifestEntry {
                    sha256: sha256_hex(&bytes),
                    size: bytes.len() as i64,
                    mtime: system_time_string(
                        &candidate.path,
                        metadata.modified().map_err(|source| StoreError::Read {
                            path: candidate.path.clone(),
                            source,
                        })?,
                    )?,
                },
            );
            let _ = metadata;
        }
        self.write_manifest(&manifest, identity)?;
        Ok(manifest)
    }

    /// Updates one manifest record after a successful entry write.
    /// Like Go's UpdateManifestEntry, this treats `path` as a verbatim map key;
    /// entry filesystem operations validate their paths separately.
    pub fn update_manifest_entry(
        &self,
        path: &str,
        ciphertext: &[u8],
        identity: &Identity,
    ) -> Result<(), StoreError> {
        self.with_write_lock(|store| {
            store.update_manifest_entry_unlocked(path, ciphertext, identity)
        })
    }

    fn update_manifest_entry_unlocked(
        &self,
        path: &str,
        ciphertext: &[u8],
        identity: &Identity,
    ) -> Result<(), StoreError> {
        let mut manifest = match self.load_manifest(identity) {
            Ok(value) => value,
            Err(StoreError::Read { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                Manifest {
                    version: 1,
                    generation: 0,
                    created: utc_now_string(&self.root)?,
                    updated: go_zero_time(),
                    entries: BTreeMap::new(),
                }
            }
            Err(error) => return Err(error),
        };
        manifest.entries.insert(
            path.to_owned(),
            ManifestEntry {
                sha256: sha256_hex(ciphertext),
                size: ciphertext.len() as i64,
                mtime: utc_now_string(&self.root)?,
            },
        );
        manifest.generation = manifest.generation.wrapping_add(1);
        self.write_manifest(&manifest, identity)
    }

    /// Removes one manifest record. Missing manifests are a no-op.
    /// The key is used verbatim, including empty or non-filesystem strings.
    pub fn remove_manifest_entry(&self, path: &str, identity: &Identity) -> Result<(), StoreError> {
        self.with_write_lock(|store| store.remove_manifest_entry_unlocked(path, identity))
    }

    fn remove_manifest_entry_unlocked(
        &self,
        path: &str,
        identity: &Identity,
    ) -> Result<(), StoreError> {
        let mut manifest = match self.load_manifest(identity) {
            Ok(value) => value,
            Err(StoreError::Read { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        manifest.entries.remove(path);
        manifest.generation = manifest.generation.wrapping_add(1);
        self.write_manifest(&manifest, identity)
    }

    fn write_manifest(&self, manifest: &Manifest, identity: &Identity) -> Result<(), StoreError> {
        let mut manifest = manifest.clone();
        if manifest.version == 0 {
            manifest.version = 1;
        }
        manifest.updated = utc_now_string(&self.root)?;
        let recipients = self.encryption_recipients(identity)?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&manifest).map_err(|error| StoreError::Config(error.to_string()))?,
        );
        let ciphertext = encrypt(&plaintext, &recipients)
            .map_err(|error| StoreError::Decryption(error.to_string()))?;
        publication::replace(&self.root.join(MANIFEST_FILE), &ciphertext, &self.root_cap)
    }
}

#[cfg(any(not(unix), test))]
fn ensure_directory_recursive(path: &Path) -> Result<fs::File, StoreError> {
    #[cfg(unix)]
    {
        use rustix::fs::{CWD, Mode, OFlags, fsync, mkdirat, openat};
        use std::os::fd::AsFd;
        let mut dir = if path.is_absolute() {
            openat(
                CWD,
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                Mode::empty(),
            )
        } else {
            openat(
                CWD,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                Mode::empty(),
            )
        }
        .map_err(|source| StoreError::Write {
            path: path.to_path_buf(),
            source: source.into(),
        })?;
        for component in path.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => name,
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(StoreError::UnsafePath(path.display().to_string()));
                }
            };
            match openat(
                &dir,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                Mode::empty(),
            ) {
                Ok(next) => dir = next,
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    let created = match mkdirat(&dir, name, Mode::from_raw_mode(0o700)) {
                        Ok(()) => true,
                        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => false,
                        Err(source) => {
                            return Err(StoreError::Write {
                                path: path.to_path_buf(),
                                source: source.into(),
                            });
                        }
                    };
                    if created {
                        // Persist the new directory entry before descending;
                        // the retained parent capability is the publication root.
                        fsync(&dir).map_err(|source| StoreError::Write {
                            path: path.to_path_buf(),
                            source: source.into(),
                        })?;
                    }
                    // Another creator may have won mkdirat; either way reopen
                    // the component relative to the retained parent capability.
                    dir = openat(
                        &dir,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(|source| StoreError::Write {
                        path: path.to_path_buf(),
                        source: source.into(),
                    })?;
                }
                Err(source) => {
                    return Err(StoreError::Write {
                        path: path.to_path_buf(),
                        source: source.into(),
                    });
                }
            }
        }
        let _ = dir.as_fd();
        Ok(fs::File::from(dir))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path).map_err(|source| StoreError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        ensure_directory(path)
    }
}

/// An encrypted, persistent search index. Only encrypted bytes are retained on
/// disk; plaintext is held transiently while a query is executed.
#[derive(Debug, Default)]
pub struct SearchIndex {
    salt: Vec<u8>,
    ciphertext: Vec<u8>,
    doc: Option<IndexDocument>,
    root: PathBuf,
    // Retain the directory handle on every platform; invalidation uses it on Unix.
    _root_cap: Option<std::sync::Arc<fs::File>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct EmptyIndexValue {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct IndexDocument {
    #[serde(rename = "v", default, deserialize_with = "deserialize_null_generic")]
    values: BTreeMap<String, Vec<String>>,
    #[serde(
        rename = "ti",
        default,
        deserialize_with = "deserialize_null_generic",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    token_index: BTreeMap<String, BTreeMap<String, EmptyIndexValue>>,
    #[serde(
        rename = "pt",
        default,
        deserialize_with = "deserialize_null_generic",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    path_tokens: BTreeMap<String, Vec<String>>,
    #[serde(
        rename = "hi",
        default,
        deserialize_with = "deserialize_null_generic",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    host_index: BTreeMap<String, BTreeMap<String, EmptyIndexValue>>,
    #[serde(
        rename = "ph",
        default,
        deserialize_with = "deserialize_null_generic",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    path_hosts: BTreeMap<String, Vec<String>>,
    #[serde(
        rename = "c",
        default,
        deserialize_with = "deserialize_null_generic",
        skip_serializing_if = "is_zero"
    )]
    entry_count: usize,
    #[serde(
        rename = "p",
        default,
        deserialize_with = "deserialize_null_generic",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    paths: BTreeMap<String, EmptyIndexValue>,
    #[serde(
        rename = "s",
        default,
        deserialize_with = "deserialize_index_salt",
        serialize_with = "serialize_index_salt",
        skip_serializing_if = "Vec::is_empty"
    )]
    salt: Vec<u8>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

fn deserialize_null_generic<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_index_salt<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = Option::<String>::deserialize(deserializer)?;
    encoded
        .map(|value| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(serde::de::Error::custom)
        })
        .transpose()
        .map(|value| value.unwrap_or_default())
}

fn serialize_index_salt<S>(salt: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use base64::Engine;
    serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(salt))
}

impl SearchIndex {
    /// Builds and persists an encrypted index from every decryptable entry.
    /// Rejects a nonempty vault with no searchable values, preserving any
    /// existing index. An empty vault can still produce a valid empty index.
    pub fn build(store: &Store, identity: &Identity) -> Result<Self, StoreError> {
        let paths = store.list(identity)?;
        let mut document = IndexDocument {
            entry_count: paths.len(),
            ..Default::default()
        };
        for path in &paths {
            document.paths.insert(path.clone(), EmptyIndexValue {});
            if let Ok(entry) = store.get(path, identity) {
                let mut values = Vec::new();
                for (field, value) in &entry.data {
                    collect_index_strings(&mut values, field, value);
                }
                values.sort();
                if !values.is_empty() {
                    document.values.insert(path.clone(), values);
                }
            }
        }
        // Go's buildIndex rejects this before publishing. Host extraction only
        // accepts nonempty strings, which are already included in values here.
        if !paths.is_empty() && document.values.is_empty() {
            return Err(StoreError::SearchIndexBuildEmpty);
        }
        let mut salt = vec![0u8; 16];
        getrandom::fill(&mut salt).map_err(|source| StoreError::Write {
            path: store.root.join(".search-index"),
            source: io::Error::other(source.to_string()),
        })?;
        document.salt = salt.clone();
        let plaintext =
            serde_json::to_vec(&document).map_err(|error| StoreError::Config(error.to_string()))?;
        let encrypted = symvault_crypto::encrypt_index(&plaintext, identity, &salt)
            .map_err(|error| StoreError::Decryption(error.to_string()))?;
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&encrypted);
        publication::replace(&store.root.join(".search-index"), &bytes, &store.root_cap)?;
        Ok(Self {
            salt,
            ciphertext: encrypted,
            doc: Some(document),
            root: store.root.clone(),
            _root_cap: Some(std::sync::Arc::clone(&store.root_cap)),
        })
    }

    /// Loads a current or legacy encrypted index, rejecting stale indexes.
    pub fn load(store: &Store, identity: &Identity) -> Result<Option<Self>, StoreError> {
        let path = store.root.join(".search-index");
        let raw = match store.read_path(&path) {
            Ok(value) => value,
            Err(StoreError::Read { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let (salt, ciphertext) = if raw.first() == Some(&1) && raw.len() > 18 {
            (raw[1..17].to_vec(), raw[17..].to_vec())
        } else {
            (Vec::new(), raw)
        };
        let plaintext = match symvault_crypto::decrypt_index(&ciphertext, identity, &salt) {
            Ok(value) => value,
            Err(_) => {
                let _ = store.remove_path(&path);
                return Ok(None);
            }
        };
        let document: IndexDocument = match serde_json::from_slice(&plaintext) {
            Ok(value) => value,
            Err(_) => {
                let _ = store.remove_path(&path);
                return Ok(None);
            }
        };
        if document.entry_count != store.list(identity)?.len() {
            let _ = store.remove_path(&path);
            return Ok(None);
        }
        Ok(Some(Self {
            salt,
            ciphertext,
            doc: Some(document),
            root: store.root.clone(),
            _root_cap: Some(std::sync::Arc::clone(&store.root_cap)),
        }))
    }

    /// Returns matching logical paths for a case-insensitive substring query.
    pub fn search(
        &mut self,
        candidates: &[String],
        needle: &str,
    ) -> Result<BTreeSet<String>, StoreError> {
        if needle.is_empty() {
            return Ok(BTreeSet::new());
        }
        if self.doc.is_none() {
            let identity_error = StoreError::Config("search index is not loaded".into());
            return Err(identity_error);
        }
        let query = needle.to_lowercase();
        let allowed: BTreeSet<_> = candidates.iter().cloned().collect();
        Ok(self
            .doc
            .as_ref()
            .expect("checked above")
            .values
            .iter()
            .filter(|(path, values)| {
                allowed.contains(*path) && values.iter().any(|value| value.contains(&query))
            })
            .map(|(path, _)| path.clone())
            .collect())
    }

    /// Removes the persisted index and all transient plaintext.
    pub fn invalidate(&mut self) -> Result<(), StoreError> {
        self.doc = None;
        self.salt.clear();
        self.ciphertext.zeroize();
        self.ciphertext.clear();
        if self.root.as_os_str().is_empty() {
            return Ok(());
        }
        let path = self.root.join(".search-index");
        #[cfg(unix)]
        if let Some(root_cap) = &self._root_cap {
            rooted::remove(root_cap, Path::new(".search-index"), &path)?;
            return Ok(());
        }
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(StoreError::Write { path, source }),
        }
    }
}

fn collect_index_strings(values: &mut Vec<String>, field: &str, value: &serde_json::Value) {
    match value {
        serde_json::Value::String(value) if field == "backup_codes" => value
            .split('\n')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .for_each(|value| values.push(value.to_lowercase())),
        serde_json::Value::String(value) if !value.is_empty() => values.push(value.to_lowercase()),
        serde_json::Value::Array(values_array) => values_array
            .iter()
            .for_each(|value| collect_index_strings(values, "", value)),
        serde_json::Value::Object(object) => object
            .values()
            .for_each(|value| collect_index_strings(values, "", value)),
        _ => {}
    }
}

#[cfg(test)]
mod tests;
