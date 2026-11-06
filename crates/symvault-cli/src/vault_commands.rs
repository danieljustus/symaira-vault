//! Read-only vault commands and the bounded initialization bootstrap.
//!
//! The command dispatcher owns argument parsing and session policy.  These
//! functions accept an already-unlocked identity so callers can reuse the
//! same session boundary for every command without duplicating key handling.

use std::{collections::BTreeMap, io::Write, path::Path};

#[cfg(test)]
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use symvault_core::config::{AgentProfile, Config, GitConfig, VaultConfig};
use symvault_crypto::{
    Argon2idParams, Identity, SecretBytes, encrypt_identity_argon2id, generate_identity,
};
use symvault_gojson::yaml::{self, Node};
use symvault_store::{Entry, Store};
use symvault_sync::safeio;

/// Metadata emitted by `list --output json`.
#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct ListEntryInfo {
    pub path: String,
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub secret_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub usage_hint: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub auto_rotate: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub has_value: bool,
    #[serde(skip_serializing_if = "is_zero")]
    pub field_count: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// The result of resolving an exact entry path, optionally to one field.
#[derive(Debug, Eq, PartialEq)]
pub enum GetResult {
    Entry {
        path: String,
        entry: Box<Entry>,
    },
    Field {
        path: String,
        field: String,
        value: serde_json::Value,
    },
}

#[derive(Debug, Serialize, Eq, PartialEq)]
struct TotpOutput {
    code: String,
    period: i64,
    remaining: i64,
}

#[derive(Serialize)]
struct GetEntryOutput<'a> {
    #[serde(rename = "Fields")]
    fields: &'a BTreeMap<String, serde_json::Value>,
    #[serde(rename = "TOTP")]
    totp: Option<TotpOutput>,
    #[serde(rename = "Path")]
    path: &'a str,
    #[serde(rename = "Modified")]
    modified: String,
}

/// Opens an existing vault using a caller-provided unlocked identity.
pub fn open_vault(root: &Path, identity: &Identity) -> Result<Store, String> {
    Store::open_with_legacy_migration(root, identity)
        .map_err(|error| format!("cannot open vault: {error}"))
}

/// Creates the first vault files and returns the generated identity.
///
/// The passphrase is borrowed only for the encryption call.  Session storage
/// and prompts remain outside this module so tests and platform callers can
/// inject their own policy without touching a real keychain.
pub fn initialize(root: &Path, passphrase: &SecretBytes) -> Result<Identity, String> {
    if passphrase.as_bytes().is_empty() {
        return Err("passphrase is empty".to_owned());
    }
    if root.join("config.yaml").exists() || root.join("identity.age").exists() {
        return Err(format!("vault already initialized at {}", root.display()));
    }

    safeio::create_dir_all(&root.join("entries"))
        .map_err(|error| format!("create vault dir: {error}"))?;

    let config = Config {
        vault_dir: root.to_string_lossy().into_owned(),
        default_agent: "cli".to_owned(),
        agents: BTreeMap::from([(
            "cli".to_owned(),
            AgentProfile {
                allowed_paths: vec!["*".to_owned()],
                can_write: true,
                require_approval: false,
                ..AgentProfile::default()
            },
        )]),
        vault: Some(VaultConfig {
            search_index: true,
            auto_heal_zero_key: true,
            ..VaultConfig::default()
        }),
        git: Some(GitConfig {
            auto_push: true,
            auto_pull: false,
            auto_pull_interval: std::time::Duration::ZERO,
            commit_template: "Update from Symaira Vault".to_owned(),
            author: String::new(),
            email: String::new(),
        }),
        ..Config::default()
    };
    let config_bytes = config
        .to_yaml_bytes()
        .map_err(|error| format!("marshal config: {error}"))?;
    safeio::write_atomic(&root.join("config.yaml"), &config_bytes)
        .map_err(|error| format!("write config: {error}"))?;

    let identity = generate_identity();
    let encrypted = encrypt_identity_argon2id(&identity, passphrase, Argon2idParams::default())
        .map_err(|error| format!("save identity: {error}"))?;
    if let Err(error) = safeio::write_atomic(&root.join("identity.age"), &encrypted) {
        let _ = std::fs::remove_file(root.join("config.yaml"));
        let _ = std::fs::remove_dir(root.join("entries"));
        return Err(format!("save identity: {error}"));
    }
    // A vault Rust creates needs no pre-migration backup (D1).
    symvault_store::data_safety::mark_created(root)
        .map_err(|error| format!("write rust marker: {error}"))?;
    Ok(identity)
}

/// Lists entry metadata, optionally restricted to a path prefix.
pub fn list(root: &Path, identity: &Identity, prefix: &str) -> Result<Vec<ListEntryInfo>, String> {
    let store = open_vault(root, identity)?;
    let reader = store.read_session(identity);
    let paths = reader
        .list()
        .map_err(|error| format!("cannot list entries: {error}"))?;
    paths
        .into_iter()
        .filter(|path| prefix.is_empty() || path.starts_with(prefix))
        .map(|path| {
            let info = match reader.get(&path) {
                Ok(entry) => {
                    let has_value = has_value(&entry);
                    let field_count = entry.data.len();
                    ListEntryInfo {
                        path,
                        secret_type: entry.secret_metadata.secret_type,
                        usage_hint: entry.secret_metadata.usage_hint,
                        auto_rotate: entry.secret_metadata.auto_rotate,
                        has_value,
                        field_count,
                    }
                }
                Err(error) if error.is_resource_failure() => return Err(error.to_string()),
                Err(_) => ListEntryInfo {
                    path,
                    secret_type: String::new(),
                    usage_hint: String::new(),
                    auto_rotate: false,
                    has_value: false,
                    field_count: 0,
                },
            };
            Ok(info)
        })
        .collect()
}

fn has_value(entry: &Entry) -> bool {
    ["password", "secret"]
        .into_iter()
        .any(|field| entry.data.get(field).is_some_and(|value| !value.is_null()))
}

/// Why `get` could not resolve a query to one entry or field.
#[derive(Debug, Eq, PartialEq)]
pub enum GetError {
    /// No entry has this path and the search fallback found nothing.
    NotFound(String),
    /// The search fallback found several entries; `paths` is Go's match order.
    Ambiguous { query: String, paths: Vec<String> },
    /// The store refused the path itself (empty, `..`, absolute, ...).
    InvalidPath(String),
    /// Any other failure, already worded for the user.
    Other(String),
}

impl std::fmt::Display for GetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(path) => write!(formatter, "entry not found: {path}"),
            Self::Ambiguous { query, .. } => write!(formatter, "ambiguous path: {query}"),
            Self::InvalidPath(path) => write!(formatter, "entry path {path:?} is not valid"),
            Self::Other(message) => formatter.write_str(message),
        }
    }
}

impl From<GetError> for String {
    fn from(error: GetError) -> Self {
        error.to_string()
    }
}

/// Go's `GetField(candidatePath, candidateField)` probe of `get`: the query is
/// split at its last dot (not at the first byte) and only counts as
/// `path.field` when that entry exists and holds the field (an empty field
/// names the whole entry). `None` means the query is not an exact
/// `path.field`; the caller then treats it as a path.
pub fn exact_field_with(
    reader: &symvault_store::ReadSession<'_>,
    query: &str,
) -> Result<Option<GetResult>, String> {
    let Some(index) = query.rfind('.').filter(|index| *index > 0) else {
        return Ok(None);
    };
    let (path, field) = (&query[..index], &query[index + 1..]);
    match reader.get(path) {
        Ok(entry) => {
            if field.is_empty() {
                return Ok(Some(GetResult::Entry {
                    path: path.to_owned(),
                    entry: Box::new(entry),
                }));
            }
            Ok(entry
                .data
                .get(field)
                .cloned()
                .map(|value| GetResult::Field {
                    path: path.to_owned(),
                    field: field.to_owned(),
                    value,
                }))
        }
        Err(error) if error.is_resource_failure() => Err(error.to_string()),
        Err(_) => Ok(None),
    }
}

/// [`exact_field_with`] on a freshly opened vault.
// The integration tests include this file without the binary that calls it.
#[allow(dead_code)]
pub fn exact_field(
    root: &Path,
    identity: &Identity,
    query: &str,
) -> Result<Option<GetResult>, String> {
    let store = open_vault(root, identity)?;
    let reader = store.read_session(identity);
    exact_field_with(&reader, query)
}

/// Resolves a `path.field` query or an exact entry path. A miss is
/// [`GetError::NotFound`]; `search_commands::get_or_search` adds Go's substring
/// search fallback on top of it.
pub fn get(root: &Path, identity: &Identity, query: &str) -> Result<GetResult, GetError> {
    let store = open_vault(root, identity).map_err(GetError::Other)?;
    let reader = store.read_session(identity);
    if let Some(result) = exact_field_with(&reader, query).map_err(GetError::Other)? {
        return Ok(result);
    }
    read_exact(&reader, query)
}

/// Reads the entry stored at exactly `path`, without the `path.field` split.
// The integration tests include this file without the binary that calls it.
#[allow(dead_code)]
pub fn get_exact(root: &Path, identity: &Identity, path: &str) -> Result<GetResult, GetError> {
    let store = open_vault(root, identity).map_err(GetError::Other)?;
    let reader = store.read_session(identity);
    read_exact(&reader, path)
}

fn read_exact(reader: &symvault_store::ReadSession<'_>, path: &str) -> Result<GetResult, GetError> {
    match reader.get(path) {
        Ok(entry) => Ok(GetResult::Entry {
            path: path.to_owned(),
            entry: Box::new(entry),
        }),
        Err(error) if error.is_resource_failure() => Err(GetError::Other(error.to_string())),
        Err(symvault_store::StoreError::EntryNotFound(_)) => {
            Err(GetError::NotFound(path.to_owned()))
        }
        Err(symvault_store::StoreError::InvalidEntryPath(invalid)) => {
            Err(GetError::InvalidPath(invalid))
        }
        Err(error) => Err(GetError::Other(format!("cannot read entry: {error}"))),
    }
}

/// Writes list output in the format selected by the dispatcher.
pub fn write_list<W: Write>(
    output: &mut W,
    entries: &[ListEntryInfo],
    format: &str,
    quiet: bool,
) -> Result<(), String> {
    if quiet {
        return Ok(());
    }
    match format {
        "text" | "" => entries.iter().try_for_each(|entry| {
            writeln!(output, "{}", entry.path).map_err(|error| error.to_string())
        }),
        "json" => {
            // Go marshals the nil slice of an empty listing as `null`.
            if entries.is_empty() {
                output
                    .write_all(b"null")
                    .map_err(|error| error.to_string())?;
            } else {
                serde_json::to_writer(&mut *output, entries).map_err(|error| error.to_string())?;
            }
            writeln!(output).map_err(|error| error.to_string())
        }
        "yaml" => {
            // yaml.v3 marshals the struct with lower-cased field names and no
            // omitempty, so every field is present.
            let node = Node::Seq(
                entries
                    .iter()
                    .map(|entry| {
                        Node::Map(vec![
                            ("path".to_owned(), Node::Str(entry.path.clone())),
                            ("type".to_owned(), Node::Str(entry.secret_type.clone())),
                            ("usagehint".to_owned(), Node::Str(entry.usage_hint.clone())),
                            ("autorotate".to_owned(), Node::Bool(entry.auto_rotate)),
                            ("hasvalue".to_owned(), Node::Bool(entry.has_value)),
                            (
                                "fieldcount".to_owned(),
                                Node::Int(i64::try_from(entry.field_count).unwrap_or(i64::MAX)),
                            ),
                        ])
                    })
                    .collect(),
            );
            output
                .write_all(yaml::to_string(&node).as_bytes())
                .map_err(|error| error.to_string())
        }
        other => Err(format!(
            "unknown output format: {other:?} (valid: text, json, yaml)"
        )),
    }
}

/// Writes get output. Field reads never print surrounding entry metadata.
#[cfg(test)]
#[allow(dead_code)] // Used by integration tests that include this module.
pub fn write_get<W: Write>(
    output: &mut W,
    result: &GetResult,
    format: &str,
    quiet: bool,
) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs() as i64;
    let mut diagnostics = io::sink();
    write_get_at(output, &mut diagnostics, result, format, quiet, now)
}

/// Writes get output at a fixed Unix timestamp for deterministic contract tests.
///
/// `diagnostics` receives the text-mode TOTP status or warning that Go writes to
/// stderr. Structured output contains the generated TOTP object and does not
/// write diagnostics.
pub fn write_get_at<W: Write, E: Write>(
    output: &mut W,
    diagnostics: &mut E,
    result: &GetResult,
    format: &str,
    quiet: bool,
    unix_time: i64,
) -> Result<(), String> {
    match result {
        GetResult::Field { value, .. } => match format {
            _ if quiet => Ok(()),
            "text" | "" => writeln!(output, "{}", value_text(value)).map_err(|e| e.to_string()),
            "json" => {
                serde_json::to_writer(&mut *output, value).map_err(|e| e.to_string())?;
                writeln!(output).map_err(|e| e.to_string())
            }
            "yaml" => output
                .write_all(yaml::to_string(&Node::from_json(value)).as_bytes())
                .map_err(|e| e.to_string()),
            other => Err(format!(
                "unknown output format: {other:?} (valid: text, json, yaml)"
            )),
        },
        GetResult::Entry { path, entry } => match format {
            "text" | "" => {
                if !quiet {
                    write_entry_text(output, path, entry)?;
                }
                match entry_totp(entry, unix_time) {
                    Ok(Some(totp)) => writeln!(
                        diagnostics,
                        "TOTP Code: {} (expires in {}s)",
                        totp.code, totp.remaining
                    )
                    .map_err(|error| error.to_string()),
                    Ok(None) => Ok(()),
                    Err(_error) if quiet => Ok(()),
                    Err(error) => writeln!(
                        diagnostics,
                        "Warning: could not generate TOTP code: {error}"
                    )
                    .map_err(|error| error.to_string()),
                }
            }
            "json" => {
                if quiet {
                    return Ok(());
                }
                let value = GetEntryOutput {
                    fields: &entry.data,
                    totp: entry_totp(entry, unix_time).ok().flatten(),
                    path,
                    modified: modified_text(&entry.metadata.updated),
                };
                serde_json::to_writer(&mut *output, &value).map_err(|e| e.to_string())?;
                writeln!(output).map_err(|e| e.to_string())
            }
            "yaml" => {
                if quiet {
                    return Ok(());
                }
                let totp = match entry_totp(entry, unix_time).ok().flatten() {
                    Some(totp) => Node::Map(vec![
                        ("code".to_owned(), Node::Str(totp.code)),
                        ("period".to_owned(), Node::Int(totp.period)),
                        ("remaining".to_owned(), Node::Int(totp.remaining)),
                    ]),
                    None => Node::Null,
                };
                let node = Node::Map(vec![
                    (
                        "fields".to_owned(),
                        Node::Map(
                            entry
                                .data
                                .iter()
                                .map(|(name, value)| (name.clone(), Node::from_json(value)))
                                .collect(),
                        ),
                    ),
                    ("totp".to_owned(), totp),
                    ("path".to_owned(), Node::Str(path.clone())),
                    (
                        "modified".to_owned(),
                        Node::Str(modified_text(&entry.metadata.updated)),
                    ),
                ]);
                output
                    .write_all(yaml::to_string(&node).as_bytes())
                    .map_err(|e| e.to_string())
            }
            other => Err(format!(
                "unknown output format: {other:?} (valid: text, json, yaml)"
            )),
        },
    }
}

fn entry_totp(entry: &Entry, unix_time: i64) -> Result<Option<TotpOutput>, String> {
    let Some(serde_json::Value::Object(totp)) = entry.data.get("totp") else {
        return Ok(None);
    };
    let Some(secret) = totp.get("secret").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    if secret.is_empty() {
        return Ok(None);
    }
    let algorithm = totp
        .get("algorithm")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("SHA1");
    let digits = json_integer(totp.get("digits")).unwrap_or(6);
    let period = json_integer(totp.get("period")).unwrap_or(30);
    let code = symvault_core::totp::generate_totp_at(secret, algorithm, digits, period, unix_time)
        .map_err(|error| error.to_string())?;
    let period = i64::from(code.period);
    let remaining = period - unix_time.rem_euclid(period);
    Ok(Some(TotpOutput {
        code: code.code,
        period,
        remaining,
    }))
}

fn json_integer(value: Option<&serde_json::Value>) -> Option<i32> {
    value
        .and_then(serde_json::Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .or_else(|| {
            value
                .and_then(serde_json::Value::as_f64)
                .map(|value| value as i32)
        })
}

fn value_text(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

fn modified_text(value: &str) -> String {
    value
        .get(..16)
        .map_or_else(|| value.to_owned(), |prefix| prefix.replace('T', " "))
}

fn write_entry_text<W: Write>(output: &mut W, path: &str, entry: &Entry) -> Result<(), String> {
    writeln!(output, "Path: {path}").map_err(|e| e.to_string())?;
    writeln!(
        output,
        "Modified: {}",
        modified_text(&entry.metadata.updated)
    )
    .map_err(|e| e.to_string())?;
    writeln!(output).map_err(|e| e.to_string())?;
    for (field, value) in &entry.data {
        writeln!(output, "{field}: {}", value_text(value)).map_err(|e| e.to_string())?;
    }
    Ok(())
}
