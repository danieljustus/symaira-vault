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
    Store::open(root, identity).map_err(|error| format!("cannot open vault: {error}"))
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
    Ok(identity)
}

/// Lists entry metadata, optionally restricted to a path prefix.
pub fn list(root: &Path, identity: &Identity, prefix: &str) -> Result<Vec<ListEntryInfo>, String> {
    let store = open_vault(root, identity)?;
    let paths = store
        .list(identity)
        .map_err(|error| format!("cannot list entries: {error}"))?;
    paths
        .into_iter()
        .filter(|path| prefix.is_empty() || path.starts_with(prefix))
        .map(|path| {
            let info = match store.get(&path, identity) {
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

/// Resolves an exact path or `path.field` query.
pub fn get(root: &Path, identity: &Identity, query: &str) -> Result<GetResult, String> {
    let store = open_vault(root, identity)?;
    if let Some((path, field)) = query
        .rsplit_once('.')
        .filter(|(_, field)| !field.is_empty())
        && let Ok(entry) = store.get(path, identity)
        && let Some(value) = entry.data.get(field).cloned()
    {
        return Ok(GetResult::Field {
            path: path.to_owned(),
            field: field.to_owned(),
            value,
        });
    }
    let exact_error = match store.get(query, identity) {
        Ok(entry) => {
            return Ok(GetResult::Entry {
                path: query.to_owned(),
                entry: Box::new(entry),
            });
        }
        Err(error) => error,
    };

    let needle = query.to_ascii_lowercase();
    let matches: Vec<_> = store
        .list(identity)
        .map_err(|error| format!("cannot read entry: {error}"))?
        .into_iter()
        .filter(|path| path.to_ascii_lowercase().contains(&needle))
        .collect();
    match matches.as_slice() {
        [path] => {
            let entry = store
                .get(path, identity)
                .map_err(|error| format!("cannot read entry: {error}"))?;
            Ok(GetResult::Entry {
                path: path.clone(),
                entry: Box::new(entry),
            })
        }
        [] => Err(format!("cannot read entry: {exact_error}")),
        _ => Err(format!("ambiguous path: {query}")),
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
            serde_json::to_writer(&mut *output, entries).map_err(|error| error.to_string())?;
            writeln!(output).map_err(|error| error.to_string())
        }
        other => Err(format!(
            "unknown output format: {other:?} (valid: text, json)"
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
            other => Err(format!(
                "unknown output format: {other:?} (valid: text, json)"
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
