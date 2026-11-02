//! CLI entry mutations using the existing encrypted store and Git adapter.
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};
use symvault_core::{password, totp};
use symvault_crypto::Identity;
use symvault_store::{Entry, SecretMetadata, SecretType, Store, StoreError, WriteRecord};
use symvault_sync::GoTime;

pub fn sensitive_field(field: &str) -> bool {
    let lower = field.to_lowercase();
    ["password", "token", "secret", "key", "passwd", "pwd"]
        .iter()
        .any(|part| lower.contains(part))
}

#[allow(clippy::too_many_arguments)]
pub fn set_entry(
    root: &Path,
    identity: &Identity,
    query: &str,
    value: String,
    allow_empty: bool,
    force: bool,
    totp_secret: Option<&str>,
    totp_issuer: Option<&str>,
    totp_account: Option<&str>,
) -> Result<String, String> {
    let (path, data) = set_entry_data(
        query,
        value,
        allow_empty,
        force,
        totp_secret,
        totp_issuer,
        totp_account,
    )?;
    set_fields(root, identity, &path, data)?;
    Ok(path)
}

/// Validates a `set` request and builds the fields it writes, without
/// touching the vault: Go runs every one of these checks before `WithVault`
/// resolves and unlocks it (cmd/crud/set.go).
pub fn set_entry_data(
    query: &str,
    value: String,
    allow_empty: bool,
    force: bool,
    totp_secret: Option<&str>,
    totp_issuer: Option<&str>,
    totp_account: Option<&str>,
) -> Result<(String, BTreeMap<String, Value>), String> {
    let (path, field) = query
        .rsplit_once('.')
        .filter(|(path, _)| !path.is_empty())
        .unwrap_or((query, "password"));
    let field = if field.is_empty() { "password" } else { field };
    if value.is_empty() && sensitive_field(field) && !allow_empty {
        return Err(format!(
            "cannot set empty value for sensitive field {field:?} (use --allow-empty to override)"
        ));
    }
    if !force && field == "password" && !value.is_empty() {
        password::validate_password_strength(&value)?;
    }
    let mut data = BTreeMap::from([(field.to_owned(), Value::String(value))]);
    if let Some(secret) = totp_secret
        && !secret.is_empty()
    {
        totp::validate_totp_secret(secret).map_err(|error| error.to_string())?;
        let mut totp_data = serde_json::Map::new();
        totp_data.insert("secret".to_owned(), Value::String(secret.to_owned()));
        if let Some(issuer) = totp_issuer
            && !issuer.is_empty()
        {
            totp_data.insert("issuer".to_owned(), Value::String(issuer.to_owned()));
        }
        if let Some(account) = totp_account
            && !account.is_empty()
        {
            totp_data.insert("account_name".to_owned(), Value::String(account.to_owned()));
        }
        data.insert("totp".to_owned(), Value::Object(totp_data));
    }
    Ok((path.to_owned(), data))
}

#[allow(dead_code)]
pub fn set_value(
    root: &Path,
    identity: &Identity,
    query: &str,
    value: String,
    allow_empty: bool,
    force: bool,
) -> Result<String, String> {
    set_entry(
        root,
        identity,
        query,
        value,
        allow_empty,
        force,
        None,
        None,
        None,
    )
}

pub fn set_fields(
    root: &Path,
    identity: &Identity,
    path: &str,
    data: BTreeMap<String, Value>,
) -> Result<(), String> {
    write_fields(root, identity, path, data, &BTreeMap::new(), false, "set")
}

/// Imports one entry. `raw_lengths` holds the exact Go byte length of the
/// string values whose stored text differs in length (Go's field limit counts
/// the bytes of the imported string, not of its JSON text).
pub fn import_fields(
    root: &Path,
    identity: &Identity,
    path: &str,
    data: BTreeMap<String, Value>,
    raw_lengths: &BTreeMap<String, usize>,
) -> Result<(), String> {
    write_fields(root, identity, path, data, raw_lengths, false, "import")
}

pub fn replace_fields(
    root: &Path,
    identity: &Identity,
    path: &str,
    data: BTreeMap<String, Value>,
    raw_lengths: &BTreeMap<String, usize>,
) -> Result<(), String> {
    write_fields(root, identity, path, data, raw_lengths, true, "import")
}

/// Go's `ValidateFieldLengths`: no string value may exceed 4096 bytes, nested
/// objects included. `raw_lengths` overrides the length of a top-level string
/// whose Go byte string was longer or shorter than its stored text.
pub fn validate_field_lengths(
    data: &BTreeMap<String, Value>,
    raw_lengths: &BTreeMap<String, usize>,
) -> Result<(), String> {
    fn validate(key: &str, value: &Value, raw: Option<usize>) -> Result<(), String> {
        match value {
            Value::String(text) if raw.unwrap_or(text.len()) > 4096 => {
                return Err(format!(
                    "field {} exceeds maximum length of 4096 characters",
                    symvault_core::go_quote(key)
                ));
            }
            Value::Object(map) => {
                for (key, value) in map {
                    validate(key, value, None)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    for (key, value) in data {
        validate(key, value, raw_lengths.get(key).copied())?;
    }
    Ok(())
}

pub fn set_secret_type(
    root: &Path,
    identity: &Identity,
    path: &str,
    secret_type: &str,
) -> Result<(), String> {
    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| error.to_string())?;
    let mut entry = store
        .get(path, identity)
        .map_err(|error| format!("cannot read entry {path}: {error}"))?;
    // Go's SetSecretMetadata replaces the whole metadata with the importer's
    // type and the type's usage hint.
    entry.secret_metadata = SecretMetadata {
        secret_type: secret_type.to_owned(),
        usage_hint: SecretType::from_name(secret_type)
            .map_or("", SecretType::usage_hint)
            .to_owned(),
        ..SecretMetadata::default()
    };
    store
        .write_entry_with_recipients_at(
            path,
            &entry,
            identity,
            &GoTime::now().to_rfc3339_nano(),
            None,
        )
        .map_err(|error| error.to_string())?;
    auto_commit(&store, identity, path, "Update");
    Ok(())
}

fn write_fields(
    root: &Path,
    identity: &Identity,
    path: &str,
    data: BTreeMap<String, Value>,
    raw_lengths: &BTreeMap<String, usize>,
    replace: bool,
    action: &str,
) -> Result<(), String> {
    validate_field_lengths(&data, raw_lengths)?;
    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| error.to_string())?;
    let (mut entry, new) = if replace {
        (Entry::default(), true)
    } else {
        match store.get(path, identity) {
            Ok(entry) => (entry, false),
            Err(StoreError::EntryNotFound(_)) => (Entry::default(), true),
            Err(error) => return Err(format!("cannot read entry {path}: {error}")),
        }
    };
    if let Some(Value::String(value)) = data.get("password") {
        entry.metadata.tags.retain(|tag| tag != "weak-password");
        if !value.is_empty() && password::assess_password_strength(value).weak {
            entry.metadata.tags.push("weak-password".into());
        }
    }
    fn merge(target: &mut Value, source: Value) {
        match (target, source) {
            (Value::Object(target), Value::Object(source)) => {
                for (key, value) in source {
                    merge(target.entry(key).or_insert(Value::Null), value);
                }
            }
            (target, source) => *target = source,
        }
    }
    let record = WriteRecord {
        action: action.into(),
        field: if data.len() == 1 {
            data.keys().next().unwrap().clone()
        } else {
            String::new()
        },
        ..WriteRecord::default()
    };
    for (key, value) in data {
        merge(entry.data.entry(key).or_insert(Value::Null), value);
    }
    // Go's existing-entry merge rereads the entry, dropping the pending write record.
    store
        .write_entry_with_recipients_at(
            path,
            &entry,
            identity,
            &GoTime::now().to_rfc3339_nano(),
            new.then_some(&record),
        )
        .map_err(|error| error.to_string())?;
    auto_commit(&store, identity, path, "Update");
    Ok(())
}

pub fn delete(root: &Path, identity: &Identity, path: &str) -> Result<(), String> {
    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| error.to_string())?;
    store
        .delete_entry_with_identity(path, identity)
        .map_err(|error| error.to_string())?;
    auto_commit(&store, identity, path, "Delete");
    Ok(())
}

pub(crate) fn auto_commit(store: &Store, identity: &Identity, path: &str, action: &str) {
    if let Err(error) = symvault_sync::auto_commit_entry(store, identity, path, action) {
        eprintln!("Warning: auto-commit failed: {error}");
    }
}
