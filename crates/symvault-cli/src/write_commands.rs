//! CLI entry mutations using the existing encrypted store and Git adapter.
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};
use symvault_core::{config::Config, password};
use symvault_crypto::Identity;
use symvault_store::{Entry, Store, StoreError, WriteRecord};
use symvault_sync::{CommitOptions, GitRepository, GoTime};

pub fn sensitive_field(field: &str) -> bool {
    let lower = field.to_lowercase();
    ["password", "token", "secret", "key", "passwd", "pwd"]
        .iter()
        .any(|part| lower.contains(part))
}

pub fn set_value(
    root: &Path,
    identity: &Identity,
    query: &str,
    value: String,
    allow_empty: bool,
    force: bool,
) -> Result<String, String> {
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
    set_fields(
        root,
        identity,
        path,
        BTreeMap::from([(field.to_owned(), Value::String(value))]),
    )?;
    Ok(path.to_owned())
}

pub fn set_fields(
    root: &Path,
    identity: &Identity,
    path: &str,
    data: BTreeMap<String, Value>,
) -> Result<(), String> {
    write_fields(root, identity, path, data, false, "set")
}

pub fn import_fields(
    root: &Path,
    identity: &Identity,
    path: &str,
    data: BTreeMap<String, Value>,
) -> Result<(), String> {
    write_fields(root, identity, path, data, false, "import")
}

pub fn replace_fields(
    root: &Path,
    identity: &Identity,
    path: &str,
    data: BTreeMap<String, Value>,
) -> Result<(), String> {
    write_fields(root, identity, path, data, true, "import")
}

pub fn set_secret_type(
    root: &Path,
    identity: &Identity,
    path: &str,
    secret_type: &str,
) -> Result<(), String> {
    let store = Store::open(root, identity).map_err(|error| error.to_string())?;
    let mut entry = store
        .get(path, identity)
        .map_err(|error| format!("cannot read entry {path}: {error}"))?;
    entry.secret_metadata.secret_type = secret_type.to_owned();
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
    replace: bool,
    action: &str,
) -> Result<(), String> {
    fn validate(key: &str, value: &Value) -> Result<(), String> {
        match value {
            Value::String(text) if text.len() > 4096 => {
                return Err(format!(
                    "field {key:?} exceeds maximum length of 4096 characters"
                ));
            }
            Value::Object(map) => {
                for (key, value) in map {
                    validate(key, value)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    for (key, value) in &data {
        validate(key, value)?;
    }
    let store = Store::open(root, identity).map_err(|error| error.to_string())?;
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
    let store = Store::open(root, identity).map_err(|error| error.to_string())?;
    store
        .delete_entry_with_identity(path, identity)
        .map_err(|error| error.to_string())?;
    auto_commit(&store, identity, path, "Delete");
    Ok(())
}

fn auto_commit(store: &Store, identity: &Identity, path: &str, action: &str) {
    let result = (|| {
        let entry_path = store
            .configured_entry_path(path, identity)
            .map_err(|error| error.to_string())?;
        let relative = entry_path
            .strip_prefix(store.root())
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        let repo = GitRepository::open(store.root()).map_err(|error| error.to_string())?;
        repo.commit(CommitOptions {
            message: format!("{action} {path}"),
            affected_paths: vec![relative, "manifest.age".into()],
            ..CommitOptions::default()
        })
        .map_err(|error| error.to_string())?;
        let config =
            Config::load(store.root().join("config.yaml")).map_err(|error| error.to_string())?;
        if config.git.is_some_and(|git| git.auto_push) {
            let result = repo.push("origin");
            if let Some(error) = result.error {
                return Err(error);
            }
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        eprintln!("Warning: auto-commit failed: {error}");
    }
}
