//! Built-in template CLI; custom Go text/template execution remains unavailable.
use std::{collections::BTreeMap, path::Path};
use symvault_crypto::Identity;
use symvault_store::Store;

pub fn generate(
    root: &Path,
    identity: &Identity,
    kind: &str,
    name: &str,
    prefix: &str,
    args: &[String],
    dry_run: bool,
) -> Result<String, String> {
    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| error.to_string())?;
    let mut refs = BTreeMap::new();
    if !prefix.is_empty() {
        for path in store.list(identity).map_err(|error| error.to_string())? {
            if !path.starts_with(prefix) {
                continue;
            }
            let entry = store
                .get(&path, identity)
                .map_err(|error| format!("read entry {path:?}: {error}"))?;
            for field in entry.data.keys() {
                let basename = path.rsplit('/').next().unwrap_or(&path);
                refs.insert(format!("{basename}.{field}"), format!("{path}.{field}"));
            }
        }
    }
    for arg in args {
        let (key, value) = arg
            .split_once('=')
            .ok_or_else(|| format!("invalid ref format: {arg:?} (expected KEY=path[.field])"))?;
        if key.is_empty() || value.is_empty() {
            return Err(format!("empty key or ref in: {arg:?}"));
        }
        refs.insert(key.to_owned(), value.to_owned());
    }
    if refs.is_empty() {
        return Err(
            "no secret references provided: use positional KEY=ref arguments or --prefix"
                .to_owned(),
        );
    }
    // Do not silently substitute a built-in when the user configured an override.
    if let Some(home) = std::env::var_os("HOME") {
        let custom = Path::new(&home).join(".config/symvault/templates");
        if std::fs::read_dir(custom).is_ok_and(|entries| {
            entries
                .flatten()
                .any(|entry| entry.file_name().to_str() == Some(&format!("{kind}.tmpl")))
        }) {
            return Err("custom Go templates are not yet supported by the Rust runtime".to_owned());
        }
    }
    // Match Go's template lookup before resolving secret references.
    symvault_sync::template::render_builtin(kind, name, &BTreeMap::new())
        .map_err(|error| format!("render template: {error}"))?;
    let mut values = BTreeMap::new();
    for (alias, reference) in refs {
        let value = if dry_run {
            "***".to_owned()
        } else {
            resolve(&store, identity, &reference)
                .map_err(|error| format!("render template: resolve ref {alias:?}: {error}"))?
        };
        values.insert(alias, value);
    }
    symvault_sync::template::render_builtin(kind, name, &values)
        .map_err(|error| format!("render template: {error}"))
}

fn resolve(store: &Store, identity: &Identity, reference: &str) -> Result<String, String> {
    let (path, field) = if reference.is_empty() {
        return Err("invalid secret reference: empty reference".to_owned());
    } else if let Some(rest) = reference.strip_prefix("op://") {
        rest.rsplit_once('/')
            .filter(|(_, field)| !field.is_empty())
            .ok_or_else(|| {
                format!("invalid secret reference: missing field in op:// reference: {reference}")
            })?
    } else {
        reference.rsplit_once('.').filter(|(path, field)| !path.is_empty() && !field.is_empty()).ok_or_else(|| format!("invalid secret reference: expected path.field or op://path/field syntax, got: {reference}"))?
    };
    let entry = store
        .get(path, identity)
        .map_err(|error| format!("resolve ref {reference:?}: {error}"))?;
    let value = entry
        .data
        .get(field)
        .ok_or_else(|| format!("resolve ref {reference:?}: field {field:?} not found"))?;
    match value {
        serde_json::Value::Null => Err("resolved value is nil".to_owned()),
        serde_json::Value::String(value) => Ok(value.clone()),
        // Complex fmt.Sprintf("%v") values need their own parity contract.
        _ => Err(
            "non-string template references are not yet supported by the Rust runtime".to_owned(),
        ),
    }
}
