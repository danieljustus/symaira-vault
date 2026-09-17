//! Native `find`/`search` command adapter.
//!
//! The encrypted search index remains the value-search implementation.  This
//! module only joins its path candidates with decrypted field names and the
//! URL host filter required by the Go command contract.

use std::{collections::BTreeSet, path::Path};

use serde::Serialize;
use symvault_crypto::Identity;
use symvault_store::{Entry, Store, search_index_store::SearchIndexStore};
use url::Url;

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct SearchMatch {
    pub path: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

/// Search paths and decrypted fields using the shared persistent index.
pub fn find(
    root: &Path,
    identity: &Identity,
    query: &str,
    url_filter: Option<&str>,
) -> Result<Vec<SearchMatch>, String> {
    let store =
        Store::open(root, identity).map_err(|error| format!("cannot open vault: {error}"))?;
    let mut paths = store
        .list(identity)
        .map_err(|error| format!("cannot list entries: {error}"))?;

    let normalized_url = url_filter
        .filter(|value| !value.is_empty())
        .map(normalize_host)
        .transpose()?;
    if let Some(host) = normalized_url.as_deref() {
        paths.retain(|path| {
            store
                .get(path, identity)
                .ok()
                .is_some_and(|entry| entry_has_host(&entry, host))
        });
    }

    if query.is_empty() && normalized_url.is_some() {
        return Ok(paths
            .into_iter()
            .map(|path| SearchMatch {
                path,
                fields: vec!["url".to_owned()],
            })
            .collect());
    }

    let needle = query.to_ascii_lowercase();
    let path_matches: BTreeSet<_> = paths
        .iter()
        .filter(|path| path.to_ascii_lowercase().contains(&needle))
        .cloned()
        .collect();

    let indexed_paths = if needle.is_empty() {
        BTreeSet::new()
    } else {
        let indexes = SearchIndexStore::new();
        let loaded = matches!(indexes.load(&store, identity), Ok(true));
        let ready = loaded || indexes.build(&store, identity).is_ok();
        if ready {
            indexes
                .search(&store, &paths, &needle)
                .unwrap_or_else(|_| paths.iter().cloned().collect())
        } else {
            // The Go implementation falls back to decrypting all candidates
            // when its encrypted index is absent or stale.
            paths.iter().cloned().collect()
        }
    };

    let mut field_matches = Vec::new();
    for path in paths {
        if path_matches.contains(&path) || !indexed_paths.contains(&path) {
            continue;
        }
        let entry = store
            .get(&path, identity)
            .map_err(|error| format!("search entry {path}: {error}"))?;
        let mut fields = Vec::new();
        for (field, value) in &entry.data {
            collect_field_matches(value, field, &needle, &mut fields);
        }
        fields.sort();
        fields.dedup();
        if !fields.is_empty() {
            field_matches.push(SearchMatch { path, fields });
        }
    }

    let mut result: Vec<_> = path_matches
        .into_iter()
        .map(|path| SearchMatch {
            path,
            fields: vec!["path".to_owned()],
        })
        .collect();
    result.extend(field_matches);
    result.sort_by(|left, right| {
        let left_path = left.fields == ["path"];
        let right_path = right.fields == ["path"];
        right_path
            .cmp(&left_path)
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(result)
}

fn collect_field_matches(
    value: &serde_json::Value,
    prefix: &str,
    needle: &str,
    fields: &mut Vec<String>,
) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                let field = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                collect_field_matches(child, &field, needle, fields);
            }
        }
        serde_json::Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                let field = format!("{prefix}[{index}]");
                collect_field_matches(child, &field, needle, fields);
            }
        }
        serde_json::Value::String(text) if !prefix.is_empty() => {
            if text.to_ascii_lowercase().contains(needle) {
                fields.push(prefix.to_owned());
            }
        }
        serde_json::Value::Number(number) if !prefix.is_empty() => {
            if number.to_string().to_ascii_lowercase().contains(needle) {
                fields.push(prefix.to_owned());
            }
        }
        serde_json::Value::Bool(value) if !prefix.is_empty() => {
            if value.to_string().contains(needle) {
                fields.push(prefix.to_owned());
            }
        }
        serde_json::Value::Null => {}
        _ => {}
    }
}

fn entry_has_host(entry: &Entry, target: &str) -> bool {
    let Some(value) = entry.data.get("url") else {
        return false;
    };
    match value {
        serde_json::Value::String(value) => normalize_host(value).is_ok_and(|host| host == target),
        serde_json::Value::Array(values) => values.iter().any(|value| {
            value
                .as_str()
                .and_then(|value| normalize_host(value).ok())
                .is_some_and(|host| host == target)
        }),
        _ => false,
    }
}

fn normalize_host(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return Err(format!(
            "invalid url {raw:?}: host is empty or contains whitespace"
        ));
    }
    let parsed = if trimmed.contains("://") {
        Url::parse(trimmed)
    } else if trimmed.starts_with("//") {
        Url::parse(&format!("https:{trimmed}"))
    } else {
        Url::parse(&format!("https://{trimmed}"))
    }
    .map_err(|error| format!("invalid url {raw:?}: {error}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("invalid url {raw:?}: missing host"))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err(format!("invalid url {raw:?}: empty hostname"));
    }
    let port = parsed.port();
    let is_default_port = matches!(
        (parsed.scheme(), port),
        ("http", Some(80)) | ("https", Some(443))
    );
    if is_default_port || port.is_none() {
        return Ok(host);
    }
    if host.contains(':') {
        Ok(format!("[{host}]:{}", port.expect("checked above")))
    } else {
        Ok(format!("{host}:{}", port.expect("checked above")))
    }
}
