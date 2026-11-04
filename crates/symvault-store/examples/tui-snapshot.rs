#![deny(unsafe_code)]

//! Read-only vault snapshotter for the native TUI contract (`tui_contract.py`).
//!
//! Reproduces what the former Go fixture helper's `--snapshot` mode printed: one row per
//! entry (`path`, `data_sha256` of the Go-style JSON of the entry data, `tags`, `version`),
//! and with `--config-receipt` the clipboard duration the vault's configuration carries.
//! It never writes below `--root` and reads only the files the vault itself owns.

use std::{env, fs, path::PathBuf, process};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use symvault_core::config::Config;
use symvault_crypto::{SecretBytes, decrypt_identity};
use symvault_store::Store;

const PASSPHRASE: &[u8] = b"public-tui-passphrase-782a";

fn argument(args: &[String], name: &str) -> Option<String> {
    let index = args.iter().position(|arg| arg == name)?;
    args.get(index + 1).cloned()
}

/// `json.Marshal` escapes `<`, `>`, `&`, U+2028 and U+2029 inside strings.
fn go_escape(compact: &str) -> String {
    let mut out = String::with_capacity(compact.len());
    for ch in compact.chars() {
        match ch {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out
}

fn clipboard_seconds(root: &std::path::Path) -> Result<i64, String> {
    let config = Config::load(root.join("config.yaml")).map_err(|error| error.to_string())?;
    // `Config::load` of a configuration without a clipboard section is the default (30).
    Ok(config.clipboard.map_or(30, |clipboard| clipboard.auto_clear_duration))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let root = PathBuf::from(argument(&args, "--root").ok_or("missing --root")?);
    let identity_file = fs::read(root.join("identity.age")).map_err(|error| error.to_string())?;
    let identity = decrypt_identity(&identity_file, &SecretBytes::new(PASSPHRASE))
        .map_err(|error| error.to_string())?;
    let store = Store::open(&root, &identity).map_err(|error| error.to_string())?;
    if let Some(receipt) = argument(&args, "--config-receipt") {
        let seconds = clipboard_seconds(&root)?;
        let document = json!({
            "vault_clipboard_seconds": seconds,
            "persisted_clipboard_seconds": clipboard_seconds(&root)?,
        });
        fs::write(&receipt, document.to_string()).map_err(|error| error.to_string())?;
    }
    let mut rows = Vec::new();
    for path in store.list(&identity).map_err(|error| error.to_string())? {
        let entry = store.get(&path, &identity).map_err(|error| error.to_string())?;
        let data = serde_json::to_string(&entry.data).map_err(|error| error.to_string())?;
        let digest = Sha256::digest(go_escape(&data).as_bytes());
        let tags = if entry.metadata.tags.is_empty() {
            Value::Null
        } else {
            json!(entry.metadata.tags)
        };
        rows.push(json!({
            "path": path,
            "data_sha256": hex::encode(digest),
            "tags": tags,
            "version": entry.metadata.version,
        }));
    }
    println!("{}", Value::Array(rows));
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("tui-snapshot: {error}");
        process::exit(1);
    }
}
