#![deny(unsafe_code)]

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process,
};
use symvault_crypto::parse_identity;
use symvault_store::{Entry, Store};

#[derive(Serialize)]
struct Journal {
    version: u32,
    entries: Vec<JournalEntry>,
}

#[derive(Serialize)]
struct JournalEntry {
    path: String,
    temp: String,
    backup: String,
    digest: String,
    installed: bool,
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn entry_path(root: &Path, path: &str) -> Result<PathBuf, String> {
    if path.is_empty() || path.contains('/') || path.contains('\\') || path.contains("..") {
        return Err(format!("unsupported adapter entry path: {path}"));
    }
    Ok(root.join("entries").join(format!("{path}.age")))
}

fn prepare_rust_crash(root: &Path, path: &str) -> Result<(), String> {
    let target = entry_path(root, path)?;
    let original = fs::read(&target).map_err(|error| format!("read target: {error}"))?;
    let parent = target
        .parent()
        .ok_or_else(|| "target has no parent".to_owned())?;
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "target name is not UTF-8".to_owned())?;
    let temp = parent.join(format!(".{name}.reencrypt-1-0-0.tmp"));
    let backup = parent.join(format!(".{name}.reencrypt-1-0-0.backup"));
    fs::rename(&target, &backup).map_err(|error| format!("create backup: {error}"))?;
    fs::write(&target, &original).map_err(|error| format!("install replacement: {error}"))?;
    fs::write(&temp, &original).map_err(|error| format!("write staged replacement: {error}"))?;

    let journal = Journal {
        version: 1,
        entries: vec![JournalEntry {
            path: target.to_string_lossy().into_owned(),
            temp: temp.to_string_lossy().into_owned(),
            backup: backup.to_string_lossy().into_owned(),
            digest: digest(&original),
            installed: true,
        }],
    };
    let encoded = serde_json::to_vec(&journal).map_err(|error| error.to_string())?;
    fs::write(root.join(".reencrypt.journal"), encoded)
        .map_err(|error| format!("write crash journal: {error}"))
}

fn argument(args: &[String], name: &str) -> Result<String, String> {
    let index = args
        .iter()
        .position(|arg| arg == name)
        .ok_or_else(|| format!("missing {name}"))?;
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    let action = argument(&args, "--action")?;
    let root = PathBuf::from(argument(&args, "--root")?);
    let identity =
        parse_identity(&argument(&args, "--identity")?).map_err(|error| error.to_string())?;
    let path = argument(&args, "--path")?;
    match action.as_str() {
        "read" => {
            let store = Store::open(&root, &identity).map_err(|error| error.to_string())?;
            let entry: Entry = store
                .get(&path, &identity)
                .map_err(|error| error.to_string())?;
            serde_json::to_writer(io::stdout(), &entry).map_err(|error| error.to_string())?;
            println!();
            Ok(())
        }
        "prepare-rust-crash" => prepare_rust_crash(&root, &path),
        _ => Err(format!("unsupported action {action}")),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("reencrypt-journal-adapter: {error}");
        process::exit(1);
    }
}
