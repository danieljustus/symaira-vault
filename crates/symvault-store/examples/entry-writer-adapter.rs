#![deny(unsafe_code)]

use std::{io, process};

use serde::Deserialize;
use symvault_crypto::parse_identity;
use symvault_store::{Entry, Store};

#[derive(Deserialize)]
struct Request {
    action: String,
    root: String,
    identity: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    entry: Entry,
    #[serde(default)]
    now: String,
}

fn run() -> Result<(), String> {
    let request: Request =
        serde_json::from_reader(io::stdin()).map_err(|error| error.to_string())?;
    let identity = parse_identity(&request.identity).map_err(|error| error.to_string())?;
    // Differential adapters test store semantics against Go, not decision D1 (the
    // pre-mutation backup): the root is declared Rust-created so the gate does not
    // refuse the Go-created vault. The `.symvault-rust` marker is a declared D1
    // artifact and is ignored by tree comparisons.
    let store = Store::open(
        symvault_store::data_safety::test_support_pre_marked(&request.root),
        &identity,
    )
    .map_err(|error| error.to_string())?;
    let result = match request.action.as_str() {
        "write" => {
            store
                .write_entry_with_recipients_at(
                    &request.path,
                    &request.entry,
                    &identity,
                    &request.now,
                    None,
                )
                .map_err(|error| error.to_string())?;
            serde_json::json!({"case_id": "rust_write_entry_with_recipients"})
        }
        "write-single" => {
            store
                .write_entry_at(
                    &request.path,
                    &request.entry,
                    &identity,
                    &request.now,
                    false,
                    None,
                )
                .map_err(|error| error.to_string())?;
            serde_json::json!({"case_id": "rust_write_entry_single_recipient"})
        }
        "read" => serde_json::to_value(
            store
                .get(&request.path, &identity)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?,
        "manifest" => serde_json::to_value(
            store
                .load_manifest(&identity)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?,
        "verify" => serde_json::to_value(
            store
                .verify_manifest(&identity)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?,
        _ => return Err("unsupported entry-writer action".into()),
    };
    serde_json::to_writer(io::stdout(), &result).map_err(|error| error.to_string())?;
    println!();
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("entry-writer-adapter: {error}");
        process::exit(1);
    }
}
