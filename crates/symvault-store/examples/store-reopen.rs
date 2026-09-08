#![deny(unsafe_code)]

use std::{env, fs, path::PathBuf, process};

use symvault_crypto::parse_identity;
use symvault_store::{Entry, Store};

const IDENTITY: &str = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL";

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
    let path = argument(&args, "--path")?;
    let identity = parse_identity(IDENTITY).map_err(|error| error.to_string())?;
    let store = Store::open(&root, &identity).map_err(|error| error.to_string())?;

    match action.as_str() {
        "read" => {
            let entry = store
                .get(&path, &identity)
                .map_err(|error| error.to_string())?;
            serde_json::to_writer(std::io::stdout(), &entry).map_err(|error| error.to_string())?;
            println!();
        }
        "write" => {
            let entry_file = PathBuf::from(argument(&args, "--entry-file")?);
            let bytes = fs::read(entry_file).map_err(|error| error.to_string())?;
            let entry: Entry = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            store
                .write_new_entry(&path, &entry, &identity)
                .map_err(|error| error.to_string())?;
            let result = serde_json::json!({"path": path, "written": true});
            serde_json::to_writer(std::io::stdout(), &result).map_err(|error| error.to_string())?;
            println!();
        }
        other => return Err(format!("unsupported action {other}")),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("store-reopen: {error}");
        process::exit(1);
    }
}
