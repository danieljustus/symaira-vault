#![deny(unsafe_code)]

use std::{env, fs, path::PathBuf, process};

use symvault_crypto::parse_identity;
use symvault_store::{Entry, SearchIndex, Store};

fn arg(args: &[String], name: &str) -> Result<String, String> {
    let index = args
        .iter()
        .position(|value| value == name)
        .ok_or_else(|| format!("missing {name}"))?;
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    let action = arg(&args, "--action")?;
    let root = PathBuf::from(arg(&args, "--root")?);
    let case_id = args
        .windows(2)
        .find(|pair| pair[0] == "--case-id")
        .map(|pair| pair[1].as_str())
        .unwrap_or("adapter");
    let identity = parse_identity(&arg(&args, "--identity")?).map_err(|error| error.to_string())?;
    let store = Store::open(&root, &identity).map_err(|error| error.to_string())?;

    match action.as_str() {
        "build" => {
            SearchIndex::build(&store, &identity).map_err(|error| error.to_string())?;
            println!("{{\"case_id\":\"rust_build_index\"}}");
        }
        "load-search" => {
            let mut index = SearchIndex::load(&store, &identity)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| format!("{case_id}: search index missing or rejected"))?;
            let candidates = store.list(&identity).map_err(|error| error.to_string())?;
            let matches = index
                .search(&candidates, &arg(&args, "--query")?)
                .map_err(|error| error.to_string())?;
            let result = serde_json::json!({
                "case_id": "rust_load_go_index_search",
                "matches": matches,
            });
            serde_json::to_writer(std::io::stdout(), &result).map_err(|error| error.to_string())?;
            println!();
        }
        "write-build" => {
            let bytes = fs::read(arg(&args, "--entry-file")?).map_err(|error| error.to_string())?;
            let entry: Entry = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            let path = arg(&args, "--path")?;
            store
                .write_new_entry(&path, &entry, &identity)
                .map_err(|error| error.to_string())?;
            SearchIndex::build(&store, &identity).map_err(|error| error.to_string())?;
            println!("{{\"case_id\":\"rust_build_index_for_go_load\"}}");
        }
        other => return Err(format!("unsupported action {other}")),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("search-index-adapter: {error}");
        process::exit(1);
    }
}
