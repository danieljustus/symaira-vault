#![deny(unsafe_code)]

use std::{
    env, fs,
    path::PathBuf,
    process,
    sync::{Arc, Barrier, mpsc},
    thread,
};

use symvault_crypto::parse_identity;
use symvault_store::{Entry, SearchIndex, Store, search_index_store::SearchIndexStore};

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
        #[cfg(unix)]
        "load-list-error" => {
            use std::os::unix::fs::PermissionsExt;

            // Open the store before injecting the failure so this probes load's
            // freshness check, not Store::open's layout discovery.
            let entries = root.join("entries");
            let permissions = fs::metadata(&entries)
                .map_err(|error| error.to_string())?
                .permissions();
            fs::set_permissions(&entries, fs::Permissions::from_mode(0o000))
                .map_err(|error| error.to_string())?;
            let loaded = SearchIndex::load(&store, &identity);
            fs::set_permissions(&entries, permissions).map_err(|error| error.to_string())?;
            let permission_error = matches!(loaded,
                Err(symvault_store::StoreError::Read { ref source, .. })
                    if source.kind() == std::io::ErrorKind::PermissionDenied);
            let index_removed = !root.join(".search-index").exists();
            let retry_absent = SearchIndex::load(&store, &identity)
                .map_err(|error| error.to_string())?
                .is_none();
            let mut rebuilt =
                SearchIndex::build(&store, &identity).map_err(|error| error.to_string())?;
            let matches = rebuilt
                .search(
                    &store.list(&identity).map_err(|error| error.to_string())?,
                    "MARKER",
                )
                .map_err(|error| error.to_string())?;
            let result = serde_json::json!({
                "permission_error": permission_error,
                "index_removed": index_removed,
                "retry_absent": retry_absent,
                "matches": matches,
            });
            serde_json::to_writer(std::io::stdout(), &result).map_err(|error| error.to_string())?;
            println!();
        }
        "build-observation" => {
            let result = match SearchIndex::build(&store, &identity) {
                Ok(mut index) => {
                    let candidates = store.list(&identity).map_err(|error| error.to_string())?;
                    let matches = index
                        .search(&candidates, "MARKER")
                        .map_err(|error| error.to_string())?;
                    let cross_line_matches = index
                        .search(&candidates, "FIRST\nSYNTHETIC")
                        .map_err(|error| error.to_string())?;
                    let padded_matches = index
                        .search(&candidates, " FIRST ")
                        .map_err(|error| error.to_string())?;
                    let mut loaded = SearchIndex::load(&store, &identity)
                        .map_err(|error| error.to_string())?
                        .ok_or("built index was not loadable")?;
                    let loaded_matches = loaded
                        .search(&candidates, "MARKER")
                        .map_err(|error| error.to_string())?;
                    let loaded_cross_line_matches = loaded
                        .search(&candidates, "FIRST\nSYNTHETIC")
                        .map_err(|error| error.to_string())?;
                    let loaded_padded_matches = loaded
                        .search(&candidates, " FIRST ")
                        .map_err(|error| error.to_string())?;
                    serde_json::json!({
                        "accepted": true, "error": "", "matches": matches,
                        "loaded_matches": loaded_matches,
                        "cross_line_matches": cross_line_matches,
                        "loaded_cross_line_matches": loaded_cross_line_matches,
                        "padded_matches": padded_matches,
                        "loaded_padded_matches": loaded_padded_matches,
                    })
                }
                Err(error) => serde_json::json!({
                    "accepted": false, "error": error.to_string(), "matches": null,
                    "loaded_matches": null, "cross_line_matches": null,
                    "loaded_cross_line_matches": null, "padded_matches": null,
                    "loaded_padded_matches": null,
                }),
            };
            serde_json::to_writer(std::io::stdout(), &result).map_err(|error| error.to_string())?;
            println!();
        }
        "build" => {
            SearchIndex::build(&store, &identity).map_err(|error| error.to_string())?;
            println!("{{\"case_id\":\"rust_build_index\"}}");
        }
        "load-search" => {
            let mut index = match SearchIndex::load(&store, &identity) {
                Ok(Some(index)) => index,
                Ok(None) => return Err(format!("{case_id}: search index missing or rejected")),
                Err(error) => {
                    return Err(format!(
                        "{case_id}: search index missing or rejected: {error}"
                    ));
                }
            };
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
        "concurrent-load-invalidate" => {
            // Build outside the wrapper so the first wrapper load has to
            // commit the persisted bytes into an initially empty slot.
            let _ = SearchIndex::build(&store, &identity).map_err(|error| error.to_string())?;
            let indexes = Arc::new(SearchIndexStore::new());
            if indexes
                .is_loaded(&store)
                .map_err(|error| error.to_string())?
            {
                return Err("fresh search-index store unexpectedly started loaded".to_owned());
            }
            // Capture the persisted framing before any concurrent invalidation.
            // The Go oracle writes a binary version byte, a 16-byte salt, and
            // nonempty ciphertext; this is the persistence assertion, not a
            // post-race read of a file that may already have been removed.
            let raw_before =
                fs::read(root.join(".search-index")).map_err(|error| error.to_string())?;
            let format_version = raw_before.first().copied();
            let ciphertext_nonempty = raw_before.len() > 1 + 16;
            if format_version != Some(0x01) || !ciphertext_nonempty {
                return Err(format!(
                    "unexpected persisted index framing: format={format_version:?}, bytes={}",
                    raw_before.len()
                ));
            }
            let plaintext_absent = !raw_before
                .windows(b"Concurrent marker".len())
                .any(|window| window == b"Concurrent marker");
            let (load_committed, first_load) = mpsc::sync_channel(1);
            let (loads_finished, wait_for_loads) = mpsc::channel();
            let race_start = Arc::new(Barrier::new(2));

            let loader_indexes = Arc::clone(&indexes);
            let loader_store = store.clone();
            let loader_identity = identity;
            let loader_race_start = Arc::clone(&race_start);
            let loader = thread::spawn(move || {
                let result = match loader_indexes.load(&loader_store, &loader_identity) {
                    Ok(true) => match loader_indexes.is_loaded(&loader_store) {
                        Ok(true) => Ok(()),
                        Ok(false) => {
                            Err("successful load did not commit an in-memory index".to_owned())
                        }
                        Err(error) => Err(error.to_string()),
                    },
                    Ok(false) => {
                        Err("load-before-invalidate did not find persisted index".to_owned())
                    }
                    Err(error) => Err(error.to_string()),
                };
                let run_race = result.is_ok();
                load_committed
                    .send(result)
                    .map_err(|_| "load-before-invalidate result receiver dropped".to_owned())?;
                if !run_race {
                    return Ok(());
                }
                loader_race_start.wait();
                let mut load_result = Ok(());
                for _ in 1..32 {
                    if let Err(error) = loader_indexes.load(&loader_store, &loader_identity) {
                        load_result = Err(error.to_string());
                        break;
                    }
                }
                loads_finished
                    .send(())
                    .map_err(|_| "invalidator stopped waiting for concurrent loads".to_owned())?;
                load_result
            });

            match first_load
                .recv()
                .map_err(|_| "load-before-invalidate worker terminated".to_owned())?
            {
                Ok(()) => {}
                Err(error) => {
                    loader
                        .join()
                        .map_err(|_| "loader thread panicked".to_owned())??;
                    return Err(format!("load-before-invalidate barrier: {error}"));
                }
            }

            let invalidator_indexes = Arc::clone(&indexes);
            let invalidator_store = store.clone();
            let invalidator_race_start = Arc::clone(&race_start);
            let invalidator = thread::spawn(move || {
                invalidator_race_start.wait();
                for _ in 0..31 {
                    invalidator_indexes
                        .invalidate(&invalidator_store)
                        .map_err(|error| error.to_string())?;
                }
                // The last invalidation is ordered after every loader commit.
                // It is the terminal concurrent transition, not test cleanup.
                wait_for_loads
                    .recv()
                    .map_err(|_| "loader stopped before completing concurrent loads".to_owned())?;
                invalidator_indexes
                    .invalidate(&invalidator_store)
                    .map_err(|error| error.to_string())?;
                Ok::<(), String>(())
            });

            let loader_result = loader
                .join()
                .map_err(|_| "loader thread panicked".to_owned())?;
            let invalidator_result = invalidator
                .join()
                .map_err(|_| "invalidator thread panicked".to_owned())?;
            loader_result?;
            invalidator_result?;
            let index_absent = !root.join(".search-index").exists();
            let index_unloaded = !indexes
                .is_loaded(&store)
                .map_err(|error| error.to_string())?;
            if !index_absent || !index_unloaded {
                return Err(format!(
                    "concurrent invalidation did not commit: absent={index_absent}, unloaded={index_unloaded}"
                ));
            }
            // Observe the race before this extra best-effort cleanup of the
            // process-wide wrapper state.
            indexes
                .invalidate(&store)
                .map_err(|error| error.to_string())?;
            let result = serde_json::json!({
                "index_absent": index_absent,
                "index_unloaded": index_unloaded,
                "format_version": format_version,
                "ciphertext_nonempty": ciphertext_nonempty,
                "plaintext_absent": plaintext_absent,
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
