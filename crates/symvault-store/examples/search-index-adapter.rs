#![deny(unsafe_code)]

use std::{env, fs, path::PathBuf, process};

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
        "wrapper-negative" => {
            use std::os::unix::fs::PermissionsExt;
            use symvault_store::StoreError;

            let case = arg(&args, "--case")?;
            let indexes = SearchIndexStore::new();
            if !indexes.load(&store, &identity).map_err(|e| e.to_string())? {
                return Err("fixture index missing".into());
            }
            let path = root.join(".search-index");
            let entries = root.join("entries");
            let root_mode = fs::metadata(&root)
                .map_err(|e| e.to_string())?
                .permissions();
            let entries_mode = fs::metadata(&entries)
                .map_err(|e| e.to_string())?
                .permissions();
            let wrong =
                parse_identity(&arg(&args, "--wrong-identity")?).map_err(|e| e.to_string())?;
            match case.as_str() {
                "absent" => fs::remove_file(&path),
                "corrupt" | "delete-failure" => fs::write(&path, b"corrupt"),
                "stale" => fs::copy(entries.join("doc.age"), entries.join("extra.age")).map(|_| ()),
                "list-failure" | "wrong-identity" => Ok(()),
                _ => return Err(format!("unknown wrapper case {case}")),
            }
            .map_err(|e| e.to_string())?;
            if case == "list-failure" {
                fs::set_permissions(&entries, fs::Permissions::from_mode(0o000))
                    .map_err(|e| e.to_string())?;
            }
            if case == "delete-failure" {
                fs::set_permissions(&root, fs::Permissions::from_mode(root_mode.mode() & !0o222))
                    .map_err(|e| e.to_string())?;
            }
            let before = fs::read(&path).ok();
            let loaded = indexes.load(
                &store,
                if case == "wrong-identity" {
                    &wrong
                } else {
                    &identity
                },
            );
            let (outcome, detail) = match loaded {
                Ok(_) => ("success", "".to_owned()),
                Err(StoreError::Decryption(_)) => ("decryption", "".to_owned()),
                Err(StoreError::Read { source, .. })
                    if source.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    ("permission", "".to_owned())
                }
                Err(StoreError::SearchIndex(message)) if message == "stale index" => {
                    ("stale", message)
                }
                Err(error) => ("unexpected", error.to_string()),
            };
            // Search the retained wrapper slot while the failure is still in
            // effect; never fall back to SearchIndex::load or entry scanning.
            let observe_search = |query| match indexes.search(&store, &["doc".into()], query) {
                Ok(matches) => {
                    serde_json::json!({"outcome": if matches.is_empty() { "empty" } else { "nonempty" }, "matches": matches})
                }
                Err(error) => serde_json::json!({"outcome": "error", "error": error.to_string()}),
            };
            let matches = observe_search("MARKER");
            let empty = observe_search("no-such-value");
            let retained = indexes.is_loaded(&store).map_err(|e| e.to_string())?;
            let after = fs::read(&path).ok();
            let invalidation = indexes.invalidate(&store);
            let result = serde_json::json!({
                "load_outcome": outcome, "load_detail": detail,
                "loaded": retained, "search": matches, "empty_search": empty,
                "file_exists": after.is_some(),
                "bytes_retained": before.is_some() && before == after,
                "invalidate_ok": invalidation.is_ok(),
                "invalidated_loaded": indexes.is_loaded(&store).map_err(|e| e.to_string())?,
                "invalidated_file_exists": path.exists(),
                "invalidated_bytes_retained": before.is_some() && before == fs::read(&path).ok(),
            });
            fs::set_permissions(&entries, entries_mode).map_err(|e| e.to_string())?;
            fs::set_permissions(&root, root_mode).map_err(|e| e.to_string())?;
            serde_json::to_writer(std::io::stdout(), &result).map_err(|e| e.to_string())?;
            println!();
        }
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
        "load-invalidate" => {
            // Build outside the wrapper so the first wrapper load has to
            // commit the persisted bytes into an initially empty slot.
            let _ = SearchIndex::build(&store, &identity).map_err(|error| error.to_string())?;
            let indexes = SearchIndexStore::new();
            if indexes
                .is_loaded(&store)
                .map_err(|error| error.to_string())?
            {
                return Err("fresh search-index store unexpectedly started loaded".to_owned());
            }
            // Capture the persisted framing before invalidation.
            // The Go oracle writes a binary version byte, a 16-byte salt, and
            // nonempty ciphertext; this is the persistence assertion, not a
            // post-invalidation read of a file that may already have been removed.
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
            if !indexes
                .load(&store, &identity)
                .map_err(|error| error.to_string())?
            {
                return Err("persisted index was not loaded".into());
            }
            indexes
                .invalidate(&store)
                .map_err(|error| error.to_string())?;
            let index_absent = !root.join(".search-index").exists();
            let index_unloaded = !indexes
                .is_loaded(&store)
                .map_err(|error| error.to_string())?;
            if !index_absent || !index_unloaded {
                return Err(format!(
                    "invalidation did not commit: absent={index_absent}, unloaded={index_unloaded}"
                ));
            }
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
