//! `symvault import review list|promote` over quarantined import batches.
//!
//! Go reference: `cmd/admin/import.go` `newImportReviewListCmd` /
//! `newImportReviewPromoteCmd` (lines ~370-478). The byte contract lives in
//! `tests/fixtures/import-review/cases.json` (frozen oracle `a226a6f7`);
//! `tests/cli_import_review.rs` replays every case against this code.

use std::collections::BTreeMap;
use std::path::Path;

use symvault_crypto::Identity;
use symvault_store::StoreError;
use symvault_sync::GoTime;

use crate::write_commands::auto_commit;

/// `import review list` — group `quarantine/` entries by their first path
/// segment and print one line per batch, ascending (BTreeMap order equals
/// Go's sorted map keys).
pub(crate) fn list(root: &Path, identity: &Identity, quiet: bool) -> Result<(), String> {
    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| error.to_string())?;
    let entries = store
        .list(identity)
        .map_err(|error| format!("list quarantine: {error}"))?;

    let mut batches: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in &entries {
        let Some(rest) = entry.strip_prefix("quarantine/") else {
            continue;
        };
        // Go: strings.SplitN(..., "/", 2) — group over the first segment.
        let id = rest.split('/').next().unwrap_or("");
        if !id.is_empty() {
            *batches.entry(id).or_default() += 1;
        }
    }

    if batches.is_empty() {
        if !quiet {
            println!("No quarantined imports found.");
        }
        return Ok(());
    }
    for (id, count) in &batches {
        if !quiet {
            println!("{id}  ({count} entries)");
        }
    }
    Ok(())
}

/// `import review promote <import-id>` — move every entry under
/// `quarantine/<id>/` to its destination path (prefix stripped), reporting
/// skips on stdout like Go's `cli.PrintQuietAware`. A failed quarantine
/// delete does not fail the promote; any other per-entry problem does.
pub(crate) fn promote(
    root: &Path,
    identity: &Identity,
    import_id: &str,
    overwrite: bool,
    quiet: bool,
) -> Result<(), String> {
    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| error.to_string())?;
    let prefix = format!("quarantine/{import_id}/");
    let entries: Vec<String> = store
        .list(identity)
        .map_err(|error| format!("list quarantine batch: {error}"))?
        .into_iter()
        .filter(|path| path.starts_with(&prefix))
        .collect();

    if entries.is_empty() {
        return Err(format!(
            "no quarantined entries found for import-id {import_id:?}"
        ));
    }

    let mut had_error = false;
    for entry_path in entries {
        // Go: destPath := strings.TrimPrefix(entryPath, quarantinePrefix).
        let Some(dest_path) = entry_path.strip_prefix(&prefix) else {
            continue;
        };
        if dest_path.is_empty() {
            continue;
        }

        match store.get(dest_path, identity) {
            Ok(_) => {
                if !overwrite {
                    if !quiet {
                        println!(
                            "Warning: skipping {dest_path} \u{2014} destination already exists (use --overwrite)"
                        );
                    }
                    had_error = true;
                    continue;
                }
            }
            Err(StoreError::EntryNotFound(_)) => {}
            Err(error) => {
                if !quiet {
                    println!("Warning: cannot check destination {dest_path}: {error}");
                }
                had_error = true;
                continue;
            }
        }

        let entry = match store.get(&entry_path, identity) {
            Ok(entry) => entry,
            Err(error) => {
                if !quiet {
                    println!("Warning: failed to read {entry_path}: {error}");
                }
                had_error = true;
                continue;
            }
        };

        if let Err(error) = store.write_entry_with_recipients_at(
            dest_path,
            &entry,
            identity,
            &GoTime::now().to_rfc3339_nano(),
            None,
        ) {
            if !quiet {
                println!("Warning: failed to write {dest_path}: {error}");
            }
            had_error = true;
            continue;
        }
        auto_commit(&store, identity, dest_path, "Update");

        // Go: a failed quarantine delete only warns — the promote itself
        // succeeded, so had_error stays untouched.
        if let Err(error) = store.delete_entry_with_identity(&entry_path, identity) {
            if !quiet {
                println!("Warning: failed to delete quarantine entry {entry_path}: {error}");
            }
        } else {
            auto_commit(&store, identity, &entry_path, "Delete");
        }

        if !quiet {
            println!("Promoted: {dest_path}");
        }
    }

    if had_error {
        return Err("some entries could not be promoted".to_owned());
    }
    Ok(())
}
