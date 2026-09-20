//! Manifest verification using the shared encrypted Store.
use std::{
    io::{self, Write},
    path::Path,
};
use symvault_crypto::Identity;
use symvault_store::{Store, StoreError};

pub fn verify(
    root: &Path,
    identity: &Identity,
    rebuild: bool,
    rebuild_only: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    let store = Store::open(root, identity).map_err(|error| error.to_string())?;
    if rebuild || rebuild_only {
        store
            .rebuild_manifest(identity)
            .map_err(|error| format!("rebuild manifest: {error}"))?;
        writeln!(output, "Manifest rebuilt from on-disk entries.")
            .map_err(|error| error.to_string())?;
        if rebuild_only {
            return Ok(());
        }
    }
    let result = match store.verify_manifest(identity) {
        Ok(result) => result,
        Err(StoreError::Read { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            return writeln!(output, "No manifest found. Run `symvault verify --rebuild` to create one from on-disk entries.").map_err(|error| error.to_string());
        }
        Err(error) => return Err(error.to_string()),
    };
    writeln!(
        output,
        "Manifest verification: {} entries match, {} missing, {} tampered, {} unknown",
        result.ok,
        result.missing.len(),
        result.tampered.len(),
        result.unknown.len()
    )
    .map_err(|error| error.to_string())?;
    for (title, paths, suffix) in [
        ("Missing entries:", &result.missing, ""),
        ("Tampered entries:", &result.tampered, " (hash mismatch)"),
        ("Unknown entries (not in manifest):", &result.unknown, ""),
    ] {
        if !paths.is_empty() {
            writeln!(output, "\n{title}").map_err(|error| error.to_string())?;
            for path in paths {
                writeln!(output, "  - {path}{suffix}").map_err(|error| error.to_string())?;
            }
        }
    }
    if !result.unknown.is_empty() {
        writeln!(
            output,
            "\nHint: run `symvault verify --rebuild` to add these entries to the manifest."
        )
        .map_err(|error| error.to_string())?;
    }
    if !result.tampered.is_empty() {
        return Err(format!(
            "manifest integrity check failed: {} tampered entries",
            result.tampered.len()
        ));
    }
    Ok(())
}
