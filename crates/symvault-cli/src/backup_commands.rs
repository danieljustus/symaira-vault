//! CLI backup/restore orchestration over the shared archive implementation.
use std::{
    fs,
    path::{Path, PathBuf},
};
use symvault_sync::archive;

pub fn backup(root: &Path, destination: &Path, exclude_git: bool) -> Result<PathBuf, String> {
    let mut destination = destination.as_os_str().to_owned();
    if !destination.as_encoded_bytes().ends_with(b".tar.gz") {
        destination.push(".tar.gz");
    }
    let destination = PathBuf::from(destination);
    archive::backup(root, &destination, exclude_git)
        .map_err(|error| format!("backup failed: {error}"))?;
    Ok(destination)
}

pub fn restore(root: &Path, source: &Path) -> Result<(), String> {
    fs::metadata(source).map_err(|error| format!("archive not found: {error}"))?;
    archive::restore(source, root, true).map_err(|error| format!("restore failed: {error}"))?;
    for required in ["identity.age", "config.yaml"] {
        fs::metadata(root.join(required))
            .map_err(|_| format!("restore failed: missing required file: {required}"))?;
    }
    fs::metadata(root.join("entries"))
        .map_err(|_| "restore failed: missing entries directory".to_owned())?;
    Ok(())
}
