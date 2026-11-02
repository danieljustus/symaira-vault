//! CLI backup/restore orchestration.
//!
//! `backup` is a port of Go's `admin.CreateBackup` (`cmd/admin/backup.go`),
//! including its observable side effects: the archive is created in place
//! (`O_CREATE|O_WRONLY|O_TRUNC`, 0600 only for a new file), missing parent
//! directories are made with mode 0700, and a walk or read failure leaves the
//! members written so far in the archive. `restore` goes through the shared
//! `symvault_sync::archive::restore`, which already follows `RestoreBackup`.
use std::{fs, path::Path};
use symvault_sync::archive;

/// `backup`: the Go-faithful writer shared with the pre-mutation data-safety gate.
pub fn backup(
    root: &Path,
    destination: &Path,
    exclude_git: bool,
) -> Result<std::path::PathBuf, String> {
    symvault_sync::backup_writer::backup(root, destination, exclude_git)
}

/// The operation name in the `*PathError` Go's `os.Stat` returns. Unix reports
/// `stat`; on Windows (`os/stat_windows.go`) a missing path fails in
/// `GetFileAttributesEx` and any other failure falls through to `CreateFile`.
fn go_stat_op(error: &std::io::Error) -> &'static str {
    if !cfg!(windows) {
        "stat"
    } else if error.kind() == std::io::ErrorKind::NotFound {
        "GetFileAttributesEx"
    } else {
        "CreateFile"
    }
}

pub fn restore(root: &Path, source: &Path) -> Result<(), String> {
    fs::metadata(source).map_err(|error| {
        format!(
            "archive not found: {} {}: {}",
            go_stat_op(&error),
            source.display(),
            archive::go_reason(&error)
        )
    })?;
    archive::restore(source, root, true).map_err(|error| format!("restore failed: {error}"))?;
    for required in ["identity.age", "config.yaml"] {
        fs::metadata(root.join(required))
            .map_err(|_| format!("restore failed: missing required file: {required}"))?;
    }
    fs::metadata(root.join("entries"))
        .map_err(|_| "restore failed: missing entries directory".to_owned())?;
    Ok(())
}
