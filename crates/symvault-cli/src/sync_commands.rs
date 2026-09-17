//! Non-interactive pull/push orchestration for the vault repository.
//!
//! The command does not unlock the vault: synchronization operates on the
//! encrypted files and git metadata only.  Git transport and process bounds
//! remain in `symvault-sync::GitRepository`.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use symvault_sync::{is_offline_error, GitRepository};

const REMOTE_NAME: &str = "origin";

/// Runs `sync`, pulling first and optionally pushing after a successful pull.
///
/// Quiet mode suppresses both normal output and warnings, matching the Go CLI.
/// A transport failure classified as offline is a successful no-op with a
/// warning; other pull failures remain command errors.
pub(crate) fn sync(
    root: &Path,
    push_after: bool,
    force: bool,
    quiet: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), String> {
    let repo = GitRepository::open(root).map_err(|error| error.to_string())?;
    let pull = if force {
        repo.force_pull(REMOTE_NAME)
    } else {
        repo.pull(REMOTE_NAME)
    };

    if pull.skipped {
        if !quiet {
            writeln!(stdout, "No remote configured. Skipping sync.")
                .map_err(|error| error.to_string())?;
        }
        return Ok(());
    }
    if let Some(error) = pull.error {
        if !quiet && is_offline_error(&error) {
            writeln!(stdout, "Warning: could not reach remote — offline")
                .map_err(|write_error| write_error.to_string())?;
            return Ok(());
        }
        return Err(format!("sync failed: {error}"));
    }

    if let Err(error) = repo.record_last_sync() {
        if !quiet {
            writeln!(stderr, "Warning: could not record sync time: {error}")
                .map_err(|write_error| write_error.to_string())?;
        }
    }
    if !quiet {
        if pull.updated {
            writeln!(stdout, "Pulled from remote").map_err(|error| error.to_string())?;
        } else {
            writeln!(stdout, "Already up to date").map_err(|error| error.to_string())?;
        }
    }

    if push_after {
        let push = repo.push(REMOTE_NAME);
        if !quiet {
            if push.success {
                writeln!(stdout, "Pushed to remote").map_err(|error| error.to_string())?;
            } else {
                writeln!(stdout, "Push skipped or failed").map_err(|error| error.to_string())?;
            }
        }
    }

    if !quiet {
        // The Go command reports the complete count before listing paths.
        // Keep this scan after all transfer output for the same ordering.
        write_conflict_warnings(root, stderr)?;
    }
    Ok(())
}

fn write_conflict_warnings(root: &Path, stderr: &mut impl Write) -> Result<(), String> {
    let files = conflict_files(root)?;
    if files.is_empty() {
        return Ok(());
    }
    writeln!(stderr, "Warning: {} conflict file(s) created:", files.len())
        .map_err(|error| error.to_string())?;
    for path in files {
        writeln!(stderr, "  {}", path.display()).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn conflict_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    scan_conflict_dir(root, Path::new(""), &mut files)?;
    let entries = root.join("entries");
    if entries.is_dir() {
        scan_conflict_dir(&entries, Path::new("entries"), &mut files)?;
    }
    Ok(files)
}

fn scan_conflict_dir(root: &Path, prefix: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let Ok(entries) = fs::read_dir(root) else {
        // Go's conflict scan is best effort: an unreadable directory simply
        // yields no warning and never changes sync's transfer result.
        return Ok(());
    };
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if (name.starts_with(".conflict") && name.len() > 11)
                || (name.starts_with("config.conflict") && name.len() > 14)
            {
                files.push(prefix.join(name.as_ref()));
            }
        }
    }
    files.sort();
    Ok(())
}
