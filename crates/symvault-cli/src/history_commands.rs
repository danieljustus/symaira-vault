//! Read-only rendering for the Go CLI's `git log [path]` command.

use std::{io::Write, path::Path};

use symvault_sync::{Commit, GitRepository};

/// Opens the vault repository and returns history for all files or one path.
///
/// Go treats a missing repository as an empty history, so this helper does the
/// same rather than turning an optional history view into an initialization
/// error.
pub fn log(root: &Path, path: Option<&str>, limit: usize) -> Result<Vec<Commit>, String> {
    let Ok(repo) = GitRepository::open(root) else {
        return Ok(Vec::new());
    };
    repo.log_path(path, limit)
        .map_err(|error| error.to_string())
}

/// Writes the text format used by `symvault git log`.
pub fn write_log<W: Write>(output: &mut W, commits: &[Commit], quiet: bool) -> Result<(), String> {
    if quiet {
        return Ok(());
    }
    for commit in commits {
        let hash = commit.hash.get(..7).unwrap_or(&commit.hash);
        let date = commit.date.get(..10).unwrap_or(&commit.date);
        writeln!(output, "{hash}  {date}  {}", commit.message.trim_end())
            .map_err(|error| error.to_string())?;
        writeln!(output, "  Author: {}", commit.author).map_err(|error| error.to_string())?;
    }
    Ok(())
}
