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

/// Runs the Go CLI's explicit origin push/pull through the bounded Git adapter.
/// A vault without a repository or origin is a successful no-op in Go.
pub fn transfer(root: &Path, action: &str) -> Result<&'static str, String> {
    let message = match action {
        "push" => "Pushed to remote",
        "pull" => "Pulled from remote",
        _ => return Err(format!("unknown action: {action} (use push, pull, or log)")),
    };
    let Ok(repo) = GitRepository::open(root) else {
        return Ok(message);
    };
    let (error, skipped) = if action == "push" {
        let result = repo.push("origin");
        (result.error, result.skipped)
    } else {
        let result = repo.pull("origin");
        (result.error, result.skipped)
    };
    if let Some(error) = error.filter(|_| !skipped) {
        return Err(format!("{action} failed: {error}"));
    }
    Ok(message)
}
