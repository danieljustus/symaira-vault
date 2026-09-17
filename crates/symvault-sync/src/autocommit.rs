//! Go-compatible post-mutation Git history for encrypted vault entries.
//!
//! The vault mutation remains successful when Git is not configured or the
//! repository is absent. Callers can surface a returned error as a warning,
//! matching Go's `AutoCommitEntry` behavior after the encrypted write.

use std::path::Path;

use symvault_crypto::Identity;
use symvault_store::Store;

use crate::git::{CommitOptions, GitError, GitRepository};

/// Commit one entry mutation and its manifest, then push when the vault's
/// existing Git configuration requests it.
pub fn auto_commit_entry(
    store: &Store,
    identity: &Identity,
    path: &str,
    action: &str,
) -> Result<(), String> {
    let config_path = store.root().join("config.yaml");
    let auto_push = symvault_core::config::Config::load(&config_path)
        .map_err(|error| format!("load config for auto-commit: {error}"))?
        .git
        .is_some_and(|git| git.auto_push);
    let repo = match GitRepository::open(store.root()) {
        Ok(repo) => repo,
        Err(GitError::InvalidPath(_)) => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    let entry_path = store
        .configured_entry_path(path, identity)
        .map_err(|error| error.to_string())?;
    let relative = relative_path(store.root(), &entry_path)?;
    repo.commit(CommitOptions {
        message: format!("{action} {path}"),
        affected_paths: vec![relative, "manifest.age".into()],
        ..CommitOptions::default()
    })
    .map_err(|error| error.to_string())?;
    if auto_push {
        let result = repo.push("origin");
        if !result.success && !result.skipped {
            if let Some(error) = result.error {
                return Err(error);
            }
            return Err("git push failed".into());
        }
    }
    Ok(())
}

fn relative_path(root: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(root)
        .map_err(|error| error.to_string())
        .map(|path| path.to_string_lossy().replace('\\', "/"))
}
