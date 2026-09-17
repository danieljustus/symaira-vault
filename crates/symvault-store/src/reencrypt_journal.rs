use serde::Deserialize;
use std::{
    ffi::OsStr,
    fs, io,
    path::{Component, Path, PathBuf},
};
use symvault_crypto::Identity;

use crate::{Store, StoreError};

const JOURNAL_VERSION: u32 = 1;
const JOURNAL_NAME: &str = ".reencrypt.journal";

#[derive(Debug, Deserialize)]
struct Journal {
    version: u32,
    entries: Vec<JournalEntry>,
}

#[derive(Debug, Deserialize)]
struct JournalEntry {
    path: String,
    #[serde(default)]
    temp: String,
    #[serde(default)]
    backup: String,
    #[serde(default)]
    digest: String,
}

struct ResolvedEntry {
    target: PathBuf,
    temp: Option<PathBuf>,
    backup: Option<PathBuf>,
    digest: String,
}

pub(crate) fn recover_if_present(store: &Store, identity: &Identity) -> Result<(), StoreError> {
    let journal = store.root.join(JOURNAL_NAME);
    if !regular_exists(store, &journal)? {
        return Ok(());
    }

    // The journal may have been completed by a concurrent opener while this
    // opener waited for the shared write lock. Recheck its existence inside
    // the lock before reading it.
    store.with_write_lock(|store| recover_locked_if_present(store, identity))
}

pub(crate) fn recover_locked_if_present(
    store: &Store,
    identity: &Identity,
) -> Result<(), StoreError> {
    let journal = store.root.join(JOURNAL_NAME);
    if regular_exists(store, &journal)? {
        recover_locked(store, identity)
    } else {
        Ok(())
    }
}

fn recover_locked(store: &Store, identity: &Identity) -> Result<(), StoreError> {
    let root = &store.root;
    let journal_path = root.join(JOURNAL_NAME);
    let bytes = read_journal(store, &journal_path)?;
    let journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|error| StoreError::Config(format!("parse re-encryption journal: {error}")))?;
    if journal.version != JOURNAL_VERSION {
        return Err(StoreError::Config(format!(
            "unsupported re-encryption journal version {}",
            journal.version
        )));
    }

    // Resolve and validate every path before the first rename or removal.
    let entries = journal
        .entries
        .iter()
        .map(|entry| resolve_entry(root, entry))
        .collect::<Result<Vec<_>, _>>()?;

    for entry in &entries {
        if entry.digest.is_empty() {
            remove_artifact(store, entry.temp.as_deref())?;
            remove_artifact(store, entry.backup.as_deref())?;
            continue;
        }

        if target_matches(store, &entry.target, &entry.digest)? {
            // Keep the backup until manifest publication succeeds below.
        } else if let Some(backup) = entry.backup.as_ref() {
            if regular_exists(store, backup)? {
                if regular_exists(store, &entry.target)? {
                    return Err(StoreError::Config(format!(
                        "refusing to replace changed recovery target: {}",
                        entry.target.display()
                    )));
                }
                rename_path(store, backup, &entry.target)?;
            } else if !regular_exists(store, &entry.target)? {
                return Err(StoreError::Config(format!(
                    "target and original backup are both missing: {}",
                    entry.target.display()
                )));
            }
        } else if regular_exists(store, &entry.target)? {
            return Err(StoreError::Config(format!(
                "re-encryption target changed without an original backup: {}",
                entry.target.display()
            )));
        } else {
            return Err(StoreError::Config(format!(
                "target and original backup are both missing: {}",
                entry.target.display()
            )));
        }
        remove_artifact(store, entry.temp.as_deref())?;
    }

    let manifest = root.join("manifest.age");
    let old_manifest = read_optional(store, &manifest)?;
    if let Err(error) = store.rebuild_manifest_locked(identity) {
        let rollback = rollback_locked(store, &entries);
        let restore = if let Some(old_manifest) = old_manifest.as_deref() {
            crate::publication::replace(&manifest, old_manifest, &store.root_cap)
        } else {
            store.remove_path(&manifest).map(|_| ())
        };
        let cleanup = if rollback.is_ok() && restore.is_ok() {
            remove_journal(store)
        } else {
            Ok(())
        };
        return Err(manifest_failure(error, rollback, restore, cleanup));
    }

    for entry in &entries {
        remove_artifact(store, entry.temp.as_deref())?;
        remove_artifact(store, entry.backup.as_deref())?;
    }
    remove_journal(store)
}

fn resolve_entry(root: &Path, entry: &JournalEntry) -> Result<ResolvedEntry, StoreError> {
    let target = journal_target(root, &entry.path)?;
    let temp = optional_artifact(root, &entry.temp, &target, ".tmp")?;
    let backup = optional_artifact(root, &entry.backup, &target, ".backup")?;
    if temp.is_some() && temp == backup {
        return Err(StoreError::UnsafePath(entry.temp.clone()));
    }
    if entry.digest.is_empty() && (temp.is_some() || backup.is_some()) {
        return Err(StoreError::Config(
            "journal artifact has no ciphertext digest".to_owned(),
        ));
    }
    Ok(ResolvedEntry {
        target,
        temp,
        backup,
        digest: entry.digest.clone(),
    })
}

fn journal_target(root: &Path, value: &str) -> Result<PathBuf, StoreError> {
    let canonical_root = canonical_journal_root(root)?;
    let path = normalize_journal_path(&canonical_root, Path::new(value))?;
    let relative = validated_relative(&canonical_root, &path)?;
    let mut components = relative.components();
    if components.next() != Some(Component::Normal(OsStr::new("entries")))
        || path.extension() != Some(OsStr::new("age"))
    {
        return Err(StoreError::UnsafePath(value.to_owned()));
    }
    validate_parents(&canonical_root, &relative, &path)?;
    Ok(path)
}

fn optional_artifact(
    root: &Path,
    value: &str,
    target: &Path,
    suffix: &str,
) -> Result<Option<PathBuf>, StoreError> {
    if value.is_empty() {
        return Ok(None);
    }
    let canonical_root = canonical_journal_root(root)?;
    let path = normalize_journal_path(&canonical_root, Path::new(value))?;
    let relative = validated_relative(&canonical_root, &path)?;
    if path == target || path.parent() != target.parent() {
        return Err(StoreError::UnsafePath(value.to_owned()));
    }
    let target_name = target
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| StoreError::UnsafePath(value.to_owned()))?;
    let artifact_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| StoreError::UnsafePath(value.to_owned()))?;
    if !valid_reencrypt_artifact_name(artifact_name, target_name, suffix) {
        return Err(StoreError::UnsafePath(value.to_owned()));
    }
    validate_parents(&canonical_root, &relative, &path)?;
    Ok(Some(path))
}

fn valid_reencrypt_artifact_name(name: &str, target: &str, suffix: &str) -> bool {
    let rust_prefix = format!(".{target}.reencrypt-");
    let rust_name = name
        .strip_prefix(&rust_prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .is_some_and(|value| !value.is_empty() && !value.contains('/'));
    match suffix {
        ".tmp" => {
            let go_unix_prefix = format!(".{target}.reencrypt-");
            let go_unix_name = name
                .strip_prefix(&go_unix_prefix)
                .is_some_and(|random| is_hex(random, 24));
            let go_windows_name = name.strip_prefix(".reencrypt-").is_some_and(|random| {
                !random.is_empty() && random.chars().all(|c| c.is_ascii_alphanumeric())
            });
            rust_name || go_unix_name || go_windows_name
        }
        ".backup" => {
            let go_unix_prefix = format!(".{target}.backup.reencrypt-");
            let go_unix_name = name
                .strip_prefix(&go_unix_prefix)
                .is_some_and(|random| is_hex(random, 24));
            let go_windows_prefix = format!("{target}.reencrypt-backup");
            let go_windows_name = name.strip_prefix(&go_windows_prefix).is_some_and(|suffix| {
                suffix.is_empty()
                    || (suffix.starts_with('.') && suffix[1..].chars().all(|c| c.is_ascii_digit()))
            });
            rust_name || go_unix_name || go_windows_name
        }
        _ => false,
    }
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn canonical_journal_root(root: &Path) -> Result<PathBuf, StoreError> {
    root.canonicalize().map_err(|source| StoreError::Read {
        path: root.to_path_buf(),
        source,
    })
}

fn validated_relative(root: &Path, path: &Path) -> Result<PathBuf, StoreError> {
    if !path.is_absolute() {
        return Err(StoreError::UnsafePath(path.display().to_string()));
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|_| StoreError::UnsafePath(path.display().to_string()))?;
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(StoreError::UnsafePath(path.display().to_string()));
    }
    Ok(relative.to_owned())
}

// Journal paths are emitted as absolute paths by both implementations. A
// caller can nevertheless spell the same root through a platform alias (for
// example /var versus /private/var on macOS). Resolve only the existing
// parent so the final file name is never followed; all mutation helpers still
// use rooted NOFOLLOW operations after this normalization.
fn normalize_journal_path(root: &Path, path: &Path) -> Result<PathBuf, StoreError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(StoreError::UnsafePath(path.display().to_string()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::UnsafePath(path.display().to_string()))?;
    let canonical_parent = parent.canonicalize().map_err(|source| StoreError::Read {
        path: parent.to_path_buf(),
        source,
    })?;
    validate_journal_ancestors(root, parent, path)?;
    if !canonical_parent.starts_with(root) {
        return Err(StoreError::UnsafePath(path.display().to_string()));
    }
    let name = path
        .file_name()
        .ok_or_else(|| StoreError::UnsafePath(path.display().to_string()))?;
    Ok(canonical_parent.join(name))
}

fn validate_journal_ancestors(
    root: &Path,
    parent: &Path,
    display: &Path,
) -> Result<(), StoreError> {
    let mut current = parent;
    loop {
        let metadata = fs::symlink_metadata(current).map_err(|source| StoreError::Read {
            path: current.to_path_buf(),
            source,
        })?;
        let canonical = current.canonicalize().map_err(|source| StoreError::Read {
            path: current.to_path_buf(),
            source,
        })?;
        if canonical == root {
            return Ok(());
        }
        if metadata.file_type().is_symlink() {
            return Err(StoreError::Symlink(current.to_path_buf()));
        }
        if !canonical.starts_with(root) {
            return Err(StoreError::UnsafePath(display.display().to_string()));
        }
        if !metadata.file_type().is_dir() {
            return Err(StoreError::NotRegularFile(current.to_path_buf()));
        }
        current = current
            .parent()
            .ok_or_else(|| StoreError::UnsafePath(display.display().to_string()))?;
    }
}

fn validate_parents(root: &Path, relative: &Path, display: &Path) -> Result<(), StoreError> {
    let mut current = root.to_owned();
    for component in relative.parent().into_iter().flat_map(Path::components) {
        let Component::Normal(name) = component else {
            return Err(StoreError::UnsafePath(display.display().to_string()));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StoreError::Symlink(current));
            }
            Ok(_) => return Err(StoreError::NotRegularFile(current)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::UnsafePath(display.display().to_string()));
            }
            Err(source) => {
                return Err(StoreError::Read {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn regular_exists(store: &Store, path: &Path) -> Result<bool, StoreError> {
    let relative = validated_relative(&store.root, path)?;
    #[cfg(not(unix))]
    let _ = &relative;
    #[cfg(unix)]
    {
        crate::rooted::regular_exists_at(&store.root_cap, &relative, path)
    }
    #[cfg(not(unix))]
    {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => Ok(true),
            Ok(_) => Err(StoreError::NotRegularFile(path.to_owned())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(StoreError::Read {
                path: path.to_owned(),
                source,
            }),
        }
    }
}

fn read_journal(store: &Store, path: &Path) -> Result<Vec<u8>, StoreError> {
    let relative = validated_relative(&store.root, path)?;
    #[cfg(not(unix))]
    let _ = &relative;
    #[cfg(unix)]
    {
        crate::rooted::read(&store.root_cap, &relative, path)
    }
    #[cfg(not(unix))]
    {
        fs::read(path).map_err(|source| StoreError::Read {
            path: path.to_owned(),
            source,
        })
    }
}

fn target_matches(store: &Store, path: &Path, expected: &str) -> Result<bool, StoreError> {
    let Some(bytes) = read_optional(store, path)? else {
        return Ok(false);
    };
    Ok(crate::sha256_hex(&bytes).eq_ignore_ascii_case(expected))
}

fn read_optional(store: &Store, path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    if !regular_exists(store, path)? {
        return Ok(None);
    }
    let relative = validated_relative(&store.root, path)?;
    #[cfg(not(unix))]
    let _ = &relative;
    #[cfg(unix)]
    {
        crate::rooted::read(&store.root_cap, &relative, path).map(Some)
    }
    #[cfg(not(unix))]
    {
        fs::read(path).map(Some).map_err(|source| StoreError::Read {
            path: path.to_owned(),
            source,
        })
    }
}

fn remove_artifact(store: &Store, path: Option<&Path>) -> Result<(), StoreError> {
    let Some(path) = path else {
        return Ok(());
    };
    let relative = validated_relative(&store.root, path)?;
    #[cfg(not(unix))]
    let _ = &relative;
    #[cfg(unix)]
    {
        crate::rooted::remove(&store.root_cap, &relative, path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        if regular_exists(store, path)? {
            fs::remove_file(path).map_err(|source| StoreError::Write {
                path: path.to_owned(),
                source,
            })?;
        }
        Ok(())
    }
}

fn rename_path(store: &Store, source: &Path, destination: &Path) -> Result<(), StoreError> {
    let source_relative = validated_relative(&store.root, source)?;
    let destination_relative = validated_relative(&store.root, destination)?;
    #[cfg(not(unix))]
    let _ = (&source_relative, &destination_relative);
    #[cfg(unix)]
    {
        crate::rooted::rename(
            &store.root_cap,
            &source_relative,
            &destination_relative,
            destination,
        )
    }
    #[cfg(not(unix))]
    {
        fs::rename(source, destination).map_err(|source| StoreError::Write {
            path: destination.to_owned(),
            source,
        })
    }
}

fn rollback_locked(store: &Store, entries: &[ResolvedEntry]) -> Result<(), StoreError> {
    for entry in entries.iter().rev() {
        let Some(backup) = entry.backup.as_ref() else {
            continue;
        };
        if !regular_exists(store, backup)? {
            continue;
        }
        if regular_exists(store, &entry.target)? {
            if !entry.digest.is_empty() && !target_matches(store, &entry.target, &entry.digest)? {
                return Err(StoreError::Config(format!(
                    "refusing to overwrite changed rollback target: {}",
                    entry.target.display()
                )));
            }
            remove_artifact(store, Some(&entry.target))?;
        }
        rename_path(store, backup, &entry.target)?;
    }
    for entry in entries {
        remove_artifact(store, entry.temp.as_deref())?;
    }
    Ok(())
}

fn manifest_failure(
    manifest_error: StoreError,
    rollback: Result<(), StoreError>,
    restore: Result<(), StoreError>,
    cleanup: Result<(), StoreError>,
) -> StoreError {
    let mut details = vec![format!("rebuild manifest: {manifest_error}")];
    if let Err(error) = rollback {
        details.push(format!("rollback failed: {error}"));
    }
    if let Err(error) = restore {
        details.push(format!("restore manifest failed: {error}"));
    }
    if let Err(error) = cleanup {
        details.push(format!("remove re-encryption journal failed: {error}"));
    }
    StoreError::Config(details.join("; "))
}

fn remove_journal(store: &Store) -> Result<(), StoreError> {
    let path = store.root.join(JOURNAL_NAME);
    let relative = validated_relative(&store.root, &path)?;
    #[cfg(not(unix))]
    let _ = &relative;
    #[cfg(unix)]
    {
        crate::rooted::remove(&store.root_cap, &relative, &path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::remove_file(&path).map_err(|source| StoreError::Write { path, source })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    #[test]
    fn lexical_root_alias_is_normalized_but_symlinked_ancestor_is_rejected() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("vault");
        let entries = root.join("entries");
        fs::create_dir_all(&entries).unwrap();

        let alias_parent = parent.path().join("alias-parent");
        symlink(parent.path(), &alias_parent).unwrap();
        let aliased_target = alias_parent.join("vault/entries/a.age");
        let normalized = journal_target(&root, aliased_target.to_str().unwrap()).unwrap();
        assert_eq!(normalized, root.join("entries/a.age"));

        let outside = parent.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, entries.join("linked")).unwrap();
        let unsafe_target = root.join("entries/linked/a.age");
        assert!(matches!(
            journal_target(&root, unsafe_target.to_str().unwrap()),
            Err(StoreError::Symlink(_))
        ));
    }
}
