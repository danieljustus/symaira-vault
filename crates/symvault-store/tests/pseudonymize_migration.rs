#![cfg(unix)]

//! Vault-wide pseudonymize migration, mirroring the Go command contract and its
//! regression suite (`cmd/admin/migrate_pseudonymize_test.go`, #1088).
//!
//! The Go production code once deleted the whole vault: it enabled
//! `pseudonymize_paths` *after* the rewrite loop, so every write resolved back
//! to the entry's own plaintext path and the following remove deleted it. The
//! Rust entry point therefore refuses to run while the flag is off, and the
//! caller enables it first.

use std::fs;
use std::path::Path;

use symvault_crypto::{Identity, parse_identity};
use symvault_store::{Entry, PseudonymizeSummary, Store, StoreError};

// Public deterministic test identity already used by the Go/Rust fixture suite.
const IDENTITY: &str = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL";

fn vault(pseudonymize: bool) -> (tempfile::TempDir, Identity, std::path::PathBuf) {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let root = temp.path().join("vault");
    fs::create_dir_all(root.join("entries")).unwrap();
    fs::write(
        root.join("config.yaml"),
        format!("vault:\n  pseudonymize_paths: {pseudonymize}\n"),
    )
    .unwrap();
    fs::write(root.join("identity.age"), b"non-secret presence fixture").unwrap();
    let identity = parse_identity(IDENTITY).unwrap();
    (temp, identity, root)
}

fn count_entry_files(root: &Path) -> usize {
    fn walk(dir: &Path, count: &mut usize) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, count);
            } else if path.extension().and_then(|value| value.to_str()) == Some("age") {
                *count += 1;
            }
        }
    }
    let mut count = 0;
    walk(&root.join("entries"), &mut count);
    count
}

fn entry_for(path: &str) -> Entry {
    let mut data = std::collections::BTreeMap::new();
    data.insert(
        "username".to_owned(),
        serde_json::json!(format!("user-{path}")),
    );
    Entry {
        path: path.to_owned(),
        data,
        ..Entry::default()
    }
}

/// Every entry survives the migration and no plaintext-named file remains.
#[test]
fn migrate_pseudonymize_keeps_every_entry() {
    let (_temp, identity, root) = vault(false);
    let logical_paths = ["example.one", "work/nested/two", "deep/a/b/c/three"];

    {
        let store = Store::open(&root, &identity).unwrap();
        for path in logical_paths {
            store
                .write_entry(path, &entry_for(path), &identity)
                .expect("write entry");
        }
        assert_eq!(count_entry_files(&root), logical_paths.len());
    }

    // Caller order mirrors the Go command: enable the flag, reopen, migrate.
    fs::write(
        root.join("config.yaml"),
        "vault:\n  pseudonymize_paths: true\n",
    )
    .unwrap();

    let store = Store::open(&root, &identity).unwrap();
    let summary = store.migrate_pseudonymize(&identity).expect("migrate");
    assert_eq!(
        summary,
        PseudonymizeSummary {
            scanned: logical_paths.len(),
            migrated: logical_paths.len(),
        }
    );

    // Still exactly one file per entry, and every entry stays readable.
    assert_eq!(count_entry_files(&root), logical_paths.len());
    let listed = store.list(&identity).unwrap();
    assert_eq!(listed.len(), logical_paths.len());
    for path in logical_paths {
        let read = store.get(path, &identity).expect("read after migration");
        assert_eq!(read.path, path, "embedded logical path preserved");
        let plain = root.join("entries").join(format!("{path}.age"));
        assert!(
            !plain.exists(),
            "plaintext-named entry file still present: {}",
            plain.display()
        );
    }
}

/// A second run must not hash already-derived names again.
#[test]
fn migrate_pseudonymize_second_run_is_noop() {
    let (_temp, identity, root) = vault(false);
    {
        let store = Store::open(&root, &identity).unwrap();
        store
            .write_entry("only.entry", &entry_for("only.entry"), &identity)
            .expect("write entry");
    }
    fs::write(
        root.join("config.yaml"),
        "vault:\n  pseudonymize_paths: true\n",
    )
    .unwrap();

    let store = Store::open(&root, &identity).unwrap();
    let first = store.migrate_pseudonymize(&identity).expect("first run");
    assert_eq!(first.migrated, 1);
    let after_first = count_entry_files(&root);

    let second = store.migrate_pseudonymize(&identity).expect("second run");
    assert_eq!(
        second.migrated, 0,
        "second run rewrote an already-pseudonymized entry"
    );
    assert_eq!(count_entry_files(&root), after_first);
    assert_eq!(
        store.list(&identity).unwrap(),
        vec!["only.entry".to_owned()]
    );
}

/// Running with the flag off is refused instead of destroying the vault.
#[test]
fn migrate_pseudonymize_requires_the_flag_first() {
    let (_temp, identity, root) = vault(false);
    {
        let store = Store::open(&root, &identity).unwrap();
        store
            .write_entry("kept.entry", &entry_for("kept.entry"), &identity)
            .expect("write entry");
    }
    let store = Store::open(&root, &identity).unwrap();
    let error = store.migrate_pseudonymize(&identity).unwrap_err();
    assert!(
        matches!(error, StoreError::Config(_)),
        "expected a config refusal, got {error:?}"
    );
    assert_eq!(
        count_entry_files(&root),
        1,
        "refusal must leave the vault untouched"
    );
}
