//! D1 data-safety backups through the C ABI: the host's directory is honoured,
//! an unset one falls back to the documented environment default, and with
//! neither the first mutation of an unmarked (Go-created) vault is refused.
//!
//! Go's `pkg/mobilebind` took no backups at all, so none of this is in the
//! recorded fixture; it is listed in `known-divergences.json` (`side_effects`,
//! category `data-safety-backup`) and pinned here. The process-wide backup
//! directory and the environment are shared state: every test takes `LOCK`.

#![allow(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;

use symvault_ffi::abi::{self, SvBuf};
use symvault_ffi::api;

static LOCK: Mutex<()> = Mutex::new(());

const MARKER: &str = ".symvault-rust";
const ENTRY: &str = r#"{"data":{"user":"alice"}}"#;

fn empty() -> SvBuf {
    SvBuf {
        ptr: ptr::null_mut(),
        len: 0,
    }
}

fn error_text(buf: SvBuf) -> String {
    if buf.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the library returned `len` initialized bytes at `ptr`.
    let text = String::from_utf8(unsafe { std::slice::from_raw_parts(buf.ptr, buf.len) }.to_vec())
        .expect("UTF-8");
    // SAFETY: `buf` came from the library and is freed exactly once.
    unsafe { abi::symvault_buf_free(buf) };
    text
}

/// `symvault_set_backup_dir` with the host's string; returns (status, error).
fn set_backup_dir(dir: &str) -> (i32, String) {
    let mut err = empty();
    // SAFETY: the path bytes and `err` are valid for the call.
    let status = unsafe { abi::symvault_set_backup_dir(dir.as_ptr(), dir.len(), &mut err) };
    (status, error_text(err))
}

/// A Rust-created vault with its marker removed: what the gate sees when the
/// app opens a vault that a Go build (or the Mac client) created earlier.
fn unmarked_vault(root: &Path) -> (PathBuf, String) {
    let vault = root.join("vault");
    let dir = vault.to_str().expect("utf-8");
    api::init_vault(dir, b"correct horse").expect("init");
    let identity = api::open_vault_with_passphrase(dir, b"correct horse").expect("open");
    let identity = identity.to_string();
    forget_marker(&vault);
    (vault, identity)
}

fn forget_marker(vault: &Path) {
    let marker = vault.join(MARKER);
    if marker.exists() {
        fs::remove_file(marker).expect("remove marker");
    }
}

fn write(vault: &Path, identity: &str, name: &str) -> Result<(), String> {
    api::write_entry_json(vault.to_str().expect("utf-8"), name, ENTRY, identity)
}

fn archives(dir: &Path) -> Vec<String> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = read
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn assert_one_archive(dir: &Path) {
    let names = archives(dir);
    assert_eq!(
        names.len(),
        1,
        "exactly one backup in {}: {names:?}",
        dir.display()
    );
    assert!(
        names[0].starts_with("pre-rust-") && names[0].ends_with(".tar.gz"),
        "{names:?}"
    );
}

/// Runs `body` with the given environment variables set or removed, restoring
/// them afterwards (the caller holds `LOCK`).
fn with_env(vars: &[(&str, Option<&Path>)], body: impl FnOnce()) {
    let saved: Vec<(String, Option<std::ffi::OsString>)> = vars
        .iter()
        .map(|(name, _)| ((*name).to_owned(), std::env::var_os(name)))
        .collect();
    for (name, value) in vars {
        // SAFETY: tests in this binary serialize on `LOCK`; no other thread
        // reads the environment while it changes.
        unsafe {
            match value {
                Some(path) => std::env::set_var(name, path),
                None => std::env::remove_var(name),
            }
        }
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    for (name, value) in saved {
        // SAFETY: as above.
        unsafe {
            match value {
                Some(old) => std::env::set_var(&name, old),
                None => std::env::remove_var(&name),
            }
        }
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn the_hosts_backup_directory_receives_the_first_mutation_backup() {
    let _guard = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let temp = tempfile::tempdir().expect("tempdir");
    let (vault, identity) = unmarked_vault(temp.path());
    let chosen = temp.path().join("host-backups");
    let xdg = temp.path().join("xdg");

    with_env(&[("XDG_STATE_HOME", Some(xdg.as_path()))], || {
        let (status, err) = set_backup_dir(chosen.to_str().expect("utf-8"));
        assert_eq!((status, err.as_str()), (0, ""));
        write(&vault, &identity, "site/example").expect("first write after the backup");
    });

    assert_one_archive(&chosen);
    assert!(
        vault.join(MARKER).is_file(),
        "the marker follows a verified backup"
    );
    assert!(
        !xdg.exists(),
        "the explicit directory takes precedence over $XDG_STATE_HOME"
    );
    // Marked now: further writes take no second backup.
    write(&vault, &identity, "site/second").expect("second write");
    assert_one_archive(&chosen);

    let (status, _) = set_backup_dir("");
    assert_eq!(status, 0);
}

#[test]
fn an_unset_directory_falls_back_to_xdg_state_home_then_home() {
    let _guard = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let temp = tempfile::tempdir().expect("tempdir");
    let (vault, identity) = unmarked_vault(temp.path());
    let chosen = temp.path().join("host-backups");
    let xdg = temp.path().join("xdg");
    let home = temp.path().join("home");

    // Host set, then cleared with an empty string: the choice must not linger.
    assert_eq!(set_backup_dir(chosen.to_str().expect("utf-8")).0, 0);
    assert_eq!(set_backup_dir("").0, 0);

    with_env(
        &[
            ("XDG_STATE_HOME", Some(xdg.as_path())),
            ("HOME", Some(home.as_path())),
        ],
        || write(&vault, &identity, "one").expect("write"),
    );
    assert_one_archive(&xdg.join("symvault").join("backups"));
    assert!(
        archives(&chosen).is_empty(),
        "the cleared choice is not used"
    );

    // No $XDG_STATE_HOME: $HOME/.local/state/symvault/backups.
    forget_marker(&vault);
    with_env(
        &[("XDG_STATE_HOME", None), ("HOME", Some(home.as_path()))],
        || write(&vault, &identity, "two").expect("write"),
    );
    assert_one_archive(&home.join(".local/state/symvault/backups"));
}

#[test]
fn without_any_directory_the_first_mutation_is_refused_and_nothing_is_written() {
    let _guard = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let temp = tempfile::tempdir().expect("tempdir");
    let (vault, identity) = unmarked_vault(temp.path());
    assert_eq!(set_backup_dir("").0, 0);

    with_env(
        &[
            ("XDG_STATE_HOME", None),
            ("HOME", None),
            ("USERPROFILE", None),
        ],
        || {
            let error = write(&vault, &identity, "refused").expect_err("must be refused");
            assert!(
                error.contains("cannot determine the backup directory"),
                "{error}"
            );
        },
    );
    assert!(
        !vault.join(MARKER).exists(),
        "a refused backup leaves no marker"
    );
    let listing =
        api::list_entries_json(vault.to_str().expect("utf-8"), "", &identity).expect("list");
    assert_eq!(listing, "[]", "the refused write created no entry");
}

#[test]
fn a_relative_directory_is_refused_and_keeps_the_previous_choice() {
    let _guard = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let temp = tempfile::tempdir().expect("tempdir");
    let chosen = temp.path().join("host-backups");
    assert_eq!(set_backup_dir(chosen.to_str().expect("utf-8")).0, 0);

    let (status, err) = set_backup_dir("relative/backups");
    assert_eq!(status, 1);
    assert_eq!(err, "backup directory must be an absolute path");
    assert_eq!(
        symvault_sync::data_safety::backup_dir().expect("dir"),
        chosen,
        "a refused path must not replace the host's earlier choice"
    );
    assert_eq!(set_backup_dir("").0, 0);
}

/// `known-divergences.json` `side_effects`: every D1 entry names tests that
/// exist, and every test of this file is named by an entry, so the record and
/// the behavior cannot drift apart.
#[test]
fn the_d1_divergence_entries_are_pinned_by_existing_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let document: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root.join("testdata/port/ffi/known-divergences.json")).expect("read"),
    )
    .expect("known-divergences JSON");
    let entries = document["side_effects"].as_array().expect("side_effects");
    let ids: Vec<&str> = entries
        .iter()
        .map(|e| e["id"].as_str().expect("id"))
        .collect();
    assert_eq!(
        ids,
        [
            "D1/first-mutation-backup",
            "D1/refused-without-backup-directory",
            "D1/set-backup-dir-fallback",
            "D1/ios-backup-excluded-from-icloud",
        ]
    );
    let mut pinned_here = Vec::new();
    for entry in entries {
        assert_eq!(entry["category"], "data-safety-backup");
        for key in [
            "owner",
            "approval",
            "reason",
            "go_behavior",
            "rust_behavior",
        ] {
            assert!(
                entry[key].as_str().is_some_and(|text| !text.is_empty()),
                "{}: {key}",
                entry["id"]
            );
        }
        let pins = entry["pinned_by"].as_array().expect("pinned_by");
        assert!(!pins.is_empty(), "{} pins no test", entry["id"]);
        for pin in pins {
            let (file, name) = pin
                .as_str()
                .expect("pin")
                .split_once("::")
                .expect("file::test");
            let source = fs::read_to_string(root.join(file))
                .unwrap_or_else(|error| panic!("{file}: {error}"));
            let declaration = if file.ends_with(".swift") {
                format!("func {name}(")
            } else {
                format!("fn {name}(")
            };
            assert!(source.contains(&declaration), "{pin}: no such test");
            if file == "crates/symvault-ffi/tests/backup_dir.rs" {
                pinned_here.push(name.to_owned());
            }
        }
    }
    let own = include_str!("backup_dir.rs");
    for chunk in own.split("#[test]\nfn ").skip(1) {
        let name = chunk.split('(').next().expect("name");
        if name != "the_d1_divergence_entries_are_pinned_by_existing_tests" {
            assert!(
                pinned_here.iter().any(|pinned| pinned == name),
                "{name} has no side_effects entry"
            );
        }
    }
}
