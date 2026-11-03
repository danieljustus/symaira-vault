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
    validate_pins(entries).expect("exact divergence pins");
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
            if file.ends_with(".rs") {
                // The attribute sits on the line before the declaration; unit
                // tests inside `mod tests` are indented.
                let attributed = source.lines().zip(source.lines().skip(1)).any(|(a, b)| {
                    a.trim() == "#[test]" && b.trim_start().starts_with(&declaration)
                });
                assert!(attributed, "{pin}: not a test");
            } else {
                assert!(name.starts_with("test"), "{pin}: not a Swift test");
            }
            if file == "crates/symvault-ffi/tests/backup_dir.rs" {
                pinned_here.push(name.to_owned());
            }
        }
    }
    let own = include_str!("backup_dir.rs");
    for chunk in own.split("#[test]\nfn ").skip(1) {
        let name = chunk.split('(').next().expect("name");
        if ![
            "the_d1_divergence_entries_are_pinned_by_existing_tests",
            "pin_validator_rejects_missing_extra_and_duplicate",
        ]
        .contains(&name)
        {
            assert!(
                pinned_here.iter().any(|pinned| pinned == name),
                "{name} has no side_effects entry"
            );
        }
    }
}

fn validate_pins(entries: &[serde_json::Value]) -> Result<(), String> {
    let expected: &[(&str, &[&str])] = &[
        (
            "D1/first-mutation-backup",
            &[
                "crates/symvault-ffi/tests/backup_dir.rs::the_hosts_backup_directory_receives_the_first_mutation_backup",
                "crates/symvault-ffi/tests/backup_dir.rs::thread_override_resists_global_directory_interleaving",
                "client/Tests/SymvaultIOSTests/MobileVaultCoreTests.swift::testBackupDirectoryIsExcludedFromBackupAndUsedByTheDataSafetyGate",
            ][..],
        ),
        (
            "D1/refused-without-backup-directory",
            &[
                "crates/symvault-ffi/tests/backup_dir.rs::without_any_directory_the_first_mutation_is_refused_and_nothing_is_written",
            ][..],
        ),
        (
            "D1/set-backup-dir-fallback",
            &[
                "crates/symvault-ffi/tests/backup_dir.rs::an_unset_directory_falls_back_to_xdg_state_home_then_home",
                "crates/symvault-ffi/tests/backup_dir.rs::a_relative_directory_is_refused_and_keeps_the_previous_choice",
                "crates/symvault-ffi/tests/abi.rs::the_host_chooses_the_backup_directory",
                "crates/symvault-ffi/tests/abi.rs::a_pushed_scope_restores_an_override_set_through_the_c_api",
                "crates/symvault-ffi/tests/abi.rs::a_closed_scopes_token_is_refused_when_a_later_scope_has_the_same_depth",
                "crates/symvault-ffi/tests/abi.rs::a_token_from_another_thread_is_refused_at_equal_depth",
                "crates/symvault-ffi/tests/abi.rs::unwind_restores_the_named_scope_and_drops_leaked_inner_scopes",
                "crates/symvault-sync/src/data_safety.rs::a_stale_token_is_refused_even_when_the_depth_matches_again",
                "crates/symvault-sync/src/data_safety.rs::a_token_from_another_thread_is_refused_even_at_equal_depth",
                "crates/symvault-sync/src/data_safety.rs::unwind_closes_the_named_scope_and_everything_inside_it",
                "crates/symvault-ffi/swift/Tests/SymvaultFFITests/BackupScopeTests.swift::testARefusedPopStillRestoresThroughTheUnwind",
            ][..],
        ),
        (
            "D1/ios-backup-excluded-from-icloud",
            &[
                "client/Tests/SymvaultIOSTests/MobileVaultCoreTests.swift::testBackupDirectoryIsExcludedFromBackupAndUsedByTheDataSafetyGate",
                "client/Tests/SymvaultIOSTests/MobileVaultCoreTests.swift::testDefaultBackupDirectoryIsApplicationSupportNotCaches",
                "client/Tests/SymvaultIOSTests/MobileVaultCoreTests.swift::testUnusableBackupDirectoryFailsTheCallBeforeTheVaultIsTouched",
                "client/Tests/SymvaultIOSTests/MobileVaultCoreTests.swift::testExistingBackupDirectoryIsMadePrivateAndSymlinkIsRefused",
            ][..],
        ),
    ];
    if entries.len() != expected.len() {
        return Err("entry count".into());
    }
    for (entry, (id, pins)) in entries.iter().zip(expected) {
        if entry["id"].as_str() != Some(id) {
            return Err("entry id".into());
        }
        let actual = entry["pinned_by"].as_array().ok_or("pins")?;
        let mut set = std::collections::BTreeSet::new();
        for pin in actual {
            if !set.insert(pin.as_str().ok_or("pin type")?) {
                return Err("duplicate pin".into());
            }
        }
        let expected_set: std::collections::BTreeSet<_> = pins.iter().copied().collect();
        if set != expected_set {
            return Err("pin set".into());
        }
    }
    Ok(())
}

#[test]
fn pin_validator_rejects_missing_extra_and_duplicate() {
    let doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../testdata/port/ffi/known-divergences.json"
    ))
    .unwrap();
    let entries = doc["side_effects"].as_array().unwrap();
    assert!(validate_pins(entries).is_ok());
    for mode in 0..3 {
        let mut altered = entries.clone();
        let pins = altered[0]["pinned_by"].as_array_mut().unwrap();
        match mode {
            0 => {
                pins.pop();
            }
            1 => pins.push(serde_json::json!("extra::test")),
            _ => pins.push(pins[0].clone()),
        }
        assert!(validate_pins(&altered).is_err(), "mode {mode}");
    }
}

#[test]
fn thread_override_resists_global_directory_interleaving() {
    let _guard = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let temp = tempfile::tempdir().unwrap();
    let (vault, identity) = unmarked_vault(temp.path());
    let chosen = temp.path().join("chosen");
    let wrong = temp.path().join("wrong");
    let start = std::sync::Arc::new(std::sync::Barrier::new(2));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_start = start.clone();
    let worker_stop = stop.clone();
    let wrong_text = wrong.to_str().unwrap().to_owned();
    let worker = std::thread::spawn(move || {
        assert_eq!(set_backup_dir(&wrong_text).0, 0);
        worker_start.wait();
        while !worker_stop.load(std::sync::atomic::Ordering::SeqCst) {
            assert_eq!(set_backup_dir(&wrong_text).0, 0);
            assert_eq!(set_backup_dir("").0, 0);
        }
    });
    let chosen_text = chosen.to_str().unwrap();
    let mut err = empty();
    // SAFETY: bytes and error pointer are valid for this call.
    assert_eq!(
        unsafe {
            abi::symvault_set_thread_backup_dir(chosen_text.as_ptr(), chosen_text.len(), &mut err)
        },
        0
    );
    let xdg = temp.path().join("xdg");
    with_env(&[("XDG_STATE_HOME", Some(&xdg))], || {
        start.wait();
        write(&vault, &identity, "site/example").unwrap();
    });
    assert!(archives(&xdg.join("symvault/backups")).is_empty());
    // SAFETY: a null, zero-length path clears the calling thread's override.
    assert_eq!(
        unsafe { abi::symvault_set_thread_backup_dir(ptr::null(), 0, &mut err) },
        0
    );
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    worker.join().unwrap();
    assert_one_archive(&chosen);
    assert!(archives(&wrong).is_empty());
    assert_eq!(set_backup_dir("").0, 0);
}
