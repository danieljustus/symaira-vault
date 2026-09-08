#![cfg(unix)]

use std::{fs, os::unix::fs::symlink};

use symvault_crypto::parse_identity;
use symvault_store::{Entry, Store};

// Public deterministic test identity already used by the Go/Rust fixture suite.
const IDENTITY: &str = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL";

#[test]
fn deletion_stays_in_retained_root_and_rejects_special_targets() {
    use symvault_store::StoreError;
    for legacy in [false, true] {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let root = temp.path().join("vault");
        let moved = temp.path().join("moved");
        fs::create_dir_all(root.join("entries")).unwrap();
        fs::write(
            root.join("config.yaml"),
            b"vault:\n  pseudonymize_paths: false\n",
        )
        .unwrap();
        fs::write(root.join("identity.age"), b"non-secret presence fixture").unwrap();
        let relative = if legacy {
            "victim.age"
        } else {
            "entries/victim.age"
        };
        fs::write(root.join(relative), b"original").unwrap();
        let identity = parse_identity(IDENTITY).unwrap();
        let store = Store::open(&root, &identity).unwrap();
        fs::rename(&root, &moved).unwrap();
        // A real replacement directory also bypasses ambient no-symlink checks.
        fs::create_dir_all(root.join("entries")).unwrap();
        fs::write(root.join(relative), b"outsider sentinel").unwrap();
        store.delete_entry("victim").unwrap();
        assert!(!moved.join(relative).exists());
        assert_eq!(fs::read(root.join(relative)).unwrap(), b"outsider sentinel");
        assert!(matches!(
            store.delete_entry("victim"),
            Err(StoreError::EntryNotFound(_))
        ));
        assert!(matches!(
            store.delete_entry("missing/child"),
            Err(StoreError::EntryNotFound(_))
        ));
        assert!(!moved.join("entries/missing").exists());

        fs::write(moved.join("blocked.age"), b"legacy must survive").unwrap();
        symlink(root.join(relative), moved.join("entries/blocked.age")).unwrap();
        assert!(matches!(
            store.delete_entry("blocked"),
            Err(StoreError::Symlink(_))
        ));
        assert_eq!(
            fs::read(moved.join("blocked.age")).unwrap(),
            b"legacy must survive"
        );
        assert_eq!(fs::read(root.join(relative)).unwrap(), b"outsider sentinel");
        fs::create_dir(moved.join("entries/directory.age")).unwrap();
        assert!(matches!(
            store.delete_entry("directory"),
            Err(StoreError::NotRegularFile(_))
        ));
        let socket = moved.join("entries/socket.age");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert!(matches!(
            store.delete_entry("socket"),
            Err(StoreError::NotRegularFile(_))
        ));
        assert!(socket.exists());
        symlink(&root, moved.join("entries/escape")).unwrap();
        assert!(store.delete_entry("escape/victim").is_err());
        assert_eq!(fs::read(root.join(relative)).unwrap(), b"outsider sentinel");
    }
}

#[test]
fn entry_and_manifest_mutations_retain_opened_root_after_path_replacement() {
    for pseudonymize in [false, true] {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let root = temp.path().join("vault");
        let moved = temp.path().join("moved");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("entries")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(
            root.join("config.yaml"),
            format!("vault:\n  pseudonymize_paths: {pseudonymize}\n"),
        )
        .unwrap();
        // Store::open validates presence; no identity decryption is involved.
        fs::write(root.join("identity.age"), b"non-secret presence fixture").unwrap();
        let identity = parse_identity(IDENTITY).unwrap();
        let recipient = symvault_crypto::recipient_string(&identity);
        fs::write(root.join("recipients.txt"), format!("{recipient}\n")).unwrap();
        fs::write(
            outside.join("recipients.txt"),
            b"invalid-outsider-recipient\n",
        )
        .unwrap();
        fs::write(outside.join("sentinel"), b"must not change").unwrap();
        let store = Store::open(&root, &identity).unwrap();
        let path = "nested.name/service.v1";
        store
            .write_entry_with_recipients_at(
                path,
                &Entry::default(),
                &identity,
                "2026-09-08T10:11:12Z",
                None,
            )
            .unwrap();
        fs::rename(&root, &moved).unwrap();
        symlink(&outside, &root).unwrap();
        let entry = Entry {
            data: [("label".into(), serde_json::json!("after-root-replacement"))].into(),
            ..Entry::default()
        };
        store
            .write_entry_with_recipients_at(path, &entry, &identity, "2026-09-08T10:12:12Z", None)
            .unwrap();
        store
            .write_entry_at(path, &entry, &identity, "2026-09-08T10:13:12Z", false, None)
            .unwrap();
        store
            .write_new_entry("new.nested/fresh.v2", &entry, &identity)
            .unwrap();
        assert_eq!(store.recipients().unwrap(), [recipient]);
        assert!(
            store
                .load_manifest(&identity)
                .unwrap()
                .entries
                .contains_key(path)
        );
        let reopened = Store::open(&moved, &identity).unwrap();
        assert_eq!(reopened.get(path, &identity).unwrap().data, entry.data);
        assert_eq!(
            reopened.get("new.nested/fresh.v2", &identity).unwrap().data,
            entry.data
        );
        assert_eq!(reopened.verify_manifest(&identity).unwrap().ok, 1);
        assert_eq!(
            fs::read(outside.join("sentinel")).unwrap(),
            b"must not change"
        );
        assert_eq!(
            fs::read(outside.join("recipients.txt")).unwrap(),
            b"invalid-outsider-recipient\n"
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 2);
    }
}

#[test]
fn manifest_rebuild_reads_mtime_from_retained_root() {
    use std::time::{Duration, SystemTime};

    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let root = temp.path().join("vault");
    let moved = temp.path().join("moved");
    let outside = temp.path().join("outside");
    fs::create_dir_all(root.join("entries")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(
        root.join("config.yaml"),
        b"vault:\n  pseudonymize_paths: false\n",
    )
    .unwrap();
    fs::write(root.join("identity.age"), b"presence fixture").unwrap();
    let identity = parse_identity(IDENTITY).unwrap();
    let store = Store::open(&root, &identity).unwrap();
    store
        .write_entry_at(
            "observed",
            &Entry::default(),
            &identity,
            "2026-09-08T10:11:12Z",
            false,
            None,
        )
        .unwrap();

    let retained_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_001);
    let outsider_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_002);
    fs::File::open(root.join("entries/observed.age"))
        .unwrap()
        .set_modified(retained_time)
        .unwrap();
    fs::create_dir_all(outside.join("entries")).unwrap();
    fs::write(outside.join("config.yaml"), b"vault: invalid\n").unwrap();
    fs::write(outside.join("identity.age"), b"outsider identity").unwrap();
    fs::write(outside.join("entries/observed.age"), b"outsider bytes").unwrap();
    fs::File::open(outside.join("entries/observed.age"))
        .unwrap()
        .set_modified(outsider_time)
        .unwrap();

    fs::rename(&root, &moved).unwrap();
    symlink(&outside, &root).unwrap();
    let rebuilt = store.rebuild_manifest(&identity).unwrap();
    let expected = time::OffsetDateTime::from(retained_time)
        .to_offset(time::UtcOffset::UTC)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    assert_eq!(rebuilt.entries["observed"].mtime, expected);
    assert_ne!(
        rebuilt.entries["observed"].mtime,
        time::OffsetDateTime::from(outsider_time)
            .to_offset(time::UtcOffset::UTC)
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    );
    assert_eq!(
        fs::read(outside.join("entries/observed.age")).unwrap(),
        b"outsider bytes"
    );
}
