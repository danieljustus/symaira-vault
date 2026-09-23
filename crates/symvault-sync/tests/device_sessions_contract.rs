use std::path::Path;

use serde::Deserialize;
use symvault_sync::DeviceSessionStore;

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    token: String,
    input: String,
    valid: bool,
    device_id: String,
    after: String,
    raw_absent: bool,
    cleanup: bool,
    #[serde(default)]
    load_error: bool,
}

#[test]
fn replays_go_device_session_fixture() {
    let raw =
        include_str!("../../../testdata/port/device_sessions/contract.json").replace("\r\n", "\n");
    let fixture: Fixture = serde_json::from_str(&raw).expect("parse Go-generated fixture");
    assert_eq!(fixture.cases.len(), 6);
    for case in fixture.cases {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(".symvault/device-sessions.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, case.input.as_bytes()).unwrap();
        let store = DeviceSessionStore::new(Some(dir.path()));
        if case.load_error {
            assert!(
                store.is_err(),
                "{} must reject malformed timestamp",
                case.name
            );
            continue;
        }
        let store = store.unwrap();
        let actual = store.validate(&case.token).unwrap();
        assert_eq!(actual.is_some(), case.valid, "{} validity", case.name);
        assert_eq!(
            actual.unwrap_or_default(),
            case.device_id,
            "{} device",
            case.name
        );
        if case.cleanup {
            store.cleanup_expired().unwrap();
        }
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            after,
            case.after.as_bytes(),
            "{} persisted bytes",
            case.name
        );
        assert_eq!(
            !String::from_utf8_lossy(&after).contains(&case.token),
            case.raw_absent,
            "{} raw token",
            case.name
        );
    }
}

#[test]
fn enroll_hashes_bearer_and_observes_other_instance_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let server = DeviceSessionStore::new(Some(dir.path())).unwrap();
    let token = server.enroll("device-one", "Phone", "public-key").unwrap();
    assert_eq!(
        server.validate(&token).unwrap().as_deref(),
        Some("device-one")
    );
    let path = dir.path().join(".symvault/device-sessions.json");
    assert!(!std::fs::read_to_string(&path).unwrap().contains(&token));
    let revoker = DeviceSessionStore::new(Some(Path::new(dir.path()))).unwrap();
    revoker.revoke("device-one").unwrap();
    assert_eq!(server.validate(&token).unwrap(), None);
    server.save().unwrap();
    assert!(server.list().unwrap()[0].revoked);
}

#[test]
fn unknown_token_fails_and_revoke_covers_every_session_for_device() {
    let dir = tempfile::tempdir().unwrap();
    let store = DeviceSessionStore::new(Some(dir.path())).unwrap();
    assert_eq!(store.validate("unknown-token").unwrap(), None);
    let first = store.enroll("device-one", "Phone", "key-a").unwrap();
    let second = store.enroll("device-one", "Tablet", "key-b").unwrap();
    store.revoke("device-one").unwrap();
    assert_eq!(store.validate(&first).unwrap(), None);
    assert_eq!(store.validate(&second).unwrap(), None);
}

#[test]
fn malformed_store_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".symvault/device-sessions.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"{\"hash\":{\"created_at\":\"bad\"}}\n").unwrap();
    assert!(DeviceSessionStore::new(Some(dir.path())).is_err());
}

#[cfg(unix)]
#[test]
fn session_store_uses_private_modes() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let store = DeviceSessionStore::new(Some(dir.path())).unwrap();
    let token = store.enroll("device-one", "Phone", "public-key").unwrap();
    let file = dir.path().join(".symvault/device-sessions.json");
    let directory = file.parent().unwrap();
    assert_eq!(
        std::fs::metadata(directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!std::fs::read_to_string(file).unwrap().contains(&token));
}
