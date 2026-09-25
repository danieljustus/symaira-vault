use std::path::Path;

use serde::Deserialize;
use symvault_sync::DeviceSessionStore;

/// The Go oracle commit `internal/pairing/devicesession_fixturegen_test.go`
/// pins; the fixture is only meaningful against exactly that source.
const ORACLE_COMMIT_SHA: &str = "27da9111e64ab2aa6cacb0f35e921077f3be30ee";

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Oracle {
    commit_sha: String,
    go_version: String,
    source_files: Vec<String>,
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
}

fn fixture() -> Fixture {
    let raw =
        include_str!("../../../testdata/port/device_sessions/contract.json").replace("\r\n", "\n");
    serde_json::from_str(&raw).expect("parse Go-generated fixture")
}

/// The fixture's provenance is checked on the Go side byte for byte; here the
/// oracle it names is pinned so a fixture produced from a different source
/// cannot be replayed as if it were this one.
#[test]
fn fixture_pins_the_go_oracle() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit_sha, ORACLE_COMMIT_SHA);
    assert_eq!(fixture.oracle.go_version, "go1.26.6");
    assert_eq!(
        fixture.oracle.source_files,
        [
            "internal/pairing/devicesession.go",
            "internal/mcp/auth/token.go"
        ]
    );
}

#[test]
fn replays_go_device_session_fixture() {
    let fixture = fixture();
    assert_eq!(fixture.cases.len(), 4);
    for case in fixture.cases {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(".symvault/device-sessions.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, case.input.as_bytes()).unwrap();
        let store = DeviceSessionStore::new(Some(dir.path())).unwrap();
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

/// Go's `List` iterates a map, so its order is non-deterministic and the
/// contract is set equality; the storage-key order returned here is the one
/// deliberate difference (recorded rather than asserted), while *which*
/// sessions come back — revoked ones included — is compared exactly.
#[test]
fn list_returns_every_session_including_revoked_ones() {
    let dir = tempfile::tempdir().unwrap();
    let store = DeviceSessionStore::new(Some(dir.path())).unwrap();
    let first = store.enroll("device-a", "Phone", "key-a").unwrap();
    let second = store.enroll("device-b", "Tablet", "key-b").unwrap();
    store.revoke("device-b").unwrap();

    let mut listed: Vec<String> = store
        .list()
        .unwrap()
        .into_iter()
        .map(|session| session.device_id)
        .collect();
    listed.sort();
    assert_eq!(listed, ["device-a", "device-b"]);

    let live: Vec<String> = store
        .list()
        .unwrap()
        .into_iter()
        .filter(|session| session.revoked)
        .map(|session| session.device_id)
        .collect();
    assert_eq!(live, ["device-b"]);
    assert_eq!(store.validate(&first).unwrap().as_deref(), Some("device-a"));
    assert_eq!(store.validate(&second).unwrap(), None);
}

/// The persisted bytes are a `json.MarshalIndent` contract: field order,
/// `name,omitempty`, and Go's HTML escaping of `<`, `>`, `&` (and U+2028 /
/// U+2029, which Go always escapes). `serde_json` writes those characters
/// literally, so this pins the hand-written renderer.
#[test]
fn persisted_bytes_follow_go_json_escaping_and_field_order() {
    let dir = tempfile::tempdir().unwrap();
    let store = DeviceSessionStore::new(Some(dir.path())).unwrap();
    let token = store
        .enroll("device-one", "Tom & Jerry <3>\u{2028}", "pk&<>")
        .unwrap();

    let path = dir.path().join(".symvault/device-sessions.json");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("Tom \\u0026 Jerry \\u003c3\\u003e\\u2028"),
        "{body}"
    );
    assert!(body.contains("pk\\u0026\\u003c\\u003e"), "{body}");
    assert!(!body.contains("Tom & Jerry"), "{body}");
    assert!(!body.contains("pk&<>"), "{body}");

    let mut previous = 0;
    for field in [
        "\"prefix\"",
        "\"device_id\"",
        "\"name\"",
        "\"public_key\"",
        "\"created_at\"",
        "\"expires_at\"",
        "\"revoked\"",
    ] {
        let at = body
            .find(field)
            .unwrap_or_else(|| panic!("{field} in {body}"));
        assert!(at > previous, "{field} out of order in {body}");
        previous = at;
    }

    // The escaped form is what Go writes, so Go reads it back and so does this
    // store: a reload still validates the raw token.
    let reloaded = DeviceSessionStore::new(Some(dir.path())).unwrap();
    assert_eq!(
        reloaded.validate(&token).unwrap().as_deref(),
        Some("device-one")
    );
}

/// Go decodes a field-sparse store entry into zero values rather than failing:
/// empty `prefix`/`public_key`, the zero `time.Time` for both timestamps
/// (rendered `0001-01-01T00:00:00Z`) and `revoked: false`. The expected bytes
/// are what `json.MarshalIndent` produced for exactly that decoded session.
#[test]
fn sparse_entry_decodes_and_remarshals_the_way_go_does() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".symvault/device-sessions.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let key = "a".repeat(64);
    std::fs::write(&path, format!("{{\"{key}\": {{\"device_id\": \"d\"}}}}\n")).unwrap();

    let store = DeviceSessionStore::new(Some(dir.path())).expect("sparse entry must load");
    let sessions = store.list().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].prefix, "");
    assert_eq!(sessions[0].created_at, "0001-01-01T00:00:00Z");
    assert!(!sessions[0].revoked);
    assert_eq!(store.validate("any-token").unwrap(), None);

    store.save().unwrap();
    let body = std::fs::read_to_string(&path).unwrap();
    let expected = format!(
        "{{\n  \"{key}\": {{\n    \"prefix\": \"\",\n    \"device_id\": \"d\",\n    \"public_key\": \"\",\n    \"created_at\": \"0001-01-01T00:00:00Z\",\n    \"expires_at\": \"0001-01-01T00:00:00Z\",\n    \"revoked\": false\n  }}\n}}"
    );
    assert_eq!(body, expected);
}

/// Go's `mergeRevocationsFromDisk` ignores read and parse failures: a store
/// file that goes bad between load and use leaves the in-memory copy usable
/// instead of erroring every call. The subsequent save then replaces the bad
/// file, as Go's does.
#[test]
fn revocation_merge_survives_a_corrupt_store_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = DeviceSessionStore::new(Some(dir.path())).unwrap();
    let token = store.enroll("device-one", "Phone", "key").unwrap();
    let path = dir.path().join(".symvault/device-sessions.json");

    std::fs::write(&path, b"not json").unwrap();
    assert_eq!(
        store.validate(&token).unwrap().as_deref(),
        Some("device-one"),
        "a bad store file must not stop validation"
    );

    store.revoke("device-one").unwrap();
    assert_eq!(store.validate(&token).unwrap(), None);
    let body = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("store is JSON again");
    assert!(parsed.as_object().unwrap().len() == 1, "{body}");
    assert!(body.contains("\"revoked\": true"), "{body}");
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
