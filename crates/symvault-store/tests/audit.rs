use std::{collections::BTreeMap, fs, time::UNIX_EPOCH};

use serde::Deserialize;
use symvault_store::audit::{
    AuditKey, ExportOptions, KeyStore, Logger, RotationConfig, canonical_json, compute_hmac,
    export_directory, key_fingerprint, load_or_create_key_with_keyring,
    load_or_create_key_with_local_fallback, redact_path, rotate_key_with_local_fallback,
    verify_entries, verify_jsonl,
};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/port/audit/audit.json"
);

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    oracle: Oracle,
    keys: Vec<KeyVector>,
    entries: Vec<serde_json::Value>,
    legacy: serde_json::Value,
    negative_cases: Vec<NegativeCase>,
    export: ExportVector,
    rotation: RotationVector,
    keystore: KeystoreVector,
}
#[derive(Debug, Deserialize)]
struct KeystoreVector {
    keyring_service: String,
    keyring_account_prefix: String,
    stored_hex: String,
    legacy_key_hex: String,
    migrated_key_hex: String,
    legacy_file_removed: bool,
    reopened_matches: bool,
}
#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    source_digest: String,
    generator_digest: String,
}
#[derive(Debug, Deserialize)]
struct KeyVector {
    name: String,
    key_hex: String,
    kid: String,
}
#[derive(Debug, Deserialize)]
struct NegativeCase {
    name: String,
    lines: Vec<serde_json::Value>,
    valid: bool,
    total: usize,
    verified: usize,
    legacy: usize,
    tampered: usize,
    unverifiable: usize,
    first_bad_index: isize,
}
#[derive(Debug, Deserialize)]
struct ExportVector {
    action: String,
    failed_only: bool,
    redacted_path: String,
    total: usize,
}
#[derive(Debug, Deserialize)]
struct RotationVector {
    archive_prefix: String,
    archive_kid: String,
    bootstrap: bool,
}

fn fixture() -> Fixture {
    serde_json::from_str(&fs::read_to_string(FIXTURE).unwrap()).unwrap()
}
fn hex_bytes(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn key_map(fixture: &Fixture) -> BTreeMap<String, AuditKey> {
    fixture
        .keys
        .iter()
        .map(|vector| {
            (
                vector.kid.clone(),
                AuditKey::new(hex_bytes(&vector.key_hex)).unwrap(),
            )
        })
        .collect()
}
fn entries(fixture: &Fixture) -> Vec<symvault_store::audit::LogEntry> {
    fixture
        .entries
        .iter()
        .map(|entry| serde_json::from_value(entry.clone()).unwrap())
        .collect()
}
fn jsonl(lines: &[serde_json::Value]) -> Vec<u8> {
    lines
        .iter()
        .flat_map(|line| serde_json::to_vec(line).unwrap().into_iter().chain(*b"\n"))
        .collect()
}

#[test]
fn go_fixture_is_provenance_bound_and_canonical_bytes_match() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "fca3f894");
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert_eq!(fixture.entries.len(), 4);
    assert_eq!(fixture.rotation.archive_prefix, "audit-hmac-key.rotated.");
    assert!(fixture.rotation.bootstrap);
    assert_eq!(fixture.rotation.archive_kid, fixture.keys[0].kid);
    let key_names: Vec<_> = fixture
        .keys
        .iter()
        .map(|vector| vector.name.as_str())
        .collect();
    assert_eq!(key_names, ["old", "new"]);

    let entries = entries(&fixture);
    let mut previous = Vec::new();
    for entry in &entries {
        let key_bytes = hex_bytes(
            &fixture
                .keys
                .iter()
                .find(|vector| vector.kid == entry.kid)
                .unwrap()
                .key_hex,
        );
        let expected = compute_hmac(&key_bytes, &previous, entry);
        assert_eq!(entry.hmac, expected);
        previous = hex_bytes(&entry.hmac);
        assert_eq!(canonical_json(entry), {
            let mut no_hmac = entry.clone();
            no_hmac.hmac.clear();
            serde_json::to_vec(&no_hmac).unwrap()
        });
    }
}

#[test]
fn go_fixture_chain_and_all_negative_mutations_match() {
    let fixture = fixture();
    let entries = entries(&fixture);
    let keys = key_map(&fixture);
    let current = fixture.keys[1].kid.as_str();
    let (result, statuses) = verify_entries(&entries, &keys, current);
    assert!(result.valid);
    assert_eq!((result.total, result.verified, result.tampered), (4, 4, 0));
    assert_eq!(statuses, ["verified", "verified", "verified", "verified"]);

    for case in &fixture.negative_cases {
        let case_keys = if case.name == "key_mismatch" {
            let mut mismatch_keys = key_map(&fixture);
            mismatch_keys.insert(
                fixture.keys[0].kid.clone(),
                AuditKey::new(b"audit-fixture-bad-key-0000000000").unwrap(),
            );
            mismatch_keys
        } else {
            keys.clone()
        };
        let result = verify_jsonl(&jsonl(&case.lines), &case_keys, current);
        assert_eq!(result.valid, case.valid, "{}", case.name);
        assert_eq!(result.total, case.total, "{}", case.name);
        assert_eq!(result.verified, case.verified, "{}", case.name);
        assert_eq!(result.legacy, case.legacy, "{}", case.name);
        assert_eq!(result.tampered, case.tampered, "{}", case.name);
        assert_eq!(result.unverifiable, case.unverifiable, "{}", case.name);
        assert_eq!(result.first_bad_idx, case.first_bad_index, "{}", case.name);
    }

    let legacy = serde_json::to_vec(&fixture.legacy).unwrap();
    let mut combined = legacy;
    combined.push(b'\n');
    combined.extend(jsonl(&fixture.entries));
    let result = verify_jsonl(&combined, &keys, current);
    assert!(result.valid);
    assert_eq!((result.legacy, result.verified), (1, 4));
}

#[test]
fn export_filters_and_redacts_without_hiding_chain_errors() {
    let fixture = fixture();
    let temp = tempfile::tempdir().unwrap();
    let log = temp.path().join("audit-agent.log");
    let key = AuditKey::new(hex_bytes(&fixture.keys[0].key_hex)).unwrap();
    let mut logger = Logger::open(
        &log,
        key.clone(),
        RotationConfig {
            max_file_size: u64::MAX,
            max_backups: 5,
            max_age: None,
        },
    )
    .unwrap();
    logger
        .append(serde_json::from_value(fixture.entries[0].clone()).unwrap())
        .unwrap();
    logger
        .append(serde_json::from_value(fixture.entries[1].clone()).unwrap())
        .unwrap();
    drop(logger);
    let mut keys = BTreeMap::new();
    keys.insert(key_fingerprint(&hex_bytes(&fixture.keys[0].key_hex)), key);
    let exported = export_directory(
        temp.path(),
        "agent",
        &ExportOptions {
            action: Some(fixture.export.action.clone()),
            failed_only: fixture.export.failed_only,
            redact_paths: true,
            verify_hmac: true,
        },
        &keys,
        &fixture.keys[0].kid,
    )
    .unwrap();
    assert_eq!(exported.total, fixture.export.total);
    assert_eq!(exported.entries[0].entry.path, "");
    assert_eq!(
        exported.entries[0].redacted_path,
        fixture.export.redacted_path
    );
    assert_eq!(redact_path("safe/password"), fixture.export.redacted_path);
    assert_eq!(exported.entries[0].entry.hmac.len(), 64);
}

#[test]
fn rotation_archive_bootstrap_retention_and_private_output_work() {
    let fixture = fixture();
    let temp = tempfile::tempdir().unwrap();
    let store = KeyStore::new(temp.path());
    let (_, archive) = store.rotate().unwrap();
    assert!(archive.is_none());
    let old = fs::read(temp.path().join("audit-hmac-key")).unwrap();
    assert_eq!(old.len(), 32);
    let key_view = AuditKey::new(old.clone()).unwrap();
    assert_eq!(format!("{key_view}"), "<redacted>");
    assert!(!format!("{key_view:?}").contains("audit-fixture"));
    let (_, archive) = store.rotate().unwrap();
    let archive = archive.unwrap();
    assert!(
        archive
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(&fixture.rotation.archive_prefix)
    );
    assert!(archive.to_string_lossy().ends_with(&key_fingerprint(&old)));
    assert_eq!(fs::read(&archive).unwrap(), old);
    assert_eq!(store.archived().unwrap().len(), 1);
    store.enforce_retention(0, None).unwrap();
    assert!(store.archived().unwrap().is_empty());
    assert!(
        !fs::metadata(temp.path().join("audit-hmac-key"))
            .unwrap()
            .permissions()
            .readonly()
    );
}

#[test]
fn file_rotation_preserves_the_hmac_chain_across_archive_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit-agent.log");
    let key = AuditKey::new(b"audit-fixture-old-key-0000000000").unwrap();
    let kid = key_fingerprint(b"audit-fixture-old-key-0000000000");
    let mut logger = Logger::open(
        &path,
        key.clone(),
        RotationConfig {
            max_file_size: 1,
            max_backups: 1,
            max_age: None,
        },
    )
    .unwrap();
    logger
        .append(symvault_store::audit::LogEntry {
            timestamp: "2026-01-01T00:00:00Z".into(),
            agent: "agent".into(),
            action: "one".into(),
            ok: true,
            ..Default::default()
        })
        .unwrap();
    logger
        .append(symvault_store::audit::LogEntry {
            timestamp: "2026-01-01T00:00:01Z".into(),
            agent: "agent".into(),
            action: "two".into(),
            ok: true,
            ..Default::default()
        })
        .unwrap();
    let archive = fs::read_dir(temp.path())
        .unwrap()
        .map(|item| item.unwrap().path())
        .find(|path| path.to_string_lossy().contains(".rotated."))
        .unwrap();
    let mut bytes = fs::read(archive).unwrap();
    bytes.extend(fs::read(&path).unwrap());
    let mut keys = BTreeMap::new();
    keys.insert(kid, key);
    let result = verify_jsonl(&bytes, &keys, keys.keys().next().unwrap());
    assert!(result.valid);
    assert_eq!(result.verified, 2);
}

#[test]
fn export_verifies_rotated_file_before_current_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit-agent.log");
    let key_bytes = b"audit-fixture-old-key-0000000000";
    let key = AuditKey::new(key_bytes).unwrap();
    let kid = key_fingerprint(key_bytes);
    let mut logger = Logger::open(
        &path,
        key,
        RotationConfig {
            max_file_size: u64::MAX,
            max_backups: 5,
            max_age: None,
        },
    )
    .unwrap();
    logger
        .append(symvault_store::audit::LogEntry {
            timestamp: "2026-01-01T00:00:00Z".into(),
            agent: "agent".into(),
            action: "before".into(),
            ok: true,
            ..Default::default()
        })
        .unwrap();
    logger
        .rotate_at(UNIX_EPOCH + std::time::Duration::from_secs(1_767_225_600))
        .unwrap();
    logger
        .append(symvault_store::audit::LogEntry {
            timestamp: "2026-01-01T00:00:01Z".into(),
            agent: "agent".into(),
            action: "after".into(),
            ok: true,
            ..Default::default()
        })
        .unwrap();
    drop(logger);

    let mut keys = BTreeMap::new();
    keys.insert(kid.clone(), AuditKey::new(key_bytes).unwrap());
    let exported = export_directory(
        temp.path(),
        "agent",
        &ExportOptions {
            verify_hmac: true,
            ..Default::default()
        },
        &keys,
        &kid,
    )
    .unwrap();
    assert_eq!(exported.entries.len(), 2);
    assert_eq!(exported.entries[0].entry.action, "before");
    assert_eq!(exported.entries[1].entry.action, "after");
    assert_eq!(exported.entries[0].verify_status, "verified");
    assert_eq!(exported.entries[1].verify_status, "verified");
}

#[test]
fn log_rotation_enforces_max_age_retention() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit-agent.log");
    let key = AuditKey::new(b"audit-fixture-old-key-0000000000").unwrap();
    let mut logger = Logger::open(
        &path,
        key,
        RotationConfig {
            max_file_size: u64::MAX,
            max_backups: 5,
            max_age: Some(std::time::Duration::ZERO),
        },
    )
    .unwrap();
    logger
        .append(symvault_store::audit::LogEntry {
            timestamp: "2026-01-01T00:00:00Z".into(),
            agent: "agent".into(),
            action: "before".into(),
            ok: true,
            ..Default::default()
        })
        .unwrap();
    logger.rotate_at(UNIX_EPOCH).unwrap();
    let rotated = fs::read_dir(temp.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|item| item.file_name().to_string_lossy().contains(".rotated."))
        .count();
    assert_eq!(rotated, 0);
}

#[test]
#[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
fn production_keyring_address_migrates_legacy_key_and_reopens_chain() {
    use symvault_core::session::{Keyring, MemoryKeyring};
    use symvault_store::audit::{LogEntry, open_with_keyring};
    let root = tempfile::tempdir().unwrap();
    let legacy = root.path().join("audit-hmac-key");
    let fixture = fixture();
    let key = hex_bytes(&fixture.keystore.legacy_key_hex);
    fs::write(&legacy, &key).unwrap();
    let keyring = MemoryKeyring::new();
    let mut log =
        open_with_keyring("fixture", root.path(), &keyring, RotationConfig::default()).unwrap();
    log.append(LogEntry {
        timestamp: "2026-09-17T00:00:00Z".into(),
        agent: "fixture".into(),
        action: "export".into(),
        ok: true,
        ..LogEntry::default()
    })
    .unwrap();
    let kid = log.kid().to_owned();
    drop(log);
    assert_eq!(!legacy.exists(), fixture.keystore.legacy_file_removed);
    let address = format!(
        "{}|{}{}",
        fixture.keystore.keyring_service,
        fixture.keystore.keyring_account_prefix,
        root.path().display()
    );
    let stored = keyring.get(&address).unwrap();
    assert_eq!(stored, fixture.keystore.stored_hex.as_bytes());
    assert_eq!(stored, fixture.keystore.migrated_key_hex.as_bytes());
    let log =
        open_with_keyring("fixture", root.path(), &keyring, RotationConfig::default()).unwrap();
    assert_eq!(log.kid() == kid, fixture.keystore.reopened_matches);
    assert!(
        open_with_keyring(
            "../outside",
            root.path(),
            &keyring,
            RotationConfig::default()
        )
        .is_err()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(log.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn keyring_loader_roundtrips_without_creating_an_audit_log() {
    use symvault_core::session::{Keyring, MemoryKeyring};

    let root = tempfile::tempdir().unwrap();
    let keyring = MemoryKeyring::new();
    let first = load_or_create_key_with_keyring(root.path(), &keyring).unwrap();
    let address = format!("symaira|audit-hmac-key:{}", root.path().display());
    let stored = keyring.get(&address).unwrap();
    assert_eq!(stored.len(), 64);
    assert_eq!(
        first.fingerprint(),
        key_fingerprint(&hex_bytes(&String::from_utf8(stored).unwrap()))
    );
    assert!(!root.path().join("audit-fixture.log").exists());

    let second = load_or_create_key_with_keyring(root.path(), &keyring).unwrap();
    assert_eq!(second.fingerprint(), first.fingerprint());
    assert!(!root.path().join("audit-fixture.log").exists());
}

#[test]
fn encrypted_local_fallback_bootstraps_rotates_and_reopens_durably() {
    let root = tempfile::tempdir().unwrap();
    let key_path = root.path().join("audit-hmac-key");
    let kek_path = root.path().join("audit-hmac-key.kek");

    let (first, archive) = rotate_key_with_local_fallback(root.path()).unwrap();
    assert!(archive.is_none());
    assert_eq!(
        load_or_create_key_with_local_fallback(root.path()).unwrap(),
        first
    );
    let stored = fs::read(&key_path).unwrap();
    assert!(stored.starts_with(b"sv-local-v1:"));
    assert!(stored.len() > b"sv-local-v1:".len() + 32);
    let kek = fs::read(&kek_path).unwrap();
    assert_eq!(kek.len(), 32);

    let (second, archive) = rotate_key_with_local_fallback(root.path()).unwrap();
    let archive = archive.expect("second invocation rotates the persisted key");
    assert_eq!(
        archive.file_name().unwrap().to_string_lossy(),
        format!("audit-hmac-key.rotated.{}", first.fingerprint())
    );
    assert!(fs::read(&archive).unwrap().starts_with(b"sv-local-v1:"));
    assert_eq!(
        load_or_create_key_with_local_fallback(root.path()).unwrap(),
        second
    );
    assert_ne!(first, second);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&key_path, &kek_path, &archive] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    assert!(fs::read_dir(root.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp.")
    }));
}

#[test]
fn encrypted_local_fallback_fails_closed_on_corrupt_key_or_kek() {
    let root = tempfile::tempdir().unwrap();
    let key_path = root.path().join("audit-hmac-key");
    rotate_key_with_local_fallback(root.path()).unwrap();
    let mut stored = fs::read(&key_path).unwrap();
    *stored.last_mut().unwrap() ^= 1;
    fs::write(&key_path, stored).unwrap();
    assert!(load_or_create_key_with_local_fallback(root.path()).is_err());

    let root = tempfile::tempdir().unwrap();
    rotate_key_with_local_fallback(root.path()).unwrap();
    fs::write(root.path().join("audit-hmac-key.kek"), b"short").unwrap();
    assert!(load_or_create_key_with_local_fallback(root.path()).is_err());
}

#[test]
fn go_local_fallback_ciphertext_fixture_decrypts_in_rust() {
    #[derive(Deserialize)]
    struct LocalFixture {
        marker: String,
        kek_hex: String,
        key_hex: String,
        ciphertext_hex: String,
    }
    const LOCAL_FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/audit/local-fallback.json"
    );
    let vector: LocalFixture = serde_json::from_slice(&fs::read(LOCAL_FIXTURE).unwrap()).unwrap();
    let root = tempfile::tempdir().unwrap();
    let kek = hex_bytes(&vector.kek_hex);
    fs::write(root.path().join("audit-hmac-key.kek"), &kek).unwrap();
    let mut stored = vector.marker.into_bytes();
    stored.extend_from_slice(&hex_bytes(&vector.ciphertext_hex));
    fs::write(root.path().join("audit-hmac-key"), stored).unwrap();
    let key = load_or_create_key_with_local_fallback(root.path()).unwrap();
    let expected = AuditKey::new(hex_bytes(&vector.key_hex)).unwrap();
    assert_eq!(key, expected);
}

#[test]
fn encrypted_local_fallback_migrates_legacy_plaintext_before_archiving() {
    let root = tempfile::tempdir().unwrap();
    let current = root.path().join("audit-hmac-key");
    let legacy = [0x42; 32];
    fs::write(&current, legacy).unwrap();

    let loaded = load_or_create_key_with_local_fallback(root.path()).unwrap();
    assert_eq!(loaded, AuditKey::new(legacy).unwrap());
    assert!(fs::read(&current).unwrap().starts_with(b"sv-local-v1:"));

    let (_, archive) = rotate_key_with_local_fallback(root.path()).unwrap();
    let archive = archive.unwrap();
    assert!(fs::read(&archive).unwrap().starts_with(b"sv-local-v1:"));
    fs::copy(&archive, &current).unwrap();
    assert_eq!(
        load_or_create_key_with_local_fallback(root.path()).unwrap(),
        AuditKey::new(legacy).unwrap()
    );
}
