use std::{collections::BTreeMap, fs, time::UNIX_EPOCH};

use serde::Deserialize;
use symvault_store::audit::{
    AuditKey, ExportOptions, KeyStore, Logger, RotationConfig, canonical_json, compute_hmac,
    export_directory, key_fingerprint, redact_path, verify_entries, verify_jsonl,
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
    assert_eq!(fixture.oracle.commit, "a57f565a");
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
