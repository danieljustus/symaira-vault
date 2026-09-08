#![deny(unsafe_code)]

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;
use symvault_store::audit::{
    AuditChain, AuditLogEntry, LogEntry, canonical_json, compute_hmac, key_fingerprint,
    verify_jsonl, verify_jsonl_against_keys,
};

const FIXTURE: &[u8] = include_bytes!("../../../testdata/port/audit/chain.json");

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    oracle: Oracle,
    key_hex: String,
    entries: Vec<EntryVector>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_files: Vec<String>,
    generator_digest: String,
}

#[derive(Debug, Deserialize)]
struct EntryVector {
    entry: AuditLogEntry,
    canonical_json: String,
    hmac: String,
    line: String,
}

fn fixture() -> Fixture {
    serde_json::from_slice(FIXTURE).expect("decode Go-generated audit fixture")
}

fn key_from_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex high nibble");
            let low = (pair[1] as char).to_digit(16).expect("hex low nibble");
            ((high << 4) | low) as u8
        })
        .collect()
}

fn hmac_bytes(value: &str) -> Vec<u8> {
    key_from_hex(value)
}

#[test]
fn pinned_go_fixture_covers_canonical_bytes_and_deterministic_append() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "caadd5e");
    assert_eq!(fixture.oracle.release, "v0.22.1");
    assert_eq!(
        fixture.oracle.source_files,
        [
            "internal/audit/audit.go",
            "internal/audit/audit_hmac_test.go",
            "internal/audit/keystore.go"
        ]
    );
    assert_eq!(
        fixture.oracle.generator_files,
        [
            "scripts/rust-port/cmd/auditgen/main.go",
            "scripts/rust-port/cmd/auditgen/main_test.go"
        ]
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);

    let key = key_from_hex(&fixture.key_hex);
    assert_eq!(key.len(), 32);
    assert_eq!(key_fingerprint(&key), "630dcd29");

    let mut chain = AuditChain::new(&key).expect("non-empty fixture key");
    let mut previous = Vec::new();
    let mut jsonl = Vec::new();
    for vector in &fixture.entries {
        assert_eq!(
            canonical_json(&vector.entry).expect("canonical JSON"),
            vector.canonical_json.as_bytes()
        );
        assert_eq!(
            compute_hmac(&key, &previous, &vector.entry).expect("HMAC"),
            vector.hmac
        );
        assert!(
            vector
                .hmac
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
        assert_eq!(vector.hmac, vector.hmac.to_ascii_lowercase());
        assert_eq!(vector.hmac.len(), 64);

        let line = chain.append(vector.entry.clone()).expect("append entry");
        assert_eq!(line, format!("{}\n", vector.line).as_bytes());
        jsonl.extend_from_slice(&line);
        previous = hmac_bytes(&vector.hmac);
    }

    let result = verify_jsonl(&jsonl, &key).expect("verify fixture chain");
    assert!(result.valid);
    assert_eq!(result.total, fixture.entries.len());
    assert_eq!(result.verified, fixture.entries.len());
    assert_eq!(result.legacy, 0);
    assert_eq!(result.tampered, 0);
    assert_eq!(result.unverifiable, 0);
    assert_eq!(result.first_bad_idx, -1);
}

#[test]
fn tampering_a_canonical_field_is_detected_at_its_original_index() {
    let fixture = fixture();
    let key = key_from_hex(&fixture.key_hex);
    let mut lines: Vec<String> = fixture
        .entries
        .iter()
        .map(|vector| vector.line.clone())
        .collect();
    let mut tampered: Value = serde_json::from_str(&lines[1]).expect("fixture JSON");
    tampered["action"] = Value::String("tampered-action".into());
    lines[1] = serde_json::to_string(&tampered).expect("serialize tampered JSON");
    let data = format!("{}\n", lines.join("\n"));

    let result = verify_jsonl(data.as_bytes(), &key).expect("verify tampered chain");
    assert!(!result.valid);
    assert_eq!(result.total, 3);
    assert_eq!(result.verified, 2);
    assert_eq!(result.tampered, 1);
    assert_eq!(result.first_bad_idx, 1);
    assert_eq!(result.legacy, 0);
}

#[test]
fn legacy_prefix_is_accepted_but_missing_hmac_after_chain_is_a_reset() {
    let fixture = fixture();
    let key = key_from_hex(&fixture.key_hex);
    let legacy =
        br#"{"ts":"2024-01-15T10:29:59Z","agent":"fixture-agent","action":"legacy","ok":true}"#;

    let prefix_data = format!(
        "{}\n{}\n",
        String::from_utf8_lossy(legacy),
        fixture.entries[0].line
    );
    let prefix_result = verify_jsonl(prefix_data.as_bytes(), &key).expect("verify legacy prefix");
    assert!(prefix_result.valid);
    assert_eq!(prefix_result.total, 2);
    assert_eq!(prefix_result.legacy, 1);
    assert_eq!(prefix_result.verified, 1);
    assert_eq!(prefix_result.tampered, 0);
    assert_eq!(prefix_result.first_bad_idx, -1);

    let reset_data = format!(
        "{}\n{}\n{}\n{}\n",
        fixture.entries[0].line,
        String::from_utf8_lossy(legacy),
        fixture.entries[1].line,
        fixture.entries[2].line
    );
    let reset_result = verify_jsonl(reset_data.as_bytes(), &key).expect("verify reset attempt");
    assert!(!reset_result.valid);
    assert_eq!(reset_result.total, 4);
    assert_eq!(reset_result.legacy, 0);
    assert_eq!(reset_result.verified, 3);
    assert_eq!(reset_result.tampered, 1);
    assert_eq!(reset_result.first_bad_idx, 1);
}

#[test]
fn kid_selects_a_known_generation_and_unknown_generation_is_unverifiable() {
    let fixture = fixture();
    let key = key_from_hex(&fixture.key_hex);
    let current_kid = key_fingerprint(&key);
    let mut keys = BTreeMap::new();
    keys.insert(current_kid.clone(), key.clone());

    let result = verify_jsonl_against_keys(
        format!("{}\n", fixture.entries[0].line).as_bytes(),
        &keys,
        &current_kid,
    )
    .expect("verify known kid");
    assert!(result.valid);
    assert_eq!(result.verified, 1);
    assert_eq!(result.unverifiable, 0);

    let mut unknown: Value = serde_json::from_str(&fixture.entries[0].line).expect("fixture JSON");
    unknown["kid"] = Value::String("deadbeef".into());
    let unknown_data = format!(
        "{}\n",
        serde_json::to_string(&unknown).expect("serialize unknown kid")
    );
    let result = verify_jsonl_against_keys(unknown_data.as_bytes(), &keys, &current_kid)
        .expect("verify unknown kid");
    assert!(result.valid);
    assert_eq!(result.verified, 0);
    assert_eq!(result.unverifiable, 1);
    assert_eq!(result.tampered, 0);
}

#[test]
fn canonical_json_uses_go_html_escaping_and_omits_hmac() {
    let entry = LogEntry {
        timestamp: "2024-01-15T10:30:00Z".into(),
        agent: "a<&>\u{2028}\u{2029}".into(),
        action: "get".into(),
        hmac: "should-not-be-canonicalized".into(),
        ok: true,
        ..LogEntry::default()
    };
    let canonical =
        String::from_utf8(canonical_json(&entry).expect("canonical JSON")).expect("UTF-8 JSON");
    assert_eq!(
        canonical,
        "{\"ts\":\"2024-01-15T10:30:00Z\",\"agent\":\"a\\u003c\\u0026\\u003e\\u2028\\u2029\",\"action\":\"get\",\"ok\":true}"
    );
    assert!(!canonical.contains("hmac"));
}
