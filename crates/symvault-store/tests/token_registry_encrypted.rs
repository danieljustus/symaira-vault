use std::{collections::BTreeMap, fs};

use symvault_crypto::{encrypt, generate_identity, parse_recipient, recipient_string};
use symvault_store::token_registry::{TokenRecord, load_read_only, lookup_raw_bearer};
use time::OffsetDateTime;

const PLAINTEXT_BEARER: &str = "fixture-plaintext-bearer";
const ENCRYPTED_BEARER: &str = "fixture-encrypted-bearer";

fn record(bearer: &str, agent: &str) -> TokenRecord {
    TokenRecord {
        id: format!("token-{agent}"),
        label: String::new(),
        hash: symvault_store::sha256_hex(bearer.as_bytes()),
        prefix: bearer[..4].to_owned(),
        allowed_tools: Some(vec!["health".into()]),
        tool_registry_hash: String::new(),
        agent_name: agent.into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: None,
        last_used_at: None,
        revoked: false,
        revoked_at: None,
        refresh_token_hash: String::new(),
        refresh_expires_at: None,
    }
}

fn registry_bytes(entry: TokenRecord) -> Vec<u8> {
    let mut tokens = BTreeMap::new();
    tokens.insert(entry.id.clone(), entry);
    serde_json::to_vec(&serde_json::json!({ "version": 2, "tokens": tokens }))
        .expect("serialize registry")
}

fn encrypted_registry(identity: &symvault_crypto::Identity, entry: TokenRecord) -> Vec<u8> {
    let recipient = parse_recipient(&recipient_string(identity)).expect("parse recipient");
    encrypt(&registry_bytes(entry), &[recipient]).expect("encrypt Go-compatible age envelope")
}

#[test]
fn encrypted_registry_precedes_plaintext_and_falls_back_when_missing() {
    let vault = tempfile::tempdir().expect("vault directory");
    let identity = generate_identity();
    let encrypted = encrypted_registry(&identity, record(ENCRYPTED_BEARER, "encrypted"));
    let encrypted_path = vault.path().join("registry.age");
    let plaintext_path = vault.path().join("mcp-tokens.json");
    let plaintext = registry_bytes(record(PLAINTEXT_BEARER, "plaintext"));
    fs::write(&encrypted_path, &encrypted).expect("write encrypted registry");
    fs::write(&plaintext_path, &plaintext).expect("write plaintext fallback");

    let loaded = load_read_only(vault.path(), Some(&identity)).expect("load encrypted registry");
    let now = OffsetDateTime::now_utc();
    assert!(
        lookup_raw_bearer(&loaded, ENCRYPTED_BEARER, now)
            .expect("encrypted bearer lookup")
            .is_some()
    );
    assert!(
        lookup_raw_bearer(&loaded, PLAINTEXT_BEARER, now)
            .expect("plaintext bearer lookup")
            .is_none()
    );
    assert_eq!(fs::read(&encrypted_path).unwrap(), encrypted);
    assert_eq!(fs::read(&plaintext_path).unwrap(), plaintext);

    fs::remove_file(&encrypted_path).expect("remove encrypted registry");
    let fallback = load_read_only(vault.path(), Some(&identity)).expect("load plaintext fallback");
    assert!(
        lookup_raw_bearer(&fallback, PLAINTEXT_BEARER, now)
            .expect("fallback bearer lookup")
            .is_some()
    );
}

#[test]
fn wrong_identity_fails_closed_instead_of_using_plaintext_fallback() {
    let vault = tempfile::tempdir().expect("vault directory");
    let identity = generate_identity();
    let wrong_identity = generate_identity();
    fs::write(
        vault.path().join("registry.age"),
        encrypted_registry(&identity, record(ENCRYPTED_BEARER, "encrypted")),
    )
    .expect("write encrypted registry");
    fs::write(
        vault.path().join("mcp-tokens.json"),
        registry_bytes(record(PLAINTEXT_BEARER, "plaintext")),
    )
    .expect("write plaintext fallback");

    assert!(load_read_only(vault.path(), Some(&wrong_identity)).is_err());
}

#[test]
fn encrypted_registry_read_is_bounded_and_rejects_symlinks() {
    let vault = tempfile::tempdir().expect("vault directory");
    let identity = generate_identity();
    let encrypted_path = vault.path().join("registry.age");
    fs::write(&encrypted_path, vec![0; 1024 * 1024 + 1]).expect("write oversized envelope");
    assert!(load_read_only(vault.path(), Some(&identity)).is_err());

    fs::remove_file(&encrypted_path).expect("remove oversized envelope");
    let outside = vault.path().join("outside.age");
    fs::write(
        &outside,
        encrypted_registry(&identity, record(ENCRYPTED_BEARER, "encrypted")),
    )
    .expect("write envelope target");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, &encrypted_path).expect("link encrypted registry");
        assert!(load_read_only(vault.path(), Some(&identity)).is_err());
    }
}
