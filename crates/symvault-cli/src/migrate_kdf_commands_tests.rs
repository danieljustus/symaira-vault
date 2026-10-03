use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

fn fixture() -> (PathBuf, Identity, SecretBytes, Vec<u8>) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "symvault-migrate-kdf-{}-{}",
        std::process::id(),
        COUNT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("fixture root");
    let identity = symvault_crypto::generate_identity();
    let passphrase = SecretBytes::new(b"fixture migrate passphrase");
    let original = symvault_crypto::encrypt_identity_scrypt(&identity, &passphrase, 10)
        .expect("legacy envelope");
    fs::write(root.join("identity.age"), &original).expect("identity");
    fs::write(
        root.join("config.yaml"),
        b"vault:\n  format_version: 1\n  scrypt_work_factor: 18\n  auto_migrate_kdf: false\ncustom: retained\n",
    )
    .expect("config");
    (root, identity, passphrase, original)
}

#[test]
fn migrates_and_retains_backup_and_config_fields() {
    let (root, expected, passphrase, original) = fixture();
    let result = migrate_kdf(&root, &expected, &passphrase).expect("migration");
    assert_eq!(result, MigrationResult::Migrated);
    let migrated = fs::read(root.join("identity.age")).expect("migrated identity");
    assert_eq!(
        symvault_crypto::detect_envelope(&migrated),
        EnvelopeFormat::Argon2id
    );
    assert_eq!(
        fs::read(root.join("identity.age.bak")).expect("backup"),
        original
    );
    let decrypted = decrypt_identity(&migrated, &passphrase).expect("decrypt migrated");
    assert_eq!(
        symvault_crypto::recipient_string(&decrypted),
        symvault_crypto::recipient_string(&expected)
    );
    let config = String::from_utf8(fs::read(root.join("config.yaml")).expect("config")).unwrap();
    assert!(config.contains("format_version: 2"));
    assert!(!config.contains("scrypt_work_factor"));
    assert!(config.contains("auto_migrate_kdf: false"));
    assert!(config.contains("custom: retained"));
    assert!(config.contains("\n  auto_migrate_kdf: false\n"));
    assert!(!config.contains("\n    auto_migrate_kdf: false\n"));
    symvault_core::config::Config::load_from_bytes(config.as_bytes())
        .expect("migrated config remains valid YAML");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn migrates_flow_config_without_dropping_unknown_fields() {
    let (root, expected, passphrase, _) = fixture();
    fs::write(
        root.join("config.yaml"),
        b"vault: {format_version: 1, scrypt_work_factor: 18, auto_migrate_kdf: false, custom_nested: {keep: [one, two]}}\nroot_unknown: [true, 7]\n",
    )
    .expect("flow config");

    migrate_kdf(&root, &expected, &passphrase).expect("flow migration");
    let rendered = fs::read(root.join("config.yaml")).expect("rendered config");
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_slice(&rendered).expect("valid YAML");
    let vault = value
        .get("vault")
        .and_then(serde_yaml_ng::Value::as_mapping)
        .expect("vault mapping");
    assert_eq!(
        vault
            .get("format_version")
            .and_then(serde_yaml_ng::Value::as_i64),
        Some(2)
    );
    assert!(vault.get("scrypt_work_factor").is_none());
    assert_eq!(
        vault
            .get("auto_migrate_kdf")
            .and_then(serde_yaml_ng::Value::as_bool),
        Some(false)
    );
    assert!(vault.get("custom_nested").is_some());
    assert_eq!(
        value
            .get("root_unknown")
            .and_then(serde_yaml_ng::Value::as_sequence)
            .map(Vec::len),
        Some(2)
    );
    symvault_core::config::Config::load_from_bytes(&rendered).expect("config remains loadable");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn malformed_config_preserves_identity_without_backup() {
    let (root, expected, passphrase, original) = fixture();
    fs::write(root.join("config.yaml"), b"vault: [malformed\n").expect("bad config");
    let error = migrate_kdf(&root, &expected, &passphrase).expect_err("bad config");
    assert!(error.contains("load config"));
    assert_eq!(
        fs::read(root.join("identity.age")).expect("identity"),
        original
    );
    assert!(!root.join("identity.age.bak").exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn uses_go_compatible_argon2id_config_overrides() {
    let (root, expected, passphrase, _) = fixture();
    fs::write(
        root.join("config.yaml"),
        b"vault:\n  argon2id_time: 2\n  argon2id_memory: 19456\n  argon2id_threads: 1\n",
    )
    .expect("custom config");
    migrate_kdf(&root, &expected, &passphrase).expect("custom migration");
    let bytes = fs::read(root.join("identity.age")).expect("identity");
    let raw = String::from_utf8_lossy(&bytes);
    assert!(raw.contains("t=2,m=19456,p=1"), "argon2id stanza: {raw}");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn already_modern_and_unknown_files_are_not_mutated() {
    let (root, expected, passphrase, original) = fixture();
    assert_eq!(
        inspect_identity(&root).expect("inspect"),
        MigrationResult::NeedsMigration
    );
    assert_eq!(
        migrate_kdf(&root, &expected, &passphrase).expect("migrate"),
        MigrationResult::Migrated
    );
    let migrated = fs::read(root.join("identity.age")).expect("migrated");
    assert_eq!(
        migrate_kdf(&root, &expected, &passphrase).expect("already"),
        MigrationResult::AlreadyArgon2id
    );
    fs::write(root.join("identity.age"), b"not an age envelope\n").expect("unknown");
    assert_eq!(
        migrate_kdf(&root, &expected, &passphrase).expect("unknown"),
        MigrationResult::Unsupported
    );
    assert_eq!(
        fs::read(root.join("identity.age")).expect("unknown bytes"),
        b"not an age envelope\n"
    );
    assert_ne!(migrated, original);
    let _ = fs::remove_dir_all(root);
}

fn policy_fixture() -> (tempfile::TempDir, SecretBytes, Vec<u8>, Vec<u8>) {
    use base64::Engine as _;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../testdata/port/crypto/kdf-policy-v1.json"
    ))
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let original = base64::engine::general_purpose::STANDARD
        .decode(fixture["cases"][0]["ciphertext"].as_str().unwrap())
        .unwrap();
    let config = b"vault:\n  format_version: 2\n  argon2id_time: 5\n  argon2id_memory: 65536\n  argon2id_threads: 4\n  custom: retained\nroot_unknown: [true, 7]\n".to_vec();
    fs::write(root.path().join("identity.age"), &original).unwrap();
    fs::write(root.path().join("config.yaml"), &config).unwrap();
    (
        root,
        SecretBytes::new(fixture["passphrase"].as_str().unwrap().as_bytes()),
        original,
        config,
    )
}

#[test]
fn policy_migration_retains_originals_and_rewrites_same_identity() {
    let (root, passphrase, original, config) = policy_fixture();
    assert_eq!(
        inspect_identity(root.path()).unwrap(),
        MigrationResult::NeedsResourceMigration
    );
    let identity =
        symvault_crypto::decrypt_identity_for_legacy_kdf_migration(&original, &passphrase).unwrap();
    assert!(
        migrate_kdf(root.path(), &identity, &passphrase)
            .unwrap_err()
            .contains("--allow-legacy-kdf")
    );
    assert!(!root.path().join("identity.age.bak").exists());
    migrate_resource_policy(root.path(), &passphrase).unwrap();
    assert_eq!(
        fs::read(root.path().join("identity.age.bak")).unwrap(),
        original
    );
    assert_eq!(
        fs::read(root.path().join("config.yaml.bak")).unwrap(),
        config
    );
    assert_eq!(
        inspect_identity(root.path()).unwrap(),
        MigrationResult::AlreadyArgon2id
    );
    let migrated = fs::read(root.path().join("identity.age")).unwrap();
    assert_eq!(
        symvault_crypto::recipient_string(&decrypt_identity(&migrated, &passphrase).unwrap()),
        symvault_crypto::recipient_string(&identity)
    );
    let rendered = fs::read_to_string(root.path().join("config.yaml")).unwrap();
    assert!(rendered.contains("custom: retained"));
    assert!(rendered.contains("root_unknown:"));
    assert!(rendered.contains("argon2id_time: 3"));
}

#[test]
fn policy_migration_wrong_passphrase_and_old_backup_do_not_mutate_files() {
    let (root, passphrase, original, config) = policy_fixture();
    assert!(
        migrate_resource_policy(root.path(), &SecretBytes::new(b"wrong public fixture")).is_err()
    );
    assert!(!root.path().join("identity.age.bak").exists());
    fs::write(
        root.path().join("identity.age.bak"),
        b"earlier retained backup",
    )
    .unwrap();
    assert!(
        migrate_resource_policy(root.path(), &passphrase)
            .unwrap_err()
            .contains("backup differs")
    );
    assert_eq!(
        fs::read(root.path().join("identity.age")).unwrap(),
        original
    );
    assert_eq!(fs::read(root.path().join("config.yaml")).unwrap(), config);
    assert_eq!(
        fs::read(root.path().join("identity.age.bak")).unwrap(),
        b"earlier retained backup"
    );
}

#[test]
fn policy_migration_restores_both_files_after_post_replacement_failure() {
    let (root, passphrase, original, config) = policy_fixture();
    let config_path = root.path().join("config.yaml");
    let mut failed = false;
    let mut replace = |path: &Path, data: &[u8]| {
        safeio::write_atomic(path, data)?;
        if path == config_path && !failed {
            failed = true;
            return Err(safeio::SafeIoError::Io(std::io::Error::other(
                "injected post-replacement failure",
            )));
        }
        Ok(())
    };
    assert!(
        migrate_resource_policy_locked(root.path(), &passphrase, &mut replace)
            .unwrap_err()
            .contains("injected post-replacement failure")
    );
    assert_eq!(
        fs::read(root.path().join("identity.age")).unwrap(),
        original
    );
    assert_eq!(fs::read(root.path().join("config.yaml")).unwrap(), config);
    assert_eq!(
        fs::read(root.path().join("identity.age.bak")).unwrap(),
        original
    );
    assert_eq!(
        fs::read(root.path().join("config.yaml.bak")).unwrap(),
        config
    );
}

#[test]
fn policy_migration_accepts_null_vault_configuration() {
    let (root, passphrase, _, _) = policy_fixture();
    let config = b"vault: null\ncustom: retained\n";
    fs::write(root.path().join("config.yaml"), config).unwrap();
    migrate_resource_policy(root.path(), &passphrase).unwrap();
    assert_eq!(
        fs::read(root.path().join("config.yaml.bak")).unwrap(),
        config
    );
    let rendered = fs::read_to_string(root.path().join("config.yaml")).unwrap();
    assert!(rendered.contains("custom: retained") && rendered.contains("argon2id_time: 3"));
}
