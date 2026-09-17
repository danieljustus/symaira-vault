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
