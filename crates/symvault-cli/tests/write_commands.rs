#![allow(dead_code)]
#[path = "../src/write_commands.rs"]
mod write_commands;
use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use symvault_crypto::generate_identity;
use symvault_store::Store;

#[test]
fn writes_preserve_other_fields_reject_corruption_and_delete() {
    let root = std::env::temp_dir().join(format!(
        "symvault-write-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("config.yaml"),
        b"vaultDir: .\ngit:\n  autoPush: false\n",
    )
    .unwrap();
    let repo = symvault_sync::GitRepository::init(&root).unwrap();
    repo.create_gitignore().unwrap();
    for (key, value) in [
        ("user.name", "Fixture"),
        ("user.email", "fixture@example.invalid"),
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["config", key, value])
                .status()
                .unwrap()
                .success()
        );
    }
    let identity = generate_identity();
    fs::create_dir_all(root.join("entries")).unwrap();
    fs::write(
        root.join("identity.age"),
        symvault_crypto::encrypt_identity_scrypt(
            &identity,
            &symvault_crypto::SecretBytes::new(b"fixture-passphrase"),
            10,
        )
        .unwrap(),
    )
    .unwrap();
    let store = Store::open(&root, &identity).unwrap();
    write_commands::set_value(
        &root,
        &identity,
        "example.password",
        "secret".into(),
        false,
        true,
    )
    .unwrap();
    write_commands::set_value(
        &root,
        &identity,
        "example.username",
        "alice".into(),
        false,
        false,
    )
    .unwrap();
    let entry = store.get("example", &identity).unwrap();
    assert_eq!(entry.data["password"], "secret");
    assert_eq!(entry.data["username"], "alice");
    assert_eq!(entry.metadata.version, 2);
    assert!(entry.metadata.tags.iter().any(|tag| tag == "weak-password"));
    assert_eq!(repo.log(5).unwrap().len(), 2);
    assert!(
        write_commands::set_value(
            &root,
            &identity,
            "example.password",
            String::new(),
            false,
            true
        )
        .is_err()
    );
    let before = store.get("example", &identity).unwrap();
    assert!(
        write_commands::replace_fields(
            &root,
            &identity,
            "example",
            std::collections::BTreeMap::from([(
                "password".into(),
                serde_json::json!("x".repeat(4097))
            )])
        )
        .is_err()
    );
    assert_eq!(store.get("example", &identity).unwrap(), before);
    let path = store.configured_entry_path("example", &identity).unwrap();
    fs::write(&path, b"corrupt ciphertext").unwrap();
    assert!(
        write_commands::set_value(
            &root,
            &identity,
            "example.username",
            "bob".into(),
            false,
            false
        )
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), b"corrupt ciphertext");
    write_commands::delete(&root, &identity, "example").unwrap();
    assert!(!path.exists());

    // Test set_entry with TOTP
    let valid_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    write_commands::set_entry(
        &root,
        &identity,
        "totp_test",
        "SecretPassword123".into(),
        false,
        true,
        Some(valid_secret),
        Some("MyIssuer"),
        Some("user@test.org"),
    )
    .unwrap();

    let entry = store.get("totp_test", &identity).unwrap();
    assert_eq!(
        entry.data.get("password"),
        Some(&serde_json::json!("SecretPassword123"))
    );
    let totp_val = entry.data.get("totp").expect("totp field present");
    assert_eq!(
        totp_val.get("secret"),
        Some(&serde_json::json!(valid_secret))
    );
    assert_eq!(totp_val.get("issuer"), Some(&serde_json::json!("MyIssuer")));
    assert_eq!(
        totp_val.get("account_name"),
        Some(&serde_json::json!("user@test.org"))
    );

    // Reject weak/short secret
    let err = write_commands::set_entry(
        &root,
        &identity,
        "totp_bad",
        "SecretPassword123".into(),
        false,
        true,
        Some("SHORT"),
        None,
        None,
    )
    .unwrap_err();
    assert!(err.contains("TOTP secret too short"));

    fs::remove_dir_all(root).unwrap();
}
