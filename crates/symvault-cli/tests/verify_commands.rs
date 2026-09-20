#[path = "../src/verify_commands.rs"]
mod verify_commands;

#[test]
fn verify_reports_missing_manifest_and_tampering_without_repairing_it() {
    let root = std::env::temp_dir().join(format!("vault-verify-{}", std::process::id()));
    std::fs::create_dir_all(root.join("entries")).unwrap();
    std::fs::write(root.join("config.yaml"), b"{}").unwrap();
    std::fs::write(root.join("identity.age"), b"synthetic identity").unwrap();
    let identity = symvault_crypto::generate_identity();
    let mut output = Vec::new();
    verify_commands::verify(&root, &identity, false, false, &mut output).unwrap();
    assert!(
        String::from_utf8(output)
            .unwrap()
            .starts_with("No manifest found.")
    );
    let store = symvault_store::Store::open(&root, &identity).unwrap();
    store
        .write_entry_with_recipients_at(
            "item",
            &symvault_store::Entry::default(),
            &identity,
            "2026-09-17T00:00:00Z",
            None,
        )
        .unwrap();
    let target = store.configured_entry_path("item", &identity).unwrap();
    std::fs::write(&target, b"corrupt ciphertext").unwrap();
    let mut output = Vec::new();
    let error = verify_commands::verify(&root, &identity, false, false, &mut output).unwrap_err();
    assert_eq!(error, "manifest integrity check failed: 1 tampered entries");
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("  - item (hash mismatch)\n")
    );
    assert_eq!(std::fs::read(target).unwrap(), b"corrupt ciphertext");
    std::fs::remove_dir_all(root).unwrap();
}
