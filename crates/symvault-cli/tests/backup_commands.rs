#[path = "../src/backup_commands.rs"]
mod backup_commands;

#[test]
fn backup_suffix_restore_and_required_files_match_go() {
    let root = std::env::temp_dir().join(format!("vault-backup-cli-{}", std::process::id()));
    std::fs::create_dir_all(root.join("source/entries")).unwrap();
    for (name, bytes) in [
        ("identity.age", "synthetic identity"),
        ("config.yaml", "synthetic config"),
        ("entries/item.age", "synthetic ciphertext"),
    ] {
        std::fs::write(root.join("source").join(name), bytes).unwrap();
    }
    let backup =
        backup_commands::backup(&root.join("source"), &root.join("nested/copy"), true).unwrap();
    assert!(backup.ends_with("copy.tar.gz"));
    backup_commands::restore(&root.join("restored"), &backup).unwrap();
    assert_eq!(
        std::fs::read(root.join("restored/entries/item.age")).unwrap(),
        b"synthetic ciphertext"
    );
    std::fs::remove_file(root.join("source/identity.age")).unwrap();
    backup_commands::backup(&root.join("source"), &backup, true).unwrap();
    assert!(
        backup_commands::restore(&root.join("invalid"), &backup)
            .unwrap_err()
            .contains("missing required file: identity.age")
    );
    std::fs::remove_dir_all(root).unwrap();
}
