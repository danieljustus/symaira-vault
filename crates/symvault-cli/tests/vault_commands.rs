#[path = "../src/vault_commands.rs"]
mod vault_commands;

use std::{
    collections::BTreeMap,
    fs,
    io::Cursor,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use symvault_crypto::{SecretBytes, decrypt_identity};
use symvault_store::{Entry, EntryMetadata, SecretMetadata, Store};

fn temporary_root() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("symvault-cli-commands-{suffix}"))
}

#[test]
fn initialize_round_trip_and_read_only_commands() {
    let root = temporary_root();
    fs::create_dir_all(&root).expect("root");
    let passphrase = SecretBytes::new(b"correct horse battery staple");
    let identity = vault_commands::initialize(&root, &passphrase).expect("initialize");

    let encrypted = fs::read(root.join("identity.age")).expect("identity");
    let recovered = decrypt_identity(&encrypted, &passphrase).expect("decrypt identity");
    assert_eq!(
        symvault_crypto::recipient_string(&recovered),
        symvault_crypto::recipient_string(&identity)
    );

    let store = Store::open(&root, &identity).expect("open");
    let mut data = BTreeMap::new();
    data.insert("password".to_owned(), serde_json::json!("secret"));
    data.insert("username".to_owned(), serde_json::json!("alice"));
    store
        .write_new_entry(
            "work/github",
            &Entry {
                data,
                metadata: EntryMetadata {
                    created: "2026-01-01T00:00:00Z".to_owned(),
                    updated: "2026-01-02T03:04:05Z".to_owned(),
                    version: 1,
                    ..EntryMetadata::default()
                },
                secret_metadata: SecretMetadata {
                    secret_type: "login".to_owned(),
                    usage_hint: "credential".to_owned(),
                    ..SecretMetadata::default()
                },
                ..Entry::default()
            },
            &identity,
        )
        .expect("write entry");

    let entries = vault_commands::list(&root, &identity, "work/").expect("list");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "work/github");
    assert!(entries[0].has_value);
    assert_eq!(entries[0].field_count, 2);

    let mut output = Cursor::new(Vec::new());
    vault_commands::write_list(&mut output, &entries, "text", false).expect("text list");
    assert_eq!(output.into_inner(), b"work/github\n");

    let mut output = Cursor::new(Vec::new());
    vault_commands::write_list(&mut output, &entries, "json", false).expect("json list");
    let json: serde_json::Value = serde_json::from_slice(&output.into_inner()).expect("json");
    assert_eq!(json[0]["path"], "work/github");
    assert_eq!(json[0]["type"], "login");
    assert_eq!(json[0]["field_count"], 2);

    let mut output = Cursor::new(Vec::new());
    vault_commands::write_list(&mut output, &entries, "text", true).expect("quiet list");
    assert!(output.into_inner().is_empty());

    let result = vault_commands::get(&root, &identity, "work/github.password").expect("get");
    let mut output = Cursor::new(Vec::new());
    vault_commands::write_get(&mut output, &result, "text", false).expect("text get");
    assert_eq!(output.into_inner(), b"secret\n");

    let result = vault_commands::get(&root, &identity, "work/github").expect("get entry");
    let mut output = Cursor::new(Vec::new());
    vault_commands::write_get(&mut output, &result, "json", false).expect("json get");
    let json: serde_json::Value = serde_json::from_slice(&output.into_inner()).expect("json");
    assert_eq!(json["Path"], "work/github");
    assert_eq!(json["Fields"]["username"], "alice");

    let result = vault_commands::get(&root, &identity, "work/github.missing");
    assert!(result.is_err());
    assert!(matches!(
        vault_commands::get(&root, &identity, "github"),
        Ok(vault_commands::GetResult::Entry { path, .. }) if path == "work/github"
    ));

    let dotted_path = "work/dotted.name";
    store
        .write_new_entry(
            dotted_path,
            &Entry {
                data: BTreeMap::from([(String::from("value"), serde_json::json!("dotted"))]),
                ..Entry::default()
            },
            &identity,
        )
        .expect("write dotted entry");
    assert!(matches!(
        vault_commands::get(&root, &identity, dotted_path),
        Ok(vault_commands::GetResult::Entry { .. })
    ));

    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn initialize_rejects_existing_vault_and_empty_passphrase() {
    let root = temporary_root();
    fs::create_dir_all(&root).expect("root");
    assert!(vault_commands::initialize(&root, &SecretBytes::new(b"")).is_err());
    fs::write(root.join("config.yaml"), b"vaultDir: test\n").expect("config");
    assert!(
        vault_commands::initialize(&root, &SecretBytes::new(b"long enough passphrase")).is_err()
    );
    fs::remove_dir_all(root).expect("cleanup");
}
