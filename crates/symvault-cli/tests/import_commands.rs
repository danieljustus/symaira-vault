#![deny(unsafe_code)]

#[path = "../src/export_commands.rs"]
#[allow(dead_code)]
mod export_commands;
#[path = "../src/import_commands.rs"]
mod import_commands;
#[allow(dead_code)]
#[path = "../src/vault_commands.rs"]
mod vault_commands;

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use symvault_crypto::SecretBytes;
use symvault_store::{Entry, Store};

fn temporary_root() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    std::env::temp_dir().join(format!(
        "symvault-cli-import-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn csv_import_and_malformed_input_preserve_vault_state() {
    let root = temporary_root();
    fs::create_dir_all(&root).expect("root");
    let identity =
        vault_commands::initialize(&root, &SecretBytes::new(b"correct horse battery staple"))
            .expect("initialize");
    let store = Store::open(&root, &identity).expect("open");
    store
        .write_new_entry("existing", &Entry::default(), &identity)
        .expect("existing entry");

    let source = root.join("import.csv");
    fs::write(
        &source,
        b"title,password\nnew-entry,secret\nexisting,changed\n",
    )
    .expect("source");
    let options = import_commands::ImportOptions {
        source: source.clone(),
        format: Some("csv".into()),
        dry_run: false,
        prefix: "imports".into(),
        skip_existing: false,
        overwrite: false,
        mapping: String::new(),
    };
    let mut writes = Vec::new();
    let result = import_commands::run_import(
        &root,
        &identity,
        &options,
        |_, _, path, data| {
            writes.push((path.to_owned(), data));
            Ok(())
        },
        |_, _, _, _| panic!("unexpected replacement"),
    )
    .expect("import");
    assert_eq!(result.format, "csv");
    assert_eq!(result.imported, 2);
    assert_eq!(result.skipped, 0);
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0].0, "imports/new-entry");
    assert_eq!(writes[0].1["password"], "secret");

    let malformed = root.join("malformed.csv");
    fs::write(&malformed, b"title,password\n\"unterminated,secret\n").expect("malformed");
    let malformed_options = import_commands::ImportOptions {
        source: malformed,
        ..options
    };
    let mut malformed_writes = 0;
    let error = import_commands::run_import(
        &root,
        &identity,
        &malformed_options,
        |_, _, _, _| {
            malformed_writes += 1;
            Ok(())
        },
        |_, _, _, _| Ok(()),
    )
    .expect_err("malformed import must fail");
    assert!(error.contains("parse import source"));
    assert_eq!(malformed_writes, 0);
    assert!(
        Store::open(&root, &identity)
            .unwrap()
            .get("existing", &identity)
            .is_ok()
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn mapping_parser_matches_go_empty_segments_and_duplicate_keys() {
    let mapping =
        export_commands::parse_mapping("title=Name,, password=Secret,title=Title").unwrap();
    assert_eq!(
        mapping,
        BTreeMap::from([
            ("password".to_owned(), "Secret".to_owned()),
            ("title".to_owned(), "Title".to_owned()),
        ])
    );
    assert!(export_commands::parse_mapping("title").is_err());
}

#[test]
fn failed_overwrite_keeps_the_existing_entry() {
    let root = temporary_root();
    fs::create_dir_all(&root).expect("root");
    let identity =
        vault_commands::initialize(&root, &SecretBytes::new(b"correct horse battery staple"))
            .expect("initialize");
    let store = Store::open(&root, &identity).expect("open");
    store
        .write_new_entry(
            "existing",
            &Entry {
                data: BTreeMap::from([("password".into(), serde_json::json!("old"))]),
                ..Entry::default()
            },
            &identity,
        )
        .expect("existing entry");

    let source = root.join("overwrite.csv");
    fs::write(&source, b"title,password\nexisting,new\n").expect("source");
    let options = import_commands::ImportOptions {
        source,
        format: Some("csv".into()),
        dry_run: false,
        prefix: String::new(),
        skip_existing: false,
        overwrite: true,
        mapping: String::new(),
    };
    let error = import_commands::run_import(
        &root,
        &identity,
        &options,
        |_, _, _, _| panic!("overwrite must use replacement callback"),
        |_, _, _, _| Err("injected replacement failure".into()),
    )
    .expect_err("replacement failure must be returned");
    assert!(error.contains("cannot overwrite entry existing"));
    let entry = Store::open(&root, &identity)
        .unwrap()
        .get("existing", &identity)
        .unwrap();
    assert_eq!(entry.data["password"], "old");
    let _ = fs::remove_dir_all(root);
}
