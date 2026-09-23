#![deny(unsafe_code)]

#[path = "../src/export_commands.rs"]
#[allow(dead_code)]
mod export_commands;
#[path = "../src/import_commands.rs"]
mod import_commands;
#[allow(dead_code)]
#[path = "../src/vault_commands.rs"]
mod vault_commands;
#[allow(dead_code)]
#[path = "../src/write_commands.rs"]
mod write_commands;

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use symvault_crypto::SecretBytes;
use symvault_store::{Entry, Store};

fn decode_base64(value: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            break;
        }
        let digit = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .expect("fixture base64 alphabet") as u32;
        buffer = (buffer << 6) | digit;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    output
}

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
        |_, _, _, _| panic!("unexpected secret metadata"),
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
        ..options.clone()
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
        |_, _, _, _| panic!("unexpected secret metadata"),
    )
    .expect_err("malformed import must fail");
    assert!(error.contains("parse import source"));
    assert_eq!(malformed_writes, 0);

    let collision = root.join("collision.csv");
    fs::write(
        &collision,
        b"name,url,username,password,note\n\xFF,https://one.example,u1,p1,\n\xFE,https://two.example,u2,p2,\n",
    )
    .expect("collision source");
    let collision_options = import_commands::ImportOptions {
        source: collision,
        format: Some("chrome".into()),
        ..options
    };
    let mut collision_writes = 0;
    let error = import_commands::run_import(
        &root,
        &identity,
        &collision_options,
        |_, _, _, _| {
            collision_writes += 1;
            Ok(())
        },
        |_, _, _, _| Ok(()),
        |_, _, _, _| panic!("unexpected secret metadata"),
    )
    .expect_err("colliding paths must fail before writes");
    assert!(error.contains("distinct CSV paths"));
    assert_eq!(collision_writes, 0);
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
fn quarantine_prefix_uses_go_import_id_shape_and_rejects_prefix() {
    let (prefix, import_id) =
        import_commands::resolve_import_prefix("", true).expect("quarantine prefix");
    let import_id = import_id.expect("quarantine import ID");
    assert_eq!(prefix, format!("quarantine/{import_id}"));
    assert_eq!(
        symvault_sync::importer::apply_prefix(&prefix, "example"),
        format!("quarantine/{import_id}/example")
    );
    let suffix = import_id.strip_prefix("import-").expect("import prefix");
    let (date, random) = suffix.split_once('-').expect("date separator");
    assert_eq!(date.len(), 8);
    assert!(date.bytes().all(|byte| byte.is_ascii_digit()));
    assert_eq!(random.len(), 8);
    assert!(
        random
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    assert_eq!(
        import_commands::resolve_import_prefix("work", true).unwrap_err(),
        "--quarantine and --prefix cannot be used together"
    );
    assert_eq!(
        import_commands::resolve_import_prefix("work", false).unwrap(),
        ("work".into(), None)
    );
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
        |_, _, _, _| panic!("metadata must not run after replacement failure"),
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

#[test]
fn cxf_import_preserves_secret_metadata_and_write_version() {
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../../testdata/port/import/cxf.json"))
            .expect("CXF fixture");
    let input = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "CXF-001-features")
        .and_then(|case| case["input_b64"].as_str())
        .map(decode_base64)
        .expect("feature CXF input");

    let root = temporary_root();
    fs::create_dir_all(&root).expect("root");
    let identity =
        vault_commands::initialize(&root, &SecretBytes::new(b"correct horse battery staple"))
            .expect("initialize");
    let source = root.join("features.zip");
    fs::write(&source, input).expect("source");
    let result = import_commands::run_import(
        &root,
        &identity,
        &import_commands::ImportOptions {
            source,
            format: Some("cxf".into()),
            dry_run: false,
            prefix: String::new(),
            skip_existing: false,
            overwrite: false,
            mapping: String::new(),
        },
        write_commands::import_fields,
        write_commands::replace_fields,
        write_commands::set_secret_type,
    )
    .expect("CXF import");
    assert!(result.imported > 0);

    let store = Store::open(&root, &identity).expect("open imported vault");
    let entries: Vec<_> = store
        .list(&identity)
        .unwrap()
        .into_iter()
        .map(|path| store.get(&path, &identity).unwrap())
        .filter(|entry| !entry.secret_metadata.secret_type.is_empty())
        .collect();
    assert!(
        entries
            .iter()
            .any(|entry| entry.secret_metadata.secret_type == "ssh_key")
    );
    assert!(entries.iter().all(|entry| entry.metadata.version >= 2));
    let _ = fs::remove_dir_all(root);
}
