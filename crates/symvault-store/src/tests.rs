use std::{collections::BTreeMap, fs, path::Path};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use symvault_crypto::parse_identity;

use super::*;

const IDENTITY: &str = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL";
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/port/store/store.json"
);

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    oracle: Oracle,
    vaults: Vec<VaultVector>,
    malformed_cases: Vec<Malformed>,
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
struct VaultVector {
    name: String,
    layout: String,
    files: Vec<FileVector>,
    directories: Vec<DirVector>,
    entries: Vec<EntryVector>,
    presence: Presence,
    migration: MigrationVector,
    type_vectors: Vec<TypeVector>,
}
#[derive(Debug, Deserialize)]
struct TypeVector {
    name: String,
    value: String,
    path: Option<String>,
    field: Option<String>,
    explicit: Option<String>,
    expected: String,
}
#[derive(Debug, Deserialize)]
struct MigrationVector {
    before: TreeVector,
    after: TreeVector,
    marker: String,
    marker_sha256: String,
    data_preserved: bool,
}
#[derive(Debug, Deserialize)]
struct TreeVector {
    files: Vec<FileVector>,
    directories: Vec<DirVector>,
}
#[derive(Debug, Deserialize)]
struct FileVector {
    path: String,
    mode: u32,
    size: i64,
    sha256: String,
    content: String,
}
#[derive(Debug, Deserialize)]
struct DirVector {
    path: String,
    mode: u32,
}
#[derive(Debug, Deserialize)]
struct EntryVector {
    name: String,
    path: String,
    storage_path: String,
    expected: serde_json::Value,
    expected_json: String,
    before_expected: serde_json::Value,
    before_json: String,
}
#[derive(Debug, Deserialize)]
struct Malformed {
    name: String,
    input: String,
}

fn fixture() -> (String, Fixture) {
    let raw = fs::read_to_string(FIXTURE).expect("Go store fixture");
    let value = serde_json::from_str(&raw).expect("valid store fixture");
    (raw, value)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_fixture(value: &Fixture) -> Result<(), String> {
    if value.schema_version != 1 {
        return Err("schema version changed".into());
    }
    if value.oracle.commit != "caadd5e" || value.oracle.release != "v0.22.1" {
        return Err("oracle pin changed".into());
    }
    if value.oracle.source_files.len() != 12
        || value.oracle.generator_files.len() != 2
        || value.oracle.source_digest.len() != 64
        || value.oracle.generator_digest.len() != 64
    {
        return Err("oracle provenance is incomplete".into());
    }
    let vault_names: Vec<_> = value
        .vaults
        .iter()
        .map(|vault| vault.name.as_str())
        .collect();
    if vault_names != ["fresh", "legacy"] {
        return Err(format!("vault names changed: {vault_names:?}"));
    }
    for (vault, expected_layout) in value.vaults.iter().zip(["fresh", "legacy"]) {
        if vault.layout != expected_layout
            || vault.files.len() != 9
            || vault.entries.len() != 3
            || vault.directories.is_empty()
        {
            return Err(format!("{} cardinality/layout changed", vault.name));
        }
        if !vault.presence.config || !vault.presence.identity || !vault.presence.recipients {
            return Err(format!("{} presence incomplete", vault.name));
        }
        if vault.migration.marker != ".symvault-migrated"
            || vault.migration.marker_sha256 != sha256_hex(b"")
            || !vault.migration.data_preserved
            || vault.migration.before.files.is_empty()
            || vault.migration.after.files.is_empty()
        {
            return Err(format!("{} migration evidence incomplete", vault.name));
        }
        let before_semantic: BTreeMap<_, _> = vault
            .migration
            .before
            .files
            .iter()
            .map(|file| (file.path.trim_start_matches("entries/"), &file.sha256))
            .collect();
        let after_semantic: BTreeMap<_, _> = vault
            .migration
            .after
            .files
            .iter()
            .filter(|file| file.path != ".symvault-migrated")
            .map(|file| (file.path.trim_start_matches("entries/"), &file.sha256))
            .collect();
        if before_semantic != after_semantic {
            return Err(format!("{} migration changed file content", vault.name));
        }
        for entry in &vault.entries {
            if entry.before_expected != entry.expected || entry.before_json != entry.expected_json {
                return Err(format!(
                    "{} entry {} changed during migration",
                    vault.name, entry.name
                ));
            }
            if entry.expected_json.is_empty() || entry.before_json.is_empty() {
                return Err(format!(
                    "{} entry {} lacks exact JSON bytes",
                    vault.name, entry.name
                ));
            }
        }
        if vault.type_vectors.len() != 25 {
            return Err(format!("{} type vector cardinality changed", vault.name));
        }
        let type_names: Vec<_> = vault
            .type_vectors
            .iter()
            .map(|vector| vector.name.as_str())
            .collect();
        if type_names
            != [
                "empty",
                "ssh",
                "certificate",
                "database",
                "github_pat",
                "github_fine_grained",
                "github_malformed",
                "aws",
                "aws_malformed",
                "totp",
                "totp_malformed",
                "jwt",
                "jwt_malformed",
                "basic",
                "basic_malformed",
                "generic_api_key",
                "generic_malformed",
                "password",
                "explicit_custom",
                "explicit_payment",
                "unknown_explicit",
                "path_seed",
                "field_certificate",
                "field_connection_string",
                "path_api_key",
            ]
        {
            return Err(format!("{} type vector names changed", vault.name));
        }
        let entry_names: Vec<_> = vault
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        if entry_names != ["minimal", "full", "nested/large"] {
            return Err(format!("{} entry names changed", vault.name));
        }
        for file in &vault.files {
            let bytes = STANDARD
                .decode(&file.content)
                .map_err(|error| error.to_string())?;
            if bytes.len() as i64 != file.size || sha256_hex(&bytes) != file.sha256 {
                return Err(format!(
                    "{} file digest mismatch for {}",
                    vault.name, file.path
                ));
            }
        }
    }
    let malformed: Vec<_> = value
        .malformed_cases
        .iter()
        .map(|case| case.name.as_str())
        .collect();
    if malformed != ["empty", "not_age", "bad_stanza"] {
        return Err("malformed names changed".into());
    }
    Ok(())
}

fn materialize(root: &Path, vault: &VaultVector) {
    let tree = if vault.layout == "legacy" {
        &vault.migration.before
    } else {
        &vault.migration.after
    };
    for dir in &tree.directories {
        fs::create_dir_all(root.join(&dir.path)).unwrap();
        set_mode(&root.join(&dir.path), dir.mode);
    }
    for file in &tree.files {
        let path = root.join(&file.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, STANDARD.decode(&file.content).unwrap()).unwrap();
        set_mode(&path, file.mode);
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

#[test]
fn manifest_verification_reports_valid_tampered_missing_and_unknown() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &value.vaults[0]);
    let store = Store::open(temp.path(), &identity).unwrap();
    let clean = store.verify_manifest(&identity).unwrap();
    assert_eq!(clean.ok, 3);
    assert!(clean.missing.is_empty());
    assert!(clean.tampered.is_empty());
    assert!(clean.unknown.is_empty());

    fs::remove_file(temp.path().join("entries/minimal.age")).unwrap();
    fs::write(temp.path().join("entries/full.age"), b"tampered").unwrap();
    fs::write(temp.path().join("entries/unknown.age"), b"unknown").unwrap();
    let result = store.verify_manifest(&identity).unwrap();
    assert_eq!(result.missing, vec!["minimal"]);
    assert_eq!(result.tampered, vec!["full"]);
    assert_eq!(result.unknown, vec!["unknown.age"]);
}

#[test]
fn legacy_migration_moves_ciphertext_and_is_idempotent() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &value.vaults[1]);
    let store = Store::open(temp.path(), &identity).unwrap();
    assert_eq!(store.layout(), Layout::Legacy);
    store.migrate_legacy().unwrap();
    store.migrate_legacy().unwrap();
    assert!(temp.path().join(".symvault-migrated").is_file());
    assert_eq!(
        store.list(&identity).unwrap(),
        vec!["full", "minimal", "nested/large"]
    );
    for entry in &value.vaults[1].entries {
        assert!(temp.path().join(&entry.storage_path).is_file());
        assert_eq!(
            store.get(&entry.path, &identity).unwrap(),
            serde_json::from_value::<Entry>(entry.expected.clone()).unwrap()
        );
    }
}

#[test]
fn replacement_is_atomic_and_never_follows_symlink_targets() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &value.vaults[0]);
    let store = Store::open(temp.path(), &identity).unwrap();
    let mut data = BTreeMap::new();
    data.insert("token".into(), serde_json::Value::String("old".into()));
    let entry = Entry {
        path: "replace".into(),
        data,
        ..Entry::default()
    };
    store.write_entry("replace", &entry, &identity).unwrap();
    let mut updated = entry.clone();
    updated
        .data
        .insert("token".into(), serde_json::Value::String("new".into()));
    let expected = {
        let mut value = updated.clone();
        value.metadata.version = 1;
        value
    };
    store.write_entry("replace", &updated, &identity).unwrap();
    assert_eq!(store.get("replace", &identity).unwrap(), expected);
    assert!(
        !fs::read_dir(temp.path().join("entries"))
            .unwrap()
            .any(|item| {
                item.unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp-")
            })
    );
    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("outside");
        fs::write(&target, b"must stay").unwrap();
        fs::remove_file(temp.path().join("entries/replace.age")).unwrap();
        std::os::unix::fs::symlink(&target, temp.path().join("entries/replace.age")).unwrap();
        assert!(matches!(
            store.write_entry("replace", &updated, &identity),
            Err(StoreError::Symlink(_))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"must stay");
    }
}

#[test]
fn encrypted_search_index_matches_case_insensitive_nested_values_and_invalidates() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &value.vaults[0]);
    let store = Store::open(temp.path(), &identity).unwrap();
    let mut index = SearchIndex::build(&store, &identity).unwrap();
    let candidates = store.list(&identity).unwrap();
    assert_eq!(
        index
            .search(&candidates, "FIXTURE-USER")
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["minimal"]
    );
    assert_eq!(
        index
            .search(&candidates, "DEEP-FIXTURE")
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["nested/large"]
    );
    let raw = fs::read(temp.path().join(".search-index")).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("fixture-user"));
    let mut loaded = SearchIndex::load(&store, &identity).unwrap().unwrap();
    assert_eq!(
        loaded
            .search(&candidates, "fixture-full-user")
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["full"]
    );
    loaded.invalidate().unwrap();
    assert!(!temp.path().join(".search-index").exists());
}

#[test]
fn stale_or_corrupt_search_index_is_discarded() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &value.vaults[0]);
    let store = Store::open(temp.path(), &identity).unwrap();
    let _ = SearchIndex::build(&store, &identity).unwrap();
    fs::write(temp.path().join(".search-index"), b"corrupt").unwrap();
    assert!(SearchIndex::load(&store, &identity).unwrap().is_none());
    let mut data = BTreeMap::new();
    data.insert("value".into(), serde_json::Value::String("new".into()));
    store
        .write_entry(
            "new",
            &Entry {
                data,
                ..Entry::default()
            },
            &identity,
        )
        .unwrap();
    let _ = SearchIndex::build(&store, &identity).unwrap();
    fs::remove_file(temp.path().join("entries/new.age")).unwrap();
    assert!(SearchIndex::load(&store, &identity).unwrap().is_none());
}

#[test]
fn fixture_has_authoritative_provenance_and_exact_cardinality() {
    let (_, value) = fixture();
    validate_fixture(&value).unwrap();
}

#[test]
fn fixture_omission_and_tamper_checks_fail_closed() {
    let (raw, value) = fixture();
    validate_fixture(&value).unwrap();
    for key in ["vaults", "malformed_cases"] {
        let mut omitted: serde_json::Value = serde_json::from_str(&raw).unwrap();
        omitted[key].as_array_mut().unwrap().pop();
        let parsed: Fixture = serde_json::from_value(omitted).unwrap();
        assert!(validate_fixture(&parsed).is_err(), "accepted omitted {key}");
    }
    let mut tampered: serde_json::Value = serde_json::from_str(&raw).unwrap();
    tampered["vaults"][0]["files"][0]["content"] =
        serde_json::Value::String(STANDARD.encode(b"tampered"));
    let parsed: Fixture = serde_json::from_value(tampered).unwrap();
    assert!(validate_fixture(&parsed).is_err(), "accepted tampered file");
}

#[test]
fn fresh_and_legacy_layouts_open_list_and_get_every_entry() {
    let (_, value) = fixture();
    validate_fixture(&value).unwrap();
    let identity = parse_identity(IDENTITY).unwrap();
    for vault_vector in &value.vaults {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        materialize(&root, vault_vector);
        let store = Store::open(&root, &identity).unwrap();
        assert_eq!(
            store.layout(),
            if vault_vector.layout == "fresh" {
                Layout::Fresh
            } else {
                Layout::Legacy
            }
        );
        assert_eq!(store.presence(), &vault_vector.presence);
        assert_eq!(store.recipients().unwrap().len(), 1);
        assert_eq!(
            store.list(&identity).unwrap(),
            vec!["full", "minimal", "nested/large"]
        );
        for vector in &vault_vector.entries {
            let expected: Entry = serde_json::from_value(vector.expected.clone()).unwrap();
            let storage_path = if vault_vector.layout == "legacy" {
                root.join(format!("{}.age", vector.path))
            } else {
                root.join(&vector.storage_path)
            };
            assert!(storage_path.is_file(), "missing {}", vector.storage_path);
            let got = store.get(&vector.path, &identity).unwrap();
            assert_eq!(got, expected, "{} {}", vault_vector.name, vector.name);
            assert_eq!(
                serde_json::to_vec(&got).unwrap(),
                vector.expected_json.as_bytes(),
                "serialized JSON {} {}",
                vault_vector.name,
                vector.name
            );
            let debug = format!("{got:?}");
            for value in got.data.values() {
                if let serde_json::Value::String(value) = value {
                    assert!(!debug.contains(value), "debug leaked entry value");
                }
            }
            assert_eq!(
                store.get_metadata(&vector.path, &identity).unwrap(),
                expected.metadata
            );
        }
        let expected_tree = if vault_vector.layout == "legacy" {
            &vault_vector.migration.before
        } else {
            &vault_vector.migration.after
        };
        let files = store.files().unwrap();
        assert_eq!(
            files.len(),
            expected_tree.files.len() + expected_tree.directories.len()
        );
        for file in &expected_tree.files {
            let got = files
                .iter()
                .find(|candidate| candidate.path == file.path)
                .unwrap();
            assert_eq!(got.kind, FileKind::Regular, "kind {}", file.path);
            #[cfg(unix)]
            assert_eq!(got.mode, file.mode, "mode {}", file.path);
            assert_eq!(got.size, file.size as u64, "size {}", file.path);
            assert_eq!(got.sha256, file.sha256, "hash {}", file.path);
        }
        for directory in &expected_tree.directories {
            let got = files
                .iter()
                .find(|candidate| candidate.path == directory.path)
                .unwrap();
            assert_eq!(got.kind, FileKind::Directory, "kind {}", directory.path);
            #[cfg(unix)]
            assert_eq!(got.mode, directory.mode, "mode {}", directory.path);
            assert_eq!(got.sha256, sha256_hex(b""), "hash {}", directory.path);
        }
    }
}

#[test]
fn fresh_layout_writes_a_new_entry_atomically_and_reads_it_back() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    materialize(root, &value.vaults[0]);
    let store = Store::open(root, &identity).unwrap();
    let mut data = BTreeMap::new();
    data.insert(
        "token".to_owned(),
        serde_json::Value::String("write-slice-secret".to_owned()),
    );
    let entry = Entry {
        path: "written".to_owned(),
        data,
        ..Entry::default()
    };

    store.write_new_entry("written", &entry, &identity).unwrap();
    assert_eq!(store.get("written", &identity).unwrap(), entry);
    assert!(root.join("entries/written.age").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(root.join("entries/written.age"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert!(!fs::read_dir(root.join("entries")).unwrap().any(|item| {
        item.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".written.age.tmp-")
    }));

    let error = store
        .write_new_entry("written", &entry, &identity)
        .unwrap_err();
    assert!(matches!(error, StoreError::Config(message) if message.contains("replacement")));
}

#[test]
fn fresh_layout_write_supports_pseudonymized_nested_and_dotted_paths() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    materialize(root, &value.vaults[0]);
    fs::write(
        root.join(CONFIG_FILE),
        b"vault:\n  pseudonymize_paths: true\n",
    )
    .unwrap();
    let store = Store::open(root, &identity).unwrap();
    let entry = Entry {
        data: BTreeMap::from([(
            "token".to_owned(),
            serde_json::Value::String("pseudonymized-secret".to_owned()),
        )]),
        ..Entry::default()
    };
    store
        .write_new_entry("nested.name/written.v1", &entry, &identity)
        .unwrap();
    let got = store.get("nested.name/written.v1", &identity).unwrap();
    assert_eq!(got.path, "nested.name/written.v1");
    assert_eq!(got.data, entry.data);
    assert!(!root.join("entries/nested.name").exists());
    let hash = symvault_crypto::pseudonymize_path(&identity, "nested.name/written.v1");
    assert!(
        root.join(format!("entries/{}/{}.age", &hash[..2], hash))
            .is_file()
    );
}

#[test]
fn fresh_layout_write_uses_all_configured_recipients_and_preserves_dots() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let other = parse_identity(
        "AGE-SECRET-KEY-18HD87KNMWKY3RW97YR2PYU6HGWDZXAGW6JF74LNNHUA6A8K5ZF9QTWUTK3",
    )
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    materialize(root, &value.vaults[0]);
    fs::write(
        root.join(RECIPIENTS_FILE),
        format!("{}\n", recipient_string(&other)),
    )
    .unwrap();
    let store = Store::open(root, &identity).unwrap();
    let entry = Entry::default();
    store
        .write_new_entry("service.v1", &entry, &identity)
        .unwrap();
    let ciphertext = fs::read(root.join("entries/service.v1.age")).unwrap();
    assert_eq!(
        symvault_crypto::decrypt(&ciphertext, &other).unwrap(),
        serde_json::to_vec(&entry).unwrap()
    );
}

#[test]
fn fresh_layout_write_rejects_invalid_paths_before_touching_disk() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    materialize(root, &value.vaults[0]);
    let store = Store::open(root, &identity).unwrap();
    let error = store
        .write_new_entry("../written", &Entry::default(), &identity)
        .unwrap_err();
    assert!(matches!(error, StoreError::InvalidEntryPath(_)));
    assert!(!root.join("written.age").exists());
}
#[test]
fn malformed_encrypted_vectors_are_rejected() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    materialize(&root, &value.vaults[0]);
    let malformed_root = root.join("entries/malformed");
    fs::create_dir_all(&malformed_root).unwrap();
    for case in &value.malformed_cases {
        let error = symvault_crypto::decrypt(case.input.as_bytes(), &identity).unwrap_err();
        assert_eq!(
            error.class(),
            symvault_crypto::FailureClass::MalformedEnvelope,
            "{}",
            case.name
        );
        fs::write(
            malformed_root.join(format!("{}.age", case.name)),
            case.input.as_bytes(),
        )
        .unwrap();
    }
    let store = Store::open(&root, &identity).unwrap();
    let listed = store.list(&identity).unwrap();
    for case in &value.malformed_cases {
        let path = format!("malformed/{}", case.name);
        assert!(listed.contains(&path), "missing {path} from list");
        assert!(matches!(
            store.get(&path, &identity),
            Err(StoreError::Decryption(_))
        ));
    }
}

#[test]
fn bounded_reads_reject_oversized_config_and_entry() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let config_temp = tempfile::tempdir().unwrap();
    let config_root = config_temp.path();
    materialize(config_root, &value.vaults[0]);
    fs::write(
        config_root.join(CONFIG_FILE),
        vec![b'x'; (MAX_FILE_BYTES + 1) as usize],
    )
    .unwrap();
    assert!(matches!(
        Store::open(config_root, &identity),
        Err(StoreError::Limit { .. })
    ));

    let entry_temp = tempfile::tempdir().unwrap();
    let entry_root = entry_temp.path();
    materialize(entry_root, &value.vaults[0]);
    fs::write(
        entry_root.join("entries/minimal.age"),
        vec![b'x'; (MAX_FILE_BYTES + 1) as usize],
    )
    .unwrap();
    let store = Store::open(entry_root, &identity).unwrap();
    assert!(matches!(
        store.get("minimal", &identity),
        Err(StoreError::Limit { .. })
    ));
}

#[test]
fn path_validation_and_symlink_reads_fail_closed() {
    for path in [
        "../identity",
        "a/../../b",
        "./entry",
        "/absolute",
        "entries/../identity",
        "",
    ] {
        assert!(validate_entry_path(path).is_err(), "accepted {path:?}");
    }
    let (_, value) = fixture();
    let _identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    materialize(&root, &value.vaults[0]);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            root.join("entries/minimal.age"),
            root.join("entries/link.age"),
        )
        .unwrap();
        assert!(matches!(
            Store::open(&root, &_identity),
            Err(StoreError::Symlink(_))
        ));
    }
}

#[test]
fn type_inference_matches_read_only_entry_contract() {
    let (_, value) = fixture();
    for vector in &value.vaults[0].type_vectors {
        let got = if vector.path.is_some() || vector.field.is_some() || vector.explicit.is_some() {
            infer_secret_type(
                vector.path.as_deref().unwrap_or_default(),
                vector.field.as_deref().unwrap_or_default(),
                &vector.value,
                vector.explicit.as_deref(),
            )
        } else {
            detect_secret_type(&vector.value)
        };
        assert_eq!(got.as_str(), vector.expected, "{}", vector.name);
    }
    assert_eq!(
        infer_secret_type("service/api-key", "", "ordinary", None),
        SecretType::ApiKey
    );
    assert_eq!(
        infer_secret_type("anything", "token", "ordinary", None),
        SecretType::BearerToken
    );
    assert_eq!(
        infer_secret_type("anything", "", "postgres://fixture", None),
        SecretType::DatabaseUrl
    );
    assert_eq!(
        infer_secret_type("anything", "", "ordinary", Some("certificate")),
        SecretType::Certificate
    );
    assert_eq!(
        infer_secret_type("anything", "", "ordinary", None),
        SecretType::Password
    );
}

#[test]
fn file_manifest_is_sorted_and_contains_metadata() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    materialize(&root, &value.vaults[0]);
    let store = Store::open(&root, &identity).unwrap();
    let files = store.files().unwrap();
    let paths: Vec<_> = files.iter().map(|file| file.path.as_str()).collect();
    let mut sorted = paths.clone();
    sorted.sort_unstable();
    assert_eq!(paths, sorted);
    #[cfg(unix)]
    assert!(files.iter().all(|file| file.mode > 0));
}

#[cfg(unix)]
#[test]
fn atomic_create_holds_parent_capability_across_ancestor_replacement() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let checked = root.path().join("checked");
    let outside = root.path().join("outside");
    fs::create_dir(&checked).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"must stay unchanged").unwrap();

    let parent = ensure_directory_recursive(&checked.canonicalize().unwrap()).unwrap();
    fs::rename(&checked, root.path().join("actual")).unwrap();
    symlink(&outside, &checked).unwrap();

    let target = checked.join("published.age");
    atomic_create(&target, b"published only in retained directory", &parent).unwrap();
    assert_eq!(
        fs::read(outside.join("sentinel")).unwrap(),
        b"must stay unchanged"
    );
    assert_eq!(
        fs::read(root.path().join("actual/published.age")).unwrap(),
        b"published only in retained directory"
    );
    assert!(!outside.join("published.age").exists());

    fs::write(
        root.path().join("actual/collision.age"),
        b"collision sentinel",
    )
    .unwrap();
    let collision = root.path().join("checked/collision.age");
    let error = atomic_create(&collision, b"replacement", &parent).unwrap_err();
    assert!(matches!(error, StoreError::Config(message) if message.contains("replacement")));
    assert_eq!(
        fs::read(root.path().join("actual/collision.age")).unwrap(),
        b"collision sentinel"
    );
}

#[cfg(unix)]
#[test]
fn concurrent_capability_publication_creates_all_entries_without_temp_leaks() {
    use std::thread;

    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let parent_path = root_path.join("entries/shared/deep");
    let mut workers = Vec::new();
    for index in 0..8 {
        let parent_path = parent_path.clone();
        workers.push(thread::spawn(move || {
            let parent = ensure_directory_recursive(&parent_path).unwrap();
            let target = parent_path.join(format!("entry-{index}.age"));
            atomic_create(&target, format!("payload-{index}").as_bytes(), &parent).unwrap();
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    for index in 0..8 {
        assert_eq!(
            fs::read(parent_path.join(format!("entry-{index}.age"))).unwrap(),
            format!("payload-{index}").as_bytes()
        );
    }
    assert!(!fs::read_dir(&parent_path).unwrap().any(|item| {
        item.unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")
    }));
}
