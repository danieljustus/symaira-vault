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
        value.classification = 2;
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
fn remove_path_rejects_targets_outside_root() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &value.vaults[0]);
    let store = Store::open(temp.path(), &identity).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("sentinel");
    fs::write(&target, b"must stay").unwrap();

    assert!(matches!(
        store.remove_path(&target),
        Err(StoreError::UnsafePath(_))
    ));
    assert_eq!(fs::read(&target).unwrap(), b"must stay");
}

#[test]
fn write_lock_preserves_existing_contents() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &value.vaults[0]);
    let store = Store::open(temp.path(), &identity).unwrap();
    let path = temp.path().join(LOCK_FILE);
    fs::write(&path, b"existing lock contents").unwrap();

    for _ in 0..2 {
        store.with_write_lock(|_| Ok(())).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"existing lock contents");
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
fn single_recipient_writer_infers_go_classification_from_string_values() {
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let (_, fixture) = fixture();
    materialize(temp.path(), &fixture.vaults[0]);
    let store = Store::open(temp.path(), &identity).unwrap();
    let cases = [
        ("password", "ordinary", 2),
        ("api", concat!("AKIA", "1234567890123456"), 3),
        ("bearer", "header.payload.signature", 3),
        ("basic", "user:password", 3),
        ("database", "postgres://user:password@example", 3),
        ("ssh", concat!("-----BEGIN RSA ", "PRIVATE KEY-----"), 4),
        ("certificate", "-----BEGIN CERTIFICATE-----", 4),
        ("totp", "JBSWY3DPEHPK3PXP", 4),
    ];
    for (name, value, expected) in cases {
        let entry = Entry {
            data: BTreeMap::from([(
                "value".to_owned(),
                serde_json::Value::String(value.to_owned()),
            )]),
            ..Entry::default()
        };
        let path = format!("classification/{name}");
        store
            .write_entry_at(
                &path,
                &entry,
                &identity,
                "2026-09-08T10:11:12Z",
                false,
                None,
            )
            .unwrap();
        assert_eq!(
            store.get(&path, &identity).unwrap().classification,
            expected,
            "classification for {name}"
        );
    }
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
fn file_manifest_replacement_after_traversal_uses_opened_metadata() {
    use std::os::unix::fs::PermissionsExt;

    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &value.vaults[0]);
    let store = Store::open(temp.path(), &identity).unwrap();
    let relative = Path::new("replacement-race");
    let path = store.root.join(relative);
    let replacement = temp.path().join("replacement");
    fs::write(&path, b"old").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let observed = rooted::metadata(&store.root_cap, relative, &path).unwrap();

    // Reproduce the boundary between files()' metadata lookup and file_info()'s
    // read, without a scheduler-dependent race or a fabricated oracle fixture.
    let replacement_bytes = b"replacement with a different size and mode";
    fs::write(&replacement, replacement_bytes).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o640)).unwrap();
    fs::rename(&replacement, &path).unwrap();
    let info = store.file_info(relative, observed).unwrap();
    assert_eq!(info.path, "replacement-race");
    assert_eq!(info.kind, FileKind::Regular);
    assert_eq!(info.sha256, sha256_hex(replacement_bytes));
    assert_eq!(info.size, replacement_bytes.len() as u64);
    assert_eq!(info.mode, 0o640);
}

#[cfg(unix)]
#[test]
fn file_manifest_replacement_after_open_keeps_bytes_and_metadata_together() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("entry");
    let replacement = temp.path().join("replacement");
    let original_bytes = b"opened original";
    fs::write(&path, original_bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let opened = fs::File::open(&path).unwrap();

    fs::write(&replacement, b"new").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&replacement, &path).unwrap();
    let (bytes, metadata) = read_open_regular_with_metadata(opened, &path).unwrap();
    assert_eq!(bytes, original_bytes);
    assert_eq!(sha256_hex(&bytes), sha256_hex(original_bytes));
    assert_eq!(metadata.len(), original_bytes.len() as u64);
    assert_eq!(mode_bits(&metadata), 0o640);
    assert_eq!(fs::read(&path).unwrap(), b"new");
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

#[test]
fn malformed_recipient_does_not_create_destination_directories() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    materialize(root, &value.vaults[0]);
    fs::write(root.join(RECIPIENTS_FILE), b"not-an-age-recipient\n").unwrap();
    let store = Store::open(root, &identity).unwrap();
    assert!(matches!(
        store.write_new_entry("new/deep/entry", &Entry::default(), &identity),
        Err(StoreError::Config(_))
    ));
    assert!(!root.join("entries/new").exists());
}

#[test]
fn concurrent_same_target_fresh_writes_have_one_winner_and_no_temp_leak() {
    use std::sync::Arc;
    use std::thread;

    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &value.vaults[0]);
    let store = Arc::new(Store::open(temp.path(), &identity).unwrap());
    let mut workers = Vec::new();
    for index in 0..8 {
        let store = Arc::clone(&store);
        let identity = parse_identity(IDENTITY).unwrap();
        workers.push(thread::spawn(move || {
            let entry = Entry {
                data: BTreeMap::from([(
                    "winner".to_owned(),
                    serde_json::Value::String(format!("payload-{index}")),
                )]),
                ..Entry::default()
            };
            store.write_new_entry("same-target", &entry, &identity)
        }));
    }
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 7);
    let stored = store.get("same-target", &identity).unwrap();
    let payload = stored.data["winner"].as_str().unwrap();
    assert!(payload.starts_with("payload-"));
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
}

#[test]
fn go_index_salt_string_is_not_accepted_by_old_rust_schema() {
    #[allow(dead_code)]
    #[derive(serde::Deserialize)]
    struct OldRustIndexDocument {
        #[serde(rename = "v")]
        values: std::collections::BTreeMap<String, Vec<String>>,
        #[serde(rename = "c")]
        entry_count: usize,
        #[serde(rename = "p")]
        paths: std::collections::BTreeMap<String, EmptyIndexValue>,
        #[serde(rename = "s", default)]
        salt: Vec<u8>,
    }

    let go_document = r#"{
        "v":{"go-doc":["go-rust-accepted"]},
        "c":1,
        "p":{"go-doc":{}},
        "s":"AQIDBAUGBwgJCgsMDQ4PEA=="
    }"#;
    let old_result = serde_json::from_str::<OldRustIndexDocument>(go_document);
    assert!(
        old_result.is_err(),
        "old Rust Vec<u8> salt schema accepted Go base64 string"
    );
    let current = serde_json::from_str::<IndexDocument>(go_document).expect("current Go schema");
    assert_eq!(current.salt, (1u8..=16).collect::<Vec<_>>());
    assert_eq!(current.entry_count, 1);
    assert_eq!(current.values["go-doc"], vec!["go-rust-accepted"]);
    assert!(current.paths.contains_key("go-doc"));
}

#[test]
fn persisted_rust_metadata_matches_all_go_writer_vectors() {
    #[derive(Deserialize)]
    struct MetadataFixture {
        vectors: Vec<MetadataVector>,
    }
    #[derive(Deserialize)]
    struct MetadataVector {
        name: String,
        input: Entry,
        pending_write: Option<WriteRecord>,
        path: String,
        pseudonymize: bool,
        now: String,
        expected: Entry,
        expected_json: String,
    }

    let raw = include_str!("../../../testdata/port/store/metadata.json");
    let metadata_fixture: MetadataFixture = serde_json::from_str(raw).unwrap();
    assert_eq!(metadata_fixture.vectors.len(), 8);
    let case_ids: Vec<_> = metadata_fixture
        .vectors
        .iter()
        .map(|vector| vector.name.as_str())
        .collect();
    assert_eq!(
        case_ids,
        [
            "created_zero_pending",
            "nil_data_existing_version",
            "created_nonzero",
            "offset_clock",
            "created_zero_offset",
            "created_zero_walltime_offset",
            "created_near_zero_nonzero",
            "version_overflow",
        ]
    );

    let (_, store_fixture) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &store_fixture.vaults[0]);
    let store = Store::open(temp.path(), &identity).unwrap();

    for vector in metadata_fixture.vectors {
        // The overflow oracle intentionally has no logical path because it is
        // a pure metadata case; give it a valid publication path here without
        // changing the metadata input or expected wire bytes.
        let path = if vector.path.is_empty() {
            "metadata/version-overflow"
        } else {
            vector.path.as_str()
        };
        store
            .write_entry_at(
                path,
                &vector.input,
                &identity,
                &vector.now,
                vector.pseudonymize,
                vector.pending_write.as_ref(),
            )
            .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
        let persisted = store
            .get(path, &identity)
            .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
        assert_eq!(
            persisted.metadata, vector.expected.metadata,
            "{}",
            vector.name
        );
        let mut expected = vector.expected.clone();
        assert_eq!(
            serde_json::to_string(&expected).unwrap(),
            vector.expected_json
        );
        expected.classification = infer_classification(&expected);
        assert_eq!(
            serde_json::to_string(&persisted).unwrap(),
            serde_json::to_string(&expected).unwrap(),
            "persisted wire output for {}",
            vector.name
        );
    }
}

#[cfg(unix)]
#[test]
fn root_acquisition_rejects_replaced_root_before_parsing_invalid_config() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let moved = temp.path().join("moved");
    let replacement = temp.path().join("replacement");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&replacement).unwrap();
    fs::write(
        root.join("config.yaml"),
        b"vault:\n  pseudonymize_paths: false\n",
    )
    .unwrap();
    fs::write(root.join("identity.age"), b"presence fixture").unwrap();
    let canonical_root = root.canonicalize().unwrap();
    let hook_ran = Arc::new(AtomicBool::new(false));
    let error = Store::open_with_root_acquisition(&root, {
        let root = root.clone();
        let canonical_root = canonical_root.clone();
        let moved = moved.clone();
        let replacement = replacement.clone();
        let hook_ran = hook_ran.clone();
        move |canonical| {
            assert_eq!(canonical, canonical_root);
            fs::rename(&root, &moved).unwrap();
            fs::rename(&replacement, &root).unwrap();
            fs::write(root.join("config.yaml"), b"vault: invalid\n").unwrap();
            fs::write(root.join("identity.age"), b"outsider identity").unwrap();
            hook_ran.store(true, Ordering::SeqCst);
        }
    })
    .unwrap_err();
    assert!(hook_ran.load(Ordering::SeqCst));
    assert!(matches!(error, StoreError::RootChanged(path) if path == root));
    assert!(moved.join("config.yaml").exists());
}

#[cfg(unix)]
#[test]
fn read_list_verify_and_files_use_the_retained_root_capability() {
    let (_, fixture) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let moved = temp.path().join("moved");
    fs::create_dir(&root).unwrap();
    materialize(&root, &fixture.vaults[0]);
    let store = Store::open(&root, &identity).unwrap();

    fs::rename(&root, &moved).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join(CONFIG_FILE), b"vault: invalid\n").unwrap();
    fs::write(root.join(IDENTITY_FILE), b"replacement identity").unwrap();

    assert_eq!(
        store.get("minimal", &identity).unwrap(),
        serde_json::from_value::<Entry>(fixture.vaults[0].entries[0].expected.clone()).unwrap()
    );
    let verification = store.verify_manifest(&identity).unwrap();
    assert_eq!(verification.ok, 3);
    assert!(verification.missing.is_empty());
    assert!(verification.tampered.is_empty());
    assert!(
        store
            .list(&identity)
            .unwrap()
            .contains(&"minimal".to_owned())
    );
    assert!(
        store
            .files()
            .unwrap()
            .iter()
            .any(|file| file.path == "entries/minimal.age")
    );
    assert!(moved.join("entries/minimal.age").is_file());
}

#[test]
fn manifest_verification_ignores_size_mismatch_like_go() {
    let (_, fixture) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &fixture.vaults[0]);
    let store = Store::open(temp.path(), &identity).unwrap();
    let mut manifest = store.load_manifest(&identity).unwrap();
    manifest.entries.get_mut("minimal").unwrap().size += 1;
    store.write_manifest(&manifest, &identity).unwrap();

    let result = store.verify_manifest(&identity).unwrap();
    assert_eq!(result.ok, 3);
    assert!(result.tampered.is_empty());
}

#[cfg(unix)]
#[test]
fn manifest_preserves_existing_zero_created_and_crosses_i32_generation_boundary() {
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("entries")).unwrap();
    fs::write(
        root.join(CONFIG_FILE),
        b"vault:\n  pseudonymize_paths: false\n",
    )
    .unwrap();
    fs::write(root.join(IDENTITY_FILE), b"presence fixture").unwrap();
    let store = Store::open(root, &identity).unwrap();
    store
        .write_manifest(
            &Manifest {
                version: 0,
                generation: i64::from(i32::MAX),
                created: go_zero_time(),
                updated: go_zero_time(),
                entries: BTreeMap::new(),
            },
            &identity,
        )
        .unwrap();
    store
        .update_manifest_entry("crossing", b"ciphertext", &identity)
        .unwrap();
    let after_update = store.load_manifest(&identity).unwrap();
    assert_eq!(after_update.version, 1);
    assert_eq!(after_update.generation, i64::from(i32::MAX) + 1);
    assert_eq!(after_update.created, go_zero_time());
    assert!(!after_update.updated.is_empty());
    assert!(!after_update.entries["crossing"].mtime.is_empty());
    store.remove_manifest_entry("crossing", &identity).unwrap();
    let after_remove = store.load_manifest(&identity).unwrap();
    assert_eq!(after_remove.generation, i64::from(i32::MAX) + 2);
    assert_eq!(after_remove.created, go_zero_time());
}

#[test]
fn concurrent_manifest_updates_preserve_every_record() {
    use std::sync::Arc;

    let (_, fixture) = fixture();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &fixture.vaults[0]);
    let identity = parse_identity(IDENTITY).unwrap();
    let store = Arc::new(Store::open(temp.path(), &identity).unwrap());
    let mut workers = Vec::new();
    for index in 0..8 {
        let store = Arc::clone(&store);
        workers.push(std::thread::spawn(move || {
            let identity = parse_identity(IDENTITY).unwrap();
            store.update_manifest_entry(&format!("concurrent/{index}"), b"ciphertext", &identity)
        }));
    }
    for worker in workers {
        worker.join().unwrap().unwrap();
    }

    let manifest = store.load_manifest(&identity).unwrap();
    assert_eq!(manifest.entries.len(), 11);
    for index in 0..8 {
        assert!(
            manifest
                .entries
                .contains_key(&format!("concurrent/{index}"))
        );
    }
}

#[test]
fn metadata_clock_requires_rfc3339_and_preserves_semantic_go_zero() {
    let identity = parse_identity(IDENTITY).unwrap();
    let (_, fixture) = fixture();
    let temp = tempfile::tempdir().unwrap();
    materialize(temp.path(), &fixture.vaults[0]);
    let store = Store::open(temp.path(), &identity).unwrap();
    let entry = Entry::default();
    let zero = go_zero_time();
    store
        .write_entry_at("clock-zero", &entry, &identity, &zero, false, None)
        .unwrap();
    assert_eq!(
        store.get("clock-zero", &identity).unwrap().metadata.created,
        zero
    );
    let malformed = "2026-09-08T10:11:12Zgarbage";
    assert!(
        store
            .write_entry_at("clock-malformed", &entry, &identity, malformed, false, None)
            .is_err()
    );
}

#[test]
fn write_entry_at_config_layout_remains_authoritative_for_conflicting_flags() {
    let (_, fixture) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    for (config_pseudo, override_pseudo) in [(false, true), (true, false)] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        materialize(root, &fixture.vaults[0]);
        fs::write(
            root.join(CONFIG_FILE),
            format!(
                "vault:
  pseudonymize_paths: {}
",
                config_pseudo
            ),
        )
        .unwrap();
        let store = Store::open(root, &identity).unwrap();
        let path = format!("override/{}", config_pseudo);
        store
            .write_entry_at(
                &path,
                &Entry::default(),
                &identity,
                "2026-09-08T10:11:12Z",
                override_pseudo,
                None,
            )
            .unwrap();
        let hash = symvault_crypto::pseudonymize_path(&identity, &path);
        let configured_file = if config_pseudo {
            root.join(format!("entries/{}/{}.age", &hash[..2], hash))
        } else {
            root.join(format!("entries/{}.age", path))
        };
        assert!(configured_file.is_file());
        if config_pseudo {
            assert!(!root.join(format!("entries/{}.age", path)).exists());
        } else {
            assert!(
                !root
                    .join(format!("entries/{}/{}.age", &hash[..2], hash))
                    .exists()
            );
        }
        let got = store.get(&path, &identity).unwrap();
        assert_eq!(got.path, path);
        assert!(store.list(&identity).unwrap().contains(&path));
        let manifest = store.load_manifest(&identity).unwrap();
        assert!(manifest.entries.contains_key(&path));
        store.delete_entry_with_identity(&path, &identity).unwrap();
        assert!(!store.entry_exists(&path, &identity).unwrap());
        assert!(!store.list(&identity).unwrap().contains(&path));
        let after = store.load_manifest(&identity).unwrap();
        assert!(!after.entries.contains_key(&path));
    }
}

#[test]
fn open_preserves_legacy_validation_error_order() {
    let identity = parse_identity(IDENTITY).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::write(root.join(IDENTITY_FILE), b"identity").unwrap();
    fs::write(
        root.join(RECIPIENTS_FILE),
        b"invalid recipient
",
    )
    .unwrap();
    let error = Store::open(root, &identity).unwrap_err();
    assert!(
        matches!(error, StoreError::MissingFile(path) if path == root.canonicalize().unwrap().join(CONFIG_FILE))
    );
    fs::write(
        root.join(CONFIG_FILE),
        b"vault: invalid
",
    )
    .unwrap();
    fs::remove_file(root.join(IDENTITY_FILE)).unwrap();
    let error = Store::open(root, &identity).unwrap_err();
    assert!(
        matches!(error, StoreError::MissingFile(path) if path == root.canonicalize().unwrap().join(IDENTITY_FILE))
    );
    fs::write(root.join(IDENTITY_FILE), b"identity").unwrap();
    let error = Store::open(root, &identity).unwrap_err();
    assert!(matches!(error, StoreError::Config(_)));
}

#[cfg(unix)]
#[test]
fn fresh_scan_is_unbounded_but_legacy_scan_keeps_walkdir_depth_64() {
    let identity = parse_identity(IDENTITY).unwrap();
    let deep = (0..65).map(|_| "deep").collect::<Vec<_>>().join("/");
    let path = format!("{deep}/entry");
    let fresh_temp = tempfile::tempdir().unwrap();
    fs::create_dir(fresh_temp.path().join("entries")).unwrap();
    fs::write(
        fresh_temp.path().join(CONFIG_FILE),
        b"vault: {}
",
    )
    .unwrap();
    fs::write(fresh_temp.path().join(IDENTITY_FILE), b"identity").unwrap();
    let fresh = Store::open(fresh_temp.path(), &identity).unwrap();
    fresh
        .write_new_entry(&path, &Entry::default(), &identity)
        .unwrap();
    fs::create_dir(fresh_temp.path().join("entries2")).unwrap();
    fs::copy(
        fresh_temp
            .path()
            .join("entries")
            .join(&path)
            .with_extension("age"),
        fresh_temp.path().join("entries2/foo.age"),
    )
    .unwrap();
    assert_eq!(
        fresh.list(&identity).unwrap(),
        vec![path.clone(), "entries2/foo".to_owned()]
    );
    let legacy_temp = tempfile::tempdir().unwrap();
    fs::create_dir(legacy_temp.path().join("entries")).unwrap();
    fs::write(
        legacy_temp.path().join(CONFIG_FILE),
        b"vault: {}
",
    )
    .unwrap();
    fs::write(legacy_temp.path().join(IDENTITY_FILE), b"identity").unwrap();
    let source = Store::open(legacy_temp.path(), &identity).unwrap();
    source
        .write_new_entry(&path, &Entry::default(), &identity)
        .unwrap();
    let source_path = legacy_temp
        .path()
        .join("entries")
        .join(&path)
        .with_extension("age");
    let legacy_path = legacy_temp.path().join(&path).with_extension("age");
    fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
    fs::rename(source_path, &legacy_path).unwrap();
    fs::remove_dir_all(legacy_temp.path().join("entries")).unwrap();
    fs::create_dir(legacy_temp.path().join("entries")).unwrap();
    let legacy = Store::open(legacy_temp.path(), &identity).unwrap();
    assert!(legacy.list(&identity).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn rooted_walk_depth_matches_walkdir_at_exact_boundaries() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("a/b/c")).unwrap();
    for relative in ["root.age", "a/one.age", "a/b/two.age", "a/b/c/three.age"] {
        fs::write(temp.path().join(relative), b"fixture").unwrap();
    }
    let root = fs::File::open(temp.path()).unwrap();
    for depth in 0..=4 {
        let mut expected = walkdir::WalkDir::new(temp.path())
            .max_depth(depth)
            .into_iter()
            .map(Result::unwrap)
            .filter(|entry| entry.depth() > 0)
            .map(|entry| {
                entry
                    .path()
                    .strip_prefix(temp.path())
                    .unwrap()
                    .to_path_buf()
            })
            .collect::<Vec<_>>();
        let mut actual = rooted::walk_with_max_depth(&root, temp.path(), Some(depth))
            .unwrap()
            .into_iter()
            .map(|entry| entry.relative)
            .collect::<Vec<_>>();
        expected.sort();
        actual.sort();
        assert_eq!(actual, expected, "depth {depth}");
    }
}
