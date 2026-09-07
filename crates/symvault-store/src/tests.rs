use std::{fs, path::Path};

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
            || vault.files.len() != 8
            || vault.entries.len() != 3
            || vault.directories.is_empty()
        {
            return Err(format!("{} cardinality/layout changed", vault.name));
        }
        if !vault.presence.config || !vault.presence.identity || !vault.presence.recipients {
            return Err(format!("{} presence incomplete", vault.name));
        }
        let names: Vec<_> = vault
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        if names != ["minimal", "full", "nested/large"] {
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
    for dir in &vault.directories {
        fs::create_dir_all(root.join(&dir.path)).unwrap();
        set_mode(&root.join(&dir.path), dir.mode);
    }
    for file in &vault.files {
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
        let root = std::env::temp_dir().join(format!(
            "symvault-store-{}-{}",
            std::process::id(),
            vault_vector.name
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
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
            let storage_path = root.join(&vector.storage_path);
            assert!(storage_path.is_file(), "missing {}", vector.storage_path);
            let got = store.get(&vector.path, &identity).unwrap();
            assert_eq!(got, expected, "{} {}", vault_vector.name, vector.name);
            assert_eq!(
                store.get_metadata(&vector.path, &identity).unwrap(),
                expected.metadata
            );
        }
        let files = store.files().unwrap();
        assert_eq!(
            files.len(),
            vault_vector.files.len() + vault_vector.directories.len()
        );
        for file in &vault_vector.files {
            let got = files
                .iter()
                .find(|candidate| candidate.path == file.path)
                .unwrap();
            assert_eq!(got.mode, file.mode, "mode {}", file.path);
            assert_eq!(got.size, file.size as u64, "size {}", file.path);
            assert_eq!(got.sha256, file.sha256, "hash {}", file.path);
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn malformed_encrypted_vectors_are_rejected() {
    let (_, value) = fixture();
    let identity = parse_identity(IDENTITY).unwrap();
    for case in &value.malformed_cases {
        let error = symvault_crypto::decrypt(case.input.as_bytes(), &identity).unwrap_err();
        assert_eq!(
            error.class(),
            symvault_crypto::FailureClass::MalformedEnvelope,
            "{}",
            case.name
        );
    }
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
    let identity = parse_identity(IDENTITY).unwrap();
    let root = std::env::temp_dir().join(format!("symvault-store-symlink-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    materialize(&root, &value.vaults[0]);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            root.join("entries/minimal.age"),
            root.join("entries/link.age"),
        )
        .unwrap();
        assert!(matches!(
            Store::open(&root, &identity),
            Err(StoreError::Symlink(_))
        ));
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn type_inference_matches_read_only_entry_contract() {
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
    let root = std::env::temp_dir().join(format!("symvault-store-manifest-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    materialize(&root, &value.vaults[0]);
    let store = Store::open(&root, &identity).unwrap();
    let files = store.files().unwrap();
    let paths: Vec<_> = files.iter().map(|file| file.path.as_str()).collect();
    let mut sorted = paths.clone();
    sorted.sort_unstable();
    assert_eq!(paths, sorted);
    assert!(files.iter().all(|file| file.mode > 0));
    fs::remove_dir_all(root).unwrap();
}
