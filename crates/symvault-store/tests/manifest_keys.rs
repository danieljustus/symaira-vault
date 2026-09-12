#![deny(unsafe_code)]

use std::{collections::BTreeMap, fs, path::Path, process::Command};

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use symvault_crypto::parse_identity;
use symvault_store::{Entry, Store};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const REVISION: &str = "88a9ca41e668f381c6319ed26fe922d8cc22e980";
const IDENTITY: &str = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL";

#[derive(Deserialize)]
struct Fixture {
    revision: String,
    go_version: String,
    source_digest: String,
    generator_digest: String,
    payload: String,
    vectors: Vec<Vector>,
}
#[derive(Deserialize)]
struct Vector {
    name: String,
    input: Input,
    pseudonymize: bool,
    steps: Vec<Value>,
}
#[derive(Deserialize)]
struct Input {
    #[serde(default)]
    path: String,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn fixture() -> Fixture {
    let f: Fixture = serde_json::from_slice(
        &fs::read(Path::new(ROOT).join("testdata/port/store/manifest-keys.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(f.revision, REVISION);
    assert_eq!(f.go_version, "go1.26.6");
    let names = Command::new("git")
        .current_dir(ROOT)
        .args([
            "ls-tree",
            "-r",
            "--name-only",
            REVISION,
            "--",
            "internal",
            "go.mod",
            "go.sum",
        ])
        .output()
        .unwrap();
    assert!(
        names.status.success(),
        "git ls-tree failed: status={:?}, stderr={}",
        names.status,
        String::from_utf8_lossy(&names.stderr)
    );
    let mut hash = Sha256::new();
    for name in std::str::from_utf8(&names.stdout).unwrap().lines() {
        if name.ends_with("_test.go")
            || !(name.ends_with(".go") || name == "go.mod" || name == "go.sum")
        {
            continue;
        }
        hash.update(name.as_bytes());
        hash.update([0]);
        let blob = Command::new("git")
            .current_dir(ROOT)
            .args(["show", &format!("{REVISION}:{name}")])
            .output()
            .unwrap();
        assert!(blob.status.success());
        hash.update(blob.stdout);
    }
    assert_eq!(f.source_digest, format!("{:x}", hash.finalize()));
    assert_eq!(
        f.generator_digest,
        digest(
            &fs::read(Path::new(ROOT).join("scripts/rust-port/cmd/manifestkeygen/main.go"))
                .unwrap()
        )
    );
    f
}

fn materialize(root: &Path, pseudonymize: bool) {
    fs::write(
        root.join("config.yaml"),
        format!("vault:\n  pseudonymize_paths: {pseudonymize}\n"),
    )
    .unwrap();
    fs::write(root.join("identity.age"), "inert fixture marker").unwrap();
}

fn timestamp(s: &str) -> time::OffsetDateTime {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).unwrap()
}

#[test]
fn public_manifest_keys_match_go_production_fixture() {
    let fixture = fixture();
    assert_eq!(fixture.vectors.len(), 16);
    let identity = parse_identity(IDENTITY).unwrap();
    let mut executed = 0;
    for vector in fixture.vectors {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        materialize(root, vector.pseudonymize);
        let store = Store::open(root, &identity).unwrap();
        let mut created = None;
        assert_eq!(vector.steps.len(), 4);
        for (step, expected) in vector.steps.into_iter().enumerate() {
            let result = match step {
                0 | 3 => store.remove_manifest_entry(&vector.input.path, &identity),
                1 => store.update_manifest_entry(
                    &vector.input.path,
                    fixture.payload.as_bytes(),
                    &identity,
                ),
                2 => store.remove_manifest_entry("absent-map-key", &identity),
                _ => unreachable!(),
            };
            let mut actual = json!({
                "error":result.err().map(|e| e.to_string()).unwrap_or_default(),
                "exists":false,"version":0,"generation":0,"entries":{},"mode":0,
                "times_valid":false,"created_preserved":false,"files":[]
            });
            if root.join("manifest.age").exists() {
                let manifest = store.load_manifest(&identity).unwrap();
                let start = timestamp(&manifest.created);
                let end = timestamp(&manifest.updated);
                let times_valid = start != timestamp("0001-01-01T00:00:00Z")
                    && start <= end
                    && manifest
                        .entries
                        .values()
                        .all(|e| start <= timestamp(&e.mtime) && timestamp(&e.mtime) <= end);
                let entries: BTreeMap<_, _> = manifest
                    .entries
                    .iter()
                    .map(|(key, e)| (key, json!({"sha256":e.sha256,"size":e.size})))
                    .collect();
                actual["exists"] = json!(true);
                actual["version"] = json!(manifest.version);
                actual["generation"] = json!(manifest.generation);
                actual["entries"] = json!(entries);
                actual["times_valid"] = json!(times_valid);
                actual["created_preserved"] =
                    json!(created.as_ref().is_none_or(|old| old == &manifest.created));
                created = Some(manifest.created);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    actual["mode"] = json!(
                        fs::metadata(root.join("manifest.age"))
                            .unwrap()
                            .permissions()
                            .mode()
                            & 0o777
                    );
                }
                // Unix permission bits are only asserted on native Unix.
                #[cfg(not(unix))]
                {
                    actual["mode"] = expected["mode"].clone();
                }
            }
            let mut files: Vec<_> = walkdir::WalkDir::new(root)
                .min_depth(1)
                .into_iter()
                .map(|e| {
                    e.unwrap()
                        .path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/")
                })
                .collect();
            files.sort();
            actual["files"] = json!(files);
            assert_eq!(
                actual, expected,
                "{} pseudo={} step={step}",
                vector.name, vector.pseudonymize
            );
            executed += 1;
        }
    }
    assert_eq!(executed, 64);
}

#[test]
fn manifest_map_keys_do_not_relax_entry_paths_or_mask_load_errors() {
    let identity = parse_identity(IDENTITY).unwrap();
    for pseudo in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        materialize(root, pseudo);
        let store = Store::open(root, &identity).unwrap();
        let malformed = b"synthetic malformed manifest";
        fs::write(root.join("manifest.age"), malformed).unwrap();
        let update_error = store
            .update_manifest_entry("valid", b"synthetic", &identity)
            .unwrap_err()
            .to_string();
        let remove_error = store
            .remove_manifest_entry("valid", &identity)
            .unwrap_err()
            .to_string();
        for key in ["", "../outside", ".", "/outside", "nul\0key"] {
            assert_eq!(
                store
                    .update_manifest_entry(key, b"synthetic", &identity)
                    .unwrap_err()
                    .to_string(),
                update_error
            );
            assert_eq!(
                store
                    .remove_manifest_entry(key, &identity)
                    .unwrap_err()
                    .to_string(),
                remove_error
            );
            assert!(
                store
                    .write_entry(key, &Entry::default(), &identity)
                    .is_err()
            );
            assert!(store.get(key, &identity).is_err());
            assert_eq!(fs::read(root.join("manifest.age")).unwrap(), malformed);
        }
        assert!(!root.join("entries").exists());
    }
}
