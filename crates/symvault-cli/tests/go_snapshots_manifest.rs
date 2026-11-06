//! The frozen Go sources under `testdata/port/go-snapshots/` are byte-exact
//! provenance inputs (`<path>.txt` for every recorded `<path>`). They replace
//! the working-tree Go files the provenance tests used to hash, so they must
//! never drift from `MANIFEST.json` (source commit + sha256 per file).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[derive(serde::Deserialize)]
struct Manifest {
    commit: String,
    files: Vec<Entry>,
}

#[derive(serde::Deserialize)]
struct Entry {
    path: String,
    snapshot: String,
    sha256: String,
    bytes: u64,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/port/go-snapshots")
}

fn walk(dir: &Path, out: &mut BTreeSet<String>, base: &Path) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, out, base);
        } else {
            let relative = path.strip_prefix(base).unwrap();
            out.insert(relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

#[test]
fn snapshots_match_manifest_byte_for_byte() {
    let root = root();
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(root.join("MANIFEST.json")).unwrap()).unwrap();
    assert_eq!(manifest.commit.len(), 40, "source commit is a full sha");
    assert!(!manifest.files.is_empty());
    let mut listed = BTreeSet::from(["MANIFEST.json".to_owned()]);
    for entry in &manifest.files {
        assert_eq!(entry.snapshot, format!("{}.txt", entry.path));
        let bytes = std::fs::read(root.join(&entry.snapshot))
            .unwrap_or_else(|error| panic!("read snapshot {}: {error}", entry.snapshot));
        assert_eq!(bytes.len() as u64, entry.bytes, "{}: size", entry.path);
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            entry.sha256,
            "{}: sha256 drifted from commit {}",
            entry.path,
            manifest.commit
        );
        assert!(
            listed.insert(entry.snapshot.clone()),
            "duplicate manifest entry {}",
            entry.path
        );
    }
    let mut on_disk = BTreeSet::new();
    walk(&root, &mut on_disk, &root);
    on_disk.remove("README.md");
    assert_eq!(on_disk, listed, "snapshot tree and MANIFEST.json diverge");
}
