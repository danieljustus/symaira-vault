#![cfg(unix)]
//! Go-free recovery of re-encryption journals written by the Go oracle.
//!
//! `testdata/port/store/reencrypt-journal.json` is recorded once from the Go production journal functions
//! (`scripts/rust-port/reencrypt_journal_fixture.py capture`): a vault frozen after a crash with the
//! replacement only staged, and one frozen after the replacement was committed but before the journal was
//! removed. Each scenario also holds the tree Go's own recovery leaves behind. `Store::open` must recover
//! the frozen pre-crash tree to exactly that tree (the staged state is rolled back to the original, the
//! committed state keeps the replacement): every stable file byte for byte, no journal, backup or
//! temporary file, and a manifest the identity can decrypt that lists the entry.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use symvault_crypto::parse_identity;
use symvault_store::Store;

const TREE_ROOT: &str = "@TREE_ROOT@";
/// Rust's write lock and the declared D1 marker are Rust-side artifacts; Go's `Open` also leaves its own
/// empty `.symvault-migrated`. None of them is data.
const RUST_ARTIFACTS: [&str; 2] = [".lock", ".symvault-rust"];
const GO_ARTIFACTS: [&str; 2] = [".lock", ".symvault-migrated"];
/// Go's `Open` also normalizes config.yaml (a side effect of opening, not of journal recovery). Rust leaves
/// the file alone: it is asserted to equal the frozen pre-crash bytes instead of Go's rewritten ones.
const GO_REWRITES: [&str; 1] = ["config.yaml"];

#[derive(Deserialize)]
struct Fixture {
    oracle_commit: String,
    scenarios: Vec<Scenario>,
}

#[derive(Deserialize)]
struct Scenario {
    name: String,
    identity: String,
    entry: String,
    value: String,
    pre_crash: BTreeMap<String, Option<String>>,
    go_post_recovery: BTreeMap<String, String>,
}

fn fixture() -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/port/store/reencrypt-journal.json");
    serde_json::from_slice(&fs::read(path).expect("fixture")).expect("fixture JSON")
}

fn materialize(scenario: &Scenario, root: &Path) {
    use base64::Engine;
    fs::create_dir_all(root).unwrap();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    for (name, data) in &scenario.pre_crash {
        let target = root.join(name);
        match data {
            None => {
                fs::create_dir_all(&target).unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Some(encoded) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap();
                // The journal and config.yaml carry the capture-time vault root as a token.
                let text = String::from_utf8_lossy(&bytes);
                let bytes = if text.contains(TREE_ROOT) {
                    text.replace(TREE_ROOT, root.to_str().unwrap()).into_bytes()
                } else {
                    bytes
                };
                fs::write(&target, bytes).unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
    }
}

/// relative path -> sha256 of a file (the vault root replaced by its token, as in the recording), or "dir".
fn tree(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path: PathBuf = entry.unwrap().path();
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if path.is_dir() {
                out.insert(name, "dir".to_owned());
                walk(root, &path, out);
            } else {
                let bytes = fs::read(&path).unwrap();
                let text = String::from_utf8_lossy(&bytes);
                let bytes = if text.contains(root.to_str().unwrap()) {
                    text.replace(root.to_str().unwrap(), TREE_ROOT).into_bytes()
                } else {
                    bytes
                };
                out.insert(name, hex::encode(Sha256::digest(bytes)));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// The differences between what recovery left and what Go's recovery left. Only data files are compared
/// byte for byte; `manifest.age` is re-encrypted (random) and is checked by decryption instead.
fn differences(go: &BTreeMap<String, String>, rust: &BTreeMap<String, String>) -> Vec<String> {
    let go: BTreeMap<_, _> = go
        .iter()
        .filter(|(k, _)| !GO_ARTIFACTS.contains(&k.as_str()))
        .collect();
    let rust: BTreeMap<_, _> = rust
        .iter()
        .filter(|(k, _)| !RUST_ARTIFACTS.contains(&k.as_str()))
        .collect();
    let rewritten = |key: &str| GO_REWRITES.contains(&key);
    let mut found = Vec::new();
    for key in go
        .keys()
        .chain(rust.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        match (go.get(*key), rust.get(*key)) {
            (Some(_), None) => found.push(format!("missing after Rust recovery: {key}")),
            (None, Some(_)) => found.push(format!("extra after Rust recovery: {key}")),
            (Some(a), Some(b)) if key.as_str() != "manifest.age" && !rewritten(key) && a != b => {
                found.push(format!("differs from Go recovery: {key}"))
            }
            _ => {}
        }
    }
    found
}

#[test]
fn go_written_crash_states_recover_to_the_tree_go_recovery_leaves() {
    let mut recovered_scenarios = 0;
    let fixture = fixture();
    assert_eq!(fixture.oracle_commit.len(), 40);
    assert_eq!(fixture.scenarios.len(), 2, "staged and committed");
    for scenario in &fixture.scenarios {
        let temp = tempfile::tempdir_in(Path::new("/tmp").canonicalize().unwrap()).unwrap();
        let root = temp.path().join("vault");
        materialize(scenario, &root);
        assert!(
            root.join(".reencrypt.journal").is_file(),
            "{}: no journal to recover",
            scenario.name
        );
        let before = tree(&root);
        let identity = parse_identity(&scenario.identity).unwrap();

        let opened = Store::open(
            symvault_store::data_safety::test_support_pre_marked(&root),
            &identity,
        );
        let store =
            opened.unwrap_or_else(|error| panic!("{}: recovery failed: {error}", scenario.name));

        let after = tree(&root);
        let found = differences(&scenario.go_post_recovery, &after);
        assert!(found.is_empty(), "{}: {found:?}", scenario.name);
        for name in GO_REWRITES {
            assert_eq!(
                before[name], after[name],
                "{}: recovery must not rewrite {name}",
                scenario.name
            );
        }
        assert!(
            !after.contains_key(".reencrypt.journal"),
            "{}",
            scenario.name
        );
        assert!(
            after.keys().all(|name| !name.contains(".reencrypt")),
            "{}: temporary or backup file left behind: {after:?}",
            scenario.name
        );
        if scenario.name == "staged" {
            // Rolled back: the original ciphertext is untouched and the staged replacement is gone.
            assert_eq!(
                before["entries/cross-language.age"], after["entries/cross-language.age"],
                "staged: the original entry must survive the roll-back"
            );
        }
        // The frozen state really was a crash state, and recovery really changed it.
        assert_ne!(before, after, "{}", scenario.name);
        // The manifest Rust re-built decrypts with the identity and lists the recovered entry.
        assert_eq!(
            store.list(&identity).unwrap(),
            vec![scenario.entry.clone()],
            "{}",
            scenario.name
        );
        let recovered = store.get(&scenario.entry, &identity).unwrap();
        assert_eq!(recovered.data["value"], scenario.value, "{}", scenario.name);
        let verified = store.verify_manifest(&identity).unwrap();
        assert!(
            verified.tampered.is_empty() && verified.missing.is_empty(),
            "{}",
            scenario.name
        );
        recovered_scenarios += 1;
    }
    assert_eq!(
        recovered_scenarios, 2,
        "both the staged (rolled back) and the committed (kept) state recover"
    );
}

#[test]
fn the_comparison_notices_a_wrong_tree() {
    let fixture = fixture();
    let go = &fixture.scenarios[1].go_post_recovery;
    let mut rust = go.clone();
    rust.remove(".symvault-migrated");
    rust.insert(".symvault-rust".to_owned(), "x".to_owned());
    assert!(
        differences(go, &rust).is_empty(),
        "declared artifacts are ignored"
    );

    let mut stale = rust.clone();
    stale.insert(
        "entries/.cross-language.age.backup.reencrypt-ab".to_owned(),
        "x".to_owned(),
    );
    assert_eq!(
        differences(go, &stale),
        vec!["extra after Rust recovery: entries/.cross-language.age.backup.reencrypt-ab"]
    );

    let mut rolled_back = rust.clone();
    rolled_back.insert("entries/cross-language.age".to_owned(), "0".repeat(64));
    assert_eq!(
        differences(go, &rolled_back),
        vec!["differs from Go recovery: entries/cross-language.age"]
    );

    let mut missing = rust;
    missing.remove("identity.age");
    assert_eq!(
        differences(go, &missing),
        vec!["missing after Rust recovery: identity.age"]
    );
}
