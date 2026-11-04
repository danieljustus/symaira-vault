//! The committed Go-oracle recordings carry no path of the machine that
//! captured them: nothing under `/Volumes`, `/Users`, `/var/folders` or
//! `/private/var`, neither in plain strings nor inside base64 file contents of
//! the frozen vault trees (a `config.yaml` `vaultDir`, a backup marker, an
//! editor temp-file marker).

#[path = "common/operator_paths.rs"]
mod operator_paths;

use std::{fs, path::Path};

use serde_json::{Value, json};

const DIRECTORIES: [&str; 2] = [
    "testdata/port/cli-transcripts",
    "testdata/port/cli-observations",
];

fn recordings() -> Vec<std::path::PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for directory in DIRECTORIES {
        for entry in fs::read_dir(root.join(directory)).expect("recording directory") {
            let path = entry.expect("entry").path();
            if path.extension().is_some_and(|e| e == "json") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn committed_recordings_carry_no_operator_paths() {
    let files = recordings();
    assert!(
        files.len() > 40,
        "scanner saw only {} recordings",
        files.len()
    );
    let mut hits = Vec::new();
    for file in &files {
        let bytes = fs::read(file).expect("read recording");
        let value: Value = serde_json::from_slice(&bytes).expect("recording is JSON");
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        hits.extend(operator_paths::hits_in(&name, &value));
    }
    assert!(
        hits.is_empty(),
        "{} operator path(s) in committed recordings:\n{}",
        hits.len(),
        hits.join("\n")
    );
}

/// Mutation controls: the scanner must see a path in plain text, inside a
/// base64 file body, inside base64 JSON, in an object key, for every prefix.
#[test]
fn scanner_finds_planted_paths_in_every_encoding() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let yaml = STANDARD.encode("vaultDir: /Volumes/disk/tmp/symvault-zk-base-abc/vault\n");
    let nested = STANDARD.encode(json!({"p": "x", "b": yaml}).to_string());
    for prefix in operator_paths::PREFIXES {
        let plain = json!({"text": format!("{prefix}tmp/symvault-edit-1.json")});
        assert_eq!(operator_paths::hits_in("t", &plain).len(), 1, "{prefix}");
        let encoded = json!({"content": {"b64": STANDARD.encode(format!("a: {prefix}x\n"))}});
        assert_eq!(
            operator_paths::hits_in("t", &encoded).len(),
            1,
            "{prefix} b64"
        );
        let key = json!({ format!("{prefix}x"): 1 });
        assert_eq!(operator_paths::hits_in("t", &key).len(), 1, "{prefix} key");
    }
    let frozen = json!({"tree": [{"p": "config.yaml", "k": "f", "b": yaml}]});
    assert_eq!(operator_paths::hits_in("t", &frozen).len(), 1);
    assert!(
        !operator_paths::hits_in("t", &json!({"tree": nested})).is_empty(),
        "base64 JSON wrapping a base64 file body"
    );
    let clean = json!({"b": STANDARD.encode("vaultDir: <ROOT>\n"), "t": "<TMPFILE>.json"});
    assert!(operator_paths::hits_in("t", &clean).is_empty());
}
