//! ADR 0037 R10 (IO-001): a pass store whose entry or directory names are not
//! valid UTF-8, against REAL gpg.
//!
//! `testdata/port/sync/pass-gpg-invalid-names.json` was recorded at the
//! archived oracle `legacy/go-oracle` (`ce2390d7`) by the real Go pass importer
//! (`scripts/rust-port/pass_gpg_invalid_names.go.txt`) on Linux, the only
//! platform that can create such names (macOS answers EILSEQ). This replay
//! imports the recorded test key into a disposable `GNUPGHOME`, writes the same
//! file names byte for byte and runs the production `import_pass` with the
//! system `gpg`. Entry paths (raw bytes and their `encoding/json` text),
//! warnings, data and the failure of a store must equal Go's.
//!
//! One bounded difference is asserted, not hidden: `ImportError::Parse` holds a
//! Rust `String`, so an error text that names an invalid byte carries U+FFFD
//! where Go prints the raw byte; the replay compares the text with Go's raw
//! bytes decoded lossily. A missing gpg fails the test.
#![cfg(target_os = "linux")]

use serde::Deserialize;
use serde_json::Value;
use std::{
    ffi::OsStr,
    fs,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};
use symvault_sync::importer::{ImportError, import_pass};

const EXPECTED_CASES: usize = 12;
const STORE_DIR: &str = "pass-store.d";
const STORE_MARKER: &str = "@STORE";
const ORACLE_COMMIT: &str = "ce2390d748818a4beb413e97183b7795efa99411";

#[derive(Deserialize)]
struct Fixture {
    oracle: Oracle,
    keyring: Keyring,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Oracle {
    commit: String,
    goos: String,
    program_sha256: String,
}

#[derive(Deserialize)]
struct Keyring {
    secret_key_armor: String,
    agent_conf: String,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    files: Vec<FileSpec>,
    entries: Option<Vec<Expected>>,
    failed: bool,
    #[serde(default)]
    error_b64: String,
}

#[derive(Deserialize)]
struct FileSpec {
    path_b64: String,
    kind: String,
    #[serde(default)]
    content_base64: String,
    #[serde(default)]
    plaintext_base64: String,
    #[serde(default)]
    decrypts: bool,
}

#[derive(Deserialize)]
struct Expected {
    path_b64: String,
    path_json: String,
    data: Value,
    warnings_b64: Option<Vec<String>>,
}

fn b64(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("fixture base64")
}

fn gpg_env(command: &mut Command, home: &Path) {
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .env("GNUPGHOME", home)
        .env("LC_ALL", "C")
        .env("HOME", home);
}

/// Kills the disposable agent (and dirmngr/keyboxd) on drop, panics included.
struct AgentGuard(PathBuf);

impl Drop for AgentGuard {
    fn drop(&mut self) {
        let mut kill = Command::new("gpgconf");
        gpg_env(&mut kill, &self.0);
        let _ = kill.args(["--kill", "all"]).output();
    }
}

fn short_base() -> PathBuf {
    // gpg-agent sockets live under GNUPGHOME and sockaddr_un is ~104 bytes.
    let temp = std::env::temp_dir();
    if temp.as_os_str().len() > 40 {
        PathBuf::from("/tmp")
    } else {
        temp
    }
}

#[test]
fn pass_importer_matches_go_for_invalid_utf8_names() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/sync/pass-gpg-invalid-names.json"
    ))
    .expect("parse the Go recording");
    assert_eq!(fixture.oracle.commit, ORACLE_COMMIT);
    assert_eq!(fixture.oracle.goos, "linux");
    assert_eq!(fixture.oracle.program_sha256.len(), 64);
    assert_eq!(fixture.cases.len(), EXPECTED_CASES);

    let sandbox = tempfile::Builder::new()
        .prefix("pgi-")
        .tempdir_in(short_base())
        .expect("sandbox");
    let sandbox_path = fs::canonicalize(sandbox.path()).expect("canonical sandbox");
    let home = sandbox_path.join("home");
    fs::create_dir_all(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(home.join("gpg-agent.conf"), &fixture.keyring.agent_conf).unwrap();
    let _agent = AgentGuard(home.clone());
    let key_file = sandbox_path.join("secret-key.asc");
    fs::write(&key_file, &fixture.keyring.secret_key_armor).unwrap();
    let mut import = Command::new("gpg");
    gpg_env(&mut import, &home);
    let imported = import
        .args(["--batch", "--import"])
        .arg(&key_file)
        .output()
        .expect("gpg is required for this contract test (fail closed)");
    assert!(
        imported.status.success(),
        "import test key: {}",
        String::from_utf8_lossy(&imported.stderr)
    );
    // SAFETY: this binary contains exactly one test, so no other thread reads
    // or writes the environment while it is modified.
    unsafe {
        std::env::set_var("GNUPGHOME", &home);
        std::env::set_var("LC_ALL", "C");
        std::env::set_var("HOME", &home);
    }

    let mut failures = Vec::new();
    let mut executed = 0;
    for (index, case) in fixture.cases.iter().enumerate() {
        let base = sandbox_path.join(format!("case-{index}"));
        let store = base.join(STORE_DIR);
        fs::create_dir_all(&store).unwrap();
        for file in &case.files {
            let name = b64(&file.path_b64);
            let path = store.join(OsStr::from_bytes(&name));
            assert!(
                file.kind == "encrypted" || file.kind == "raw",
                "unexpected kind"
            );
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b64(&file.content_base64)).unwrap();
            if file.kind == "encrypted" && file.decrypts {
                let mut direct = Command::new("gpg");
                gpg_env(&mut direct, &home);
                let output = direct
                    .args(["--decrypt", "--batch", "--yes"])
                    .arg(&path)
                    .output()
                    .expect("run gpg --decrypt");
                if !output.status.success() || output.stdout != b64(&file.plaintext_base64) {
                    failures.push(format!(
                        "{}: gpg --decrypt does not reproduce the plaintext of {:?}",
                        case.id,
                        String::from_utf8_lossy(&name)
                    ));
                }
            }
        }
        executed += 1;
        let result = import_pass(&store);
        let id = &case.id;
        if case.failed {
            let go_raw = b64(&case.error_b64);
            let go_text = String::from_utf8_lossy(&go_raw).into_owned();
            match result {
                Ok(entries) => {
                    failures.push(format!("{id}: rust accepted {} entries", entries.len()))
                }
                Err(ImportError::Parse(text)) => {
                    let text = text.replace(store.to_str().unwrap(), STORE_MARKER);
                    if text != go_text {
                        failures.push(format!(
                            "{id}: error differs\n  go (lossy): {go_text:?}\n  rust:       {text:?}"
                        ));
                    }
                }
                Err(other) => failures.push(format!("{id}: unexpected error variant {other:?}")),
            }
            continue;
        }
        let expected = case.entries.as_deref().unwrap_or_default();
        match result {
            Err(error) => failures.push(format!("{id}: rust error {error}")),
            Ok(entries) => {
                if entries.len() != expected.len() {
                    failures.push(format!(
                        "{id}: {} entries, Go {}",
                        entries.len(),
                        expected.len()
                    ));
                    continue;
                }
                for (rust, go) in entries.iter().zip(expected) {
                    if rust.path_bytes() != b64(&go.path_b64) {
                        failures.push(format!(
                            "{id}: path bytes {:?}, Go {:?}",
                            rust.path_bytes(),
                            b64(&go.path_b64)
                        ));
                    }
                    if rust.path != go.path_json {
                        failures.push(format!(
                            "{id}: json path {:?}, Go {:?}",
                            rust.path, go.path_json
                        ));
                    }
                    let data = serde_json::to_value(&rust.data).unwrap();
                    if data != go.data {
                        failures.push(format!("{id}: data {data}, Go {}", go.data));
                    }
                    let warnings: Option<Vec<Vec<u8>>> = go
                        .warnings_b64
                        .as_ref()
                        .map(|list| list.iter().map(|w| b64(w)).collect());
                    let rust_warnings: Option<Vec<Vec<u8>>> = rust
                        .warnings
                        .as_ref()
                        .map(|list| list.iter().map(|w| w.clone().into_bytes()).collect());
                    if rust_warnings != warnings {
                        failures.push(format!("{id}: warnings {rust_warnings:?}, Go {warnings:?}"));
                    }
                }
            }
        }
    }
    assert_eq!(executed, EXPECTED_CASES);
    assert!(
        failures.is_empty(),
        "{} difference(s) from Go:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
