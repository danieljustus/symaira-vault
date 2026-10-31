//! IO-001: the production pass importer against REAL gpg.
//!
//! `testdata/port/sync/pass-gpg.json` is produced by
//! `scripts/rust-port/cmd/passgpggen`: a corpus of pass stores whose entries
//! were encrypted with the real gpg binary, evaluated by the real Go importer.
//! This replay imports the recorded armored test key into a disposable
//! GNUPGHOME and runs `symvault_sync::importer::import_pass` (the system `gpg`
//! found on PATH, no shim) over byte-identical ciphertexts.
//!
//! Environment contract (identical to the generator): `LC_ALL=C`, `GNUPGHOME`
//! and `HOME` point into disposable directories, the agent is configured with
//! `pinentry-program /usr/bin/false`. Comparison rules N1 (store root) and N2
//! (gpg version drift) are documented in the fixture's `normalization` block
//! and implemented in `scripts/rust-port/cmd/passgpggen/main.go`; this file
//! re-implements them 1:1. A missing gpg fails the test, it never skips it.
#![cfg(unix)]

use serde::Deserialize;
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};
use symvault_sync::importer::{ImportError, import_pass};

const EXPECTED_CASES: usize = 36;
const STORE_DIR: &str = "pass-store.d";
const STORE_MARKER: &str = "@STORE";

#[derive(Deserialize)]
struct Fixture {
    oracle: Oracle,
    keyring: Keyring,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Oracle {
    gpg_version: String,
    gpg_args: Vec<String>,
}

#[derive(Deserialize)]
struct Keyring {
    secret_key_armor: String,
    agent_conf: String,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    store_form: String,
    #[serde(default)]
    files: Vec<FileSpec>,
    expected: Vec<Value>,
    failed: bool,
    #[serde(default)]
    error: String,
    #[serde(default)]
    version_variant: bool,
    #[serde(default)]
    optional_stderr_lines: Vec<String>,
}

#[derive(Deserialize)]
struct FileSpec {
    path: String,
    kind: String,
    #[serde(default)]
    content_base64: String,
    #[serde(default)]
    plaintext_base64: String,
    #[serde(default)]
    decrypts: bool,
    #[serde(default)]
    target: String,
}

fn b64(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("fixture base64")
}

/// `filepath.Clean` for slash-separated paths.
fn go_clean(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let rooted = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// N1: replace the store root as Go prints it.
fn normalize_store(text: &str, arg: &str) -> String {
    let root = go_clean(arg);
    if root == "." {
        return text.to_owned();
    }
    text.replace(&root, STORE_MARKER)
}

/// N2: drop optional lines, collapse consecutive duplicates.
fn normalize_variant(text: &str, optional: &[String]) -> String {
    let mut kept: Vec<&str> = Vec::new();
    for line in text.split('\n') {
        if optional.iter().any(|skip| skip == line) {
            continue;
        }
        if kept.last() == Some(&line) {
            continue;
        }
        kept.push(line);
    }
    kept.join("\n")
}

fn errors_match(
    recorded: &str,
    got: &str,
    case: &Case,
    recorded_version: &str,
    version: &str,
) -> bool {
    if recorded_version == version || !case.version_variant {
        return recorded == got;
    }
    normalize_variant(recorded, &case.optional_stderr_lines)
        == normalize_variant(got, &case.optional_stderr_lines)
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

fn gpg_version() -> String {
    let output = Command::new("gpg")
        .arg("--version")
        .env("LC_ALL", "C")
        .output()
        .expect("gpg is required for this contract test (fail closed): not found on PATH");
    assert!(output.status.success(), "gpg --version failed");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .expect("gpg --version output")
        .trim()
        .to_owned()
}

fn materialize(store: &Path, files: &[FileSpec]) -> Vec<PathBuf> {
    fs::create_dir_all(store).unwrap();
    let mut locked = Vec::new();
    for file in files {
        // filepath.Join cleans a "." path element away.
        let path = if file.path == "." {
            store.to_path_buf()
        } else {
            store.join(&file.path)
        };
        match file.kind.as_str() {
            "encrypted" | "raw" => {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, b64(&file.content_base64)).unwrap();
            }
            "symlink" => {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::os::unix::fs::symlink(&file.target, &path).unwrap();
            }
            "dir" | "locked_dir" => {
                fs::create_dir_all(&path).unwrap();
                if file.kind == "locked_dir" {
                    locked.push(path);
                }
            }
            other => panic!("unknown file kind {other}"),
        }
    }
    locked
}

/// The argument handed to the importer and the directory to chdir into.
fn store_argument(base: &Path, form: &str) -> (String, Option<PathBuf>) {
    let base_str = base.to_str().expect("utf-8 base");
    let store = base.join(STORE_DIR);
    match form {
        "plain" => (store.to_str().unwrap().to_owned(), None),
        "trailing_slash" => (format!("{}/", store.display()), None),
        "double_slash" => (format!("{base_str}//{STORE_DIR}"), None),
        "dot_segment" => (format!("{base_str}/./{STORE_DIR}"), None),
        "parent_segment" => (format!("{base_str}/other/../{STORE_DIR}"), None),
        "relative" => (STORE_DIR.to_owned(), Some(base.to_path_buf())),
        "relative_dot" => (format!("./{STORE_DIR}"), Some(base.to_path_buf())),
        "cwd_dot" => (".".to_owned(), Some(store)),
        "symlink_root" => (format!("{base_str}/store-link"), None),
        "symlink_root_slash" => (format!("{base_str}/store-link/"), None),
        "symlink_root_gpg" => (format!("{base_str}/store-link.gpg"), None),
        "missing" => (format!("{base_str}/no-such-store"), None),
        "file" => (format!("{base_str}/afile"), None),
        other => panic!("unknown store form {other}"),
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
fn pass_importer_matches_real_gpg_go_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/sync/pass-gpg.json"
    )))
    .expect("parse source-bound fixture");
    assert_eq!(
        fixture.cases.len(),
        EXPECTED_CASES,
        "fixture cardinality is part of the gate"
    );
    assert_eq!(fixture.oracle.gpg_args, ["--decrypt", "--batch", "--yes"]);
    let version = gpg_version();

    let sandbox = tempfile::Builder::new()
        .prefix("pgc-")
        .tempdir_in(short_base())
        .expect("sandbox");
    let sandbox_path = fs::canonicalize(sandbox.path()).expect("canonical sandbox");
    let home = sandbox_path.join("home");
    fs::create_dir_all(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(home.join("gpg-agent.conf"), &fixture.keyring.agent_conf).unwrap();
    let _agent = AgentGuard(home.clone());

    // Import the test-only secret key; the keyring then holds nothing else.
    let mut import = Command::new("gpg");
    gpg_env(&mut import, &home);
    let key_file = sandbox_path.join("secret-key.asc");
    fs::write(&key_file, &fixture.keyring.secret_key_armor).unwrap();
    let imported = import
        .args(["--batch", "--import"])
        .arg(&key_file)
        .output()
        .expect("run gpg --import");
    assert!(
        imported.status.success(),
        "import test key: {}",
        String::from_utf8_lossy(&imported.stderr)
    );

    // The importer forwards GNUPGHOME/HOME/LC_ALL/PATH from this process.
    // SAFETY: this binary contains exactly one test, so no other thread reads
    // or writes the environment while it is modified.
    unsafe {
        std::env::set_var("GNUPGHOME", &home);
        std::env::set_var("LC_ALL", "C");
        std::env::set_var("HOME", &home);
    }

    let mut failures: Vec<String> = Vec::new();
    let mut executed = 0usize;
    let mut failing_stores = 0usize;
    for (index, case) in fixture.cases.iter().enumerate() {
        let base = sandbox_path.join(format!("case-{index}"));
        fs::create_dir_all(&base).unwrap();
        let mut locked = Vec::new();
        match case.store_form.as_str() {
            "missing" => {}
            "file" => fs::write(base.join("afile"), b"x").unwrap(),
            _ => {
                fs::create_dir_all(base.join("other")).unwrap();
                locked = materialize(&base.join(STORE_DIR), &case.files);
            }
        }
        match case.store_form.as_str() {
            "symlink_root" | "symlink_root_slash" => {
                std::os::unix::fs::symlink(STORE_DIR, base.join("store-link")).unwrap()
            }
            "symlink_root_gpg" => {
                std::os::unix::fs::symlink(STORE_DIR, base.join("store-link.gpg")).unwrap()
            }
            _ => {}
        }

        // The ciphertexts the keyring is meant to read must decrypt to the
        // recorded plaintext with the system gpg itself (before any directory
        // is made unreadable).
        for file in case
            .files
            .iter()
            .filter(|f| f.kind == "encrypted" && f.decrypts)
        {
            let ciphertext = base.join(STORE_DIR).join(&file.path);
            let mut direct = Command::new("gpg");
            gpg_env(&mut direct, &home);
            let output = direct
                .args(&fixture.oracle.gpg_args)
                .arg(&ciphertext)
                .output()
                .expect("run gpg --decrypt");
            if !output.status.success() || output.stdout != b64(&file.plaintext_base64) {
                failures.push(format!(
                    "{}/{}: gpg --decrypt does not reproduce the recorded plaintext",
                    case.id, file.path
                ));
            }
        }

        for dir in &locked {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o000)).unwrap();
            assert!(
                fs::read_dir(dir).is_err(),
                "{}: permission bits are not enforced (running as root?); the unreadable-directory case needs an unprivileged user",
                case.id
            );
        }

        let (arg, chdir) = store_argument(&base, &case.store_form);
        let previous = std::env::current_dir().expect("cwd");
        if let Some(dir) = &chdir {
            std::env::set_current_dir(dir).expect("chdir into case root");
        }
        let result = import_pass(Path::new(&arg));
        if chdir.is_some() {
            std::env::set_current_dir(&previous).expect("restore cwd");
        }
        for dir in &locked {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        executed += 1;

        let id = &case.id;
        if case.failed {
            failing_stores += 1;
            match result {
                Ok(entries) => {
                    failures.push(format!("{id}: rust accepted {} entries", entries.len()))
                }
                Err(ImportError::Parse(text)) => {
                    let text = normalize_store(&text, &arg);
                    if !errors_match(
                        &case.error,
                        &text,
                        case,
                        &fixture.oracle.gpg_version,
                        &version,
                    ) {
                        failures.push(format!(
                            "{id}: error differs\n  go:   {:?}\n  rust: {text:?}",
                            case.error
                        ));
                    }
                }
                Err(other) => failures.push(format!("{id}: unexpected error variant {other:?}")),
            }
        } else {
            match result {
                Ok(entries) => {
                    let actual = serde_json::to_value(entries).expect("serialize entries");
                    if actual != Value::Array(case.expected.clone()) {
                        failures.push(describe_entry_difference(id, &case.expected, &actual));
                    }
                }
                Err(error) => failures.push(format!("{id}: rust error {error}")),
            }
        }
    }

    assert_eq!(executed, EXPECTED_CASES, "every case must execute");
    assert!(failing_stores > 0, "the corpus must include failing stores");
    assert!(
        failures.is_empty(),
        "{} pass/gpg difference(s) ({version}):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn describe_entry_difference(id: &str, expected: &[Value], actual: &Value) -> String {
    let actual_entries = actual.as_array().cloned().unwrap_or_default();
    let mut lines = vec![format!(
        "{id}: entries differ (go {} entries, rust {})",
        expected.len(),
        actual_entries.len()
    )];
    for index in 0..expected.len().max(actual_entries.len()) {
        let go = expected.get(index);
        let rust = actual_entries.get(index);
        if go != rust {
            lines.push(format!(
                "  [{index}] go:   {go:?}\n  [{index}] rust: {rust:?}"
            ));
        }
    }
    lines.join("\n")
}
