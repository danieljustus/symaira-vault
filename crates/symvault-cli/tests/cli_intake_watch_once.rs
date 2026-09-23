use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

fn run(binary: &Path, home: &Path, tmp: &Path, vault: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .arg("--vault")
        .arg(vault)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("TMPDIR", tmp)
        .env("TMP", tmp)
        .env("TEMP", tmp)
        .env("SYMVAULT_PASSPHRASE", "fixture-passphrase-123")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_NO_ENV_WARNING", "1")
        .env_remove("SYMVAULT_VAULT")
        .output()
        .expect("run intake watch --once")
}

fn initialize(binary: &Path, home: &Path, tmp: &Path, vault: &Path) {
    let output = run(binary, home, tmp, vault, &["init", "--auth", "passphrase"]);
    assert!(
        output.status.success(),
        "initialize disposable vault: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config_path = vault.join("config.yaml");
    let config = fs::read_to_string(&config_path).expect("read disposable vault config");
    assert!(config.contains("auto_push: true"));
    fs::write(
        &config_path,
        config.replace("auto_push: true", "auto_push: false"),
    )
    .expect("disable network push for disposable vault");
}

fn assert_same(go: &Output, rust: &Output) {
    assert_eq!(
        rust.status.code(),
        go.status.code(),
        "Go stdout={} stderr={}; Rust stdout={} stderr={}",
        String::from_utf8_lossy(&go.stdout),
        String::from_utf8_lossy(&go.stderr),
        String::from_utf8_lossy(&rust.stdout),
        String::from_utf8_lossy(&rust.stderr)
    );
    assert_eq!(rust.stdout, go.stdout);
    assert_eq!(rust.stderr, go.stderr);
}

fn quarantine_entry_path(binary: &Path, home: &Path, tmp: &Path, vault: &Path, go: bool) -> String {
    let args = if go {
        vec!["--output", "json", "list", "quarantine/"]
    } else {
        vec!["--json", "list", "quarantine/"]
    };
    let listed = run(binary, home, tmp, vault, &args);
    assert!(
        listed.status.success(),
        "list persisted quarantine entries: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let entries: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    let paths = entries
        .as_array()
        .expect("JSON list is an array")
        .iter()
        .filter_map(|entry| entry["path"].as_str())
        .filter(|path| path.ends_with("/stable"))
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1, "one stable quarantine entry: {entries}");
    paths[0].to_owned()
}

#[test]
fn watch_once_matches_go_for_empty_debounced_and_invalid_directories() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let temp = TempDir::new().expect("temporary test root");
    let home = temp.path().join("home");
    let go_tmp = temp.path().join("go-tmp");
    let rust_tmp = temp.path().join("rust-tmp");
    let unused_vault = temp.path().join("unused-vault");
    let folder = temp.path().join("intake");
    fs::create_dir_all(&home).expect("create HOME");
    fs::create_dir_all(&go_tmp).expect("create Go temp");
    fs::create_dir_all(&rust_tmp).expect("create Rust temp");
    fs::create_dir(&folder).expect("create intake directory");

    for (json, args) in [
        (
            false,
            vec!["intake", "watch", folder.to_str().unwrap(), "--once"],
        ),
        (
            true,
            vec![
                "intake",
                "watch",
                folder.to_str().unwrap(),
                "--once",
                "--json",
            ],
        ),
    ] {
        let go = run(&go_binary, &home, &go_tmp, &unused_vault, &args);
        let rust = run(rust_binary, &home, &rust_tmp, &unused_vault, &args);
        assert_same(&go, &rust);
        assert_eq!(go.status.code(), Some(0), "json={json}");
        assert!(fs::read_dir(&go_tmp).unwrap().next().is_none());
        assert!(fs::read_dir(&rust_tmp).unwrap().next().is_none());
    }

    let candidate = folder.join("still-writing.txt");
    fs::write(&candidate, "partial credential").expect("write young candidate");
    let args = [
        "intake",
        "watch",
        folder.to_str().unwrap(),
        "--once",
        "--debounce",
        "1h",
    ];
    let go = run(&go_binary, &home, &go_tmp, &unused_vault, &args);
    let rust = run(rust_binary, &home, &rust_tmp, &unused_vault, &args);
    assert_same(&go, &rust);
    assert_eq!(go.status.code(), Some(0));
    assert_eq!(fs::read(&candidate).unwrap(), b"partial credential");

    let not_a_directory = temp.path().join("plain-file");
    fs::write(&not_a_directory, "fixture").expect("write non-directory fixture");
    let args = [
        "intake",
        "watch",
        "--once",
        not_a_directory.to_str().unwrap(),
    ];
    let go = run(&go_binary, &home, &go_tmp, &unused_vault, &args);
    let rust = run(rust_binary, &home, &rust_tmp, &unused_vault, &args);
    assert_same(&go, &rust);
    assert_eq!(go.status.code(), Some(9));
}

#[test]
fn stable_candidate_matches_go_and_persists_quarantine_attachment() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let temp = TempDir::new().expect("temporary test root");
    let go_home = temp.path().join("go-home");
    let rust_home = temp.path().join("rust-home");
    let go_tmp = temp.path().join("go-tmp");
    let rust_tmp = temp.path().join("rust-tmp");
    let go_vault = temp.path().join("go-vault");
    let rust_vault = temp.path().join("rust-vault");
    let go_folder = temp.path().join("go-intake");
    let rust_folder = temp.path().join("rust-intake");
    for dir in [
        &go_home,
        &rust_home,
        &go_tmp,
        &rust_tmp,
        &go_folder,
        &rust_folder,
    ] {
        fs::create_dir_all(dir).expect("create throwaway directory");
    }
    initialize(rust_binary, &go_home, &go_tmp, &go_vault);
    initialize(rust_binary, &rust_home, &rust_tmp, &rust_vault);
    let go_candidate = go_folder.join("stable.txt");
    let rust_candidate = rust_folder.join("stable.txt");
    fs::write(&go_candidate, "password: fixture").expect("write Go candidate");
    fs::write(&rust_candidate, "password: fixture").expect("write Rust candidate");
    std::thread::sleep(std::time::Duration::from_millis(10));

    let go_args = [
        "intake",
        "watch",
        go_folder.to_str().unwrap(),
        "--once",
        "--debounce",
        "1ns",
        "--quiet",
    ];
    let rust_args = [
        "intake",
        "watch",
        rust_folder.to_str().unwrap(),
        "--once",
        "--debounce",
        "1ns",
        "--quiet",
    ];
    let go = run(&go_binary, &go_home, &go_tmp, &go_vault, &go_args);
    let rust = run(rust_binary, &rust_home, &rust_tmp, &rust_vault, &rust_args);
    assert_eq!(
        rust.status.code(),
        go.status.code(),
        "Go stdout={} stderr={}; Rust stdout={} stderr={}",
        String::from_utf8_lossy(&go.stdout),
        String::from_utf8_lossy(&go.stderr),
        String::from_utf8_lossy(&rust.stdout),
        String::from_utf8_lossy(&rust.stderr)
    );
    assert_eq!(rust.status.code(), Some(0));
    assert_eq!(rust.stdout, go.stdout);
    assert_eq!(rust.stderr, go.stderr);
    let go_entry = quarantine_entry_path(&go_binary, &go_home, &go_tmp, &go_vault, true);
    let rust_entry = quarantine_entry_path(rust_binary, &rust_home, &rust_tmp, &rust_vault, false);
    assert_eq!(fs::read(go_candidate).unwrap(), b"password: fixture");
    assert_eq!(fs::read(rust_candidate).unwrap(), b"password: fixture");

    for (binary, home, tmp, vault, entry_path) in [
        (go_binary.as_path(), &go_home, &go_tmp, &go_vault, &go_entry),
        (
            go_binary.as_path(),
            &rust_home,
            &rust_tmp,
            &rust_vault,
            &rust_entry,
        ),
        (rust_binary, &go_home, &go_tmp, &go_vault, &go_entry),
        (rust_binary, &rust_home, &rust_tmp, &rust_vault, &rust_entry),
    ] {
        let persisted = run(binary, home, tmp, vault, &["--json", "get", entry_path]);
        assert!(
            persisted.status.success(),
            "read persisted quarantine entry {entry_path}: {}",
            String::from_utf8_lossy(&persisted.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&persisted.stdout).unwrap();
        assert_eq!(value["Fields"]["password"], "fixture");
        assert_eq!(value["Fields"]["attachment"], "cGFzc3dvcmQ6IGZpeHR1cmU=");
    }
}
