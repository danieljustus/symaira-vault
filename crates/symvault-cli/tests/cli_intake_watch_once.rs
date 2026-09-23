use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

fn run(binary: &Path, home: &Path, tmp: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("TMPDIR", tmp)
        .env("TMP", tmp)
        .env("TEMP", tmp)
        .env_remove("SYMVAULT_VAULT")
        .env_remove("SYMVAULT_PASSPHRASE")
        .output()
        .expect("run intake watch --once")
}

fn assert_same(go: &Output, rust: &Output) {
    assert_eq!(rust.status.code(), go.status.code());
    assert_eq!(rust.stdout, go.stdout);
    assert_eq!(rust.stderr, go.stderr);
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
        let go = run(&go_binary, &home, &go_tmp, &args);
        let rust = run(rust_binary, &home, &rust_tmp, &args);
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
    let go = run(&go_binary, &home, &go_tmp, &args);
    let rust = run(rust_binary, &home, &rust_tmp, &args);
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
    let go = run(&go_binary, &home, &go_tmp, &args);
    let rust = run(rust_binary, &home, &rust_tmp, &args);
    assert_same(&go, &rust);
    assert_eq!(go.status.code(), Some(9));
}

#[test]
fn stable_candidate_never_reports_success_without_a_batch_writer() {
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let temp = TempDir::new().expect("temporary test root");
    let home = temp.path().join("home");
    let tmp = temp.path().join("tmp");
    let folder = temp.path().join("intake");
    fs::create_dir_all(&home).expect("create HOME");
    fs::create_dir(&tmp).expect("create temp directory");
    fs::create_dir(&folder).expect("create intake directory");
    let candidate = folder.join("stable.txt");
    fs::write(&candidate, "password: fixture").expect("write stable candidate");
    std::thread::sleep(std::time::Duration::from_millis(10));

    let output = run(
        rust_binary,
        &home,
        &tmp,
        &[
            "intake",
            "watch",
            folder.to_str().unwrap(),
            "--once",
            "--debounce",
            "1ns",
        ],
    );
    assert_eq!(fs::read(&candidate).unwrap(), b"password: fixture");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("vault-backed batch writer is unavailable")
    );
    assert!(
        !output.status.success(),
        "missing batch writer must not claim success"
    );
}
