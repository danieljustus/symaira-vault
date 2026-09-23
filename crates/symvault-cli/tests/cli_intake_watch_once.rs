use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[cfg(unix)]
use std::{
    process::{Child, Stdio},
    time::{Duration, Instant},
};

use tempfile::TempDir;

fn run(binary: &Path, home: &Path, tmp: &Path, vault: &Path, args: &[&str]) -> Output {
    configured_command(binary, home, tmp, vault, args)
        .output()
        .expect("run intake watch --once")
}

fn configured_command(
    binary: &Path,
    home: &Path,
    tmp: &Path,
    vault: &Path,
    args: &[&str],
) -> Command {
    let mut command = Command::new(binary);
    command
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
        .env_remove("SYMVAULT_VAULT");
    command
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

fn quarantine_entry_paths(
    binary: &Path,
    home: &Path,
    tmp: &Path,
    vault: &Path,
    go: bool,
) -> Vec<String> {
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
    let Some(entries) = entries.as_array() else {
        assert!(
            entries.is_null(),
            "JSON list is an array or null: {entries}"
        );
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| entry["path"].as_str())
        .map(str::to_owned)
        .collect::<Vec<_>>()
}

fn quarantine_entry_path(binary: &Path, home: &Path, tmp: &Path, vault: &Path, go: bool) -> String {
    let paths = quarantine_entry_paths(binary, home, tmp, vault, go)
        .into_iter()
        .filter(|path| path.ends_with("/stable"))
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1, "one stable quarantine entry: {paths:?}");
    paths[0].clone()
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

    let go_repeat = run(&go_binary, &go_home, &go_tmp, &go_vault, &go_args);
    let rust_repeat = run(rust_binary, &rust_home, &rust_tmp, &rust_vault, &rust_args);
    assert_same(&go_repeat, &rust_repeat);
    assert_eq!(go_repeat.status.code(), Some(0));
    assert_eq!(
        quarantine_entry_path(&go_binary, &go_home, &go_tmp, &go_vault, true),
        go_entry,
        "Go hash dedupe must leave one entry after a repeated scan"
    );
    assert_eq!(
        quarantine_entry_path(rust_binary, &rust_home, &rust_tmp, &rust_vault, false),
        rust_entry,
        "Rust hash dedupe must leave one entry after a repeated scan"
    );
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

#[test]
fn oversized_source_matches_go_skip_and_remains_unchanged() {
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
    let contents = vec![b'x'; 1024 * 1024 + 1];
    let go_source = go_folder.join("too-large.txt");
    let rust_source = rust_folder.join("too-large.txt");
    fs::write(&go_source, &contents).expect("write oversized Go source");
    fs::write(&rust_source, &contents).expect("write oversized Rust source");

    let go_args = [
        "intake",
        "watch",
        go_folder.to_str().unwrap(),
        "--once",
        "--debounce",
        "1ns",
        "--json",
    ];
    let rust_args = [
        "intake",
        "watch",
        rust_folder.to_str().unwrap(),
        "--once",
        "--debounce",
        "1ns",
        "--json",
    ];
    let unused_vault = temp.path().join("unused-vault");
    let go = run(&go_binary, &go_home, &go_tmp, &unused_vault, &go_args);
    let rust = run(
        rust_binary,
        &rust_home,
        &rust_tmp,
        &unused_vault,
        &rust_args,
    );
    assert_eq!(rust.status.code(), go.status.code());
    assert_eq!(rust.status.code(), Some(0));
    assert_eq!(rust.stderr, go.stderr);
    let normalize = |output: &Output, source: &Path| {
        let mut summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let mut skipped = summary["skipped"][0].as_str().unwrap().to_owned();
        let source_root = source.parent().unwrap();
        for root in [
            source_root.to_path_buf(),
            fs::canonicalize(source_root).expect("canonicalize disposable source root"),
        ] {
            skipped = skipped.replace(root.to_str().unwrap(), "<source-root>");
        }
        summary["skipped"][0] = skipped.into();
        summary
    };
    let go_summary = normalize(&go, &go_source);
    let rust_summary = normalize(&rust, &rust_source);
    assert_eq!(rust_summary, go_summary);
    assert_eq!(go_summary["scanned"], 1);
    assert_eq!(go_summary["staged"], serde_json::Value::Null);
    assert_eq!(
        go_summary["skipped"][0],
        "too-large.txt: reject \"<source-root>/too-large.txt\": 1048577 bytes exceeds the 1048576 byte per-file limit"
    );
    assert_eq!(fs::read(go_source).unwrap(), contents);
    assert_eq!(fs::read(rust_source).unwrap(), contents);
}

#[cfg(unix)]
fn wait_for_entry(
    child: &mut Child,
    binary: &Path,
    home: &Path,
    tmp: &Path,
    vault: &Path,
    go: bool,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("poll continuous watcher") {
            panic!("continuous watcher exited before intake: {status}");
        }
        if let Some(path) = quarantine_entry_paths(binary, home, tmp, vault, go)
            .into_iter()
            .find(|path| path.ends_with("/late"))
        {
            return path;
        }
        assert!(
            Instant::now() < deadline,
            "continuous watcher intake timed out"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
fn stop_with_sigterm(child: &Child) {
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM to watcher");
    assert!(status.success(), "send SIGTERM: {status}");
}

#[cfg(unix)]
fn finish_with_timeout(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().expect("poll watcher shutdown").is_some() {
            return child.wait_with_output().expect("collect watcher output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("watcher did not stop within five seconds after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(unix)]
fn normalized_batch(output: &Output) -> Vec<serde_json::Value> {
    let mut batches = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    for batch in &mut batches {
        let import_id = batch["import_id"].as_str().unwrap().to_owned();
        batch["import_id"] = "<import-id>".into();
        for path in batch["written"].as_array_mut().unwrap() {
            *path = path
                .as_str()
                .unwrap()
                .replace(&import_id, "<import-id>")
                .into();
        }
    }
    batches
}

#[cfg(unix)]
#[test]
fn continuous_watch_intakes_late_file_and_stops_on_sigterm_like_go() {
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

    let go_args = [
        "intake",
        "watch",
        go_folder.to_str().unwrap(),
        "--interval",
        "50ms",
        "--debounce",
        "1ns",
        "--quiet",
        "--json",
    ];
    let rust_args = [
        "intake",
        "watch",
        rust_folder.to_str().unwrap(),
        "--interval",
        "50ms",
        "--debounce",
        "1ns",
        "--quiet",
        "--json",
    ];

    let mut go_child = configured_command(&go_binary, &go_home, &go_tmp, &go_vault, &go_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start Go watcher");
    let go_source = go_folder.join("late.txt");
    fs::write(&go_source, "token: after-start").expect("create Go source after start");
    let go_entry = wait_for_entry(
        &mut go_child,
        &go_binary,
        &go_home,
        &go_tmp,
        &go_vault,
        true,
    );
    stop_with_sigterm(&go_child);
    let go = finish_with_timeout(go_child);
    assert!(
        fs::read_dir(&go_tmp).unwrap().next().is_none(),
        "Go spool cleanup"
    );

    let mut rust_child =
        configured_command(rust_binary, &rust_home, &rust_tmp, &rust_vault, &rust_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start Rust watcher");
    let rust_source = rust_folder.join("late.txt");
    fs::write(&rust_source, "token: after-start").expect("create Rust source after start");
    let rust_entry = wait_for_entry(
        &mut rust_child,
        rust_binary,
        &rust_home,
        &rust_tmp,
        &rust_vault,
        false,
    );
    stop_with_sigterm(&rust_child);
    let rust = finish_with_timeout(rust_child);
    assert!(
        fs::read_dir(&rust_tmp).unwrap().next().is_none(),
        "Rust spool cleanup"
    );

    assert_eq!(go.status.code(), Some(0));
    assert_eq!(rust.status.code(), Some(0));
    assert_eq!(rust.stderr, go.stderr);
    assert_eq!(normalized_batch(&rust), normalized_batch(&go));
    assert_eq!(normalized_batch(&go).len(), 1);
    let go_batch: serde_json::Value = serde_json::from_slice(&go.stdout).unwrap();
    let rust_batch: serde_json::Value = serde_json::from_slice(&rust.stdout).unwrap();
    assert_eq!(go_entry, go_batch["written"][0]);
    assert_eq!(rust_entry, rust_batch["written"][0]);
    assert_eq!(fs::read(go_source).unwrap(), b"token: after-start");
    assert_eq!(fs::read(rust_source).unwrap(), b"token: after-start");

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
            "read continuous quarantine entry {entry_path}: {}",
            String::from_utf8_lossy(&persisted.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&persisted.stdout).unwrap();
        assert_eq!(value["Fields"]["token"], "after-start");
        assert_eq!(value["Fields"]["attachment"], "dG9rZW46IGFmdGVyLXN0YXJ0");
    }
}
