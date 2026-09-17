#![cfg(unix)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn temporary_root(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    env::temp_dir().join(format!("symvault-edit-differential-{name}-{suffix}"))
}

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .output()
        .expect("run CLI")
}

fn assert_success(output: &Output, command: &str) {
    assert!(
        output.status.success(),
        "{command} failed: status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn edit_matches_go_editor_json_roundtrip_and_cleans_private_temp_file() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = temporary_root("home");
    let root = temporary_root("vault");
    let fixture_dir = temporary_root("fixtures");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&fixture_dir).expect("fixtures");

    let init = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        &root,
        &home,
    );
    assert_success(&init, "Rust init");

    let set = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "set",
            "work/edit.password",
            "--value",
            "original",
            "--force",
        ],
        &root,
        &home,
    );
    assert_success(&set, "Go set");

    let go_marker = fixture_dir.join("go-temp-path");
    let go_mode = fixture_dir.join("go-temp-mode");
    let go_editor = fixture_dir.join("go-editor.sh");
    write_editor(
        &go_editor,
        &go_marker,
        &go_mode,
        r#"{"data":{"password":"edited-by-go","username":"alice"}}"#,
    );
    let go_edit = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "edit",
            "work/edit",
            "--editor",
            go_editor.to_str().unwrap(),
        ],
        &root,
        &home,
    );
    assert_success(&go_edit, "Go edit");
    assert_eq!(go_edit.stdout, b"Entry updated: work/edit\n");
    let go_temp_path = fs::read_to_string(&go_marker).expect("Go temp path marker");
    assert!(!Path::new(go_temp_path.trim()).exists(), "Go temp cleanup");
    assert_eq!(
        fs::read_to_string(&go_mode).expect("Go temp mode").trim(),
        "600"
    );

    let rust_marker = fixture_dir.join("rust-temp-path");
    let rust_mode = fixture_dir.join("rust-temp-mode");
    let rust_editor = fixture_dir.join("rust-editor.sh");
    write_editor(
        &rust_editor,
        &rust_marker,
        &rust_mode,
        r#"{"data":{"password":"edited-by-rust","username":"bob"}}"#,
    );
    let rust_edit = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "edit",
            "work/edit",
            "--editor",
            rust_editor.to_str().unwrap(),
        ],
        &root,
        &home,
    );
    assert_success(&rust_edit, "Rust edit");
    assert_eq!(rust_edit.stdout, b"Entry updated: work/edit\n");
    let rust_temp_path = fs::read_to_string(&rust_marker).expect("Rust temp path marker");
    assert!(
        !Path::new(rust_temp_path.trim()).exists(),
        "Rust temp cleanup"
    );
    assert_eq!(
        fs::read_to_string(&rust_mode)
            .expect("Rust temp mode")
            .trim(),
        "600"
    );

    let go_get = run(
        &go_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "get",
            "work/edit.password",
            "--print",
        ],
        &root,
        &home,
    );
    let rust_get = run(
        &rust_binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "get",
            "work/edit.password",
            "--print",
        ],
        &root,
        &home,
    );
    assert_success(&go_get, "Go get after Rust edit");
    assert_success(&rust_get, "Rust get after Rust edit");
    assert_eq!(go_get.stdout, b"edited-by-rust\n");
    assert_eq!(rust_get.stdout, go_get.stdout);

    let _ = fs::remove_dir_all(&home);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&fixture_dir);
}

fn write_editor(path: &Path, marker: &Path, mode: &Path, json: &str) {
    let script = format!(
        "#!/bin/sh\nprintf '%s' \"$1\" > {}\n(stat -c '%a' \"$1\" 2>/dev/null || stat -f '%Lp' \"$1\") > {}\nprintf '%s\\n' '{}' > \"$1\"\n",
        shell_quote(marker),
        shell_quote(mode),
        json.replace('\'', "'\\''")
    );
    fs::write(path, script).expect("editor script");
    let mut permissions = fs::metadata(path).expect("editor metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("editor executable");
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

use std::os::unix::fs::PermissionsExt;
