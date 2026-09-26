#![cfg(unix)]

use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};

const PASSPHRASE: &str = "differential sample passphrase";

fn run(binary: &Path, args: &[&str], home: &Path, vault: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", vault)
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run CLI")
}

fn write_editor(path: &Path, content: &str) {
    let script = format!("#!/bin/sh\ncat > \"$1\" <<'SYMAIRA_ENTRY'\n{content}\nSYMAIRA_ENTRY\n");
    fs::write(path, script).expect("write editor");
    let mut permissions = fs::metadata(path).expect("editor metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("make editor executable");
}

fn normalize_entry_name(output: &[u8], name: &str) -> Vec<u8> {
    String::from_utf8(output.to_vec())
        .expect("CLI output is UTF-8")
        .replace(name, "entry")
        .into_bytes()
}

#[test]
fn get_matches_go_for_missing_and_empty_field_maps() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = std::path::PathBuf::from(go_binary);
    let rust_binary =
        std::path::PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = tempfile::tempdir().expect("temporary home");
    let vault = home.path().join("vault");
    let initialized = run(
        &go_binary,
        &["init", "--auth", "passphrase"],
        home.path(),
        &vault,
    );
    assert!(
        initialized.status.success(),
        "Go init failed: {:?}",
        initialized.stderr
    );

    let fixtures = [
        (
            "missing-data",
            r#"{"meta":{"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z","version":2},"secret_meta":{"type":"password","usage_hint":""}}"#,
        ),
        (
            "empty-data",
            r#"{"data":{},"meta":{"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z","version":2},"secret_meta":{"type":"password","usage_hint":""}}"#,
        ),
    ];
    let mut go_outputs = Vec::new();

    for (name, content) in fixtures {
        let added = run(
            &go_binary,
            &["add", name, "--value", "sample", "--force"],
            home.path(),
            &vault,
        );
        assert!(added.status.success(), "Go add failed: {:?}", added.stderr);

        let editor = home.path().join(format!("{name}-editor.sh"));
        write_editor(&editor, content);
        let editor_arg = editor.to_str().expect("editor path");
        let edited = run(
            &go_binary,
            &["edit", name, "--editor", editor_arg],
            home.path(),
            &vault,
        );
        assert!(
            edited.status.success(),
            "Go edit failed: {:?}",
            edited.stderr
        );

        let mut formats = Vec::new();
        for format in ["text", "json", "yaml"] {
            let args = ["get", name, "--output", format];
            let go = run(&go_binary, &args, home.path(), &vault);
            let rust = run(&rust_binary, &args, home.path(), &vault);
            assert_eq!(go.status.code(), Some(0), "Go {format}: {:?}", go.stderr);
            assert_eq!(
                rust.status.code(),
                Some(0),
                "Rust {format}: {:?}",
                rust.stderr
            );
            assert_eq!(rust.stdout, go.stdout, "{name} {format} stdout differs");
            assert_eq!(rust.stderr, go.stderr, "{name} {format} stderr differs");
            formats.push(normalize_entry_name(&go.stdout, name));
        }
        go_outputs.push(formats);
    }

    assert_eq!(
        go_outputs[0], go_outputs[1],
        "missing and empty maps differ"
    );
}
