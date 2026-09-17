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
    env::temp_dir().join(format!("symvault-run-differential-{name}-{suffix}"))
}

fn run(binary: &Path, args: &[String], root: &Path, home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("RUN_SAFE_MARKER", "ambient-value")
        .env("CI", "1")
        .output()
        .expect("run CLI")
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed: status={:?}\nstdout={:?}\nstderr={:?}",
        output.status,
        output.stdout,
        output.stderr
    );
}

fn string_args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn run_matches_go_for_secret_env_file_passthrough_pattern_and_exit() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let root = temporary_root("vault");
    let home = temporary_root("home");
    let env_file = temporary_root("env");
    fs::create_dir_all(&home).expect("home");

    let init = run(
        &rust_binary,
        &string_args(&[
            "--vault",
            root.to_str().expect("vault path"),
            "init",
            "--auth",
            "passphrase",
        ]),
        &root,
        &home,
    );
    assert_success(&init, "Rust init");

    let set = run(
        &go_binary,
        &string_args(&[
            "--vault",
            root.to_str().expect("vault path"),
            "set",
            "run/password",
            "--value",
            "synthetic-run-secret",
            "--force",
        ]),
        &root,
        &home,
    );
    assert_success(&set, "Go set");

    fs::write(&env_file, b"FROM_FILE=run/password\n").expect("env file");
    let pattern_suffix = "ABCDEFGHIJKLMNOP";
    let command = format!(
        "printf '%s|%s|%s|%s' \"$TOKEN\" \"$FROM_FILE\" \"$RUN_SAFE_MARKER\" AKIA{pattern_suffix}"
    );
    let mut args = vec![
        "--vault".to_owned(),
        root.to_str().expect("vault path").to_owned(),
        "run".to_owned(),
        "--env".to_owned(),
        "TOKEN=run/password".to_owned(),
        "--env-file".to_owned(),
        env_file.to_str().expect("env path").to_owned(),
        "--passthrough".to_owned(),
        "RUN_SAFE_MARKER".to_owned(),
        "--".to_owned(),
        "sh".to_owned(),
        "-c".to_owned(),
        command,
    ];
    let go_run = run(&go_binary, &args, &root, &home);
    let rust_run = run(&rust_binary, &args, &root, &home);
    assert_success(&go_run, "Go run");
    assert_success(&rust_run, "Rust run");
    assert_eq!(rust_run.stdout, go_run.stdout, "run stdout");
    assert_eq!(rust_run.stderr, go_run.stderr, "run stderr");

    args = string_args(&[
        "--vault",
        root.to_str().expect("vault path"),
        "run",
        "--",
        "sh",
        "-c",
        "printf 'synthetic-error' >&2; exit 7",
    ]);
    let go_failed = run(&go_binary, &args, &root, &home);
    let rust_failed = run(&rust_binary, &args, &root, &home);
    assert_eq!(
        rust_failed.status.code(),
        go_failed.status.code(),
        "exit status"
    );
    assert_eq!(rust_failed.stdout, go_failed.stdout, "failed run stdout");
    assert_eq!(rust_failed.stderr, go_failed.stderr, "failed run stderr");

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&home);
    let _ = fs::remove_file(&env_file);
}
