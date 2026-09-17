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
        .env("RUN_PATTERN_CORPUS", synthetic_pattern_corpus())
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

fn synthetic_pattern_corpus() -> String {
    let aws_access = ["AKIA", "0123456789ABCDEF"].concat();
    let aws_secret = "A".repeat(40);
    let github_pat = format!("ghp_{}", "A".repeat(36));
    let github_oauth = format!("gho_{}", "B".repeat(36));
    let github_app = format!("ghs_{}", "C".repeat(36));
    let stripe_live = format!("sk_live_{}", "D".repeat(24));
    let stripe_test = format!("sk_test_{}", "E".repeat(24));
    let slack_token = format!("xoxb-{}", "F".repeat(12));
    let slack_webhook = format!(
        "https://hooks.slack.invalid/services/T{}/B{}/{}",
        "G".repeat(8),
        "H".repeat(8),
        "I".repeat(12)
    );
    let openai_key = format!("sk-{}-{}", "J".repeat(20), "K".repeat(10));
    let generic_api = format!("api_key={}", "L".repeat(16));
    let generic_secret = format!("secret-key:{}", "M".repeat(16));
    let password_url = "https://fixture:password@example.invalid/path".to_owned();
    let private_key = "-----BEGIN RSA PRIVATE KEY-----".to_owned();
    let ssh_key = format!("ssh-rsa {}", "N".repeat(100));
    let jwt = format!(
        "eyJ{}.eyJ{}.{}",
        "O".repeat(4),
        "P".repeat(4),
        "Q".repeat(4)
    );
    let email = "fixture@example.invalid".to_owned();
    let valid_card = "4111111111111111".to_owned();
    let invalid_card = "4111111111111112".to_owned();
    let valid_iban = "GB82WEST12345698765432".to_owned();
    let invalid_iban = "GB82WEST12345698765431".to_owned();
    let phone = "+1 212 555 0123".to_owned();
    let bearer = "Bearer abcdef123456".to_owned();
    let sts = format!("FQoGZXIvYXdzE{}", "R".repeat(100));
    let ssn = "123-45-6789".to_owned();
    let ipv4 = "192.0.2.1".to_owned();
    // Go's regexp package uses ASCII word boundaries. Surrounding the AWS
    // value with UTF-8 letters proves the Rust pattern keeps that behavior.
    let unicode_adjacent = format!("é{aws_access}é");

    [
        aws_access,
        aws_secret,
        github_pat,
        github_oauth,
        github_app,
        stripe_live,
        stripe_test,
        slack_token,
        slack_webhook,
        openai_key,
        generic_api,
        generic_secret,
        password_url,
        private_key,
        ssh_key,
        jwt,
        email,
        valid_card,
        invalid_card,
        valid_iban,
        invalid_iban,
        phone,
        bearer,
        sts,
        ssn,
        ipv4,
        unicode_adjacent,
        "Bearer\u{000b}short-fixture".to_owned(),
        "https://fixture:password@example.invalid/a\u{00a0}tail".to_owned(),
    ]
    .join("|")
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

    for (path, value) in [("run/overlap-short", "abcd"), ("run/overlap-long", "bcde")] {
        let set = run(
            &go_binary,
            &string_args(&[
                "--vault",
                root.to_str().expect("vault path"),
                "set",
                path,
                "--value",
                value,
                "--force",
            ]),
            &root,
            &home,
        );
        assert_success(&set, "Go set overlap fixture");
    }

    fs::write(&env_file, b"FROM_FILE=run/password.password\n").expect("env file");
    let command = "printf '%s|%s|%s|%s|%s' \"$TOKEN\" \"$FROM_FILE\" \"$RUN_SAFE_MARKER\" \"$RUN_PATTERN_CORPUS\" abcde".to_owned();
    let mut args = vec![
        "--vault".to_owned(),
        root.to_str().expect("vault path").to_owned(),
        "run".to_owned(),
        "--env".to_owned(),
        "TOKEN=run/password.password".to_owned(),
        "--env".to_owned(),
        "OVERLAP=run/overlap-short.password".to_owned(),
        "--env".to_owned(),
        "OVERLAP_LONG=run/overlap-long.password".to_owned(),
        "--env-file".to_owned(),
        env_file.to_str().expect("env path").to_owned(),
        "--passthrough".to_owned(),
        "RUN_SAFE_MARKER".to_owned(),
        "--passthrough".to_owned(),
        "RUN_PATTERN_CORPUS".to_owned(),
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
    assert!(
        rust_run.stdout.ends_with(b"|***"),
        "overlapping values must be masked as one span"
    );
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
