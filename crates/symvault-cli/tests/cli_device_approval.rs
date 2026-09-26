//! Contract for `device approval-list` and `device approval-revoke` plus the
//! device-session registry file they share.
//!
//! Expected values were captured from the pinned Go oracle
//! (`target/port/symvault-go`, `GOTOOLCHAIN=go1.26.6`, commit `3232e31f`,
//! release `unreleased`) with throwaway `HOME`/`XDG`/vault roots. Re-capture:
//!
//! ```sh
//! GOTOOLCHAIN=go1.26.6 go build -ldflags \
//!   "-s -w -X main.version=unreleased -X main.commit=none -X main.date=unknown" \
//!   -o target/port/symvault-go .
//! ```
//!
//! Two divergences are **not** asserted here because they are pre-existing and
//! cross-cutting, not properties of this slice:
//!
//! - `CLI-005` (error taxonomy, still `TODO` in the contract matrix): the oracle
//!   prints every returned error twice (`Error: …` on two lines) and phrases the
//!   uninitialised-vault error differently. The port prints the message once;
//!   the message *text* below is what both binaries agree on.
//! - Go's `List` iterates a map, so a multi-row listing has no stable order. The
//!   rows are asserted as a set, and the port's `BTreeMap` order is a documented
//!   difference rather than a contract.
use std::{
    env,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const STORE: &str = ".symvault/device-sessions.json";
const ACTIVE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const REVOKED: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const EXPIRED: &str = "3333333333333333333333333333333333333333333333333333333333333333";

/// A guard owning a unique temporary directory plus the disposable roots inside
/// it. `tempfile` rather than `as_nanos()` names, which are microsecond-coarse on
/// macOS (issue #1085).
fn disposable_roots() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let guard = tempfile::Builder::new()
        .prefix("symvault-cli-device-approval-")
        .tempdir()
        .expect("temp dir");
    let home = guard.path().join("home");
    let root = guard.path().join("vault");
    std::fs::create_dir_all(&home).expect("home");
    std::fs::create_dir_all(&root).expect("vault");
    (guard, home, root)
}

fn rust_binary() -> PathBuf {
    PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"))
}

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    run_with_stdin(binary, args, root, home, None)
}

fn run_with_stdin(
    binary: &Path,
    args: &[&str],
    root: &Path,
    home: &Path,
    stdin_text: Option<&str>,
) -> Output {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .env("NO_COLOR", "1");
    match stdin_text {
        Some(text) => {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().expect("spawn CLI");
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(text.as_bytes())
                .expect("write stdin");
            child.wait_with_output().expect("run CLI")
        }
        None => command.output().expect("run CLI"),
    }
}

#[test]
fn approval_pair_requires_an_initialized_vault_before_server_metadata() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();

    let output = run(
        &binary,
        &["device", "approval-pair", "--host", "192.168.1.42"],
        &root,
        &home,
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("vault not initialized"), "{output:?}");
    assert!(!stderr.contains("running server"), "{output:?}");
}

fn read_store(root: &Path) -> String {
    std::fs::read_to_string(root.join(STORE)).expect("read store")
}

/// Seeds the store exactly as the oracle's own `save` lays it out.
fn seed_store(root: &Path) {
    let dir = root.join(".symvault");
    std::fs::create_dir_all(&dir).expect("store dir");
    let body = format!(
        r#"{{
  "{ACTIVE}": {{
    "prefix": "ABCD",
    "device_id": "dev-active",
    "name": "Daniels iPhone",
    "public_key": "ssh-ed25519 KEY1",
    "created_at": "2026-08-01T10:11:12Z",
    "expires_at": "2999-01-01T00:00:00Z",
    "revoked": false
  }},
  "{REVOKED}": {{
    "prefix": "EFGH",
    "device_id": "dev-revoked",
    "public_key": "ssh-ed25519 KEY2",
    "created_at": "2026-08-02T10:11:12.5Z",
    "expires_at": "2999-01-01T00:00:00Z",
    "revoked": true
  }},
  "{EXPIRED}": {{
    "prefix": "IJKL",
    "device_id": "dev-expired",
    "name": "old tablet",
    "public_key": "ssh-ed25519 KEY3",
    "created_at": "2026-01-01T00:00:00Z",
    "expires_at": "2026-02-01T00:00:00Z",
    "revoked": false
  }}
}}"#
    );
    std::fs::write(root.join(STORE), body).expect("write store");
}

fn stdout_lines(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn list_reports_an_empty_store_and_creates_the_file_like_the_oracle() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();

    let output = run(&binary, &["device", "approval-list"], &root, &home);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "No approval devices enrolled.\n"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(read_store(&root), "{}");
}

#[test]
fn list_renders_every_status_with_go_column_widths() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();
    seed_store(&root);

    let output = run(&binary, &["device", "approval-list"], &root, &home);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    // Rows are compared as a set: Go iterates a map, so its order is not a
    // contract (see the module header).
    let mut lines = stdout_lines(&output);
    let header = lines.remove(0);
    assert_eq!(
        header,
        "DEVICE ID                TOKEN  NAME                     ENROLLED             EXPIRES              STATUS"
    );
    let mut rows = lines;
    rows.sort();
    assert_eq!(
        rows,
        vec![
            "dev-active               ABCD…  Daniels iPhone           2026-08-01 10:11     2999-01-01 00:00     active".to_owned(),
            "dev-expired              IJKL…  old tablet               2026-01-01 00:00     2026-02-01 00:00     expired".to_owned(),
            "dev-revoked              EFGH…  (unnamed)                2026-08-02 10:11     2999-01-01 00:00     revoked".to_owned(),
        ]
    );
}

#[test]
fn list_marks_an_expired_session_as_expired() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();
    let dir = root.join(".symvault");
    std::fs::create_dir_all(&dir).expect("store dir");
    std::fs::write(
        root.join(STORE),
        r#"{
  "3333333333333333333333333333333333333333333333333333333333333333": {
    "prefix": "IJKL",
    "device_id": "dev-expired",
    "name": "old tablet",
    "public_key": "ssh-ed25519 KEY3",
    "created_at": "2026-01-01T00:00:00Z",
    "expires_at": "2026-02-01T00:00:00Z",
    "revoked": false
  }
}"#,
    )
    .expect("write store");

    let output = run(&binary, &["device", "approval-list"], &root, &home);
    assert_eq!(
        stdout_lines(&output),
        vec![
            "DEVICE ID                TOKEN  NAME                     ENROLLED             EXPIRES              STATUS".to_owned(),
            "dev-expired              IJKL…  old tablet               2026-01-01 00:00     2026-02-01 00:00     expired".to_owned(),
        ]
    );
}

#[test]
fn quiet_suppresses_both_the_empty_notice_and_the_table() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();

    let empty = run(
        &binary,
        &["device", "approval-list", "--quiet"],
        &root,
        &home,
    );
    assert_eq!(empty.status.code(), Some(0), "{empty:?}");
    assert!(empty.stdout.is_empty(), "{empty:?}");

    seed_store(&root);
    let seeded = run(
        &binary,
        &["device", "approval-list", "--quiet"],
        &root,
        &home,
    );
    assert!(seeded.stdout.is_empty(), "{seeded:?}");
}

#[test]
fn revoke_with_yes_rewrites_the_store_and_keeps_every_other_field() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();
    seed_store(&root);

    let output = run(
        &binary,
        &["device", "approval-revoke", "-y", "dev-active"],
        &root,
        &home,
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "Approval device \"dev-active\" revoked.\n"
    );

    // The oracle's own rewrite is the expected file: only `revoked` flips, the
    // legacy `name`-less entry keeps its omitted `name`, and the fraction of
    // `created_at` survives.
    let expected = format!(
        r#"{{
  "{ACTIVE}": {{
    "prefix": "ABCD",
    "device_id": "dev-active",
    "name": "Daniels iPhone",
    "public_key": "ssh-ed25519 KEY1",
    "created_at": "2026-08-01T10:11:12Z",
    "expires_at": "2999-01-01T00:00:00Z",
    "revoked": true
  }},
  "{REVOKED}": {{
    "prefix": "EFGH",
    "device_id": "dev-revoked",
    "public_key": "ssh-ed25519 KEY2",
    "created_at": "2026-08-02T10:11:12.5Z",
    "expires_at": "2999-01-01T00:00:00Z",
    "revoked": true
  }},
  "{EXPIRED}": {{
    "prefix": "IJKL",
    "device_id": "dev-expired",
    "name": "old tablet",
    "public_key": "ssh-ed25519 KEY3",
    "created_at": "2026-01-01T00:00:00Z",
    "expires_at": "2026-02-01T00:00:00Z",
    "revoked": false
  }}
}}"#
    );
    assert_eq!(read_store(&root), expected);
}

#[test]
fn revoke_prompts_on_stderr_and_aborts_without_touching_the_store() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();
    seed_store(&root);
    let before = read_store(&root);

    let output = run_with_stdin(
        &binary,
        &["device", "approval-revoke", "dev-active"],
        &root,
        &home,
        Some("n\n"),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "This will revoke approval device \"dev-active\". Continue? [y/N]: Canceled\n"
    );
    assert_eq!(read_store(&root), before);
}

#[test]
fn revoke_accepts_a_trimmed_upper_case_answer_like_go() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();
    seed_store(&root);

    let output = run_with_stdin(
        &binary,
        &["device", "approval-revoke", "dev-active"],
        &root,
        &home,
        Some("  Y  \n"),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "Approval device \"dev-active\" revoked.\n"
    );
    assert!(read_store(&root).contains("\"device_id\": \"dev-active\""));
}

#[test]
fn revoke_errors_match_the_oracle_message_and_exit_status() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();
    seed_store(&root);

    let unknown = run(
        &binary,
        &["device", "approval-revoke", "-y", "dev-nope"],
        &root,
        &home,
    );
    assert_eq!(unknown.status.code(), Some(1), "{unknown:?}");
    assert_eq!(
        String::from_utf8_lossy(&unknown.stderr),
        "Error: approval device \"dev-nope\" not found\n"
    );

    let too_many = run(
        &binary,
        &["device", "approval-revoke", "-y", "a", "b"],
        &root,
        &home,
    );
    assert_eq!(too_many.status.code(), Some(1), "{too_many:?}");
    assert_eq!(
        String::from_utf8_lossy(&too_many.stderr),
        "Error: accepts 1 arg(s), received 2\n"
    );

    let none = run(&binary, &["device", "approval-revoke", "-y"], &root, &home);
    assert_eq!(none.status.code(), Some(1), "{none:?}");
    assert_eq!(
        String::from_utf8_lossy(&none.stderr),
        "Error: accepts 1 arg(s), received 0\n"
    );
}
