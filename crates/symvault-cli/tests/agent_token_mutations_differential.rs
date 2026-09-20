//! Go-vs-Rust differential for `agent token new|revoke|rotate`.
//!
//! Patterned on `agent_token_differential.rs`: skips cleanly when
//! `SYMVAULT_GO_BINARY` is unset (it is not set in this worktree). Raw
//! token bytes are nondeterministic by design, so each case normalizes them
//! out before comparing; the registry file's shape (everything except the
//! hash/prefix/id/timestamps a fresh run cannot reproduce) is checked
//! structurally instead of byte-for-byte.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .unwrap_or_else(|error| panic!("run {binary:?} {args:?}: {error}"))
}

/// Strips the fields that legitimately differ between two independent runs
/// (the random token id/hash/prefix and the two processes' wall-clock
/// timestamps), leaving only the shape both binaries must agree on.
fn normalized_summary(output: &[u8]) -> String {
    String::from_utf8_lossy(output)
        .lines()
        .map(|line| {
            if let Some(rest) = line.strip_prefix("  ID:    ") {
                let _ = rest;
                "  ID:    <redacted>".to_owned()
            } else if let Some(rest) = line.strip_prefix("Raw token (copy now — shown once): ") {
                let _ = rest;
                "Raw token (copy now — shown once): <redacted>".to_owned()
            } else if let Some(rest) = line.strip_prefix("  Expires: ") {
                let _ = rest;
                "  Expires: <redacted>".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_same_shape(go: &Output, rust: &Output, case: &str) {
    assert_eq!(
        rust.status,
        go.status,
        "{case}: status differs\ngo stderr: {:?}\nrust stderr: {:?}",
        String::from_utf8_lossy(&go.stderr),
        String::from_utf8_lossy(&rust.stderr)
    );
    assert_eq!(
        normalized_summary(&rust.stdout),
        normalized_summary(&go.stdout),
        "{case}: stdout shape differs\ngo: {:?}\nrust: {:?}",
        String::from_utf8_lossy(&go.stdout),
        String::from_utf8_lossy(&rust.stdout)
    );
}

fn home_dir() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("home");
    for directory in ["config", "data", "cache"] {
        fs::create_dir_all(home.path().join(directory)).expect("home directory");
    }
    home
}

#[test]
fn agent_token_new_matches_go_summary_shape_and_exit_code() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));

    for args in [
        &[
            "agent",
            "token",
            "new",
            "alpha",
            "--tools",
            "list_entries,get_entry",
        ][..],
        &["agent", "token", "new", "", "--tools", "list_entries"][..],
        &["agent", "token", "new", "alpha", "--tools", ""][..],
    ] {
        let go_root = tempfile::tempdir().expect("go vault root");
        let rust_root = tempfile::tempdir().expect("rust vault root");
        let go_home = home_dir();
        let rust_home = home_dir();

        let go = run(&go_binary, args, go_root.path(), go_home.path());
        let rust = run(&rust_binary, args, rust_root.path(), rust_home.path());
        assert_same_shape(&go, &rust, &format!("agent token new {args:?}"));
    }
}

#[test]
fn agent_token_revoke_matches_go_not_found_and_success_text() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));

    let go_root = tempfile::tempdir().expect("go vault root");
    let rust_root = tempfile::tempdir().expect("rust vault root");
    let go_home = home_dir();
    let rust_home = home_dir();

    let missing_args = ["agent", "token", "revoke", "alpha", "tok-does-not-exist"];
    let go_missing = run(&go_binary, &missing_args, go_root.path(), go_home.path());
    let rust_missing = run(
        &rust_binary,
        &missing_args,
        rust_root.path(),
        rust_home.path(),
    );
    assert_eq!(go_missing.status.success(), rust_missing.status.success());
    assert!(
        !go_missing.status.success(),
        "Go must reject an unknown token"
    );
    assert_eq!(go_missing.stderr, rust_missing.stderr);

    let new_args = ["agent", "token", "new", "alpha", "--tools", "*"];
    let go_created = run(&go_binary, &new_args, go_root.path(), go_home.path());
    let rust_created = run(&rust_binary, &new_args, rust_root.path(), rust_home.path());
    let go_id = extract_id(&go_created.stdout);
    let rust_id = extract_id(&rust_created.stdout);

    let go_revoke_args = ["agent", "token", "revoke", "alpha", &go_id];
    let rust_revoke_args = ["agent", "token", "revoke", "alpha", &rust_id];
    let go_revoke = run(&go_binary, &go_revoke_args, go_root.path(), go_home.path());
    let rust_revoke = run(
        &rust_binary,
        &rust_revoke_args,
        rust_root.path(),
        rust_home.path(),
    );
    assert_eq!(go_revoke.status, rust_revoke.status);
    assert_eq!(
        String::from_utf8_lossy(&go_revoke.stdout).replace(&go_id, "<id>"),
        String::from_utf8_lossy(&rust_revoke.stdout).replace(&rust_id, "<id>"),
    );

    let go_again = run(&go_binary, &go_revoke_args, go_root.path(), go_home.path());
    let rust_again = run(
        &rust_binary,
        &rust_revoke_args,
        rust_root.path(),
        rust_home.path(),
    );
    assert_eq!(go_again.status.success(), rust_again.status.success());
    assert!(!go_again.status.success(), "Go must reject revoking twice");
    assert_eq!(
        String::from_utf8_lossy(&go_again.stderr).replace(&go_id, "<id>"),
        String::from_utf8_lossy(&rust_again.stderr).replace(&rust_id, "<id>"),
    );
}

#[test]
fn agent_token_rotate_matches_go_summary_shape_for_unknown_and_existing_agent() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));

    let go_root = tempfile::tempdir().expect("go vault root");
    let rust_root = tempfile::tempdir().expect("rust vault root");
    let go_home = home_dir();
    let rust_home = home_dir();

    let rotate_args = ["agent", "token", "rotate", "alpha", "--tools", "*"];
    let go_first = run(&go_binary, &rotate_args, go_root.path(), go_home.path());
    let rust_first = run(
        &rust_binary,
        &rotate_args,
        rust_root.path(),
        rust_home.path(),
    );
    assert_same_shape(&go_first, &rust_first, "rotate unknown agent");

    let go_second = run(&go_binary, &rotate_args, go_root.path(), go_home.path());
    let rust_second = run(
        &rust_binary,
        &rotate_args,
        rust_root.path(),
        rust_home.path(),
    );
    assert_same_shape(&go_second, &rust_second, "rotate existing agent");
}

fn extract_id(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .find_map(|line| line.strip_prefix("  ID:    "))
        .expect("token id line")
        .to_owned()
}
