#[path = "common/go_oracle.rs"]
mod go_oracle;

use std::{
    env,
    path::Path,
    process::{Command, Output},
};

fn run(binary: &Path, args: &[&str], home: &Path) -> Output {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("CI", "1")
        .env("NO_COLOR", "1");
    go_oracle::output(&mut command).expect("run CLI")
}

fn assert_same(go: &Output, rust: &Output, args: &[&str]) {
    assert_eq!(
        rust.status.code(),
        go.status.code(),
        "status differs for {args:?}\nGo stderr: {:?}\nRust stderr: {:?}",
        go.stderr,
        rust.stderr
    );
    assert_eq!(rust.stdout, go.stdout, "stdout differs for {args:?}");
    assert_eq!(rust.stderr, go.stderr, "stderr differs for {args:?}");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn get_and_list_help_and_extra_argument_errors_match_go() {
    let oracle = go_oracle::GoOracle::begin(
        "cli_get_list_help_differential",
        "get_and_list_help_and_extra_argument_errors_match_go",
        Some(go_oracle::CONFIG_CLI_ORACLE),
    );
    let go_binary = oracle.binary();
    let rust_binary =
        std::path::PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let home = tempfile::tempdir().expect("temporary home");

    for args in [
        &["get", "--help"][..],
        &["list", "--help"][..],
        &["help", "get"][..],
        &["help", "list"][..],
        &["get", "entry", "extra"][..],
        &["list", "prefix", "extra"][..],
        &["get", "--", "--help"][..],
        &["list", "--", "--help"][..],
    ] {
        let go = run(&go_binary, args, home.path());
        let rust = run(&rust_binary, args, home.path());
        if args.contains(&"--") {
            // Both reach the vault operation rather than rendering help. The
            // existing uninitialized-vault error taxonomy differs separately.
            assert_ne!(go.status.code(), Some(0));
            assert_ne!(rust.status.code(), Some(0));
            assert!(go.stdout.is_empty());
            assert!(rust.stdout.is_empty());
            assert!(rust.stderr.starts_with(b"Error: vault not initialized"));
            continue;
        }
        assert_same(&go, &rust, args);
    }
    assert_eq!(oracle.calls(), 8);
}
