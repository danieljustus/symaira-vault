//! CLI-002: the word handling of the `completion` command group.
//!
//! Go (cobra) prints the group help for a first word that names no shell and
//! refuses any word after a shell with `unknown command "<word>" for "symvault
//! completion <shell>"`; clap used to answer with its own wording. With
//! the recorded Go answers (`testdata/port/cli-transcripts/cli_completion_args.json`)
//! every shape is compared byte for byte with Go; the Rust output is also
//! checked against the same Go contract spelled out below.

#[path = "common/go_oracle.rs"]
mod go_oracle;

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const SHELLS: [&str; 4] = ["bash", "zsh", "fish", "powershell"];

const SHAPES: &[&[&str]] = &[
    &["completion", "foo"],
    &["completion", "-"],
    &["completion", "foo", "bash"],
    &["completion", "help"],
    &["completion", "Bash"],
    &["completion", "bash", "-"],
    &["completion", "bash", "extra"],
    &["completion", "bash", "help"],
    &["completion", "zsh", "a", "b"],
    &["completion", "fish", "x"],
    &["completion", "powershell", "-"],
];

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

fn rust_binary() -> PathBuf {
    PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"))
}

#[test]
fn completion_word_shapes_follow_the_cobra_contract() {
    let home = tempfile::tempdir().expect("temporary home");
    let group_help = run(&rust_binary(), &["completion"], home.path());
    assert_eq!(group_help.status.code(), Some(0));
    assert!(group_help.stdout.starts_with(
        b"Generate the autocompletion script for symvault for the specified shell.\n"
    ));
    for args in SHAPES {
        let output = run(&rust_binary(), args, home.path());
        let shell = args[1];
        if SHELLS.contains(&shell) {
            let line = format!(
                "Error: unknown command \"{}\" for \"symvault completion {shell}\"\n",
                args[2]
            );
            assert_eq!(output.status.code(), Some(1), "{args:?}");
            assert!(output.stdout.is_empty(), "{args:?}");
            assert_eq!(
                output.stderr,
                format!("{line}{line}").into_bytes(),
                "{args:?}"
            );
        } else {
            assert_eq!(output.status.code(), Some(0), "{args:?}");
            assert_eq!(output.stdout, group_help.stdout, "{args:?}");
            assert!(output.stderr.is_empty(), "{args:?}");
        }
    }
}

#[test]
fn completion_word_shapes_match_the_go_binary() {
    let oracle = go_oracle::GoOracle::begin(
        "cli_completion_args",
        "completion_word_shapes_match_the_go_binary",
        Some(go_oracle::CONFIG_CLI_ORACLE),
    );
    let go_binary = oracle.binary();
    let home = tempfile::tempdir().expect("temporary home");
    for args in SHAPES {
        let go = run(&go_binary, args, home.path());
        let rust = run(&rust_binary(), args, home.path());
        assert_eq!(rust.status.code(), go.status.code(), "status for {args:?}");
        assert_eq!(rust.stdout, go.stdout, "stdout for {args:?}");
        assert_eq!(rust.stderr, go.stderr, "stderr for {args:?}");
    }
    assert_eq!(oracle.calls(), SHAPES.len());
}
