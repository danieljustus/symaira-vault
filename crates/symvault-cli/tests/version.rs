#![deny(unsafe_code)]

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_symvault"))
        .args(args)
        .output()
        .expect("run symvault")
}

#[test]
fn version_text_matches_go_contract() {
    let output = run(&["version"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"symvault dev\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn version_json_modes_match_go_contract() {
    for args in [
        &["version", "--json"][..],
        &["version", "--output", "json"][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            output.stdout,
            b"{\"tool\":\"symvault\",\"version\":\"dev\",\"schema_version\":1}\n"
        );
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn non_lowercase_json_formats_remain_text() {
    for args in [
        &["version", "--output", "yaml"][..],
        &["version", "--output", "wat"][..],
        &["version", "--output", "JSON"][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, b"symvault dev\n");
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn version_preserves_extra_argument_behavior() {
    let output = run(&["version", "extra"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"symvault dev\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn root_version_flag_remains_unsupported() {
    let output = run(&["--version"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"Error: unknown flag: --version\nError: unknown flag: --version\n"
    );
}

#[test]
fn version_flag_after_argument_separator_remains_an_extra_argument() {
    let output = run(&["version", "--", "--version"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"symvault dev\n");
    assert!(output.stderr.is_empty());
}
