use std::process::{Command, Output};

use sha2::{Digest, Sha256};

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");
const ROOT_HELP: &[u8] = include_bytes!("../src/help-root.txt");
const ROOT_HELP_SHA256: &str = "35e3cfbdd20cb69d00d0fc1954ec2482bc1eb6a443d29907f704f1550cb15bd7";

fn run(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .output()
        .expect("run symvault help")
}

#[test]
fn help_matches_frozen_go_root_output_and_ignores_quiet() {
    assert_eq!(
        format!("{:x}", Sha256::digest(ROOT_HELP)),
        ROOT_HELP_SHA256,
        "root help fixture must remain the captured Go oracle output"
    );

    for args in [&["help"][..], &["--quiet", "help"][..]] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert_eq!(output.stdout, ROOT_HELP);
    }
}

#[test]
fn unknown_help_topic_uses_go_root_topic_listing_and_succeeds() {
    let output = run(&["help", "missing-topic"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());

    let root = std::str::from_utf8(ROOT_HELP).expect("Go help fixture is UTF-8");
    let (_, root_usage) = root.split_once("Usage:\n").expect("Usage section");
    let root_usage = root_usage.replace("  -h, --help              help for symvault\n", "");
    let expected = format!("Unknown help topic [`missing-topic`]\nUsage:\n{root_usage}");
    assert_eq!(output.stdout, expected.as_bytes());
}

#[test]
fn help_for_known_subcommand_resolves_the_command_path() {
    let output = run(&["help", "generate", "manpages"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("manpages"), "missing topic help: {stdout}");
    assert!(stdout.contains("Usage:"), "missing usage section: {stdout}");
}
