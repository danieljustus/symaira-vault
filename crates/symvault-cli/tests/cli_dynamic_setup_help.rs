#[path = "common/go_oracle.rs"]
mod go_oracle;

use std::{path::Path, process::Command};

fn run(binary: &Path, topic: &[&str]) -> std::process::Output {
    go_oracle::output(Command::new(binary).arg("help").args(topic)).expect("run help topic")
}

fn run_flag(binary: &Path, topic: &[&str]) -> std::process::Output {
    go_oracle::output(Command::new(binary).args(topic).arg("--help")).expect("run direct help")
}

#[test]
fn dynamic_and_setup_help_match_pinned_go_bytes() {
    let oracle = go_oracle::GoOracle::begin(
        "cli_dynamic_setup_help",
        "dynamic_and_setup_help_match_pinned_go_bytes",
        Some(go_oracle::CONFIG_CLI_ORACLE),
    );
    let go_binary = oracle.binary();
    let go = go_binary.as_path();
    let rust = Path::new(env!("CARGO_BIN_EXE_symvault"));

    let topics: &[&[&str]] = &[&["dynamic"], &["dynamic", "generate"], &["setup"]];
    for &topic in topics {
        let go_output = run(go, topic);
        let rust_output = run(rust, topic);
        assert_eq!(
            rust_output.status.code(),
            go_output.status.code(),
            "topic={topic:?}"
        );
        assert_eq!(rust_output.stdout, go_output.stdout, "topic={topic:?}");
        assert_eq!(rust_output.stderr, go_output.stderr, "topic={topic:?}");
        assert_eq!(go_output.status.code(), Some(0), "topic={topic:?}");
        assert!(go_output.stderr.is_empty(), "topic={topic:?}");

        let go_flag = run_flag(go, topic);
        let rust_flag = run_flag(rust, topic);
        assert_eq!(
            rust_flag.status.code(),
            go_flag.status.code(),
            "topic={topic:?}"
        );
        assert_eq!(rust_flag.stdout, go_flag.stdout, "topic={topic:?}");
        assert_eq!(rust_flag.stderr, go_flag.stderr, "topic={topic:?}");
    }
    assert_eq!(oracle.calls(), 6);
}
