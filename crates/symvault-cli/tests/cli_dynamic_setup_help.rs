use std::{env, path::Path, process::Command};

fn run(binary: &Path, topic: &[&str]) -> std::process::Output {
    Command::new(binary)
        .arg("help")
        .args(topic)
        .output()
        .expect("run help topic")
}

#[test]
fn dynamic_and_setup_help_match_pinned_go_bytes() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go = Path::new(&go);
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
    }
}
