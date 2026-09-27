#![deny(unsafe_code)]

use std::{env, path::PathBuf, process::Command};

fn run(binary: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(binary)
        .args(args)
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run help command")
}

#[test]
fn help_command_reaches_root_and_nested_help_like_go() {
    // Go oracle built from cmd/root.go blob 39960e0ef8de334f13a0f8686c5e29c50d0f8d5a
    // with the pinned Cobra v1.10.2 dependency in go.mod. Compare route and
    // usage semantics only; Cobra and Clap intentionally render different help.
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let go = env::var_os("SYMVAULT_GO_BINARY").map(PathBuf::from);

    for args in [&["help"][..], &["help", "config", "validate"][..]] {
        let rust_output = run(&rust, args);
        assert!(
            rust_output.status.success(),
            "Rust `symvault {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&rust_output.stderr)
        );
        let rust_stdout = String::from_utf8_lossy(&rust_output.stdout).to_lowercase();
        assert!(rust_stdout.contains("usage:"));
        if args.len() == 3 {
            assert!(rust_stdout.contains("symvault config validate"));
        }

        if let Some(go) = &go {
            let go_output = run(go, args);
            assert!(
                go_output.status.success(),
                "Go `symvault {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&go_output.stderr)
            );
            let go_stdout = String::from_utf8_lossy(&go_output.stdout).to_lowercase();
            assert!(go_stdout.contains("usage:"));
            if args.len() == 3 {
                assert!(go_stdout.contains("symvault config validate"));
            }
        }
    }
}
