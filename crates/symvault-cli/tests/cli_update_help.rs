use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");

#[test]
fn update_subcommand_help_is_reachable_and_lists_go_flags() {
    let cases = [
        (
            "info",
            "symvault update info [flags]",
            &["--json", "--help"][..],
        ),
        (
            "check",
            "symvault update check [flags]",
            &["--force", "--json", "--quiet", "--help"][..],
        ),
        (
            "apply",
            "symvault update apply [flags]",
            &["--dry-run", "--force", "--json", "--help"][..],
        ),
    ];

    for (command, usage, flags) in cases {
        let output = Command::new(BINARY)
            .args(["update", command, "--help"])
            .output()
            .expect("run update help");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(0), "{command}: {stdout}");
        assert!(output.stderr.is_empty(), "{command}: {:?}", output.stderr);
        assert!(
            stdout.contains(usage),
            "{command}: missing usage in {stdout:?}"
        );
        for flag in flags {
            assert!(
                stdout.contains(flag),
                "{command}: missing {flag} in {stdout:?}"
            );
        }
        assert!(stdout.contains("Global Flags:"), "{command}: {stdout:?}");
    }
}

#[test]
fn update_apply_dry_run_uses_go_output_streams() {
    if option_env!("SYMVAULT_VERSION").unwrap_or("dev") != "dev" {
        eprintln!("skipping dev-version oracle case for a release build");
        return;
    }

    let text = Command::new(BINARY)
        .args(["update", "apply", "--dry-run", "--force"])
        .output()
        .expect("run update apply dry-run");
    assert_eq!(text.status.code(), Some(0));
    assert!(text.stdout.is_empty());
    assert_eq!(
        text.stderr,
        b"Update checks are only available for stable release builds. Current version: dev\n"
    );

    let json = Command::new(BINARY)
        .args(["update", "apply", "--dry-run", "--json"])
        .output()
        .expect("run JSON update apply dry-run");
    assert_eq!(json.status.code(), Some(0));
    assert!(json.stderr.is_empty());
    assert_eq!(
        json.stdout,
        b"{\n  \"method\": \"\",\n  \"old_version\": \"dev\",\n  \"new_version\": \"dev\",\n  \"binary_path\": \"\",\n  \"dry_run\": true\n}\n"
    );
}

#[test]
fn update_apply_without_dry_run_fails_closed() {
    let output = Command::new(BINARY)
        .args(["update", "apply", "--force"])
        .output()
        .expect("run update apply without dry-run");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"Error: update apply currently requires --dry-run in the Rust CLI\n"
    );
}
