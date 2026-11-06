#![deny(unsafe_code)]

#[path = "common/go_oracle.rs"]
mod go_oracle;
#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct TempDir(test_temp_root::TempRoot);

impl TempDir {
    fn new(label: &str) -> Self {
        Self(test_temp_root::TempRoot::existing(&format!(
            "symvault-audit-rotate-diff-{label}-"
        )))
    }
}

fn run(binary: &Path, vault: &Path, home: &Path, args: &[&str], input: Option<&[u8]>) -> Output {
    let mut cmd = Command::new(binary);
    cmd.args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("NO_COLOR", "1");
    if args.first() == Some(&"init")
        && let Some(data) = input
    {
        let pass = String::from_utf8_lossy(data)
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        cmd.env("SYMVAULT_PASSPHRASE", pass);
    }
    go_oracle::output_with_input(&mut cmd, input).expect("run command")
}

fn normalize_key_preview(output: &[u8]) -> String {
    let s = String::from_utf8_lossy(output);
    let mut lines = Vec::new();
    for line in s.lines() {
        if line.starts_with("New key:") {
            lines.push("New key: [PREVIEW] (first 4 bytes)".to_string());
        } else if line.starts_with("Old key archived to:") {
            lines.push("Old key archived to: [ARCHIVE_PATH]".to_string());
        } else {
            lines.push(line.to_string());
        }
    }
    lines.join("\n")
}

fn assert_same_normalized(go: &Output, rust: &Output, case: &str) {
    assert_eq!(
        rust.status.code(),
        go.status.code(),
        "{case}: exit code differs\ngo stderr: {:?}\nrust stderr: {:?}",
        String::from_utf8_lossy(&go.stderr),
        String::from_utf8_lossy(&rust.stderr)
    );
    assert_eq!(
        rust.stdout,
        go.stdout,
        "{case}: stdout differs\ngo: {:?}\nrust: {:?}",
        String::from_utf8_lossy(&go.stdout),
        String::from_utf8_lossy(&rust.stdout)
    );
    assert_eq!(
        normalize_key_preview(&rust.stderr),
        normalize_key_preview(&go.stderr),
        "{case}: stderr differs\ngo: {:?}\nrust: {:?}",
        String::from_utf8_lossy(&go.stderr),
        String::from_utf8_lossy(&rust.stderr)
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn audit_rotate_key_matches_go_contract() {
    let oracle = go_oracle::GoOracle::begin(
        "audit_rotate_differential",
        "audit_rotate_key_matches_go_contract",
        Some(go_oracle::CONFIG_CLI_ORACLE),
    );
    oracle.stable_under(|bytes| normalize_key_preview(bytes).into_bytes());
    let go = oracle.binary();
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = TempDir::new("home");
    let uninit_vault = home.0.join("uninit");

    // Case 1: Uninitialized vault
    let res_go = run(&go, &uninit_vault, &home.0, &["audit", "rotate-key"], None);
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["audit", "rotate-key"],
        None,
    );
    assert_same_normalized(&res_go, &res_rust, "audit rotate-key uninitialized");

    // Initialize vault with Go
    let init_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["init"],
        Some(b"audit-rotate-passphrase\naudit-rotate-passphrase\n"),
    );
    assert!(init_go.status.success(), "init failed");

    // Case 2: Bootstrap when no key exists
    let res_go = run(&go, &uninit_vault, &home.0, &["audit", "rotate-key"], None);
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["audit", "rotate-key"],
        None,
    );
    assert_same_normalized(&res_go, &res_rust, "audit rotate-key bootstrap");

    // Case 3: Rotate key when key already exists
    let res_go_rot = run(&go, &uninit_vault, &home.0, &["audit", "rotate-key"], None);
    let res_rust_rot = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["audit", "rotate-key"],
        None,
    );
    assert_same_normalized(&res_go_rot, &res_rust_rot, "audit rotate-key rotation");
}
