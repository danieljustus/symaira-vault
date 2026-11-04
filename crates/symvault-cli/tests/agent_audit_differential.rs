#[path = "common/go_oracle.rs"]
mod go_oracle;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn run(binary: &Path, args: &[&str], vault: &Path) -> Output {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env("HOME", vault)
        .env("USERPROFILE", vault)
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .env("NO_COLOR", "1");
    go_oracle::output(&mut command).expect("run agent audit")
}

fn assert_same(go: &Output, rust: &Output, case: &str) {
    assert_eq!(
        rust.status.code(),
        go.status.code(),
        "{case}: status differs\ngo stderr: {:?}\nrust stderr: {:?}",
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
        rust.stderr,
        go.stderr,
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
fn agent_audit_matches_go_for_formats_filters_limits_and_missing_logs() {
    let oracle = go_oracle::GoOracle::begin(
        "agent_audit_differential",
        "agent_audit_matches_go_for_formats_filters_limits_and_missing_logs",
        Some(go_oracle::CONFIG_CLI_ORACLE),
    );
    let rust_binary = env!("CARGO_BIN_EXE_symvault");
    let go_binary = oracle.binary();
    let rust_binary = PathBuf::from(rust_binary);
    let vault = tempfile::tempdir().expect("vault fixture");
    fs::write(
        vault.path().join("audit-fixture.log"),
        concat!(
            "not json\n",
            "{\"ts\":\"2020-01-01T00:00:00Z\",\"agent\":\"fixture\",\"action\":\"old\",\"path\":\"old/path\",\"ok\":true}\n",
            "{\"ts\":\"2099-01-01T00:00:00Z\",\"agent\":\"fixture\",\"action\":\"set\",\"path\":\"safe/<&>\",\"field\":\"password\",\"reason\":\"synthetic\",\"ok\":false}\n",
            "null\n",
            "{\"ts\":null,\"action\":\"null-fields\",\"ok\":null}\n",
        ),
    )
    .expect("audit fixture");

    for args in [
        &["--vault", "FIXTURE", "agent", "audit", "fixture"][..],
        &["--quiet", "--vault", "FIXTURE", "agent", "audit", "fixture"][..],
        &[
            "--vault", "FIXTURE", "agent", "audit", "fixture", "--format", "json", "--limit", "2",
        ][..],
        &[
            "--vault", "FIXTURE", "agent", "audit", "fixture", "--since", "24h",
        ][..],
        &["--vault", "FIXTURE", "agent", "audit", "missing"][..],
        &["--vault", "FIXTURE", "agent", "audit", "../outside"][..],
    ] {
        let args: Vec<_> = args
            .iter()
            .map(|arg| {
                if *arg == "FIXTURE" {
                    vault.path().to_str().expect("UTF-8 fixture path")
                } else {
                    *arg
                }
            })
            .collect();
        let go = run(&go_binary, &args, vault.path());
        let rust = run(&rust_binary, &args, vault.path());
        assert_same(&go, &rust, &format!("{args:?}"));
    }
    assert_eq!(oracle.calls(), 6);
}
