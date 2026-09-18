use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn run(binary: &Path, args: &[&str], vault: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", vault)
        .env("USERPROFILE", vault)
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run agent audit")
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
fn agent_audit_matches_go_for_formats_filters_limits_and_missing_logs() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let rust_binary = env!("CARGO_BIN_EXE_symvault");
    let go_binary = PathBuf::from(go_binary);
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
}
