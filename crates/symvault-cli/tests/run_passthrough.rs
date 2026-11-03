#![cfg(unix)]

#[path = "common/go_oracle.rs"]
mod go_oracle;

use std::{path::Path, process::Command};

/// Go oracle: the commit that made `run --passthrough` split comma-separated
/// names (`oracle/run-passthrough-20261003`).
const ORACLE_COMMIT: &str = "98c786e1bf97fee2b93b79ec391f14c97bfd8694";

fn command(binary: &Path, vault: &Path, home: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .args(["--vault", vault.to_str().unwrap()])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_PASSPHRASE", "synthetic-passthrough-passphrase")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("CI", "1");
    command
}

#[test]
fn comma_repeated_and_mixed_passthrough_preserve_filtering() {
    let oracle = go_oracle::GoOracle::begin(
        "run_passthrough",
        "comma_repeated_and_mixed_passthrough_preserve_filtering",
        Some(ORACLE_COMMIT),
    );
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let vault = root.path().join("vault");
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let init = command(rust_binary, &vault, &home)
        .args(["init", "--auth", "passphrase"])
        .output()
        .unwrap();
    assert!(init.status.success(), "init: {:?}", init.stderr);
    let binaries = vec![rust_binary.to_path_buf(), oracle.binary()];
    for binary in binaries {
        for names in [
            vec!["SYMV_TEST_FIRST,SYMV_TEST_SECOND,SYMV_TEST_API_TOKEN"],
            vec!["SYMV_TEST_FIRST", "SYMV_TEST_SECOND", "SYMV_TEST_API_TOKEN"],
            vec![
                "",
                ",SYMV_TEST_FIRST,",
                "SYMV_TEST_SECOND,SYMV_TEST_API_TOKEN,",
            ],
        ] {
            let mut child = command(&binary, &vault, &home);
            child.arg("run");
            for name in &names {
                child.args(["--passthrough", name]);
            }
            child
                .args(["--", "sh", "-c", "printf '%s|%s|%s|%s' \"$SYMV_TEST_FIRST\" \"$SYMV_TEST_SECOND\" \"${SYMV_TEST_API_TOKEN+x}\" \"${SYMV_TEST_UNREQUESTED+x}\""])
                .env("SYMV_TEST_FIRST", "alpha")
                .env("SYMV_TEST_SECOND", "beta")
                .env("SYMV_TEST_API_TOKEN", "synthetic-sensitive-value")
                .env("SYMV_TEST_UNREQUESTED", "unrequested");
            let output = go_oracle::output(&mut child).unwrap();
            assert!(
                output.status.success(),
                "{binary:?} {names:?}: {:?}",
                output.stderr
            );
            assert_eq!(output.stdout, b"alpha|beta||", "{binary:?} {names:?}");
            assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-sensitive-value"));
        }
    }
    assert_eq!(oracle.calls(), 3);
}
