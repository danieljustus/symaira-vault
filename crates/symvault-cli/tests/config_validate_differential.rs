#![deny(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "symvault-config-val-diff-{label}-{pid}-{suffix}-{count}"
        ));
        fs::create_dir_all(&path).expect("temporary directory");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(binary: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run command")
}

fn assert_same(go: &Output, rust: &Output, case: &str) {
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
        rust.stderr,
        go.stderr,
        "{case}: stderr differs\ngo: {:?}\nrust: {:?}",
        String::from_utf8_lossy(&go.stderr),
        String::from_utf8_lossy(&rust.stderr)
    );
}

#[test]
fn config_validate_matches_go_contract() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go = PathBuf::from(go);
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = TempDir::new("home");

    // Case 1: Missing file
    let missing = home.0.join("missing.yaml");
    let missing_str = missing.to_str().unwrap();
    let res_go = run(&go, &home.0, &["config", "validate", missing_str]);
    let res_rust = run(&rust, &home.0, &["config", "validate", missing_str]);
    assert_same(&res_go, &res_rust, "config validate missing file");

    // Case 2: Missing file with --output json
    let res_go = run(
        &go,
        &home.0,
        &["config", "validate", missing_str, "--output", "json"],
    );
    let res_rust = run(
        &rust,
        &home.0,
        &["config", "validate", missing_str, "--output", "json"],
    );
    assert_same(&res_go, &res_rust, "config validate missing file json");

    // Case 3: Valid config
    let valid = home.0.join("valid.yaml");
    fs::write(&valid, b"vault_dir: /tmp/vault\ndefault_agent: default\n").unwrap();
    let valid_str = valid.to_str().unwrap();
    let res_go = run(&go, &home.0, &["config", "validate", valid_str]);
    let res_rust = run(&rust, &home.0, &["config", "validate", valid_str]);
    assert_same(&res_go, &res_rust, "config validate valid text");

    // Case 4: Valid config with --output json
    let res_go = run(
        &go,
        &home.0,
        &["config", "validate", valid_str, "--output", "json"],
    );
    let res_rust = run(
        &rust,
        &home.0,
        &["config", "validate", valid_str, "--output", "json"],
    );
    assert_same(&res_go, &res_rust, "config validate valid json");

    // Case 5: Valid config with --quiet
    let res_go = run(&go, &home.0, &["--quiet", "config", "validate", valid_str]);
    let res_rust = run(
        &rust,
        &home.0,
        &["--quiet", "config", "validate", valid_str],
    );
    assert_same(&res_go, &res_rust, "config validate valid quiet");
}
