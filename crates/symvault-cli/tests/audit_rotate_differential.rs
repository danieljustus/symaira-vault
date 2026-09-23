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
            "symvault-audit-rotate-diff-{label}-{pid}-{suffix}-{count}"
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

fn run(binary: &Path, vault: &Path, home: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(binary);
    cmd.args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("NO_COLOR", "1");
    cmd.output().expect("run command")
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
fn audit_rotate_key_bootstrap_matches_go_contract() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go = PathBuf::from(go);
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = TempDir::new("home");
    let vault = home.0.join("vault");
    fs::create_dir_all(&vault).expect("vault directory");
    // The CLI's CI keyring is process-local. Repeated Go calls use a durable
    // FreeBSD fallback, so only bootstrap is a valid subprocess comparison.
    let res_go = run(&go, &vault, &home.0, &["audit", "rotate-key"]);
    let res_rust = run(&rust, &vault, &home.0, &["audit", "rotate-key"]);
    assert_same_normalized(&res_go, &res_rust, "audit rotate-key bootstrap");
}
