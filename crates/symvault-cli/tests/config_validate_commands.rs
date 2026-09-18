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
            "symvault-config-cmd-{label}-{pid}-{suffix}-{count}"
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

fn run_cli(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_symvault"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run symvault CLI")
}

#[test]
fn config_validate_missing_file() {
    let home = TempDir::new("home");
    let missing = home.0.join("does-not-exist.yaml");
    let missing_str = missing.to_str().unwrap();

    // 1. Text mode
    let out = run_cli(&home.0, &["config", "validate", missing_str]);
    assert_eq!(out.status.code(), Some(6));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(&format!("Error: cannot load config from {missing_str}:")));

    // 2. JSON mode
    let out_json = run_cli(
        &home.0,
        &["config", "validate", missing_str, "--output", "json"],
    );
    assert_eq!(out_json.status.code(), Some(6));
    let stdout = String::from_utf8_lossy(&out_json.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON stdout");
    assert_eq!(parsed["valid"], false);
    assert!(parsed["error"].is_string());
    let stderr = String::from_utf8_lossy(&out_json.stderr);
    assert!(stderr.contains("Error: config load failed:"));
}

#[test]
fn config_validate_invalid_schema() {
    let home = TempDir::new("home");
    let invalid_file = home.0.join("invalid-config.yaml");

    let yaml = r#"
vaultDir: ""
agents:
  default:
    approvalMode: invalid_mode
    allowedPaths:
      - "/tmp/[unterminated"
vault:
  argon2id_time: 1
  argon2id_threads: 20
  argon2id_memory: 100
clipboard:
  auto_clear_duration: -5
"#;
    fs::write(&invalid_file, yaml).unwrap();
    let path_str = invalid_file.to_str().unwrap();

    // 1. Text mode
    let out = run_cli(&home.0, &["config", "validate", path_str]);
    assert_eq!(out.status.code(), Some(6));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&format!("Configuration is invalid ({path_str}):")));
    assert!(stdout.contains("  ✗ vaultDir: must not be empty"));
    assert!(stdout.contains("  ✗ agents.default.approvalMode:"));
    assert!(stdout.contains("  ✗ agents.default.allowedPaths[0]:"));
    assert!(stdout.contains("  ✗ vault.argon2id_time:"));
    assert!(stdout.contains("  ✗ vault.argon2id_threads:"));
    assert!(stdout.contains("  ✗ vault.argon2id_memory:"));
    assert!(stdout.contains("  ✗ clipboard.autoClearDuration:"));

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Error: config validation failed:"));

    // 2. JSON mode
    let out_json = run_cli(
        &home.0,
        &["config", "validate", path_str, "--output", "json"],
    );
    assert_eq!(out_json.status.code(), Some(6));
    let stdout = String::from_utf8_lossy(&out_json.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON stdout");
    assert_eq!(parsed["valid"], false);
    let errors = parsed["errors"].as_array().expect("errors array");
    assert_eq!(errors.len(), 7);
}

#[test]
fn config_validate_valid_file() {
    let home = TempDir::new("home");
    let valid_file = home.0.join("valid-config.yaml");

    let yaml = r#"
vault_dir: /tmp/test-vault
default_agent: default
session_timeout: 15m
session_max_lifetime: 8h
agents:
  default:
    approval_mode: auto
    allowed_paths:
      - "/tmp/*"
vault:
  argon2id_time: 3
  argon2id_threads: 2
  argon2id_memory: 65536
"#;
    fs::write(&valid_file, yaml).unwrap();
    let path_str = valid_file.to_str().unwrap();

    // 1. Text mode
    let out = run_cli(&home.0, &["config", "validate", path_str]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("Configuration is valid ({path_str})\n")
    );

    // 2. JSON mode
    let out_json = run_cli(
        &home.0,
        &["config", "validate", path_str, "--output", "json"],
    );
    assert_eq!(out_json.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out_json.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON stdout");
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["path"], path_str);

    // 3. Quiet mode
    let out_quiet = run_cli(&home.0, &["--quiet", "config", "validate", path_str]);
    assert_eq!(out_quiet.status.code(), Some(0));
    assert!(out_quiet.stdout.is_empty());

    let out_json_quiet = run_cli(
        &home.0,
        &[
            "--quiet", "config", "validate", path_str, "--output", "json",
        ],
    );
    assert_eq!(out_json_quiet.status.code(), Some(0));
    assert!(out_json_quiet.stdout.is_empty());
}

#[test]
fn config_validate_default_path_and_fix_flag() {
    let home = TempDir::new("home");
    let default_dir = home.0.join(".symvault");
    fs::create_dir_all(&default_dir).unwrap();
    let default_config = default_dir.join("config.yaml");

    fs::write(
        &default_config,
        b"vault_dir: /tmp/test\ndefault_agent: default\n",
    )
    .unwrap();

    // Validates default path when no path argument given
    let out = run_cli(&home.0, &["config", "validate"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Configuration is valid"));

    // --fix is rejected as unsupported
    let out_fix = run_cli(&home.0, &["config", "validate", "--fix"]);
    assert_eq!(out_fix.status.code(), Some(6));
    assert!(
        String::from_utf8_lossy(&out_fix.stderr).contains("config validate --fix is not supported")
    );
}

#[test]
fn config_validate_no_home_fails_path_resolution() {
    let out = Command::new(env!("CARGO_BIN_EXE_symvault"))
        .args(["config", "validate"])
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run symvault CLI");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot determine config file path"));
}
