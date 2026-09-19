#![deny(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temporary_root(name: &str) -> PathBuf {
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "symvault-doctor-diff-{name}-{pid}-{suffix}-{count}"
    ));
    fs::create_dir_all(&path).expect("create temp root");
    path
}

struct TempFixture(Vec<PathBuf>);

impl TempFixture {
    fn new(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        Self(paths.into_iter().collect())
    }
}

impl Drop for TempFixture {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run CLI")
}

fn first_json(stdout: &[u8], command: &str) -> serde_json::Value {
    serde_json::Deserializer::from_slice(stdout)
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap_or_else(|| {
            panic!(
                "{command} did not write a JSON value: {:?}",
                String::from_utf8_lossy(stdout)
            )
        })
        .unwrap_or_else(|error| {
            panic!(
                "{command} JSON error: {error}; stdout={:?}",
                String::from_utf8_lossy(stdout)
            )
        })
}

fn oracle_binaries() -> (PathBuf, PathBuf) {
    let go_binary = env::var_os("SYMVAULT_GO_BINARY")
        .expect("SYMVAULT_GO_BINARY must be set for differential test");
    let go = PathBuf::from(go_binary);
    assert!(go.is_file(), "Go binary does not exist at {go:?}");
    let rust = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    assert!(rust.is_file(), "Rust binary does not exist at {rust:?}");
    (go, rust)
}

#[test]
fn differential_doctor_missing_vault_text_and_strict() {
    let (go, rust) = oracle_binaries();
    let home = temporary_root("home");
    let vault = home.join("nonexistent_vault");
    let _fix = TempFixture::new(vec![home.clone()]);

    // Non-strict: exit code 0 on both
    let args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--only",
        "vault.initialized",
        "--no-network",
    ];
    let out_go = run(&go, &args, &vault, &home);
    let out_rust = run(&rust, &args, &vault, &home);

    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));

    // Text output must be in stderr for both Go and Rust
    let err_go = String::from_utf8_lossy(&out_go.stderr);
    let err_rust = String::from_utf8_lossy(&out_rust.stderr);
    assert!(err_go.contains("Vault initialized"));
    assert!(err_rust.contains("Vault initialized"));
    assert!(err_go.contains("Score: 0/1 OK · 1 failed"));
    assert!(err_rust.contains("Score: 0/1 OK · 1 failed"));

    // Strict: exit code 8 on both
    let strict_args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--only",
        "vault.initialized",
        "--no-network",
        "--strict",
    ];
    let strict_go = run(&go, &strict_args, &vault, &home);
    let strict_rust = run(&rust, &strict_args, &vault, &home);

    assert_eq!(strict_go.status.code(), Some(8));
    assert_eq!(strict_rust.status.code(), Some(8));
}

#[test]
fn differential_doctor_missing_vault_json() {
    let (go, rust) = oracle_binaries();
    let home = temporary_root("home");
    let vault = home.join("nonexistent_vault");
    let _fix = TempFixture::new(vec![home.clone()]);

    let args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--only",
        "vault.initialized",
        "--json",
        "--no-network",
    ];
    let out_go = run(&go, &args, &vault, &home);
    let out_rust = run(&rust, &args, &vault, &home);

    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));

    let json_go = first_json(&out_go.stdout, "Go doctor --json");
    let json_rust = first_json(&out_rust.stdout, "Rust doctor --json");

    assert_eq!(json_go["schema_version"], "1.0");
    assert_eq!(json_rust["schema_version"], "1.0");
    assert_eq!(json_go["score"]["fail"], 1);
    assert_eq!(json_rust["score"]["fail"], 1);
    assert_eq!(json_go["score"]["ok"], 0);
    assert_eq!(json_rust["score"]["ok"], 0);

    let res_go = &json_go["results"][0];
    let res_rust = &json_rust["results"][0];
    assert_eq!(res_go["id"], res_rust["id"]);
    assert_eq!(res_go["name"], res_rust["name"]);
    assert_eq!(res_go["status"], res_rust["status"]);
    assert_eq!(res_go["fixable"], res_rust["fixable"]);
}

#[test]
fn differential_doctor_filter_config_matches_nothing() {
    let (go, rust) = oracle_binaries();
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

    // Parent measured fact: --only 'config.*' matches nothing -> Score: 0/0 OK, Exit 0
    let args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--only",
        "config.*",
        "--no-network",
    ];
    let out_go = run(&go, &args, &vault, &home);
    let out_rust = run(&rust, &args, &vault, &home);

    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));

    let err_go = String::from_utf8_lossy(&out_go.stderr);
    let err_rust = String::from_utf8_lossy(&out_rust.stderr);
    assert!(err_go.contains("Score: 0/0 OK"));
    assert!(err_rust.contains("Score: 0/0 OK"));

    // JSON mode: empty results
    let json_args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--only",
        "config.*",
        "--json",
        "--no-network",
    ];
    let out_json_go = run(&go, &json_args, &vault, &home);
    let out_json_rust = run(&rust, &json_args, &vault, &home);

    assert_eq!(out_json_go.status.code(), Some(0));
    assert_eq!(out_json_rust.status.code(), Some(0));

    let json_go = first_json(&out_json_go.stdout, "Go doctor empty");
    let json_rust = first_json(&out_json_rust.stdout, "Rust doctor empty");
    assert_eq!(json_go["score"]["total"], 0);
    assert_eq!(json_rust["score"]["total"], 0);
    assert_eq!(json_go["results"], serde_json::json!([]));
    assert_eq!(json_rust["results"], serde_json::json!([]));
}

#[test]
fn differential_doctor_output_json_rejected() {
    let (go, rust) = oracle_binaries();
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

    // Parent measured fact: --output json is not supported: Exit 9
    let args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--output",
        "json",
    ];
    let out_go = run(&go, &args, &vault, &home);
    let out_rust = run(&rust, &args, &vault, &home);

    assert_eq!(out_go.status.code(), Some(9));
    assert_eq!(out_rust.status.code(), Some(9));

    let err_go = String::from_utf8_lossy(&out_go.stderr);
    let err_rust = String::from_utf8_lossy(&out_rust.stderr);
    assert!(err_go.contains("output format \"json\" is not supported by 'symvault doctor'"));
    assert!(err_rust.contains("output format \"json\" is not supported by 'symvault doctor'"));
}

#[test]
fn differential_doctor_initialized_vault_parity() {
    let (go, rust) = oracle_binaries();
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

    // Initialize vault with Go CLI
    let init_out = run(
        &go,
        &[
            "--vault",
            vault.to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        &vault,
        &home,
    );
    assert!(
        init_out.status.success(),
        "init failed: {:?}",
        String::from_utf8_lossy(&init_out.stderr)
    );

    let only_filter = "vault.initialized,vault.config.*,vault.identity.encrypted,vault.permissions,git.*,vault.size,vault.stale_temp_files,vault.conflict_files,auth.passphrase.rotation";
    let args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--only",
        only_filter,
        "--json",
        "--no-network",
    ];

    let out_go = run(&go, &args, &vault, &home);
    let out_rust = run(&rust, &args, &vault, &home);

    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));

    let json_go = first_json(&out_go.stdout, "Go initialized doctor");
    let json_rust = first_json(&out_rust.stdout, "Rust initialized doctor");

    assert_eq!(json_go["schema_version"], json_rust["schema_version"]);
    assert_eq!(json_go["score"]["ok"], json_rust["score"]["ok"]);
    assert_eq!(json_go["score"]["warn"], json_rust["score"]["warn"]);
    assert_eq!(json_go["score"]["fail"], json_rust["score"]["fail"]);
    assert_eq!(json_go["score"]["total"], json_rust["score"]["total"]);

    let items_go = json_go["results"].as_array().unwrap();
    let items_rust = json_rust["results"].as_array().unwrap();
    assert_eq!(items_go.len(), items_rust.len());

    for (g, r) in items_go.iter().zip(items_rust.iter()) {
        assert_eq!(g["id"], r["id"], "ID mismatch");
        assert_eq!(g["name"], r["name"], "Name mismatch for {}", g["id"]);
        assert_eq!(g["status"], r["status"], "Status mismatch for {}", g["id"]);
        assert_eq!(
            g["fixable"], r["fixable"],
            "Fixable mismatch for {}",
            g["id"]
        );
    }
}

#[test]
fn differential_doctor_corrupted_identity_age() {
    let (go, rust) = oracle_binaries();
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

    fs::write(
        vault.join("identity.age"),
        b"this is not an age encrypted file\n",
    )
    .unwrap();

    let args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--only",
        "vault.identity.encrypted",
        "--json",
        "--no-network",
    ];
    let out_go = run(&go, &args, &vault, &home);
    let out_rust = run(&rust, &args, &vault, &home);

    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));

    let json_go = first_json(&out_go.stdout, "Go corrupt identity");
    let json_rust = first_json(&out_rust.stdout, "Rust corrupt identity");

    assert_eq!(json_go["results"][0]["status"], "fail");
    assert_eq!(json_rust["results"][0]["status"], "fail");
    assert_eq!(
        json_go["results"][0]["message"],
        json_rust["results"][0]["message"]
    );
    assert_eq!(
        json_go["results"][0]["hint"],
        json_rust["results"][0]["hint"]
    );
}

#[test]
fn differential_doctor_exclude_filter() {
    let (go, rust) = oracle_binaries();
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

    // Initialize vault
    let _ = run(
        &go,
        &[
            "--vault",
            vault.to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        &vault,
        &home,
    );

    // Exclude vault.* and git.*
    let args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--exclude",
        "vault.*,git.*",
        "--json",
        "--no-network",
    ];

    let out_go = run(&go, &args, &vault, &home);
    let out_rust = run(&rust, &args, &vault, &home);

    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));

    let json_go = first_json(&out_go.stdout, "Go exclude");
    let json_rust = first_json(&out_rust.stdout, "Rust exclude");

    // All results in Rust must not start with vault. or git.
    for r in json_rust["results"].as_array().unwrap() {
        let id = r["id"].as_str().unwrap();
        assert!(!id.starts_with("vault.") && !id.starts_with("git."));
    }

    // Passphrase rotation should be present in both
    let has_rotation_go = json_go["results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == "auth.passphrase.rotation");
    let has_rotation_rust = json_rust["results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == "auth.passphrase.rotation");
    assert!(has_rotation_go);
    assert!(has_rotation_rust);
}

#[test]
fn differential_doctor_fix_dry_run_and_apply() {
    let (go, rust) = oracle_binaries();
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

    // Dry-run: does not create git repo
    let dry_args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--only",
        "git.repo",
        "--fix",
        "--fix-dry-run",
        "--no-network",
    ];
    let out_go = run(&go, &dry_args, &vault, &home);
    let out_rust = run(&rust, &dry_args, &vault, &home);

    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));

    let stderr_go = String::from_utf8_lossy(&out_go.stderr);
    let stderr_rust = String::from_utf8_lossy(&out_rust.stderr);
    assert!(stderr_go.contains("Would fix git.repo: no git repository in vault directory"));
    assert!(stderr_rust.contains("Would fix git.repo: no git repository in vault directory"));

    assert!(!vault.join(".git").exists());

    // Apply fix: creates git repo
    let fix_args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--only",
        "git.repo",
        "--fix",
        "--no-network",
    ];
    let out_fix_rust = run(&rust, &fix_args, &vault, &home);
    assert_eq!(out_fix_rust.status.code(), Some(0));
    assert!(vault.join(".git").exists());
}
