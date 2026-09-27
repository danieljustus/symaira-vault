#![deny(unsafe_code)]

use std::{
    env, fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
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

/// Returns the pinned Go oracle and the freshly built Rust binary.
///
/// `SYMVAULT_GO_BINARY` is exported by the port-contract gate
/// (`scripts/rust-port/check_config_cli.sh`), which is where this comparison is
/// mandatory. The workspace-wide test runs have no oracle, so — like every other
/// CLI differential in this crate — they skip instead of failing; the gate is the
/// acceptance, not a silent skip.
fn oracle_binaries() -> Option<(PathBuf, PathBuf)> {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return None;
    };
    let go = PathBuf::from(go_binary);
    assert!(go.is_file(), "Go binary does not exist at {go:?}");
    let rust = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    assert!(rust.is_file(), "Rust binary does not exist at {rust:?}");
    Some((go, rust))
}

#[test]
fn differential_doctor_missing_vault_text_and_strict() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
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
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
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
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
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
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
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
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
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
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
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
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
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
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
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

#[test]
fn differential_doctor_new_checks_initialized_vault_parity() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

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
    assert!(init_out.status.success());

    let only_filter = "recipients.*,audit.log,crypto.kdf.modern,mcp.approval.tls,password.*";
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

    let json_go = first_json(&out_go.stdout, "Go new checks initialized");
    let json_rust = first_json(&out_rust.stdout, "Rust new checks initialized");

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
        assert_eq!(g["hint"], r["hint"], "Hint mismatch for {}", g["id"]);
        assert_eq!(
            g["message"], r["message"],
            "Message mismatch for {}",
            g["id"]
        );
    }
}

#[test]
fn differential_doctor_new_checks_missing_vault() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("home");
    let vault = home.join("nonexistent_vault");
    let _fix = TempFixture::new(vec![home.clone()]);

    let only_filter = "recipients.*,audit.log,crypto.kdf.modern,mcp.approval.tls,password.*";
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

    let json_go = first_json(&out_go.stdout, "Go missing vault new checks");
    let json_rust = first_json(&out_rust.stdout, "Rust missing vault new checks");

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
        assert_eq!(g["hint"], r["hint"], "Hint mismatch for {}", g["id"]);
        assert_eq!(
            g["message"], r["message"],
            "Message mismatch for {}",
            g["id"]
        );
    }
}

#[test]
fn differential_doctor_new_checks_corrupt_config() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

    fs::write(vault.join("config.yaml"), b"invalid: yaml: [\n").unwrap();

    // Only the checks that Rust actually registers can be compared; the config
    // load-failure text of `mcp.agents`/`mcp.dynamic.engines` is a known open
    // divergence (go-yaml wording vs the Rust config loader) and those checks are
    // deliberately absent from the Rust registry.
    let only_filter = "password.*";
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

    let json_go = first_json(&out_go.stdout, "Go corrupt config new checks");
    let json_rust = first_json(&out_rust.stdout, "Rust corrupt config new checks");

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
        assert_eq!(g["hint"], r["hint"], "Hint mismatch for {}", g["id"]);
        if g["id"] == "password.strength" || g["id"] == "password.reuse" {
            assert_eq!(g["message"], r["message"]);
        }
    }
}

#[test]
fn differential_doctor_new_checks_quick_filter() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

    let only_filter = "crypto.scrypt.benchmark,password.strength,password.reuse,crypto.kdf.modern,recipients.count";
    let args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--only",
        only_filter,
        "--quick",
        "--json",
        "--no-network",
    ];

    let out_go = run(&go, &args, &vault, &home);
    let out_rust = run(&rust, &args, &vault, &home);

    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));

    let json_go = first_json(&out_go.stdout, "Go quick filter");
    let json_rust = first_json(&out_rust.stdout, "Rust quick filter");

    let items_go = json_go["results"].as_array().unwrap();
    let items_rust = json_rust["results"].as_array().unwrap();
    assert_eq!(items_go.len(), items_rust.len());

    for item in items_rust {
        let id = item["id"].as_str().unwrap();
        assert_ne!(id, "crypto.scrypt.benchmark");
        assert_ne!(id, "password.strength");
        assert_ne!(id, "password.reuse");
    }
}

#[test]
fn differential_doctor_new_checks_no_network_filter() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

    let only_filter = "update.available,mcp.server.reachable,recipients.count";
    let args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--only",
        only_filter,
        "--no-network",
        "--json",
    ];

    let out_go = run(&go, &args, &vault, &home);
    let out_rust = run(&rust, &args, &vault, &home);

    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));

    let json_go = first_json(&out_go.stdout, "Go no-network filter");
    let json_rust = first_json(&out_rust.stdout, "Rust no-network filter");

    let items_go = json_go["results"].as_array().unwrap();
    let items_rust = json_rust["results"].as_array().unwrap();
    assert_eq!(items_go.len(), 1);
    assert_eq!(items_rust.len(), 1);
    assert_eq!(items_rust[0]["id"], "recipients.count");
    assert_eq!(items_go[0]["id"], "recipients.count");
}

fn start_mcp_health_server(
    status: u16,
    expected_requests: usize,
) -> (i64, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local health fixture");
    listener
        .set_nonblocking(true)
        .expect("make local fixture accept bounded");
    let port = i64::from(listener.local_addr().expect("fixture address").port());
    let server = thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut requests = Vec::new();
        while requests.len() < expected_requests && std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .expect("make accepted fixture stream blocking");
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                        .expect("bound local fixture read");
                    let mut request = [0_u8; 2048];
                    let read = stream.read(&mut request).expect("read health request");
                    let first_line = String::from_utf8_lossy(&request[..read])
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .to_owned();
                    requests.push(first_line);
                    let reason = match status {
                        200 => "OK",
                        503 => "Service Unavailable",
                        _ => "Fixture Status",
                    };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("write health response");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("accept local health request: {error}"),
            }
        }
        requests
    });
    (port, server)
}

fn run_mcp_server_doctor(binary: &Path, vault: &Path, home: &Path) -> Output {
    Command::new(binary)
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "doctor",
            "--only",
            "mcp.server.reachable",
            "--json",
        ])
        .env_clear()
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .output()
        .expect("run local MCP server doctor check")
}

#[test]
fn differential_doctor_mcp_server_reachability_local_http_cases() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    for (name, status, token_file) in [
        ("reachable-no-token", Some(200), false),
        ("reachable-with-token", Some(200), true),
        ("http-error", Some(503), false),
        ("unreachable", None, false),
    ] {
        let home = temporary_root(&format!("mcp-server-{name}-home"));
        let vault = temporary_root(&format!("mcp-server-{name}-vault"));
        let _fixture = TempFixture::new(vec![home.clone(), vault.clone()]);
        let (port, server) = match status {
            Some(status) => {
                let (port, server) = start_mcp_health_server(status, 2);
                (port, Some(server))
            }
            None => {
                let listener = TcpListener::bind("127.0.0.1:0").expect("reserve dead port");
                let port = i64::from(listener.local_addr().unwrap().port());
                drop(listener);
                (port, None)
            }
        };
        fs::write(vault.join("config.yaml"), format!("mcp:\n  port: {port}\n"))
            .expect("configure local MCP server port");
        if token_file {
            fs::write(vault.join("mcp-token"), b"synthetic test token")
                .expect("seed synthetic token-presence file");
        }

        let out_go = run_mcp_server_doctor(&go, &vault, &home);
        let out_rust = run_mcp_server_doctor(&rust, &vault, &home);
        assert_eq!(
            out_go.status.code(),
            Some(0),
            "Go stderr: {:?}",
            out_go.stderr
        );
        assert_eq!(
            out_rust.status.code(),
            Some(0),
            "Rust stderr: {:?}",
            out_rust.stderr
        );
        let go_result = first_json(&out_go.stdout, "Go MCP server doctor")["results"][0].clone();
        let rust_result =
            first_json(&out_rust.stdout, "Rust MCP server doctor")["results"][0].clone();
        for field in ["id", "name", "status", "message", "hint", "fixable"] {
            assert_eq!(
                go_result.get(field),
                rust_result.get(field),
                "{name} diverged in {field}: Go={go_result}, Rust={rust_result}"
            );
        }
        assert_eq!(go_result["id"], "mcp.server.reachable");
        if let Some(server) = server {
            let requests = server.join().expect("join local health fixture");
            assert_eq!(requests, ["GET /health HTTP/1.1", "GET /health HTTP/1.1"]);
        }
    }
}

#[test]
fn differential_doctor_new_checks_exclude_filter() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

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
    assert!(init_out.status.success());

    let exclude_filter = "recipients.*,mcp.*,crypto.*,password.*";
    let args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--exclude",
        exclude_filter,
        "--json",
        "--no-network",
    ];

    let out_go = run(&go, &args, &vault, &home);
    let out_rust = run(&rust, &args, &vault, &home);

    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));

    let json_rust = first_json(&out_rust.stdout, "Rust exclude filter");

    for r in json_rust["results"].as_array().unwrap() {
        let id = r["id"].as_str().unwrap();
        assert!(!id.starts_with("recipients."));
        assert!(!id.starts_with("mcp."));
        assert!(!id.starts_with("crypto."));
        assert!(!id.starts_with("password."));
    }
}

#[test]
fn differential_doctor_recipients_recovery_invalid() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("home");
    let vault = temporary_root("vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

    fs::write(vault.join("recipients.txt"), b"invalid-age-key\n").unwrap();

    let args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--only",
        "recipients.recovery",
        "--json",
        "--no-network",
    ];

    let out_go = run(&go, &args, &vault, &home);
    let out_rust = run(&rust, &args, &vault, &home);

    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));

    let json_go = first_json(&out_go.stdout, "Go recipients recovery invalid");
    let json_rust = first_json(&out_rust.stdout, "Rust recipients recovery invalid");

    assert_eq!(json_go["results"][0]["status"], "fail");
    assert_eq!(json_rust["results"][0]["status"], "fail");
    assert_eq!(
        json_go["results"][0]["hint"],
        "run `symvault recipients list`"
    );
    assert_eq!(
        json_rust["results"][0]["hint"],
        "run `symvault recipients list`"
    );
}

/// Wave 2a: session/tooling/manifest checks must match the pinned oracle field
/// by field on a missing vault and on a corrupt `config.yaml`. None of these IDs
/// quotes a YAML parser error, so the documented go-yaml-vs-Rust dialect
/// divergence does not apply here — any deviation is a real port defect.
#[test]
fn differential_doctor_session_tooling_checks() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("wave2a_home");
    let _fix = TempFixture::new(vec![home.clone()]);

    let missing = home.join("missing_vault");
    compare_wave2a_checks(&go, &rust, &missing, &home);

    let corrupt = home.join("corrupt_vault");
    fs::create_dir_all(&corrupt).unwrap();
    fs::write(
        corrupt.join("config.yaml"),
        "agents:\n  - this: [is: broken\n",
    )
    .unwrap();
    compare_wave2a_checks(&go, &rust, &corrupt, &home);
}

fn compare_wave2a_checks(go: &Path, rust: &Path, vault: &Path, home: &Path) {
    const IDS: &str = "auth.method,session.cache,audit.keyring.orphans,vault.manifest.intact,\
tooling.autotype.backend,tooling.clipboard.backend,daemon.status,tooling.secureui,\
tooling.precommit,session.keyring,security.env_passphrase";
    compare_doctor_ids(go, rust, vault, home, IDS);
}

/// Compares the selected doctor IDs field by field between the pinned oracle and
/// the Rust binary. Used where no documented divergence applies.
fn compare_doctor_ids(go: &Path, rust: &Path, vault: &Path, home: &Path, ids: &str) {
    let args = [
        "--vault",
        vault.to_str().unwrap(),
        "doctor",
        "--json",
        "--no-network",
        "--only",
        ids,
    ];
    let out_go = run(go, &args, vault, home);
    let out_rust = run(rust, &args, vault, home);
    let json_go = first_json(&out_go.stdout, "Go wave 2a checks");
    let json_rust = first_json(&out_rust.stdout, "Rust wave 2a checks");

    let items = |json: &serde_json::Value| -> Vec<serde_json::Value> {
        json["results"].as_array().cloned().unwrap_or_default()
    };
    let go_items = items(&json_go);
    let rust_items = items(&json_rust);
    assert_eq!(
        go_items.len(),
        rust_items.len(),
        "different number of checks for vault {vault:?}: go={go_items:?} rust={rust_items:?}"
    );
    assert!(!go_items.is_empty(), "no checks selected for {vault:?}");

    for (a, b) in go_items.iter().zip(rust_items.iter()) {
        for field in ["id", "name", "status", "message", "hint", "fixable"] {
            assert_eq!(
                a.get(field),
                b.get(field),
                "field {field} diverged for vault {vault:?}: go={a} rust={b}"
            );
        }
    }
}

fn run_mcp_tokens_doctor(
    binary: &Path,
    vault: &Path,
    home: &Path,
    env_token: Option<&str>,
) -> Output {
    let mut command = Command::new(binary);
    command
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "doctor",
            "--only",
            "mcp.tokens",
            "--json",
            "--no-network",
        ])
        .env_clear()
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .env("NO_COLOR", "1");
    if let Some(token) = env_token {
        command.env("SYMVAULT_MCP_TOKEN", token);
    }
    command
        .output()
        .expect("run MCP token doctor check in isolated environment")
}

fn run_mcp_approval_tls_doctor(binary: &Path, vault: &Path, home: &Path) -> Output {
    Command::new(binary)
        .args([
            "--vault",
            vault.to_str().unwrap(),
            "doctor",
            "--only",
            "mcp.approval.tls",
            "--json",
            "--no-network",
        ])
        .env_clear()
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", vault)
        .env("SYMVAULT_PASSPHRASE", "synthetic-doctor-fixture")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run approval TLS doctor check in isolated environment")
}

fn assert_migration_warning(output: &Output, id: &str) {
    let expected = format!(
        "WARNING: legacy MCP token migrated to scoped registry with wildcard (*) tool access (id={id}).\n         To restrict scope, run: symvault agent token new <agent> --label <label> --tools <list>\n         Then revoke the legacy token: symvault agent token revoke legacy {id}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(&expected),
        "migration warning with generated ID {id} was not emitted"
    );
}

fn doctor_result(output: &Output) -> serde_json::Value {
    first_json(&output.stdout, "MCP token doctor")["results"][0].clone()
}

fn private_mode(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        0
    }
}

fn set_fixture_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set fixture mode");
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

fn write_private_fixture(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write isolated token fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("restrict isolated token fixture permissions");
    }
}

fn normalized_registry_bytes(bytes: &[u8], generated_hash: bool) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes).expect("registry JSON");
    let tokens = value["tokens"].as_object_mut().expect("tokens map");
    assert_eq!(tokens.len(), 1, "one migrated legacy token");
    let (key, mut token) = tokens
        .iter_mut()
        .next()
        .map(|(key, token)| (key.clone(), token.take()))
        .expect("token entry");
    assert_eq!(token["id"], key, "registry key and token ID match");
    token["id"] = serde_json::Value::String("<generated-id>".into());
    token["created_at"] = serde_json::Value::String("<generated-time>".into());
    if generated_hash {
        token["hash"] = serde_json::Value::String("<generated-hash>".into());
        token["prefix"] = serde_json::Value::String("<generated-prefix>".into());
    }
    let tokens = value["tokens"].as_object_mut().expect("tokens map");
    tokens.clear();
    tokens.insert("<generated-id>".into(), token);
    serde_json::to_vec(&value).expect("normalized registry JSON")
}

#[test]
fn differential_doctor_mcp_tokens_existing_registry_is_read_only() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("mcp-tokens-readonly-home");
    let go_vault = temporary_root("mcp-tokens-readonly-go-vault");
    let rust_vault = temporary_root("mcp-tokens-readonly-rust-vault");
    let _fixture = TempFixture::new(vec![home.clone(), go_vault.clone(), rust_vault.clone()]);
    let registry = br#"{"version":2,"tokens":{"tok-fixture":{"id":"tok-fixture","label":"fixture","hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","prefix":"0123","allowed_tools":["*"],"agent_name":"fixture","created_at":"2026-09-26T00:00:00Z","revoked":false}}}
"#;
    for vault in [&go_vault, &rust_vault] {
        write_private_fixture(&vault.join("mcp-tokens.json"), registry);
        set_fixture_mode(&vault.join("mcp-tokens.json"), 0o644);
        write_private_fixture(&vault.join("mcp-token"), b"synthetic-unused-legacy-token\n");
    }

    let out_go = run_mcp_tokens_doctor(&go, &go_vault, &home, None);
    let out_rust = run_mcp_tokens_doctor(&rust, &rust_vault, &home, None);
    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));
    let result_go = doctor_result(&out_go);
    let result_rust = doctor_result(&out_rust);
    for field in ["id", "name", "status", "message", "hint", "fixable"] {
        assert_eq!(
            result_go.get(field),
            result_rust.get(field),
            "field {field}"
        );
    }
    for vault in [&go_vault, &rust_vault] {
        let registry_path = vault.join("mcp-tokens.json");
        assert_eq!(
            fs::read(&registry_path).expect("registry unchanged"),
            registry
        );
        assert_eq!(private_mode(&registry_path), 0o644);
        assert_eq!(
            fs::read(vault.join("mcp-token")).expect("legacy file unchanged"),
            b"synthetic-unused-legacy-token\n"
        );
    }
}

#[test]
fn differential_doctor_mcp_approval_tls_initializes_private_device_sessions() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("mcp-approval-tls-home");
    let go_vault = temporary_root("mcp-approval-tls-go-vault");
    let rust_vault = temporary_root("mcp-approval-tls-rust-vault");
    let _fixture = TempFixture::new(vec![home.clone(), go_vault.clone(), rust_vault.clone()]);

    let out_go = run_mcp_approval_tls_doctor(&go, &go_vault, &home);
    let out_rust = run_mcp_approval_tls_doctor(&rust, &rust_vault, &home);
    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));
    assert_eq!(doctor_result(&out_go), doctor_result(&out_rust));

    let go_file = go_vault.join(".symvault/device-sessions.json");
    let rust_file = rust_vault.join(".symvault/device-sessions.json");
    assert_eq!(fs::read(&go_file).unwrap(), b"{}");
    assert_eq!(fs::read(&go_file).unwrap(), fs::read(&rust_file).unwrap());
    assert_eq!(private_mode(&go_file), 0o600);
    assert_eq!(private_mode(&rust_file), 0o600);
    assert_eq!(private_mode(go_file.parent().unwrap()), 0o700);
    assert_eq!(private_mode(rust_file.parent().unwrap()), 0o700);
    for vault in [&go_vault, &rust_vault] {
        let names = fs::read_dir(vault.join(".symvault"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, [std::ffi::OsString::from("device-sessions.json")]);
    }
}

#[cfg(unix)]
#[test]
fn differential_doctor_mcp_approval_tls_reads_existing_store_without_parent_write_access() {
    use std::os::unix::fs::PermissionsExt;

    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("mcp-approval-tls-readonly-home");
    let go_vault = temporary_root("mcp-approval-tls-readonly-go-vault");
    let rust_vault = temporary_root("mcp-approval-tls-readonly-rust-vault");
    let _fixture = TempFixture::new(vec![home.clone(), go_vault.clone(), rust_vault.clone()]);
    let go_dir = go_vault.join(".symvault");
    let rust_dir = rust_vault.join(".symvault");
    fs::create_dir(&go_dir).unwrap();
    fs::create_dir(&rust_dir).unwrap();
    let go_file = go_dir.join("device-sessions.json");
    let rust_file = rust_dir.join("device-sessions.json");
    for file in [&go_file, &rust_file] {
        fs::write(file, b"{}\n").unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(file.parent().unwrap(), fs::Permissions::from_mode(0o500)).unwrap();
    }

    let out_go = run_mcp_approval_tls_doctor(&go, &go_vault, &home);
    let out_rust = run_mcp_approval_tls_doctor(&rust, &rust_vault, &home);
    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));
    assert_eq!(doctor_result(&out_go), doctor_result(&out_rust));
    for file in [&go_file, &rust_file] {
        assert_eq!(fs::read(file).unwrap(), b"{}\n");
        assert_eq!(private_mode(file), 0o400);
        assert_eq!(fs::read_dir(file.parent().unwrap()).unwrap().count(), 1);
        fs::set_permissions(file.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn differential_doctor_mcp_approval_tls_migrates_legacy_keys_and_counts_zero_expiry() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("mcp-approval-tls-legacy-home");
    let go_vault = temporary_root("mcp-approval-tls-legacy-go-vault");
    let rust_vault = temporary_root("mcp-approval-tls-legacy-rust-vault");
    let _fixture = TempFixture::new(vec![home.clone(), go_vault.clone(), rust_vault.clone()]);
    let raw_token = "SYNTHETIC-LEGACY-DEVICE-BEARER";
    let already_hashed_key = "f".repeat(64);
    let mut sessions = serde_json::Map::new();
    sessions.insert(
        raw_token.into(),
        serde_json::json!({
            "prefix": "",
            "device_id": "legacy-device",
            "public_key": "synthetic-public-key",
            "created_at": "2026-01-02T03:04:05Z",
            "revoked": false
        }),
    );
    sessions.insert(
        already_hashed_key,
        serde_json::json!({
            "prefix": "SYN2",
            "device_id": "zero-expiry-device",
            "public_key": "synthetic-public-key-2",
            "created_at": "2026-01-02T03:04:05Z",
            "expires_at": "0001-01-01T00:00:00Z",
            "revoked": false
        }),
    );
    let input = serde_json::to_vec(&sessions).unwrap();
    for vault in [&go_vault, &rust_vault] {
        fs::create_dir(vault.join(".symvault")).unwrap();
        write_private_fixture(&vault.join(".symvault/device-sessions.json"), &input);
    }

    let out_go = run_mcp_approval_tls_doctor(&go, &go_vault, &home);
    let out_rust = run_mcp_approval_tls_doctor(&rust, &rust_vault, &home);
    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));
    let go_result = doctor_result(&out_go);
    let rust_result = doctor_result(&out_rust);
    assert_eq!(go_result, rust_result);
    assert!(
        go_result["message"]
            .as_str()
            .unwrap()
            .contains("0 approval device(s) active, 2 expired, 0 revoked")
    );

    let go_path = go_vault.join(".symvault/device-sessions.json");
    let rust_path = rust_vault.join(".symvault/device-sessions.json");
    let go_bytes = fs::read(&go_path).unwrap();
    let rust_bytes = fs::read(&rust_path).unwrap();
    assert_eq!(go_bytes, rust_bytes, "persisted migration bytes match");
    assert!(
        !go_bytes
            .windows(raw_token.len())
            .any(|window| window == raw_token.as_bytes())
    );
    let migrated: serde_json::Value = serde_json::from_slice(&rust_bytes).unwrap();
    let expected_legacy_hash = symvault_store::sha256_hex(raw_token.as_bytes());
    assert!(migrated.get(&expected_legacy_hash).is_some());
    assert!(migrated.get(raw_token).is_none());
    assert_eq!(migrated[&expected_legacy_hash]["prefix"], "SYNT");
    assert_eq!(
        migrated[&expected_legacy_hash]["expires_at"],
        "0001-01-01T00:00:00Z"
    );
    assert_eq!(private_mode(&go_path), 0o600);
    assert_eq!(private_mode(&rust_path), 0o600);
}

#[test]
fn differential_doctor_mcp_tokens_rejects_corrupt_registry_without_migrating_legacy() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("mcp-tokens-corrupt-home");
    let go_vault = temporary_root("mcp-tokens-corrupt-go-vault");
    let rust_vault = temporary_root("mcp-tokens-corrupt-rust-vault");
    let _fixture = TempFixture::new(vec![home.clone(), go_vault.clone(), rust_vault.clone()]);
    for vault in [&go_vault, &rust_vault] {
        write_private_fixture(&vault.join("mcp-tokens.json"), b"{broken registry\n");
        write_private_fixture(
            &vault.join("mcp-token"),
            b"synthetic-preserved-legacy-token\n",
        );
    }

    let out_go = run_mcp_tokens_doctor(&go, &go_vault, &home, None);
    let out_rust = run_mcp_tokens_doctor(&rust, &rust_vault, &home, None);
    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));
    let result_go = doctor_result(&out_go);
    let result_rust = doctor_result(&out_rust);
    for field in ["id", "name", "status", "fixable"] {
        assert_eq!(
            result_go.get(field),
            result_rust.get(field),
            "field {field}"
        );
    }
    assert_eq!(result_go["status"], "warn");
    for (vault, raw_error) in [(&go_vault, &result_go), (&rust_vault, &result_rust)] {
        assert!(
            raw_error["message"]
                .as_str()
                .expect("warning message")
                .starts_with("cannot load MCP token registry: ")
        );
        let registry = vault.join("mcp-tokens.json");
        assert_eq!(fs::read(&registry).unwrap(), b"{broken registry\n");
        assert_eq!(private_mode(&registry), 0o600);
        assert_eq!(
            fs::read(vault.join("mcp-token")).unwrap(),
            b"synthetic-preserved-legacy-token\n"
        );
        assert!(!vault.join("mcp-tokens.json.tmp").exists());
    }
}

#[test]
fn differential_doctor_mcp_tokens_empty_environment_value_creates_registry() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    for (case, env_token, migrated) in [
        ("empty", "", true),
        ("nonempty", "synthetic-environment-token", false),
    ] {
        let home = temporary_root(&format!("mcp-tokens-env-{case}-home"));
        let go_vault = temporary_root(&format!("mcp-tokens-env-{case}-go-vault"));
        let rust_vault = temporary_root(&format!("mcp-tokens-env-{case}-rust-vault"));
        let _fixture = TempFixture::new(vec![home.clone(), go_vault.clone(), rust_vault.clone()]);

        let out_go = run_mcp_tokens_doctor(&go, &go_vault, &home, Some(env_token));
        let out_rust = run_mcp_tokens_doctor(&rust, &rust_vault, &home, Some(env_token));
        assert_eq!(out_go.status.code(), Some(0));
        assert_eq!(out_rust.status.code(), Some(0));
        let result_go = doctor_result(&out_go);
        let result_rust = doctor_result(&out_rust);
        for field in ["id", "name", "status", "message", "hint", "fixable"] {
            assert_eq!(
                result_go.get(field),
                result_rust.get(field),
                "{case}: field {field}"
            );
        }
        if migrated {
            for (vault, output) in [(&go_vault, &out_go), (&rust_vault, &out_rust)] {
                let bytes = fs::read(vault.join("mcp-tokens.json")).expect("empty env migrates");
                assert_eq!(private_mode(&vault.join("mcp-tokens.json")), 0o600);
                if !env_token.is_empty() {
                    assert!(!String::from_utf8_lossy(&bytes).contains(env_token));
                }
                let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                let id = json["tokens"].as_object().unwrap().values().next().unwrap()["id"]
                    .as_str()
                    .unwrap();
                assert_migration_warning(output, id);
                assert!(!vault.join("mcp-token").exists());
            }
        } else {
            for vault in [&go_vault, &rust_vault] {
                assert!(!vault.join("mcp-tokens.json").exists());
                assert!(!vault.join("mcp-token").exists());
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn differential_doctor_mcp_tokens_surfaces_legacy_symlink_removal_failure() {
    use std::os::unix::fs::symlink;

    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("mcp-tokens-symlink-home");
    let go_vault = temporary_root("mcp-tokens-symlink-go-vault");
    let rust_vault = temporary_root("mcp-tokens-symlink-rust-vault");
    let go_target = home.join("go-legacy-token");
    let rust_target = home.join("rust-legacy-token");
    let _fixture = TempFixture::new(vec![home.clone(), go_vault.clone(), rust_vault.clone()]);
    write_private_fixture(&go_target, b"synthetic-symlink-token-go\n");
    write_private_fixture(&rust_target, b"synthetic-symlink-token-rust\n");
    symlink(&go_target, go_vault.join("mcp-token")).unwrap();
    symlink(&rust_target, rust_vault.join("mcp-token")).unwrap();

    let out_go = run_mcp_tokens_doctor(&go, &go_vault, &home, None);
    let out_rust = run_mcp_tokens_doctor(&rust, &rust_vault, &home, None);
    assert_eq!(out_go.status.code(), Some(0));
    assert_eq!(out_rust.status.code(), Some(0));
    assert_eq!(
        doctor_result(&out_go)["status"],
        doctor_result(&out_rust)["status"]
    );
    for (vault, target, output) in [
        (&go_vault, &go_target, &out_go),
        (&rust_vault, &rust_target, &out_rust),
    ] {
        let link = vault.join("mcp-token");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&link).unwrap(), fs::read(target).unwrap());
        let registry = fs::read(vault.join("mcp-tokens.json")).unwrap();
        assert_eq!(private_mode(&vault.join("mcp-tokens.json")), 0o600);
        let json: serde_json::Value = serde_json::from_slice(&registry).unwrap();
        let id = json["tokens"].as_object().unwrap().values().next().unwrap()["id"]
            .as_str()
            .unwrap();
        assert_migration_warning(output, id);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.lines().any(|line| {
                line.starts_with("failed to remove legacy token file ")
                    && line.contains(" after migration:")
            }),
            "failed legacy-token cleanup must be reported: {stderr:?}"
        );
    }
}

#[test]
fn differential_doctor_mcp_tokens_migrates_isolated_legacy_and_empty_cases() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    for (case, legacy, env_token) in [
        (
            "existing-legacy",
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            Some("synthetic-environment-token"),
        ),
        ("new-legacy", None, None),
    ] {
        let home = temporary_root(&format!("mcp-tokens-{case}-home"));
        let go_vault = temporary_root(&format!("mcp-tokens-{case}-go-vault"));
        let rust_vault = temporary_root(&format!("mcp-tokens-{case}-rust-vault"));
        let _fixture = TempFixture::new(vec![home.clone(), go_vault.clone(), rust_vault.clone()]);
        if let Some(raw) = legacy {
            write_private_fixture(&go_vault.join("mcp-token"), format!("{raw}\n").as_bytes());
            write_private_fixture(&rust_vault.join("mcp-token"), format!("{raw}\n").as_bytes());
            set_fixture_mode(&go_vault.join("mcp-token"), 0o644);
            set_fixture_mode(&rust_vault.join("mcp-token"), 0o644);
        }

        let out_go = run_mcp_tokens_doctor(&go, &go_vault, &home, env_token);
        let out_rust = run_mcp_tokens_doctor(&rust, &rust_vault, &home, env_token);
        assert_eq!(
            out_go.status.code(),
            Some(0),
            "Go {case}: {:?}",
            out_go.stderr
        );
        assert_eq!(
            out_rust.status.code(),
            Some(0),
            "Rust {case}: {:?}",
            out_rust.stderr
        );
        let result_go = doctor_result(&out_go);
        let result_rust = doctor_result(&out_rust);
        for field in ["id", "name", "status", "message", "hint", "fixable"] {
            assert_eq!(
                result_go.get(field),
                result_rust.get(field),
                "{case}: field {field}"
            );
        }

        for vault in [&go_vault, &rust_vault] {
            assert!(
                !vault.join("mcp-token").exists(),
                "{case}: legacy file removed"
            );
            let registry_path = vault.join("mcp-tokens.json");
            let registry = fs::read(&registry_path).expect("migrated registry bytes");
            assert!(registry.ends_with(b"\n"), "{case}: newline-terminated JSON");
            assert_eq!(
                private_mode(&registry_path),
                0o600,
                "{case}: private registry mode"
            );
            let _: serde_json::Value = serde_json::from_slice(&registry).expect("valid registry");
        }
        // `--only mcp.tokens` still runs every Go doctor check before filtering
        // output. Its unrelated `mcp.approval.tls` check creates
        // `.symvault/device-sessions.json`; the dedicated differential below
        // pins that separate side effect rather than treating it as token
        // registry behavior.
        let go_registry = fs::read(go_vault.join("mcp-tokens.json")).unwrap();
        let rust_registry = fs::read(rust_vault.join("mcp-tokens.json")).unwrap();
        let go_id = serde_json::from_slice::<serde_json::Value>(&go_registry).unwrap()["tokens"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let rust_id =
            serde_json::from_slice::<serde_json::Value>(&rust_registry).unwrap()["tokens"]
                .as_object()
                .unwrap()
                .values()
                .next()
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned();
        assert_migration_warning(&out_go, &go_id);
        assert_migration_warning(&out_rust, &rust_id);
        if env_token.is_some() && legacy.is_some() {
            for output in [&out_go, &out_rust] {
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    stderr.lines().any(|line| {
                        line.starts_with(
                            "Warning: SYMVAULT_MCP_TOKEN is set but file token exists at ",
                        ) && line.ends_with("; using file token")
                    }),
                    "file-token precedence warning missing for {case}: {:?}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        assert_eq!(
            normalized_registry_bytes(&go_registry, legacy.is_none()),
            normalized_registry_bytes(&rust_registry, legacy.is_none()),
            "{case}: registry bytes match after replacing generated ID/time"
        );
        if let Some(raw) = legacy {
            assert!(!String::from_utf8_lossy(&go_registry).contains(raw));
            assert!(!String::from_utf8_lossy(&rust_registry).contains(raw));
        }
    }
}

#[test]
fn differential_doctor_auth_method_touchid_availability() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let home = temporary_root("touchid-home");
    let vault = temporary_root("touchid-vault");
    let _fixture = TempFixture::new(vec![home.clone(), vault.clone()]);
    fs::write(vault.join("config.yaml"), "auth_method: touchid\n")
        .expect("configure Touch ID auth method");

    compare_doctor_ids(&go, &rust, &vault, &home, "auth.method");
}

/// Wave 2b: the two MCP config checks must match on a missing vault and on an
/// oracle-initialized vault (loadable config -> agent list). The corrupt-config
/// case is excluded here by design: both IDs quote the config-loader error, which
/// is the documented go-yaml-vs-Rust dialect divergence.
#[test]
fn differential_doctor_mcp_config_checks() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    const IDS: &str = "mcp.dynamic.engines,mcp.agents";

    let home = temporary_root("wave2b_home");
    let vault = temporary_root("wave2b_vault");
    let _fix = TempFixture::new(vec![home.clone(), vault.clone()]);

    // Missing vault: "cannot load config: open <path>: no such file or directory"
    compare_doctor_ids(&go, &rust, &vault, &home, IDS);

    // Initialized vault: the config is loadable, so the agent list must match.
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
        "oracle init failed: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );
    compare_doctor_ids(&go, &rust, &vault, &home, IDS);
}
