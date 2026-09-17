#![deny(unsafe_code)]

#[path = "../src/audit_export_commands.rs"]
mod audit_export_commands;

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use symvault_store::audit::{self, LogEntry};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = env::temp_dir().join(format!("symvault-audit-export-{name}-{suffix}"));
        fs::create_dir_all(&path).expect("temporary directory");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn first_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<serde_json::Value>()
        .next()
        .expect("JSON output")
        .expect("valid JSON output")
}

fn go_export(go: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(go)
        .args(["audit", "export"])
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("CI", "1")
        .output()
        .expect("run Go audit export")
}

fn cli_export(binary: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("CI", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .output()
        .expect("run audit export")
}

#[test]
fn audit_export_json_matches_go_for_filters_and_redaction() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let home = TempDir::new("fixture");
    fs::create_dir_all(home.0.join(".symvault")).expect("audit directory");
    fs::write(
        home.0.join(".symvault/audit-fixture.log"),
        concat!(
            "{\"ts\":\"2020-01-01T00:00:00.123456789Z\",\"agent\":\"fixture\",\"action\":\"set\",\"path\":\"safe/<password>&\",\"transport\":\"cli\",\"ok\":true}\n",
            "{\"ts\":\"2020-01-02T00:00:00Z\",\"agent\":\"fixture\",\"action\":\"get\",\"path\":\"private/password\",\"ok\":false}\n",
            "not json\n"
        ),
    )
    .expect("audit fixture");

    let go = PathBuf::from(go);
    let cases: &[&[&str]] = &[
        &["--agent", "fixture", "--format", "json"],
        &[
            "--agent",
            "fixture",
            "--action",
            "get",
            "--failed",
            "--redact-paths",
            "--format",
            "json",
        ],
        &[
            "--agent", "fixture", "--action", " set ", "--format", "json",
        ],
    ];
    for &args in cases {
        let expected = go_export(&go, &home.0, args);
        assert!(
            expected.status.success(),
            "Go export failed: {}",
            String::from_utf8_lossy(&expected.stderr)
        );
        let mut actual = Vec::new();
        audit_export_commands::export(
            &home.0,
            &audit_export_commands::Options {
                agent: args[1],
                action: args
                    .iter()
                    .position(|arg| *arg == "--action")
                    .map_or("", |i| args[i + 1]),
                since: "",
                failed_only: args.contains(&"--failed"),
                redact_paths: args.contains(&"--redact-paths"),
                format: "json",
            },
            &mut actual,
        )
        .expect("Rust export");
        assert_eq!(first_json(&actual), first_json(&expected.stdout));
    }
}

#[test]
fn audit_export_accepts_injected_hmac_generations_without_keychain_access() {
    let home = TempDir::new("hmac");
    fs::create_dir_all(home.0.join(".symvault")).expect("audit directory");
    let key_bytes = [7_u8; 32];
    let key = audit::AuditKey::new(key_bytes).expect("audit key");
    let kid = audit::key_fingerprint(&key_bytes);
    let mut entry = LogEntry {
        timestamp: "2020-01-01T00:00:00.123456789Z".to_owned(),
        agent: "fixture".to_owned(),
        action: "set".to_owned(),
        path: "safe/<password>&".to_owned(),
        ok: true,
        kid: kid.clone(),
        ..LogEntry::default()
    };
    entry.hmac = audit::compute_hmac(&key_bytes, &[], &entry);
    fs::write(
        home.0.join(".symvault/audit-fixture.log"),
        format!("{}\n", serde_json::to_string(&entry).expect("audit JSON")),
    )
    .expect("audit fixture");
    let mut keys = BTreeMap::new();
    keys.insert(kid.clone(), key);
    let mut output = Vec::new();
    audit_export_commands::export_with_keys(
        &home.0,
        &audit_export_commands::Options {
            agent: "fixture",
            action: "",
            since: "",
            failed_only: false,
            redact_paths: false,
            format: "json",
        },
        true,
        &keys,
        &kid,
        &mut output,
    )
    .expect("Rust HMAC export");
    let value = first_json(&output);
    assert_eq!(value["verified"], 1);
    assert_eq!(value["entries"][0]["verify_status"], "verified");
}

#[test]
fn audit_export_cli_bytes_match_go_for_formats_empty_and_file_output() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let home = TempDir::new("cli");
    fs::create_dir_all(home.0.join(".symvault")).expect("audit directory");
    fs::write(
        home.0.join(".symvault/audit-fixture.log"),
        b"{\"ts\":\"2020-01-01T00:00:00.123456789Z\",\"agent\":\"fixture\",\"action\":\"set\",\"path\":\"safe/<password>&\",\"transport\":\"cli\",\"ok\":true}\n",
    )
    .expect("audit fixture");
    let go = PathBuf::from(go);
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));

    for args in [
        vec!["audit", "export", "--format", "json"],
        vec!["audit", "export", "--agent", "fixture", "--format", "table"],
        vec!["audit", "export", "--agent", "missing", "--format", "json"],
    ] {
        let expected = cli_export(&go, &home.0, &args);
        let actual = cli_export(&rust, &home.0, &args);
        assert_eq!(actual.status, expected.status, "status for {args:?}");
        assert_eq!(actual.stdout, expected.stdout, "stdout for {args:?}");
        assert_eq!(actual.stderr, expected.stderr, "stderr for {args:?}");
    }

    let go_output = home.0.join("go-export.json");
    let rust_output = home.0.join("rust-export.json");
    let go_args = [
        "audit",
        "export",
        "--agent",
        "fixture",
        "--format",
        "json",
        "--output",
        go_output.to_str().expect("Go output path"),
    ];
    let rust_args = [
        "audit",
        "export",
        "--agent",
        "fixture",
        "--format",
        "json",
        "--output",
        rust_output.to_str().expect("Rust output path"),
    ];
    let expected = cli_export(&go, &home.0, &go_args);
    let actual = cli_export(&rust, &home.0, &rust_args);
    assert_eq!(actual.status, expected.status, "file output status");
    assert_eq!(actual.stdout, expected.stdout, "file output stdout");
    assert_eq!(actual.stderr, expected.stderr, "file output stderr");
    assert_eq!(
        fs::read(go_output).expect("Go output"),
        fs::read(rust_output).expect("Rust output")
    );
}
