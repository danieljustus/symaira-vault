#[path = "common/go_oracle.rs"]
mod go_oracle;

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    go_oracle::output(
        Command::new(binary)
            .args(args)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("SYMVAULT_VAULT", root)
            .env("CI", "1")
            .env("NO_COLOR", "1"),
    )
    .expect("run agent list")
}

fn assert_same(go: &Output, rust: &Output, case: &str) {
    assert_eq!(
        rust.status,
        go.status,
        "{case}: status differs (go stderr: {:?}; rust stderr: {:?})",
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
fn agent_list_matches_go_text_json_and_yaml() {
    let oracle = go_oracle::GoOracle::begin(
        "agent_list_differential",
        "agent_list_matches_go_text_json_and_yaml",
        Some(go_oracle::CONFIG_CLI_ORACLE),
    );
    let go_binary = oracle.binary();
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let root = tempfile::tempdir().expect("vault root");
    let home = tempfile::tempdir().expect("home");
    fs::create_dir_all(root.path().join("config")).expect("config directory");
    fs::create_dir_all(root.path().join("data")).expect("data directory");
    fs::create_dir_all(root.path().join("cache")).expect("cache directory");
    fs::create_dir_all(home.path().join("config")).expect("home config");
    fs::create_dir_all(home.path().join("data")).expect("home data");
    fs::create_dir_all(home.path().join("cache")).expect("home cache");

    fs::write(
        root.path().join("config.yaml"),
        "agents:\n  alpha:\n    tier: standard\n    skillPath: ~/managed.md\n  zeta:\n    tier: custom\n    skillPath: ~/unmanaged.md\n",
    )
    .expect("config");
    fs::write(
        home.path().join("managed.md"),
        "---\nmanaged_by: symaira\n---\nmanaged body\n",
    )
    .expect("managed skill");
    fs::write(
        home.path().join("unmanaged.md"),
        "---\nname: other\n---\nbody\n",
    )
    .expect("unmanaged skill");
    fs::write(
        root.path().join("mcp-tokens.json"),
        r#"{
  "version": 2,
  "tokens": {
    "alpha-hash": {
      "id": "tok-alpha",
      "hash": "alpha-hash",
      "agent_name": "alpha",
      "expires_at": "2099-01-01T00:00:00Z",
      "last_used_at": "2025-02-03T04:05:06Z",
      "revoked": false
    },
    "revoked-hash": {
      "id": "tok-revoked",
      "hash": "revoked-hash",
      "agent_name": "alpha",
      "last_used_at": "2099-01-01T00:00:00Z",
      "revoked": true
    },
    "expired-hash": {
      "id": "tok-expired",
      "hash": "expired-hash",
      "agent_name": "zeta",
      "expires_at": "2000-01-01T00:00:00Z",
      "revoked": false
    }
  }
}"#,
    )
    .expect("token registry");

    for args in [
        &["agent", "list"][..],
        &["--output", "json", "agent", "list"][..],
        &["--output", "yaml", "agent", "list"][..],
        &["--output", "future", "agent", "list"][..],
    ] {
        let go = run(&go_binary, args, root.path(), home.path());
        let rust = run(&rust_binary, args, root.path(), home.path());
        assert_same(&go, &rust, &format!("agent list {args:?}"));
    }
}

/// Registry documents whose meaning depends on Go's `encoding/json` rules. Each is
/// `(case, document, Go-accepts, alpha has a valid token)`; the `Go-accepts` and
/// validity columns were recorded from the Go oracle and are asserted against
/// the Rust binary.
const GO_DECODING_CASES: &[(&str, &str, bool, bool)] = &[
    (
        "control",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha"}}}"#,
        true,
        true,
    ),
    (
        "miscased-revoked",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha","REVOKED":true}}}"#,
        true,
        false,
    ),
    (
        "miscased-keys-and-root",
        r#"{"TOKENS":{"t":{"ID":"tok-a","Hash":"h","Agent_Name":"alpha","Revoked":true}}}"#,
        true,
        false,
    ),
    (
        "duplicate-revoked-last-true",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha","revoked":false,"revoked":true}}}"#,
        true,
        false,
    ),
    (
        "duplicate-revoked-last-false",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha","revoked":true,"revoked":false}}}"#,
        true,
        true,
    ),
    (
        "duplicate-revoked-typeerror-first",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha","revoked":"yes","revoked":false}}}"#,
        false,
        false,
    ),
    ("root-null", "null", true, false),
    (
        "null-entry",
        r#"{"tokens":{"t":null,"u":{"id":"tok-a","hash":"h","agent_name":"alpha"}}}"#,
        true,
        true,
    ),
    (
        "lone-surrogate-label-revoked",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha","label":"\ud800","revoked":true}}}"#,
        true,
        false,
    ),
    (
        "timestamp-lowercase-t",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha","expires_at":"2099-01-01t00:00:00Z"}}}"#,
        false,
        false,
    ),
    (
        "timestamp-lowercase-z",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha","last_used_at":"2099-01-01T00:00:00z"}}}"#,
        false,
        false,
    ),
    (
        "timestamp-space",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha","created_at":"2099-01-01 00:00:00Z"}}}"#,
        false,
        false,
    ),
    (
        "timestamp-escaped-z",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha","expires_at":"2099-01-01T00:00:00\u005a"}}}"#,
        false,
        false,
    ),
    (
        "timestamp-one-digit-hour-future",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha","expires_at":"2099-01-01T1:00:00Z"}}}"#,
        true,
        true,
    ),
    (
        "timestamp-comma-fraction-past",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha","expires_at":"2000-01-01T00:00:00,5Z"}}}"#,
        true,
        false,
    ),
    (
        "timestamp-offset-24-future",
        r#"{"tokens":{"t":{"id":"tok-a","hash":"h","agent_name":"alpha","expires_at":"2099-01-01T00:00:00+24:00"}}}"#,
        true,
        true,
    ),
];

fn go_decoding_workspace(document: &str) -> (tempfile::TempDir, tempfile::TempDir) {
    let root = tempfile::tempdir().expect("vault root");
    let home = tempfile::tempdir().expect("home");
    for name in ["config", "data", "cache"] {
        fs::create_dir_all(home.path().join(name)).expect("home directory");
    }
    fs::write(
        root.path().join("config.yaml"),
        "agents:\n  alpha:\n    tier: standard\n",
    )
    .expect("config");
    fs::write(root.path().join("mcp-tokens.json"), document).expect("token registry");
    (root, home)
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn agent_list_registry_decoding_follows_go_encoding_json() {
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let oracle = go_oracle::GoOracle::begin(
        "agent_list_differential",
        "agent_list_registry_decoding_follows_go_encoding_json",
        Some(go_oracle::CONFIG_CLI_ORACLE),
    );
    let go_binary = oracle.binary();
    for (case, document, go_accepts, token_valid) in GO_DECODING_CASES {
        let (root, home) = go_decoding_workspace(document);
        let args = ["--output", "json", "agent", "list"];
        let rust = run(&rust_binary, &args, root.path(), home.path());
        assert_eq!(
            rust.status.success(),
            *go_accepts,
            "{case}: rust exit status"
        );
        if *go_accepts {
            let listing: serde_json::Value =
                serde_json::from_slice(&rust.stdout).expect("agent list json");
            assert_eq!(
                listing["agents"][0]["token_valid"], *token_valid,
                "{case}: {listing}"
            );
        }
        let go = run(&go_binary, &args, root.path(), home.path());
        assert_eq!(
            go.status.success(),
            *go_accepts,
            "{case}: recorded Go outcome"
        );
        assert_eq!(rust.status, go.status, "{case}: status differs");
        assert_eq!(rust.stdout, go.stdout, "{case}: stdout differs");
        if *go_accepts {
            assert_eq!(rust.stderr, go.stderr, "{case}: stderr differs");
        }
    }
}
