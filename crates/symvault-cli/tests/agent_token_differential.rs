use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run agent token list")
}

fn normalized_rows(output: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(output);
    let mut lines: Vec<_> = text.lines().collect();
    if lines.len() > 2 && lines[0].starts_with("ID ") {
        lines[1..].sort_unstable();
    }
    if lines.is_empty() {
        Vec::new()
    } else {
        let mut normalized = lines.join("\n");
        normalized.push('\n');
        normalized.into_bytes()
    }
}

fn assert_same(go: &Output, rust: &Output, case: &str) {
    assert_eq!(
        rust.status,
        go.status,
        "{case}: status differs\ngo stderr: {:?}\nrust stderr: {:?}",
        String::from_utf8_lossy(&go.stderr),
        String::from_utf8_lossy(&rust.stderr)
    );
    assert_eq!(
        normalized_rows(&rust.stdout),
        normalized_rows(&go.stdout),
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
fn agent_token_list_matches_go_plaintext_registry() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let root = tempfile::tempdir().expect("vault root");
    let home = tempfile::tempdir().expect("home");
    for directory in ["config", "data", "cache"] {
        fs::create_dir_all(home.path().join(directory)).expect("home directory");
    }

    fs::write(
        root.path().join("mcp-tokens.json"),
        r#"{
  "version": 2,
  "tokens": {
    "active-hash": {
      "id": "tok-active",
      "label": "Work",
      "hash": "active-hash",
      "allowed_tools": ["list_entries", "get_entry"],
      "agent_name": "alpha",
      "expires_at": "2099-01-01T00:00:00Z",
      "revoked": false
    },
    "revoked-hash": {
      "id": "tok-revoked",
      "label": "",
      "hash": "revoked-hash",
      "allowed_tools": [],
      "agent_name": "alpha",
      "revoked": true
    },
    "expired-hash": {
      "id": "tok-expired",
      "hash": "expired-hash",
      "agent_name": "alpha",
      "expires_at": "2000-01-01T00:00:00Z",
      "revoked": false
    },
    "empty-hash": {
      "id": "tok-empty-hash",
      "hash": "",
      "agent_name": "alpha",
      "revoked": false
    },
    "other-agent": {
      "id": "tok-other",
      "label": "Other",
      "hash": "other-agent",
      "allowed_tools": ["*"],
      "agent_name": "beta",
      "revoked": false
    },
    "empty-fields": {
      "id": "",
      "hash": "empty-fields",
      "agent_name": "",
      "revoked": false
    }
  }
}"#,
    )
    .expect("token registry");

    for args in [
        &[
            "--vault",
            "agent-token-list-placeholder",
            "agent",
            "token",
            "list",
            "alpha",
        ][..],
        &[
            "--quiet",
            "--vault",
            "agent-token-list-placeholder",
            "agent",
            "token",
            "list",
            "alpha",
        ][..],
        &[
            "--vault",
            "agent-token-list-placeholder",
            "agent",
            "token",
            "list",
            "beta",
        ][..],
        &[
            "--vault",
            "agent-token-list-placeholder",
            "agent",
            "token",
            "list",
            "",
        ][..],
    ] {
        let mut actual_args = args.to_vec();
        actual_args[1] = root.path().to_str().expect("UTF-8 root");
        let go = run(&go_binary, &actual_args, root.path(), home.path());
        let rust = run(&rust_binary, &actual_args, root.path(), home.path());
        assert_same(&go, &rust, &format!("agent token list {actual_args:?}"));
    }
}

#[test]
fn agent_token_list_rejects_malformed_registry_like_go() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let root = tempfile::tempdir().expect("vault root");
    let home = tempfile::tempdir().expect("home");
    fs::write(root.path().join("mcp-tokens.json"), b"{").expect("malformed registry");

    let args = [
        "--vault",
        root.path().to_str().expect("UTF-8 root"),
        "agent",
        "token",
        "list",
        "alpha",
    ];
    let go = run(&go_binary, &args, root.path(), home.path());
    let rust = run(&rust_binary, &args, root.path(), home.path());
    assert_eq!(go.status.success(), rust.status.success());
    assert!(!go.status.success(), "Go must reject malformed registry");
    assert!(
        !rust.status.success(),
        "Rust must reject malformed registry"
    );
    assert!(
        String::from_utf8_lossy(&rust.stderr).contains("load token registry"),
        "Rust diagnostic: {:?}",
        String::from_utf8_lossy(&rust.stderr)
    );
}
