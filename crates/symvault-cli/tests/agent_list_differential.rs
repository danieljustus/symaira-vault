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
fn agent_list_matches_go_text_json_and_yaml() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
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
