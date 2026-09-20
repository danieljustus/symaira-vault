use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path, agent: Option<&str>) -> Output {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("CI", "1")
        .env("NO_COLOR", "1");
    match agent {
        Some(agent) => command.env("SYMVAULT_AGENT", agent),
        None => command.env_remove("SYMVAULT_AGENT"),
    };
    command.output().expect("run agent whoami")
}

fn assert_same(go: &Output, rust: &Output, case: &str) {
    assert_eq!(
        rust.status.code(),
        go.status.code(),
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
fn agent_whoami_matches_go_output_and_context_errors() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let Some(rust_binary) = env::var_os("CARGO_BIN_EXE_symvault") else {
        eprintln!("skipping Rust differential: CARGO_BIN_EXE_symvault is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(rust_binary);
    let root = tempfile::tempdir().expect("vault root");
    let home = tempfile::tempdir().expect("home");
    for directory in ["config", "data", "cache"] {
        fs::create_dir_all(home.path().join(directory)).expect("home directory");
    }

    fs::write(
        root.path().join("config.yaml"),
        r#"agents:
  alpha:
    tier: standard
    approvalMode: prompt
    allowedPaths: ["work/*", "über/**"]
    allowed_tools: [get_entry, find]
    canWrite: true
    canReadValues: true
    canUseClipboard: true
    canUseAutotype: false
    canRunCommands: true
    canManageConfig: false
    requireApproval: true
    max_reads_per_hour: 7
    max_reads_per_day: 42
    max_secrets_in_session: 3
    skillPath: "~/.skills/<agent>&"
  empty:
    allowedPaths: null
"#,
    )
    .expect("config");
    fs::write(
        root.path().join("mcp-tokens.json"),
        r#"{
  "version": 2,
  "tokens": {
    "active": {
      "id": "tok-alpha",
      "hash": "active",
      "agent_name": "alpha",
      "expires_at": "2099-01-01T00:00:00Z",
      "revoked": false
    },
    "expired": {
      "id": "tok-old",
      "hash": "expired",
      "agent_name": "alpha",
      "expires_at": "2000-01-01T00:00:00Z",
      "revoked": false
    },
    "revoked": {
      "id": "tok-revoked",
      "hash": "revoked",
      "agent_name": "alpha",
      "revoked": true
    },
    "empty-hash": {
      "id": "tok-empty",
      "hash": "",
      "agent_name": "alpha",
      "revoked": false
    }
  }
}"#,
    )
    .expect("token registry");
    fs::create_dir_all(root.path().join("mcp-tokens")).expect("token directory");
    fs::write(
        root.path().join("mcp-tokens/alpha.token"),
        b"synthetic token",
    )
    .expect("token file");

    for args in [
        &(["agent", "whoami"][..]),
        &(["agent", "whoami", "--output", "json"][..]),
        &(["agent", "whoami", "--output", "future"][..]),
        &(["--quiet", "agent", "whoami"][..]),
    ] {
        let go = run(&go_binary, args, root.path(), home.path(), Some("alpha"));
        let rust = run(&rust_binary, args, root.path(), home.path(), Some("alpha"));
        assert_same(&go, &rust, &format!("alpha {args:?}"));
    }

    for agent in [Some("empty"), Some("missing"), None] {
        let go = run(
            &go_binary,
            &["agent", "whoami", "--output", "json"],
            root.path(),
            home.path(),
            agent,
        );
        let rust = run(
            &rust_binary,
            &["agent", "whoami", "--output", "json"],
            root.path(),
            home.path(),
            agent,
        );
        assert_same(&go, &rust, &format!("agent={agent:?}"));
    }
}
