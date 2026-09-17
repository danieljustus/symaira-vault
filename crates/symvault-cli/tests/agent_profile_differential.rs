use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn temporary_root(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    env::temp_dir().join(format!("symvault-agent-profile-{name}-{suffix}"))
}

fn run(binary: &Path, args: &[&str], home: &Path, vault: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .output()
        .expect("run CLI")
}

fn assert_same(go: &Output, rust: &Output, command: &str) {
    assert_eq!(
        go.status.code(),
        rust.status.code(),
        "{command} status\nGo stderr={:?}\nRust stderr={:?}",
        go.stderr,
        rust.stderr
    );
    assert_eq!(rust.stdout, go.stdout, "{command} stdout");
    assert_eq!(rust.stderr, go.stderr, "{command} stderr");
}

#[test]
fn agent_profile_show_matches_go_yaml_json_and_nil_fields() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));

    let builtin_home = temporary_root("builtin-home");
    let builtin_vault = builtin_home.join("vault");
    fs::create_dir_all(&builtin_vault).expect("builtin vault");
    fs::write(builtin_vault.join("config.yaml"), b"\n").expect("empty config");
    for output in ["yaml", "json"] {
        let args = ["agent", "profile", "show", "default", "--output", output];
        let go = run(&go_binary, &args, &builtin_home, &builtin_vault);
        let rust = run(&rust_binary, &args, &builtin_home, &builtin_vault);
        assert_same(
            &go,
            &rust,
            &format!("agent profile show default --output {output}"),
        );
    }

    let custom_home = temporary_root("custom-home");
    let custom_vault = custom_home.join("vault");
    fs::create_dir_all(&custom_vault).expect("custom vault");
    fs::write(
        custom_vault.join("config.yaml"),
        r#"agents:
  demo:
    tier: standard
    approvalMode: prompt
    allowedPaths: ["team/*", "über/**"]
    redactFields: [password]
    perToolRedactFields:
      get_entry: [password]
    canWrite: true
    canRunCommands: false
    canManageConfig: true
    canUseClipboard: true
    canUseAutotype: false
    canReadValues: true
    exposeValueTools: false
    autoUnseal: false
    requireApproval: true
    approvalTimeout: 2m
    allowed_tools: [get_entry]
    max_reads_per_hour: 7
    max_reads_per_day: 42
    max_secrets_in_session: 3
    dynamicProviders:
      foo: [bar]
    allowedEnvVars: [LANG]
    allowedExecutables: [git]
    promptInjectionMode: deny
    skillPath: /tmp/skill
    skillVersion: v1
    exposePaymentValues: true
"#
        .as_bytes(),
    )
    .expect("custom config");
    for output in ["yaml", "json"] {
        let args = ["agent", "profile", "show", "demo", "--output", output];
        let go = run(&go_binary, &args, &custom_home, &custom_vault);
        let rust = run(&rust_binary, &args, &custom_home, &custom_vault);
        assert_same(
            &go,
            &rust,
            &format!("agent profile show demo --output {output}"),
        );
    }

    let escape_home = temporary_root("escape-home");
    let escape_vault = escape_home.join("vault");
    fs::create_dir_all(&escape_vault).expect("escape vault");
    fs::write(
        escape_vault.join("config.yaml"),
        "agents:\n  demo:\n    skillPath: \"/tmp/<skill>&\"\n    skillVersion: \"v x\"\n",
    )
    .expect("escape config");
    let args = ["agent", "profile", "show", "demo", "--output", "json"];
    let go = run(&go_binary, &args, &escape_home, &escape_vault);
    let rust = run(&rust_binary, &args, &escape_home, &escape_vault);
    assert_same(&go, &rust, "agent profile show escape --output json");
}
