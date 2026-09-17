use std::{
    env, fs,
    ops::Deref,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Deref for TemporaryRoot {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path()
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temporary_root(name: &str) -> TemporaryRoot {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    TemporaryRoot(env::temp_dir().join(format!("symvault-agent-profile-{name}-{suffix}")))
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
    assert_eq!(
        rust.stdout,
        go.stdout,
        "{command} stdout\nGo UTF-8={:?}\nRust UTF-8={:?}",
        String::from_utf8_lossy(&go.stdout),
        String::from_utf8_lossy(&rust.stdout)
    );
    assert_eq!(
        rust.stderr,
        go.stderr,
        "{command} stderr\nGo UTF-8={:?}\nRust UTF-8={:?}",
        String::from_utf8_lossy(&go.stderr),
        String::from_utf8_lossy(&rust.stderr)
    );
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
    pre_call_hooks: [prepare]
    post_call_hooks: [cleanup]
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

    let export_args = ["agent", "profile", "export", "demo"];
    let go = run(&go_binary, &export_args, &custom_home, &custom_vault);
    let rust = run(&rust_binary, &export_args, &custom_home, &custom_vault);
    assert_same(&go, &rust, "agent profile export demo");

    let empty_output_args = ["agent", "profile", "export", "demo", "--output", ""];
    let go = run(&go_binary, &empty_output_args, &custom_home, &custom_vault);
    let rust = run(
        &rust_binary,
        &empty_output_args,
        &custom_home,
        &custom_vault,
    );
    assert_same(&go, &rust, "agent profile export demo --output empty");

    let go_export_path = custom_home.join("go-profile.yaml");
    let rust_export_path = custom_home.join("rust-profile.yaml");
    let go_export_args = [
        "agent",
        "profile",
        "export",
        "demo",
        "--output",
        go_export_path.to_str().expect("Go export path"),
    ];
    let rust_export_args = [
        "agent",
        "profile",
        "export",
        "demo",
        "--output",
        rust_export_path.to_str().expect("Rust export path"),
    ];
    let go = run(&go_binary, &go_export_args, &custom_home, &custom_vault);
    let rust = run(&rust_binary, &rust_export_args, &custom_home, &custom_vault);
    assert_same(&go, &rust, "agent profile export demo --output");
    assert_eq!(
        fs::read(go_export_path).expect("Go exported profile"),
        fs::read(rust_export_path).expect("Rust exported profile"),
        "exported profile bytes differ"
    );

    for command in ["show", "export"] {
        let args = ["agent", "profile", command, "missing-agent"];
        let go = run(&go_binary, &args, &custom_home, &custom_vault);
        let rust = run(&rust_binary, &args, &custom_home, &custom_vault);
        assert!(!go.status.success());
        assert_same(&go, &rust, "missing agent profile");
    }

    let empty_home = temporary_root("empty-fields-home");
    let empty_vault = empty_home.join("vault");
    fs::create_dir_all(&empty_vault).expect("empty fields vault");
    fs::write(
        empty_vault.join("config.yaml"),
        "agents:\n  demo:\n    allowedPaths: []\n    redactFields: []\n    allowed_tools: []\n    allowedEnvVars: []\n    allowedExecutables: []\n    dynamicProviders: {}\n    perToolRedactFields: {}\n",
    )
    .expect("empty fields config");
    for output in ["yaml", "json"] {
        let args = ["agent", "profile", "show", "demo", "--output", output];
        let go = run(&go_binary, &args, &empty_home, &empty_vault);
        let rust = run(&rust_binary, &args, &empty_home, &empty_vault);
        assert_same(
            &go,
            &rust,
            &format!("agent profile show empty fields --output {output}"),
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
#[cfg(unix)]
mod profile_edit_differential {
    use std::{
        env, fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Command, Output, Stdio},
    };

    fn run(
        binary: &Path,
        args: &[&str],
        root: &Path,
        home: &Path,
        editor: &Path,
        confirmation: &str,
    ) -> Output {
        let mut child = Command::new(binary)
            .args(args)
            .env("HOME", home)
            .env("USERPROFILE", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("SYMVAULT_VAULT", root)
            .env("EDITOR", editor)
            .env_remove("VISUAL")
            .env("CI", "1")
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run profile edit");
        child
            .stdin
            .take()
            .expect("profile edit stdin")
            .write_all(confirmation.as_bytes())
            .expect("confirm profile edit");
        child.wait_with_output().expect("wait for profile edit")
    }

    fn assert_same(go: &Output, rust: &Output, case: &str) {
        assert_eq!(
            rust.status.code(),
            go.status.code(),
            "{case}: status differs\ngo stderr: {:?}\nrust stderr: {:?}",
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

    fn fixture_root(name: &str, profile: &str) -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
        let root = tempfile::Builder::new()
            .prefix(&format!("symvault-profile-edit-{name}-"))
            .tempdir()
            .expect("vault root");
        let home = tempfile::Builder::new()
            .prefix(&format!("symvault-profile-edit-{name}-home-"))
            .tempdir()
            .expect("home");
        for directory in ["config", "data", "cache"] {
            fs::create_dir_all(home.path().join(directory)).expect("home directory");
        }
        fs::write(
        root.path().join("config.yaml"),
        "custom: keep\nagents:\n  demo:\n    allowedPaths: [old]\n    canWrite: false\n  other:\n    canWrite: true\n",
    )
    .expect("config");
        let editor = root.path().join("profile-editor.sh");
        let script = format!("#!/bin/sh\ncat > \"$1\" <<'YAML'\n{profile}YAML\n");
        fs::write(&editor, script).expect("editor script");
        fs::set_permissions(&editor, fs::Permissions::from_mode(0o700)).expect("editor mode");
        (root, home, editor)
    }

    #[test]
    fn agent_profile_edit_matches_go_and_preserves_cancelled_config() {
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

        let cases = [
            ("success", "allowedPaths:\n  - new\ncanWrite: true\n", "y\n"),
            (
                "cancel",
                "allowedPaths:\n  - discarded\ncanWrite: true\n",
                "n\n",
            ),
        ];
        for (name, profile, confirmation) in cases {
            let (go_root, go_home, go_editor) = fixture_root(name, profile);
            let (rust_root, rust_home, rust_editor) = fixture_root(name, profile);
            let before = fs::read(rust_root.path().join("config.yaml")).expect("rust config");
            let args = ["agent", "profile", "edit", "demo"];
            let go = run(
                &go_binary,
                &args,
                go_root.path(),
                go_home.path(),
                &go_editor,
                confirmation,
            );
            let rust = run(
                &rust_binary,
                &args,
                rust_root.path(),
                rust_home.path(),
                &rust_editor,
                confirmation,
            );
            assert_same(&go, &rust, name);
            if name == "cancel" {
                assert_eq!(
                    fs::read(rust_root.path().join("config.yaml"))
                        .expect("rust config after cancel"),
                    before,
                    "cancelled edit must not publish config"
                );
            } else {
                let updated = fs::read_to_string(rust_root.path().join("config.yaml"))
                    .expect("updated rust config");
                assert!(updated.contains("custom: keep"));
                assert!(updated.contains("other:"));
                assert!(updated.contains("- new"));
            }
        }

        let (go_root, go_home, go_editor) = fixture_root("invalid", "canWrite: [\n");
        let (rust_root, rust_home, rust_editor) = fixture_root("invalid", "canWrite: [\n");
        let before = fs::read(rust_root.path().join("config.yaml")).expect("invalid rust config");
        let args = ["agent", "profile", "edit", "demo"];
        let go = run(
            &go_binary,
            &args,
            go_root.path(),
            go_home.path(),
            &go_editor,
            "y\n",
        );
        let rust = run(
            &rust_binary,
            &args,
            rust_root.path(),
            rust_home.path(),
            &rust_editor,
            "y\n",
        );
        assert_eq!(
            go.status.success(),
            rust.status.success(),
            "invalid YAML status"
        );
        assert!(
            go.stdout.is_empty() && rust.stdout.is_empty(),
            "invalid YAML output"
        );
        assert_eq!(
            fs::read(rust_root.path().join("config.yaml")).expect("rust config after invalid edit"),
            before,
            "invalid edited YAML must not publish config"
        );

        let (go_root, go_home, go_editor) = fixture_root("unknown", "canWrite: true\n");
        let (rust_root, rust_home, rust_editor) = fixture_root("unknown", "canWrite: true\n");
        let args = ["agent", "profile", "edit", "missing"];
        let go = run(
            &go_binary,
            &args,
            go_root.path(),
            go_home.path(),
            &go_editor,
            "y\n",
        );
        let rust = run(
            &rust_binary,
            &args,
            rust_root.path(),
            rust_home.path(),
            &rust_editor,
            "y\n",
        );
        assert_same(&go, &rust, "unknown profile");
    }
}
