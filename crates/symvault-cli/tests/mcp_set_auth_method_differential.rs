//! Live Go-oracle differential for the MCP `set_auth_method` tool and `tools/list`.
//!
//! Needs `SYMVAULT_GO_BINARY` to name a Go oracle built **without cgo**
//! (`CGO_ENABLED=0`): that build has no Touch ID (the noop authenticator and
//! passphrase store), so every state exercised here is deterministic and can
//! never raise a system prompt. A cgo oracle on a Touch ID Mac would show a real
//! dialog for `method=passphrase`; the test refuses to run against one (it
//! checks `get_auth_status` first). Both implementations run on identical copies
//! of one Go-initialised vault inside disposable HOME/XDG/TMPDIR roots and the
//! comparison covers the exact stdout bytes, the exit status and the auth keys
//! `set_auth_method` writes to `config.yaml`.
//!
//! Skipped (loudly) when `SYMVAULT_GO_BINARY` is unset, like the other
//! `*_differential` tests.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use tempfile::TempDir;

const PASSPHRASE: &str = "differential-passphrase-1";

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create copy root");
    for entry in fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("dir entry");
        let target = to.join(entry.file_name());
        let kind = entry.file_type().expect("file type");
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

fn sandbox_env(command: &mut Command, root: &Path) {
    let home = root.join("home");
    let tmp = root.join("tmp");
    for dir in [&home, &tmp] {
        fs::create_dir_all(dir).expect("sandbox dir");
    }
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("TMPDIR", &tmp)
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("CI", "1")
        // Secure-input tools are listed from host GUI/TTY probes that differ per
        // implementation; pin them off so only the registry is compared.
        .env("SYMVAULT_SECUREUI", "none")
        .env("TZ", "UTC")
        .env("LC_ALL", "C");
}

struct Outcome {
    status: Option<i32>,
    stdout: Vec<u8>,
    config: Vec<u8>,
}

fn frames(calls: &[(&str, Value)], list_tools: bool) -> String {
    let mut frames = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ];
    if list_tools {
        frames.push(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    }
    for (index, (name, arguments)) in calls.iter().enumerate() {
        frames.push(json!({"jsonrpc":"2.0","id":index + 3,"method":"tools/call","params":{"name":name,"arguments":arguments}}));
    }
    frames.iter().map(|frame| format!("{frame}\n")).collect()
}

fn run_mcp(binary: &Path, template: &Path, label: &str, agent: &str, input: &str) -> Outcome {
    let scratch = TempDir::new().expect("scratch root");
    let vault = scratch.path().join("vault");
    copy_tree(template, &vault);
    let mut command = Command::new(binary);
    sandbox_env(&mut command, scratch.path());
    let mut child = command
        .current_dir(scratch.path())
        .args(["--vault"])
        .arg(&vault)
        .args(["mcp", "--stdio", "--agent", agent])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {label}: {error}"));
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write frames");
    let output = child.wait_with_output().expect("wait");
    Outcome {
        status: output.status.code(),
        stdout: output.stdout,
        config: fs::read(vault.join("config.yaml")).unwrap_or_default(),
    }
}

fn template_vault(go: &Path) -> (TempDir, PathBuf) {
    let root = TempDir::new().expect("template root");
    let vault = root.path().join("template-vault");
    let mut init = Command::new(go);
    sandbox_env(&mut init, root.path());
    let output = init
        .current_dir(root.path())
        .args(["init"])
        .arg(&vault)
        .args(["--auth", "passphrase"])
        .output()
        .expect("go init");
    assert!(
        output.status.success(),
        "go init: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config_path = vault.join("config.yaml");
    let config = fs::read_to_string(&config_path).expect("config");
    let patched = config.replacen(
        "agents:\n    cli:",
        "agents:\n    adm:\n        tier: admin\n        allowedPaths:\n            - '*'\n        canWrite: true\n        canManageConfig: true\n        requireApproval: false\n    mgr:\n        allowedPaths:\n            - '*'\n        canWrite: true\n        canManageConfig: true\n        requireApproval: false\n    cli:",
        1,
    );
    assert_ne!(config, patched, "config seed shape changed:\n{config}");
    fs::write(config_path, patched).expect("seed agents");
    (root, vault)
}

fn compare(go: &Path, rust: &Path, template: &Path, name: &str, agent: &str, input: &str) {
    let expected = run_mcp(go, template, "go", agent, input);
    let actual = run_mcp(rust, template, "rust", agent, input);
    assert_eq!(expected.status, Some(0), "{name}: oracle must exit cleanly");
    assert_eq!(
        String::from_utf8_lossy(&actual.stdout),
        String::from_utf8_lossy(&expected.stdout),
        "{name}: stdout bytes"
    );
    assert_eq!(actual.status, expected.status, "{name}: exit status");
    // Only the auth keys are compared: the Rust `mcp` start-up independently
    // re-saves `config.yaml` with the default agent profiles added (visible in
    // the `tools-list-*` cases, which call no tool), a pre-existing divergence
    // outside this slice. The keys `set_auth_method` writes must still agree.
    assert_eq!(
        auth_keys(&actual.config),
        auth_keys(&expected.config),
        "{name}: auth keys in config.yaml"
    );
}

fn auth_keys(config: &[u8]) -> Value {
    let document: Value = serde_yaml_ng::from_slice(config).expect("config.yaml parses");
    json!({
        "authMethod": document["authMethod"],
        "useTouchID": document["useTouchID"],
        "vault.authMethod": document["vault"]["authMethod"],
        "vault.useTouchID": document["vault"]["useTouchID"],
    })
}

#[test]
fn set_auth_method_and_tools_list_match_the_go_oracle() {
    let Some(go) = std::env::var_os("SYMVAULT_GO_BINARY").map(PathBuf::from) else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let (_guard, template) = template_vault(&go);

    // Safety gate: this oracle must not be able to show a Touch ID prompt.
    let probe = run_mcp(
        &go,
        &template,
        "go-probe",
        "mgr",
        &frames(&[("get_auth_status", json!({}))], false),
    );
    let probe_text = String::from_utf8_lossy(&probe.stdout);
    assert!(
        probe_text.contains("touchIDAvailable\\\":false"),
        "SYMVAULT_GO_BINARY must be a CGO_ENABLED=0 oracle without Touch ID; got {probe_text}"
    );

    type Case<'a> = (&'a str, &'a str, Vec<(&'a str, Value)>, bool);
    let cases: Vec<Case> = vec![
        ("tools-list-default-profile", "mgr", vec![], true),
        ("tools-list-admin-tier", "adm", vec![], true),
        (
            "denied-without-canManageConfig",
            "cli",
            vec![("set_auth_method", json!({"method": "passphrase"}))],
            false,
        ),
        (
            "argument-errors",
            "mgr",
            vec![
                ("set_auth_method", json!({})),
                ("set_auth_method", json!({"method": 7})),
                ("set_auth_method", json!({"method": "bogus"})),
                ("set_auth_method", json!({"method": "  BOGUS "})),
                ("set_auth_method", json!({"method": null})),
            ],
            false,
        ),
        (
            "touchid-unavailable",
            "mgr",
            vec![
                ("set_auth_method", json!({"method": "touchid"})),
                ("set_auth_method", json!({"method": "Touch-ID"})),
                ("set_auth_method", json!({"method": "biometrics"})),
            ],
            false,
        ),
        (
            "passphrase-without-biometric-store",
            "mgr",
            // `get_auth_status` is left out on purpose: the CLI reports the host's
            // real Touch ID hardware there (pre-existing), the no-cgo oracle `false`.
            vec![("set_auth_method", json!({"method": "passphrase"}))],
            false,
        ),
        (
            "empty-method-is-passphrase",
            "mgr",
            vec![("set_auth_method", json!({"method": " "}))],
            false,
        ),
    ];
    for (name, agent, calls, list_tools) in cases {
        compare(
            &go,
            &rust,
            &template,
            name,
            agent,
            &frames(&calls, list_tools),
        );
    }
}
