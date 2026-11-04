//! Recorded Go-oracle differential for the MCP `set_auth_method` tool and
//! `tools/list`.
//!
//! The Go answers (stdout bytes, exit status, the `config.yaml` the run leaves
//! behind) are replayed from
//! `testdata/port/cli-transcripts/mcp_set_auth_method_differential.json`. The
//! recording comes from a Go oracle built **without cgo**
//! (`CGO_ENABLED=0`): that build has no Touch ID (the noop authenticator and
//! passphrase store), so every state exercised here is deterministic and can
//! never raise a system prompt. A cgo oracle on a Touch ID Mac would show a real
//! dialog for `method=passphrase`; the test refuses to run against one (it
//! checks `get_auth_status` first). Both implementations run on identical copies
//! of one Go-initialised vault (frozen as a seed) inside disposable
//! HOME/XDG/TMPDIR roots and the comparison covers the exact stdout bytes, the
//! exit status and the auth keys `set_auth_method` writes to `config.yaml`.

#[path = "common/go_oracle.rs"]
mod go_oracle;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::TempDir;

/// Go oracle: the last commit that carries the Go sources (`CGO_ENABLED=0`
/// build, so no Touch ID); the tool catalog (`run_command` file inputs) of the
/// older config-cli oracle differs.
const ORACLE_COMMIT: &str = "c069d3f2b17d704525cedc1bd42840cc6a3e9896";

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
    command
        .current_dir(scratch.path())
        .args(["--vault"])
        .arg(&vault)
        .args(["mcp", "--stdio", "--agent", agent]);
    let output = go_oracle::output_with_input(&mut command, Some(input.as_bytes()))
        .unwrap_or_else(|error| panic!("spawn {label}: {error}"));
    Outcome {
        status: output.status.code(),
        stdout: output.stdout,
        config: fs::read(vault.join("config.yaml")).unwrap_or_default(),
    }
}

/// The Go-initialised template vault; `init` generates random keys, so the
/// whole tree is frozen as a seed and installed on replay.
fn template_vault(oracle: &go_oracle::GoOracle, go: &Path) -> (TempDir, PathBuf) {
    let root = TempDir::new().expect("template root");
    let vault = root.path().join("template-vault");
    oracle.seed("go-template-vault", &[root.path()], || {
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
    });
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
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn set_auth_method_and_tools_list_match_the_go_oracle() {
    // The recording comes from a CGO_ENABLED=0 build of the pinned commit.
    let oracle = go_oracle::GoOracle::begin(
        "mcp_set_auth_method_differential",
        "set_auth_method_and_tools_list_match_the_go_oracle",
        Some(ORACLE_COMMIT),
    );
    let go = oracle.binary();
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let (_guard, template) = template_vault(&oracle, &go);

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
        "the recorded Go oracle must be a CGO_ENABLED=0 build without Touch ID; got {probe_text}"
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
    assert_eq!(oracle.calls(), 8);
}
