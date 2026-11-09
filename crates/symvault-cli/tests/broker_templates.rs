//! `--broker-templates` / `broker --templates` (danieljustus/symaira-vault#1554).
//!
//! The release of credentials per host is exercised end to end against real
//! TLS/TCP peers in `crates/symvault-mcp/tests/egress_broker.rs`
//! (`egress_template_selection_limits_injection_to_the_named_templates`). This
//! file covers the CLI surface: parsing, refusal of unknown names before any
//! child starts, and the help/manual pages of the two Rust-only flags.
#![cfg(unix)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::Value;

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");
const PASSPHRASE: &str = "synthetic-1554-passphrase";

struct Sandbox {
    _guard: tempfile::TempDir,
    home: PathBuf,
    vault: PathBuf,
}

fn command(home: &Path, vault: &Path) -> Command {
    let mut command = Command::new(BINARY);
    command
        .arg("--vault")
        .arg(vault)
        .current_dir(home)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("LANG", "C")
        .env("CI", "1");
    command
}

fn sandbox() -> Sandbox {
    let guard = tempfile::Builder::new()
        .prefix("symvault-1554-")
        .tempdir()
        .expect("sandbox");
    let home = guard.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let vault = home.join("vault");
    let init = command(&home, &vault)
        .args(["init", "--auth", "passphrase"])
        .output()
        .expect("init");
    assert!(init.status.success(), "init: {:?}", init.stderr);
    // A vault-local template next to the built-in ones.
    fs::create_dir_all(vault.join("templates")).expect("templates");
    fs::write(
        vault.join("templates/corp.yaml"),
        "base_url: https://corp.example.test\nauth_type: bearer\nentry_ref: corp\n",
    )
    .expect("template");
    Sandbox {
        _guard: guard,
        home,
        vault,
    }
}

fn run(sandbox: &Sandbox, args: &[&str]) -> Output {
    command(&sandbox.home, &sandbox.vault)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run symvault")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn run_broker_refuses_unknown_templates_before_the_child_starts() {
    let sandbox = sandbox();
    let marker = sandbox.home.join("child-ran");
    let marker_arg = marker.to_str().unwrap();
    for selection in ["nosuch", "github,nosuch", "corp,corpp"] {
        let output = run(
            &sandbox,
            &[
                "run",
                "--broker",
                "--broker-templates",
                selection,
                "--",
                "/usr/bin/touch",
                marker_arg,
            ],
        );
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{selection}: {stderr}");
        assert!(
            stderr.contains("start broker: unknown broker template"),
            "{selection}: {stderr}"
        );
        let unknown = selection.rsplit(',').next().unwrap();
        assert!(
            stderr.contains(&format!("{unknown:?}")),
            "{selection} names the offender: {stderr}"
        );
        // The refusal lists what is available, vault-local and built-in alike.
        assert!(
            stderr.contains("available: ") && stderr.contains("corp") && stderr.contains("github"),
            "{selection}: {stderr}"
        );
        assert!(!marker.exists(), "{selection}: the child must not start");
    }
}

#[test]
fn run_broker_accepts_builtin_and_vault_local_templates() {
    let sandbox = sandbox();
    // The child sees the proxy but never a template credential.
    for selection in ["github", "corp", "github,corp", "github"] {
        let output = run(
            &sandbox,
            &[
                "run",
                "--broker",
                "--broker-strict",
                "--broker-templates",
                selection,
                "--",
                "/bin/sh",
                "-c",
                "echo $HTTPS_PROXY",
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "{selection}: {}",
            text(&output.stderr)
        );
        assert!(
            // `run` masks the address in its own output; the proxy URL is
            // still there, so check scheme and port shape only.
            text(&output.stdout).starts_with("http://"),
            "{selection}: {}",
            text(&output.stdout)
        );
    }
    // The flag may be repeated.
    let output = run(
        &sandbox,
        &[
            "run",
            "--broker",
            "--broker-templates",
            "github",
            "--broker-templates",
            "corp",
            "--",
            "/usr/bin/true",
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
}

#[test]
fn empty_template_names_are_a_usage_error_for_both_commands() {
    let sandbox = sandbox();
    for (args, flag) in [
        (
            &[
                "run",
                "--broker",
                "--broker-templates",
                "github,,corp",
                "--",
                "true",
            ][..],
            "--broker-templates",
        ),
        (
            &["run", "--broker", "--broker-templates=", "--", "true"][..],
            "--broker-templates",
        ),
        (&["broker", "--templates", "github, "][..], "--templates"),
        (&["broker", "--templates="][..], "--templates"),
    ] {
        let output = run(&sandbox, args);
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.contains(&format!("{flag}: template names must not be empty")),
            "{args:?}: {stderr}"
        );
        assert!(
            output.stdout.is_empty(),
            "{args:?}: {}",
            text(&output.stdout)
        );
    }
}

#[test]
fn broker_refuses_unknown_templates_without_listening() {
    let sandbox = sandbox();
    let output = run(&sandbox, &["broker", "--templates", "github,nosuch"]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("Error: unknown broker template \"nosuch\" (available: "),
        "{stderr}"
    );
    // Nothing was printed, in particular no startup banner with proxy exports.
    assert!(output.stdout.is_empty(), "{}", text(&output.stdout));
}

/// Lines of `rust` left after greedily matching every line of `go`; `None` when
/// `go` is not a subsequence of `rust`.
fn extra_lines(go: &str, rust: &str) -> Option<Vec<String>> {
    let mut go_lines = go.lines().peekable();
    let mut extra = Vec::new();
    for line in rust.lines() {
        if go_lines.peek() == Some(&line) {
            go_lines.next();
        } else {
            extra.push(line.to_owned());
        }
    }
    go_lines.peek().is_none().then_some(extra)
}

fn artifacts() -> Value {
    serde_json::from_str(include_str!("../../../testdata/port/cli/artifacts.json")).unwrap()
}

const RUN_USAGE: &str = "With --broker: inject credentials only for these templates (comma-separated, built-in or vault-local names); other template hosts are treated as hosts without a template";
const BROKER_USAGE: &str = "Inject credentials only for these templates (comma-separated, built-in or vault-local names); other template hosts are treated as hosts without a template";

/// The frozen Go help pages gain exactly one line each, in cobra's sorted and
/// aligned flag layout, for both `--help` spellings.
#[test]
fn help_pages_add_exactly_the_rust_only_flag_lines() {
    let sandbox = sandbox();
    let artifacts = artifacts();
    for (path, args, line) in [
        (
            "symvault run",
            &["run", "--help"][..],
            format!("      --broker-templates strings     {RUN_USAGE}"),
        ),
        (
            "symvault broker",
            &["broker", "--help"][..],
            format!("      --templates strings     {BROKER_USAGE}"),
        ),
    ] {
        let frozen = artifacts["help"][path].as_str().unwrap();
        let output = run(&sandbox, args);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let rust = text(&output.stdout);
        assert_eq!(
            extra_lines(frozen, &rust),
            Some(vec![line.clone()]),
            "{path}: help differs from the frozen Go page by more than the declared flag"
        );
        // `help <command>` renders the same page.
        let topic = run(&sandbox, &["help", path.strip_prefix("symvault ").unwrap()]);
        assert_eq!(text(&topic.stdout), rust, "{path}: help topic");
        // The flag is part of the inventory: `--help` stays reachable with it
        // present, and the help flag is still resolved after it.
        let flag = if path == "symvault run" {
            "--broker-templates"
        } else {
            "--templates"
        };
        let with_flag = run(&sandbox, &[args[0], flag, "github", "--help"]);
        assert_eq!(text(&with_flag.stdout), rust, "{path}: flag before --help");
    }
}

/// The run line sits between `--broker-strict` and `-e, --env` (cobra sorts
/// flags by name), the broker line after `--strict`.
#[test]
fn help_flag_lines_keep_cobra_order() {
    let sandbox = sandbox();
    for (args, before, flag, after) in [
        (
            &["run", "--help"][..],
            "--broker-strict",
            "--broker-templates",
            "-e, --env",
        ),
        (
            &["broker", "--help"][..],
            "--strict",
            "--templates",
            "\n\nGlobal Flags:",
        ),
    ] {
        let help = text(&run(&sandbox, args).stdout);
        let position = |needle: &str| help.find(needle).unwrap_or_else(|| panic!("{needle}"));
        assert!(
            position(before) < position(flag) && position(flag) < position(after),
            "{args:?}: {help}"
        );
    }
}

/// The manual pages carry the flag in their `OPTIONS` section.
#[test]
fn manual_pages_add_exactly_the_rust_only_flag_entries() {
    let sandbox = sandbox();
    let target = sandbox.home.join("man");
    let output = run(
        &sandbox,
        &["generate", "manpages", target.to_str().unwrap()],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let artifacts = artifacts();
    let mask = |page: &str| -> String {
        page.lines()
            .map(|line| {
                if line.starts_with(".TH ") {
                    ".TH".to_owned()
                } else if line.contains("Auto generated by spf13/cobra") {
                    "<HISTORY>".to_owned()
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    for (name, flag, usage) in [
        ("symvault-run.1", "--broker-templates", RUN_USAGE),
        ("symvault-broker.1", "--templates", BROKER_USAGE),
    ] {
        let page = fs::read_to_string(target.join(name)).unwrap();
        let frozen = artifacts["manpages"][name].as_str().unwrap();
        let extra = extra_lines(&mask(frozen), &mask(&page)).expect("Go page is a subsequence");
        let entry = format!("\\fB{flag}\\fP=[]");
        let usage_line = format!("\t{usage}");
        assert!(extra.contains(&entry), "{name}: {extra:?}");
        assert!(extra.contains(&usage_line), "{name}: {extra:?}");
        // Only the entry, its description and the paragraph separators.
        assert!(
            extra.iter().all(|line| line.is_empty()
                || line == ".PP"
                || *line == entry
                || *line == usage_line),
            "{name}: {extra:?}"
        );
        // The committed page in docs/man documents it too.
        let committed = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/man")
                .join(name),
        )
        .unwrap();
        assert!(
            committed.contains(&entry) && committed.contains(&usage_line),
            "docs/man/{name}"
        );
    }
}
