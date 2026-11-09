#![cfg(unix)]
//! ADR 0037 R5 (CLI-006): the `mcp agent ...` spelling.
//!
//! The output-format gate names two commands `mcp agent install` and
//! `mcp agent list` in its "supported commands" text, but the command tree has
//! no such path: `agent install` and `agent list` are top-level groups, and
//! cobra resolves `mcp agent list` to the `mcp` server command with the
//! positionals `agent list`. This test pins what Go answers for that spelling
//! (recorded from the Go oracle) in an empty sandbox and in an initialized
//! vault, for text, `--quiet`, `--json`, `--output json|yaml|xml` and the
//! server's own `--stdio` refusals. Shapes that would start the HTTP server
//! (initialized vault, no `--stdio`) are not recorded: they bind a port and
//! mint random token ids.
//!
//! Recapture (docs/rust-port/go-oracle-archive.md): `SYMVAULT_ORACLE=capture
//! SYMVAULT_GO_BINARY=<oracle> cargo test -p symvault-cli --test
//! cli_mcp_agent_spelling`; the oracle binary is a plain `go build` of the tag
//! `legacy/go-oracle` (`main.version` unset).

#[path = "common/go_oracle.rs"]
mod go_oracle;

#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// `legacy/go-oracle` (`ce2390d7`), the revision all R-series recordings use.
const ORACLE: &str = "ce2390d748818a4beb413e97183b7795efa99411";
const PASSPHRASE: &str = "synthetic-r5-passphrase";

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .env("CI", "1");
    go_oracle::output(&mut command).expect("run CLI")
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
        String::from_utf8_lossy(&rust.stdout),
        String::from_utf8_lossy(&go.stdout),
        "{case}: stdout differs"
    );
    assert_eq!(
        String::from_utf8_lossy(&rust.stderr),
        String::from_utf8_lossy(&go.stderr),
        "{case}: stderr differs"
    );
}

/// Shapes that never start the server, in either state.
const SPELLINGS: &[&[&str]] = &[
    &["mcp", "agent"],
    &["mcp", "agent", "list"],
    &["mcp", "agent", "install"],
    &["mcp", "agent", "list", "x", "y"],
    &["mcp", "agent", "bogus"],
    &["mcp", "agent", "list", "--quiet"],
    &["mcp", "agent", "list", "--json"],
    &["mcp", "agent", "install", "--json"],
    &["mcp", "agent", "list", "--output", "json"],
    &["mcp", "agent", "list", "--output", "yaml"],
    &["mcp", "agent", "list", "--output", "xml"],
    &["mcp", "agent", "install", "--output", "yaml"],
    &["mcp", "agent", "list", "--help"],
    &["mcp", "agent", "install", "--help"],
    &["mcp", "--output", "yaml", "agent", "list"],
    &["--output", "yaml", "mcp", "agent", "list"],
    &["--json", "mcp", "agent", "install"],
];

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn mcp_agent_spelling_matches_go_in_an_empty_sandbox() {
    let oracle = go_oracle::GoOracle::begin(
        "cli_mcp_agent_spelling",
        "mcp_agent_spelling_matches_go_in_an_empty_sandbox",
        Some(ORACLE),
    );
    // `mcp --help` documents the default `127.0.0.1:8080`.
    oracle.track_port(8080);
    let go_binary = oracle.binary();
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = test_temp_root::TempRoot::missing("symvault-r5-home-");
    let root = test_temp_root::TempRoot::missing("symvault-r5-empty-");
    fs::create_dir_all(&home).expect("home");
    // `--help` embeds the default config path; it is under the sandbox HOME.
    for args in SPELLINGS {
        let go = run(&go_binary, args, &root, &home);
        let rust = run(&rust_binary, args, &root, &home);
        // A capture only records Go; the comparison is the replay's job (the
        // archived tree's Rust predates this contract).
        if oracle.replaying() {
            assert_same(&go, &rust, &format!("{args:?} (empty)"));
        }
    }
    assert_eq!(oracle.calls(), SPELLINGS.len());
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn mcp_agent_spelling_matches_go_in_an_initialized_vault() {
    let oracle = go_oracle::GoOracle::begin(
        "cli_mcp_agent_spelling",
        "mcp_agent_spelling_matches_go_in_an_initialized_vault",
        Some(ORACLE),
    );
    oracle.track_port(8080);
    let go_binary = oracle.binary();
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = test_temp_root::TempRoot::missing("symvault-r5-home-");
    let root = test_temp_root::TempRoot::missing("symvault-r5-vault-");
    fs::create_dir_all(&home).expect("home");
    let init = oracle.seed_run("init", &[&root, &home], || {
        run(
            &rust_binary,
            &[
                "--vault",
                root.to_str().unwrap(),
                "init",
                "--auth",
                "passphrase",
            ],
            &root,
            &home,
        )
    });
    assert!(init.status.success(), "Rust init: {:?}", init.stderr);

    let mut count = 0;
    // The format gate and `--help` run before the server; so do the `--stdio`
    // refusals (no agent, unknown agent). Plain spellings would bind :8080.
    let initialized: &[&[&str]] = &[
        &["mcp", "agent", "list", "--json"],
        &["mcp", "agent", "install", "--output", "yaml"],
        &["mcp", "agent", "list", "--help"],
        &["mcp", "agent", "list", "--stdio"],
        &["mcp", "agent", "install", "--stdio"],
        &["mcp", "agent", "list", "--stdio", "--agent", "nosuch"],
        &["mcp", "agent", "--stdio", "--agent", "nosuch", "list"],
    ];
    for args in initialized {
        let go = run(&go_binary, args, &root, &home);
        let rust = run(&rust_binary, args, &root, &home);
        if oracle.replaying() {
            assert_same(&go, &rust, &format!("{args:?} (initialized)"));
        }
        count += 1;
    }
    assert_eq!(oracle.calls(), count);
}
