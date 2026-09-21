//! Contract for the Cobra top-level aliases and the deprecated hidden v4.0
//! compatibility commands.
//!
//! Expected values were captured from the pinned Go oracle built from
//! `testdata/port/cli/command-tree.json` (commit `3232e31f`, release
//! `unreleased`) and are reproduced here byte for byte. Re-capture with:
//!
//! ```sh
//! GOTOOLCHAIN=go1.26.6 go build -ldflags \
//!   "-s -w -X main.version=unreleased -X main.commit=none -X main.date=unknown" \
//!   -o target/port/symvault-go .
//! HOME=$(mktemp -d) target/port/symvault-go mcp token
//! ```
//!
//! The oracle prints, for every one of these deprecated commands and with the
//! same bytes under `--quiet`: the `cliout.Warnf` notice, the returned
//! `ExitNotFound` error rendered twice with an `Error: ` prefix, and the generic
//! not-found hint — empty stdout, exit status 2.
use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// A guard owning a unique temporary directory plus the disposable roots inside
/// it.
///
/// `tempfile` is used instead of `SystemTime::now().as_nanos()`: that clock is
/// only microsecond-coarse on macOS (see `history_commands.rs`, issue #1085), so
/// tests of one binary collide on the same directory name. This file must not
/// join that list.
fn disposable_roots() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let guard = tempfile::Builder::new()
        .prefix("symvault-cli-alias-stub-")
        .tempdir()
        .expect("temp dir");
    let home = guard.path().join("home");
    let root = guard.path().join("vault");
    std::fs::create_dir_all(&home).expect("home");
    (guard, home, root)
}

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run CLI")
}

fn rust_binary() -> PathBuf {
    PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"))
}

fn stub_notice(message: &str) -> String {
    format!("{message}\nError: {message}\nError: {message}\nTry: symvault find <search-term>\n")
}

/// Go's `HintForError` fallback for `ExitNotFound`, shared by every stub below.
const GROUP_NOTICE: &str =
    "This command is deprecated in v4.0. Use: symvault agent token <new|list|revoke|rotate> <name>";

const STUB_CASES: &[(&[&str], &str)] = &[
    (&["mcp", "token"], GROUP_NOTICE),
    (
        &["mcp", "token", "create"],
        "This command is deprecated in v4.0. Use: symvault agent token new <name>",
    ),
    (
        &["mcp", "token", "list"],
        "This command is deprecated in v4.0. Use: symvault agent token list <name>",
    ),
    (
        &["mcp", "token", "revoke", "abc123"],
        "This command is deprecated in v4.0. Use: symvault agent token revoke <name> <token-id>",
    ),
    // The oracle declares no `Args` restriction, so an unknown word falls
    // through to the group handler.
    (&["mcp", "token", "bogus"], GROUP_NOTICE),
    (
        &["mcp-config"],
        "This command is deprecated in v4.0. Use: symvault agent install <agent> --config-only",
    ),
    (
        &["mcp-config", "claude-code"],
        "This command is deprecated in v4.0. Use: symvault agent install <agent> --config-only",
    ),
    (
        &["mcp-token-rotate"],
        "This command is deprecated in v4.0. Use: symvault agent token rotate <name>",
    ),
    (
        &["mcp-token-rotate", "my-agent"],
        "This command is deprecated in v4.0. Use: symvault agent token rotate <name>",
    ),
];

#[test]
fn deprecated_stubs_reproduce_the_oracle_bytes() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();

    for (args, message) in STUB_CASES {
        let output = run(&binary, args, &root, &home);
        let label = format!("symvault {}", args.join(" "));
        assert_eq!(
            output.status.code(),
            Some(2),
            "{label} exit status; stderr={:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "{label} wrote to stdout");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            stub_notice(message),
            "{label} stderr"
        );
    }
}

/// The oracle prints the four lines even with `--quiet`, so the port must not
/// silence them either.
#[test]
fn deprecated_stubs_ignore_quiet_like_the_oracle() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();

    for (args, message) in STUB_CASES {
        let mut args_with_quiet = vec!["--quiet"];
        args_with_quiet.extend_from_slice(args);
        let output = run(&binary, &args_with_quiet, &root, &home);
        assert_eq!(output.status.code(), Some(2), "quiet exit for {args:?}");
        assert!(output.stdout.is_empty(), "quiet stdout for {args:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            stub_notice(message),
            "quiet stderr for {args:?}"
        );
    }
}

/// The Go tree declares `get -> [show, cat]` and `list -> [ls]` as top-level
/// aliases. Each alias must behave exactly like its canonical command.
#[test]
fn top_level_aliases_match_their_canonical_commands() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();

    let init = run(
        &binary,
        &[
            "--vault",
            root.to_str().unwrap(),
            "init",
            "--auth",
            "passphrase",
        ],
        &root,
        &home,
    );
    assert_eq!(
        init.status.code(),
        Some(0),
        "init failed: {:?}",
        String::from_utf8_lossy(&init.stderr)
    );
    let add = run(
        &binary,
        &["add", "alias/probe", "--value", "alias-probe-secret-1"],
        &root,
        &home,
    );
    assert_eq!(
        add.status.code(),
        Some(0),
        "add failed: {:?}",
        String::from_utf8_lossy(&add.stderr)
    );

    for (alias, canonical) in [
        (vec!["ls"], vec!["list"]),
        (vec!["show", "alias/probe"], vec!["get", "alias/probe"]),
        (vec!["cat", "alias/probe"], vec!["get", "alias/probe"]),
    ] {
        let aliased = run(&binary, &alias, &root, &home);
        let direct = run(&binary, &canonical, &root, &home);
        assert_eq!(
            aliased.status.code(),
            direct.status.code(),
            "{alias:?} vs {canonical:?} exit status"
        );
        assert_eq!(
            aliased.stdout, direct.stdout,
            "{alias:?} vs {canonical:?} stdout"
        );
        assert_eq!(
            aliased.stderr, direct.stderr,
            "{alias:?} vs {canonical:?} stderr"
        );
    }

    let listing = run(&binary, &["list"], &root, &home);
    assert!(
        String::from_utf8_lossy(&listing.stdout).contains("alias/probe"),
        "list did not show the entry: {:?}",
        String::from_utf8_lossy(&listing.stdout)
    );
}

/// Hidden stays hidden: the compatibility commands must not reappear in help.
#[test]
fn deprecated_stubs_stay_hidden_from_help() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();

    let root_help = run(&binary, &["--help"], &root, &home);
    let mcp_help = run(&binary, &["mcp", "--help"], &root, &home);
    for needle in ["mcp-config", "mcp-token-rotate", "token"] {
        for (label, output) in [("--help", &root_help), ("mcp --help", &mcp_help)] {
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(!text.contains(needle), "{label} exposes {needle}: {text}");
        }
    }
}
