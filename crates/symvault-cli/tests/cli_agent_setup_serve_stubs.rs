//! Contract for the deprecated hidden stubs `symvault agent setup <name>` and
//! `symvault serve token [create|list|revoke]`.
//!
//! Expected values were captured from the Go oracle built from this slice's
//! base (`f34780ac`, release `unreleased`, no Go file changes in this slice)
//! and are reproduced here byte for byte. Re-capture with:
//!
//! ```sh
//! GOTOOLCHAIN=go1.26.6 go build -ldflags \
//!   "-s -w -X main.version=unreleased -X main.commit=none -X main.date=unknown" \
//!   -o target/port/symvault-go .
//! HOME=$(mktemp -d) target/port/symvault-go agent setup claude-code
//! HOME=$(mktemp -d) target/port/symvault-go serve token create
//! ```
//!
//! The oracle prints, for every one of these stubs and with the same bytes
//! under `--quiet`: the `cliout.Warnf` notice, the returned `ExitNotFound`
//! error rendered twice with an `Error: ` prefix, and the generic not-found
//! hint — empty stdout, exit status 2.
//!
//! Documented known difference (asserted below as a negative control): bare
//! `symvault serve` and `serve install|status|uninstall` are deliberately
//! **not** ported — they belong to the HTTP/service runtime. The oracle
//! prints `Warning: 'symvault serve' is deprecated, use 'symvault mcp'
//! instead.` and then starts the server (on an empty `HOME` it continues with
//! `Error: vault not initialized. …`, exit 3); the port declares only the
//! `token` child, so clap rejects the word forms with `unrecognized
//! subcommand` (exit 1) while the bare form renders clap's help on stderr
//! (exit 1), the same shape as bare `agent`/`policy`. `symvault help` stays a
//! documented non-goal of the port, as in the merged alias slice.
use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// A guard owning a unique temporary directory plus the disposable roots
/// inside it (see `cli_alias_deprecated_stubs.rs` for why `tempfile` is used
/// instead of a clock-based name).
fn disposable_roots() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let guard = tempfile::Builder::new()
        .prefix("symvault-cli-stub-serve-")
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

/// The four stderr lines the oracle emits for a deprecated stub.
fn stub_notice(message: &str) -> String {
    format!("{message}\nError: {message}\nError: {message}\nTry: symvault find <search-term>\n")
}

const AGENT_SETUP_NOTICE: &str =
    "This command is deprecated in v4.0. Use: symvault agent install <name>";
const TOKEN_GROUP_NOTICE: &str =
    "This command is deprecated in v4.0. Use: symvault agent token <new|list|revoke|rotate> <name>";
const TOKEN_CREATE_NOTICE: &str =
    "This command is deprecated in v4.0. Use: symvault agent token new <name>";
const TOKEN_LIST_NOTICE: &str =
    "This command is deprecated in v4.0. Use: symvault agent token list <name>";
const TOKEN_REVOKE_NOTICE: &str =
    "This command is deprecated in v4.0. Use: symvault agent token revoke <name> <token-id>";

/// `(argv, expected notice)` pairs, captured from the oracle: with a name,
/// with no name at all, with extra words, with an unknown subcommand word,
/// and through the shared `newMcpTokenCmd()` group handler.
const STUB_CASES: &[(&[&str], &str)] = &[
    (&["agent", "setup", "claude-code"], AGENT_SETUP_NOTICE),
    // `ArbitraryArgs`: zero words and extra words reach the handler too.
    (&["agent", "setup"], AGENT_SETUP_NOTICE),
    (&["agent", "setup", "a", "b", "c"], AGENT_SETUP_NOTICE),
    (&["serve", "token"], TOKEN_GROUP_NOTICE),
    (&["serve", "token", "create"], TOKEN_CREATE_NOTICE),
    (&["serve", "token", "list"], TOKEN_LIST_NOTICE),
    (&["serve", "token", "revoke"], TOKEN_REVOKE_NOTICE),
    (&["serve", "token", "revoke", "abc123"], TOKEN_REVOKE_NOTICE),
    // The oracle declares no `Args` restriction, so an unknown word falls
    // through to the group handler.
    (&["serve", "token", "bogus"], TOKEN_GROUP_NOTICE),
    (&["serve", "token", "create", "extra"], TOKEN_CREATE_NOTICE),
];

#[test]
fn deprecated_setup_and_serve_token_stubs_reproduce_the_oracle_bytes() {
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
fn deprecated_setup_and_serve_token_stubs_ignore_quiet_like_the_oracle() {
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

/// The oracle builds `mcp` and `serve` from one shared `newMcpTokenCmd()`,
/// so every `serve token` path must be byte-identical to its `mcp token`
/// counterpart — the port reuses one implementation for the same reason.
#[test]
fn serve_token_is_byte_identical_to_mcp_token() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();

    for token_args in [
        &["token"][..],
        &["token", "create"],
        &["token", "list"],
        &["token", "revoke", "abc123"],
        &["token", "bogus"],
    ] {
        let (mut mcp, mut serve) = (vec!["mcp"], vec!["serve"]);
        mcp.extend_from_slice(token_args);
        serve.extend_from_slice(token_args);
        let mcp_out = run(&binary, &mcp, &root, &home);
        let serve_out = run(&binary, &serve, &root, &home);
        assert_eq!(
            mcp_out.status.code(),
            serve_out.status.code(),
            "mcp vs serve exit for {token_args:?}"
        );
        assert_eq!(mcp_out.stdout, serve_out.stdout, "mcp vs serve stdout");
        assert_eq!(mcp_out.stderr, serve_out.stderr, "mcp vs serve stderr");
    }
}

/// Hidden stays hidden: neither stub may reappear in help, and `generate
/// manpages` must not grow a page for them (both sides skip hidden commands).
#[test]
fn deprecated_serve_and_agent_setup_stay_hidden_from_help() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();

    let root_output = run(&binary, &["--help"], &root, &home);
    let agent_output = run(&binary, &["agent", "--help"], &root, &home);
    let root_help = String::from_utf8_lossy(&root_output.stdout);
    let agent_help = String::from_utf8_lossy(&agent_output.stdout);
    assert!(
        !help_lists_command(&root_help, "serve"),
        "root help exposes serve: {root_help}"
    );
    assert!(
        !help_lists_command(&agent_help, "setup"),
        "agent help exposes setup: {agent_help}"
    );
}

/// Whether `help` lists a subcommand of that name (a line starting with the
/// name, so prose such as "MCP server …" cannot match).
fn help_lists_command(help: &str, name: &str) -> bool {
    help.lines().any(|line| {
        let line = line.trim_start();
        line == name
            || line
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with(' '))
    })
}

/// Negative control: the deliberately unported `serve` runtime paths must
/// fail closed instead of masquerading as the ported stubs.
///
/// The oracle's bare `serve` prints its own deprecation warning and then
/// starts (or fails inside) the server — captured on an empty `HOME`: exit 3
/// with `Error: vault not initialized. …`; `serve install`/`uninstall` write
/// a launchd/systemd unit. None of that is ported. Instead clap rejects the
/// word forms with `unrecognized subcommand` (exit 1, stderr), and the bare
/// form renders clap's help-on-missing-subcommand on stderr with exit 1 —
/// the established shape for every required-subcommand parent in this port
/// (bare `agent`, `policy` and `device` behave the same). If a future slice
/// ports the runtime, this test is the one to update together with the
/// module docs in `deprecated_stubs`.
#[test]
fn unported_serve_runtime_paths_fail_closed_without_stub_output() {
    let binary = rust_binary();
    let (_guard, home, root) = disposable_roots();

    for args in [
        &["serve"][..],
        &["serve", "install"],
        &["serve", "status"],
        &["serve", "uninstall"],
        &["serve", "bogus"],
    ] {
        let output = run(&binary, args, &root, &home);
        let label = format!("symvault {}", args.join(" "));
        assert_eq!(
            output.status.code(),
            Some(1),
            "{label} must fail closed; stderr={:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "{label} wrote to stdout");
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Windows renders the executable name as `symvault.exe` in clap usage.
        assert!(
            stderr.contains(" serve [") || stderr.contains(" serve "),
            "{label} did not target the serve command: {stderr}"
        );
        if args.len() > 1 {
            assert!(
                stderr.starts_with("error:"),
                "{label} stderr is not a parse error: {stderr}"
            );
        } else {
            assert!(
                stderr.starts_with("Deprecated: use `symvault mcp`"),
                "{label} stderr is not the serve help: {stderr}"
            );
        }
        assert!(
            !stderr.contains("This command is deprecated"),
            "{label} must not print stub bytes: {stderr}"
        );
        assert!(
            !stderr.contains("Warning: 'symvault serve' is deprecated"),
            "{label} must not print the oracle's server warning: {stderr}"
        );
    }
}
