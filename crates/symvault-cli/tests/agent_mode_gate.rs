//! The `SYMVAULT_AGENT` preflight of Go's root `PersistentPreRunE`
//! (`internal/cli/cli.go`): for every command that requires a vault, a
//! non-empty `SYMVAULT_AGENT` must load as a profile of `<vault>/config.yaml`
//! or the process ends with exit 5 and `agent mode: <error>: <error>`.
//!
//! Each case runs the recorded Go answer and the Rust CLI on twin vaults and
//! compares exit status, stdout, stderr (each side's own temp roots masked) and
//! the file set left in the vault (the load opens `audit-<agent>.log`). The Go
//! answers are replayed from `testdata/port/cli-transcripts/agent_mode_gate.json`.
#[path = "common/go_oracle.rs"]
mod go_oracle;

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// The pinned Go revision the transcript was recorded from.
const ORACLE: &str = "ccaf3bdc1b267536cc3e895db9e6b0f0973a5261";

const PROFILES: &str = r#"agents:
  alpha:
    tier: standard
    allowedPaths: ["work/*"]
  ro:
    tier: read-only
  weird:
    tier: bogus
"#;

struct Side {
    binary: PathBuf,
    root: tempfile::TempDir,
    home: tempfile::TempDir,
}

/// Per-call environment beyond the common one.
#[derive(Clone, Copy, Default)]
struct Opts<'a> {
    /// Leave `SYMVAULT_VAULT` unset (the vault then comes from flags/profiles).
    no_vault_env: bool,
    /// `{ROOT}` in the values is replaced by the side's vault directory.
    extra: &'a [(&'a str, &'a str)],
}

enum Config<'a> {
    Text(&'a str),
    Missing,
    /// `config.yaml` is a directory.
    Directory,
    /// `config.yaml` exists but cannot be read.
    Unreadable(&'a str),
}

impl Side {
    fn new(oracle: &go_oracle::GoOracle, binary: PathBuf) -> Self {
        let root = tempfile::tempdir().expect("vault root");
        let home = tempfile::tempdir().expect("home");
        oracle.track(root.path());
        oracle.track(home.path());
        for directory in ["config", "data", "cache"] {
            fs::create_dir_all(home.path().join(directory)).expect("home directory");
        }
        Self { binary, root, home }
    }

    fn config_path(&self) -> PathBuf {
        self.root.path().join("config.yaml")
    }

    fn set_config(&self, config: &Config<'_>) {
        let path = self.config_path();
        #[cfg(unix)]
        if path.is_file() {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        if path.is_dir() {
            fs::remove_dir(&path).expect("remove config dir");
        } else if path.exists() {
            fs::remove_file(&path).expect("remove config");
        }
        match config {
            Config::Text(text) => fs::write(&path, text).expect("config"),
            Config::Missing => {}
            Config::Directory => fs::create_dir(&path).expect("config dir"),
            Config::Unreadable(text) => {
                fs::write(&path, text).expect("config");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o000))
                        .expect("chmod config");
                }
            }
        }
    }

    fn substitute(&self, text: &str) -> String {
        text.replace("{ROOT}", &self.root.path().to_string_lossy())
    }

    /// An argument with `{ROOT}` replaced and every `{FF}` turned into the
    /// byte 0xFF (not UTF-8).
    fn argument(&self, text: &str) -> OsString {
        let text = self.substitute(text);
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let mut bytes = Vec::new();
            let mut rest = text.as_str();
            while let Some(at) = rest.find("{FF}") {
                bytes.extend_from_slice(&rest.as_bytes()[..at]);
                bytes.push(0xFF);
                rest = &rest[at + 4..];
            }
            bytes.extend_from_slice(rest.as_bytes());
            OsString::from_vec(bytes)
        }
        #[cfg(not(unix))]
        {
            OsString::from(text.replace("{FF}", "\u{FFFD}"))
        }
    }

    fn run(&self, args: &[&str], agent: Option<&str>, opts: Opts<'_>) -> Output {
        let home = self.home.path();
        let mut command = Command::new(&self.binary);
        command
            .args(args.iter().map(|arg| self.argument(arg)))
            .env("HOME", home)
            .env("USERPROFILE", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("CI", "1")
            .env("NO_COLOR", "1")
            .env_remove("SYMVAULT_PROFILE")
            .env_remove("SYMVAULT_PASSPHRASE");
        if opts.no_vault_env {
            command.env_remove("SYMVAULT_VAULT");
        } else {
            command.env("SYMVAULT_VAULT", self.root.path());
        }
        match agent {
            Some(agent) => command.env("SYMVAULT_AGENT", agent),
            None => command.env_remove("SYMVAULT_AGENT"),
        };
        for (key, value) in opts.extra {
            command.env(key, self.substitute(value));
        }
        go_oracle::output(&mut command).expect("run symvault")
    }

    /// Relative path -> (kind, mode, size) of everything below the vault,
    /// except the data-safety marker only the Rust CLI writes.
    fn listing(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        walk(self.root.path(), self.root.path(), &mut map);
        map
    }

    /// Masks this side's temp roots so both sides print the same text.
    fn mask(&self, bytes: &[u8]) -> String {
        let mut text = String::from_utf8_lossy(bytes).into_owned();
        for (path, name) in [(self.root.path(), "<VAULT>"), (self.home.path(), "<HOME>")] {
            let raw = path.to_string_lossy().into_owned();
            text = text.replace(&raw, name);
            if let Ok(real) = fs::canonicalize(path) {
                text = text.replace(real.to_string_lossy().as_ref(), name);
            }
        }
        text
    }
}

fn walk(root: &Path, dir: &Path, map: &mut BTreeMap<String, String>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("read dir")
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .expect("under root")
            .to_string_lossy()
            .into_owned();
        if relative == ".symvault-rust" {
            continue;
        }
        let meta = fs::symlink_metadata(&path).expect("metadata");
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o7777
        };
        #[cfg(not(unix))]
        let mode = 0;
        if meta.is_dir() {
            map.insert(relative, format!("dir {mode:o}"));
            walk(root, &path, map);
        } else {
            map.insert(relative, format!("file {mode:o} {}", meta.len()));
        }
    }
}

struct Pair {
    go: Side,
    rust: Side,
}

impl Pair {
    fn new(test: &str) -> (go_oracle::GoOracle, Self) {
        let oracle = go_oracle::GoOracle::begin("agent_mode_gate", test, Some(ORACLE));
        let go = Side::new(&oracle, oracle.binary());
        let rust = Side::new(&oracle, PathBuf::from(env!("CARGO_BIN_EXE_symvault")));
        (oracle, Self { go, rust })
    }

    fn set_config(&self, config: &Config<'_>) {
        self.go.set_config(config);
        self.rust.set_config(config);
    }

    /// Runs one command on both sides and requires identical behaviour.
    /// Returns the Go side's (exit code, masked stderr).
    fn check(
        &self,
        label: &str,
        args: &[&str],
        agent: Option<&str>,
        opts: Opts<'_>,
    ) -> (Option<i32>, String) {
        let go = self.go.run(args, agent, opts);
        let rust = self.rust.run(args, agent, opts);
        let go_stdout = self.go.mask(&go.stdout);
        let go_stderr = self.go.mask(&go.stderr);
        assert_eq!(
            rust.status.code(),
            go.status.code(),
            "{label}: exit status differs\ngo stderr: {go_stderr:?}\nrust stderr: {:?}",
            self.rust.mask(&rust.stderr)
        );
        assert_eq!(
            self.rust.mask(&rust.stdout),
            go_stdout,
            "{label}: stdout differs"
        );
        assert_eq!(
            self.rust.mask(&rust.stderr),
            go_stderr,
            "{label}: stderr differs"
        );
        assert_eq!(
            self.rust.listing(),
            self.go.listing(),
            "{label}: vault file set differs"
        );
        (go.status.code(), go_stderr)
    }
}

const DENIED_UNKNOWN: &str = "Error: agent mode: agent \"ghost\" not found in config: agent \"ghost\" not found in config\nError: agent mode: agent \"ghost\" not found in config: agent \"ghost\" not found in config\n";

/// cobra prints the error, then `ExecuteRoot` prints it again; the `CLIError`
/// renders `<message>: <cause>` with the load error as both.
fn denied(message: &str) -> String {
    let line = format!("Error: agent mode: {message}: {message}\n");
    format!("{line}{line}")
}

/// Commands that require a vault are gated by every kind of agent value;
/// annotated ones and the cobra built-ins that do not run a command are not.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn agent_value_against_commands_that_do_and_do_not_require_a_vault() {
    let (_oracle, pair) =
        Pair::new("agent_value_against_commands_that_do_and_do_not_require_a_vault");
    pair.set_config(&Config::Text(PROFILES));

    let requiring: &[&[&str]] = &[
        &["list"],
        &["ls"],
        &["get", "x"],
        &["add", "x"],
        &["find", "x"],
        &["lock"],
        &["unlock"],
        &["init"],
        &["verify"],
        &["completion", "bash"],
        &["help", "list"],
        &["mcp"],
        &["serve"],
    ];
    let exempt: &[&[&str]] = &[
        &["version"],
        &["agent", "whoami"],
        &["agent", "list"],
        &["setup"],
        &["audit"],
        &["audit", "export"],
        &["config", "list"],
        &["policy", "list"],
        &["profile", "list"],
        &["remote", "status"],
        &["completion"],
        &["agent"],
    ];

    // Unset and empty are no agent mode at all.
    for agent in [None, Some("")] {
        for args in requiring.iter().chain(exempt) {
            // These start servers, prompt, or print the (large) completion script.
            if ["mcp", "serve", "unlock", "init", "completion"].contains(&args[0]) && args.len() > 1
                || ["mcp", "serve", "unlock", "init"].contains(&args[0])
            {
                continue;
            }
            pair.check(&format!("{agent:?} {args:?}"), args, agent, Opts::default());
        }
    }

    // An unknown agent stops every command that requires a vault with exit 5.
    for args in requiring {
        let (code, stderr) = pair.check(
            &format!("ghost {args:?}"),
            args,
            Some("ghost"),
            Opts::default(),
        );
        assert_eq!(code, Some(5), "ghost {args:?}");
        assert_eq!(stderr, DENIED_UNKNOWN, "ghost {args:?}");
    }
    // `audit rotate-key` is annotated "true" below the exempt `audit`; it is
    // only run where the gate stops it (a real run draws a random key).
    let (code, stderr) = pair.check(
        "ghost rotate-key",
        &["audit", "rotate-key"],
        Some("ghost"),
        Opts::default(),
    );
    assert_eq!((code, stderr.as_str()), (Some(5), DENIED_UNKNOWN));
    for args in exempt {
        let (code, _) = pair.check(
            &format!("ghost {args:?}"),
            args,
            Some("ghost"),
            Opts::default(),
        );
        assert_ne!(code, Some(5), "ghost {args:?} is not gated");
    }

    // A valid profile passes the gate (the command then fails on the missing
    // vault identity, as it does without an agent) and opens its audit log.
    for agent in ["alpha", "ro", "weird", "codex", "default"] {
        for args in [
            &["list"][..],
            &["get", "x"],
            &["find", "x"],
            &["add", "x"],
            &["lock"],
        ] {
            let (code, _) = pair.check(
                &format!("{agent} {args:?}"),
                args,
                Some(agent),
                Opts::default(),
            );
            assert_ne!(code, Some(5), "{agent} {args:?} must pass the gate");
        }
        assert!(
            pair.rust
                .listing()
                .contains_key(&format!("audit-{agent}.log")),
            "audit-{agent}.log is opened by the load"
        );
    }
    for args in exempt {
        pair.check(
            &format!("alpha {args:?}"),
            args,
            Some("alpha"),
            Opts::default(),
        );
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn agent_load_error_branches() {
    let (_oracle, pair) = Pair::new("agent_load_error_branches");
    let list = ["list"];
    let cases: &[(&str, Config<'_>, &str)] = &[
        ("config missing", Config::Missing, "alpha"),
        ("config is a directory", Config::Directory, "alpha"),
        ("yaml syntax error", Config::Text("agents: [\n"), "alpha"),
        ("empty config", Config::Text(""), "alpha"),
        ("empty config, builtin profile", Config::Text(""), "default"),
        (
            "wrong field type",
            Config::Text("agents:\n  bad:\n    tier: standard\n    allowedPaths: 5\n"),
            "bad",
        ),
        (
            "invalid approvalMode",
            Config::Text("agents:\n  bad:\n    approvalMode: nonsense\n"),
            "bad",
        ),
        (
            "invalid promptInjectionMode",
            Config::Text("agents:\n  bad:\n    promptInjectionMode: loud\n"),
            "bad",
        ),
        (
            "second yaml document",
            Config::Text("---\nagents: {}\n---\nagents: {}\n"),
            "bad",
        ),
        ("empty mcp.bind", Config::Text("mcp:\n  bind: ''\n"), "bad"),
        (
            "non-positive sessionTimeout",
            Config::Text("sessionTimeout: 0s\nagents:\n  bad: {}\n"),
            "bad",
        ),
        (
            "deprecated key warns and loads",
            Config::Text("envWhitelist: [HOME]\nagents:\n  bad: {}\n"),
            "bad",
        ),
        (
            "agent present with explicit empty body",
            Config::Text("agents:\n  bad: {}\n"),
            "bad",
        ),
        (
            "profile present only as a builtin of the same name",
            Config::Text("agents:\n  other: {}\n"),
            "codex",
        ),
        (
            "agent name that is not a valid audit name",
            Config::Text("agents:\n  \"a/b\": {}\n"),
            "a/b",
        ),
        (
            "agent name with traversal",
            Config::Text("agents:\n  \"..\": {}\n"),
            "..",
        ),
        (
            "agent name needing quoting",
            Config::Text("agents:\n  other: {}\n"),
            "gh\"ost\u{e9}\n",
        ),
    ];
    for (label, config, agent) in cases {
        pair.set_config(config);
        pair.check(label, &list, Some(agent), Opts::default());
    }
    #[cfg(unix)]
    {
        pair.set_config(&Config::Unreadable(PROFILES));
        // Running as root reads anything: only the Go answer decides.
        pair.check("unreadable config", &list, Some("alpha"), Opts::default());
        pair.set_config(&Config::Text(PROFILES));
    }

    // The two messages: lookup failure and load failure.
    pair.set_config(&Config::Missing);
    let (code, stderr) = pair.check("shape", &list, Some("alpha"), Opts::default());
    assert_eq!(code, Some(5));
    assert_eq!(
        stderr,
        denied(
            "load config from <VAULT>/config.yaml: open <VAULT>/config.yaml: no such file or directory"
        )
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn agent_gate_ordering_flags_and_output_modes() {
    let (_oracle, pair) = Pair::new("agent_gate_ordering_flags_and_output_modes");
    pair.set_config(&Config::Text(PROFILES));
    let ghost = Some("ghost");
    let none = Opts::default();

    // Before the gate: argument validation, unknown commands, help, the
    // output-format gate. After it: required flags.
    for args in [
        &["get"][..],
        &["agent", "token", "list"],
        &["nosuch"],
        &["list", "--help"],
        &["--help"],
        &["help"],
        &["agent"],
        &["agent", "token"],
        &["completion"],
        &["--version"],
        &["add", "--json", "x"],
        &["add", "--output", "yaml", "x"],
        &["add", "--output", "text", "x"],
        &["export"],
        &["export", "--format", "csv"],
        &["export", "--json"],
    ] {
        pair.check(&format!("ghost {args:?}"), args, ghost, none);
    }

    // JSON output modes of commands that support them.
    for args in [
        &["list", "--json"][..],
        &["list", "--output", "json"],
        &["list", "--output", "yaml"],
        &["list", "--output", "text"],
        &["list", "--json", "--output", "text"],
        &["get", "--json", "x"],
        &["find", "--output", "json", "x"],
        &["--json", "list"],
    ] {
        pair.check(&format!("ghost {args:?}"), args, ghost, none);
        pair.check(&format!("alpha {args:?}"), args, Some("alpha"), none);
    }

    // The hidden completion commands run the same pre-run.
    for args in [
        &["__complete", "list", ""][..],
        &["__completeNoDesc", "list", ""],
        &["--vault", "{ROOT}", "__complete", "list", ""],
    ] {
        pair.check(&format!("ghost {args:?}"), args, ghost, none);
    }
    pair.check(
        "alpha __complete",
        &["__complete", "list", ""],
        Some("alpha"),
        none,
    );

    // --vault / SYMVAULT_VAULT / --profile / SYMVAULT_PROFILE decide which
    // config the agent is looked up in. (A vault path that does not resolve,
    // e.g. an unknown profile, is Go's `VaultPath` error and is reported by
    // the command itself; it is not part of the agent gate.)
    pair.check(
        "vault flag",
        &["--vault", "{ROOT}", "list"],
        Some("alpha"),
        none,
    );
    pair.check(
        "vault flag =",
        &["--vault={ROOT}", "list"],
        Some("alpha"),
        none,
    );
    pair.check(
        "vault flag wins over env",
        &["list", "--vault", "{ROOT}/elsewhere"],
        Some("alpha"),
        none,
    );
    pair.check("vault flag empty", &["list", "--vault", ""], ghost, none);
    pair.check(
        "vault flag unknown dir",
        &["--vault", "{ROOT}/missing", "list"],
        Some("alpha"),
        none,
    );
    pair.check(
        "vault flag on exempt command",
        &["--vault", "{ROOT}/missing", "version"],
        Some("alpha"),
        none,
    );
    let no_env = Opts {
        no_vault_env: true,
        extra: &[],
    };
    pair.check("default vault, no config", &["list"], Some("alpha"), no_env);
    pair.check("default vault, ghost", &["list"], ghost, no_env);
    for side in [&pair.go, &pair.rust] {
        let result = side.run(&["profile", "add", "p1", "--vault", "{ROOT}"], None, no_env);
        assert!(result.status.success(), "profile add: {result:?}");
    }
    pair.check(
        "profile flag",
        &["--profile", "p1", "list"],
        Some("alpha"),
        no_env,
    );
    pair.check(
        "profile flag, ghost",
        &["--profile", "p1", "list"],
        ghost,
        no_env,
    );
    pair.check(
        "profile flag, empty name",
        &["--profile", "", "list"],
        Some("alpha"),
        no_env,
    );
    let env_profile = Opts {
        no_vault_env: true,
        extra: &[("SYMVAULT_PROFILE", "p1")],
    };
    pair.check("profile env", &["list"], Some("alpha"), env_profile);
    pair.check("profile env, ghost", &["list"], ghost, env_profile);
    pair.check(
        "vault env wins over profile env",
        &["list"],
        Some("alpha"),
        Opts {
            no_vault_env: false,
            extra: &[("SYMVAULT_PROFILE", "p2")],
        },
    );
}

/// cobra consumes `--help` / `-h` as a flag's value when the flag takes one, and
/// checks the help flag right after parsing, before the pre-run: a value is no
/// help request (the gate runs), a real help flag is (it does not), the last
/// occurrence of a bool flag decides, and `--` ends the flags.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn agent_gate_resolves_help_tokens_like_pflag() {
    let (_oracle, pair) = Pair::new("agent_gate_resolves_help_tokens_like_pflag");
    pair.set_config(&Config::Text(PROFILES));
    let ghost = Some("ghost");
    let none = Opts::default();

    // `--help` / `-h` is the value of a flag: the command is gated (and never
    // runs, so no token store appears in the vault).
    for args in [
        &["agent", "token", "new", "x", "--tools", "--help"][..],
        &["agent", "token", "new", "--tools", "-h", "x"],
        &["agent", "token", "new", "x", "--tools=--help"],
        &["agent", "token", "new", "x", "--tools", "--help=true"],
        &["run", "--broker-passthrough", "--help", "true"],
        &["broker", "--passthrough", "--help"],
        &["list", "--vault", "-h"],
        &["list", "--vault", "--help", "--", "x"],
        &["--vault", "--help", "list"],
        &["list", "--output", "-h"],
        &["--output", "--help", "list"],
        &["export", "--format", "--help"],
        &["help", "--vault", "--help"],
        &["help", "--vault", "--help", "list"],
        &["list", "--", "--help"],
        &["list", "--help=false"],
        &["list", "-h=false"],
        &["list", "--help", "--help=false"],
    ] {
        let (code, _) = pair.check(&format!("ghost {args:?}"), args, ghost, none);
        assert_eq!(code, Some(5), "ghost {args:?} is gated");
    }
    let (code, _) = pair.check(
        "profile flag value --help",
        &["--profile", "--help", "list"],
        ghost,
        none,
    );
    assert_eq!(code, Some(5));
    assert!(
        !pair.rust.listing().contains_key("mcp-tokens.json"),
        "a gated `agent token new` must not create the token store"
    );

    // A real help flag precedes the pre-run: no gate, no audit log. A parse
    // error ends the run first, wherever the help flag stands.
    for args in [
        &["list", "--help"][..],
        &["list", "-h"],
        &["list", "--help=true"],
        &["add", "x", "--help"],
        &["get", "--help"],
        &["agent", "token", "new", "x", "--tools", "a", "--help"],
        &["agent", "token", "new", "x", "--help", "--tools", "a"],
        &["help", "--help"],
        &["help", "list", "-h"],
        &["--help"],
        &["-h"],
        &["export", "-h"],
    ] {
        for agent in ["ghost", "alpha"] {
            let (code, _) = pair.check(&format!("{agent} {args:?}"), args, Some(agent), none);
            assert_eq!(code, Some(0), "{agent} {args:?} prints help");
        }
    }
    assert!(
        !pair.rust.listing().contains_key("audit-alpha.log"),
        "help never loads the agent"
    );
    for args in [
        &["list", "--help=foo"][..],
        &["list", "-h=foo"],
        &["list", "--help", "--bogus"],
        &["list", "--bogus", "--help"],
        &["agent", "token", "new", "x", "-t", "-h"],
    ] {
        let (code, _) = pair.check(&format!("ghost {args:?}"), args, ghost, none);
        assert_eq!(code, Some(1), "ghost {args:?} is a usage error");
    }
}

/// An argument that is not UTF-8 must not skip the gate.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn agent_gate_covers_non_utf8_arguments() {
    let (_oracle, pair) = Pair::new("agent_gate_covers_non_utf8_arguments");
    pair.set_config(&Config::Text(PROFILES));
    let ghost = Some("ghost");
    let none = Opts::default();

    for args in [
        &["backup", "/tmp/{FF}.tar"][..],
        &["get", "{FF}"],
        &["list", "{FF}"],
        &["list", "--output", "{FF}"],
        &["add", "x", "--vault", "{FF}"],
        &["list", "--vault", "/tmp/{FF}nov"],
    ] {
        let (code, _) = pair.check(&format!("ghost {args:?}"), args, ghost, none);
        assert_eq!(code, Some(5), "ghost {args:?} is gated");
    }
    // Go's earlier stages still come first.
    for (args, want) in [
        (&["backup", "{FF}", "--json"][..], 9),
        (&["add", "{FF}", "extra", "more"][..], 1),
        (&["nosuch", "{FF}"][..], 1),
    ] {
        let (code, _) = pair.check(&format!("ghost {args:?}"), args, ghost, none);
        assert_eq!(code, Some(want), "ghost {args:?}");
    }
    // Commands that need no vault are not gated.
    for args in [&["version", "{FF}"][..], &["agent", "whoami", "{FF}"]] {
        let (code, _) = pair.check(&format!("ghost {args:?}"), args, ghost, none);
        assert_ne!(code, Some(5), "ghost {args:?} is not gated");
    }
    // A known agent passes the gate (and opens its log); with none set the
    // command runs as before.
    for agent in [Some("alpha"), None, Some("")] {
        pair.check(
            &format!("{agent:?} backup"),
            &["backup", "/tmp/{FF}.tar"],
            agent,
            none,
        );
    }
    assert!(pair.rust.listing().contains_key("audit-alpha.log"));
}

/// cobra's generated `completion <shell>` commands support no output format;
/// the format gate runs before the agent check.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn agent_gate_completion_shells_refuse_output_formats_first() {
    let (_oracle, pair) = Pair::new("agent_gate_completion_shells_refuse_output_formats_first");
    pair.set_config(&Config::Text(PROFILES));
    let none = Opts::default();
    for shell in ["bash", "zsh", "fish", "powershell"] {
        for format in [
            &["--json"][..],
            &["--output", "json"],
            &["--output", "yaml"],
        ] {
            let mut args = vec!["completion", shell];
            args.extend_from_slice(format);
            for agent in [Some("ghost"), Some("alpha"), None] {
                let (code, stderr) = pair.check(&format!("{agent:?} {args:?}"), &args, agent, none);
                assert_eq!(code, Some(9), "{agent:?} {args:?}");
                assert!(stderr.contains(&format!("'symvault completion {shell}'")));
            }
        }
        // `--output text` is the default: the agent gate decides.
        let (code, _) = pair.check(
            &format!("ghost {shell} text"),
            &["completion", shell, "--output", "text"],
            Some("ghost"),
            none,
        );
        assert_eq!(code, Some(5));
    }
    // Without a shell the group only prints help, gate and agent alike.
    for args in [
        &["completion", "--json"][..],
        &["completion", "nosuch"],
        &["completion", "bash", "extra"],
    ] {
        pair.check(&format!("ghost {args:?}"), args, Some("ghost"), none);
    }
}
