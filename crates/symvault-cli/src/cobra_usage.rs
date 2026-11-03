//! Go/cobra command-line diagnostics for the native CLI (CLI-005, CLI-006).
//!
//! The Go CLI is a cobra program: it resolves the command by stripping flags,
//! parses flags with pflag, validates the positional arguments, and only then
//! runs the root `PersistentPreRunE`, which holds the output-format gate. Every
//! error returned along the way is printed twice by cobra and by the root
//! executor and exits 1 (9 for the gate). clap words and orders these
//! differently, so this module repeats cobra's resolution *before* clap parses
//! and produces Go's bytes for the failures it knows; everything else falls
//! through to clap unchanged.
//!
//! The behavior is frozen by `testdata/port/cli/error-taxonomy.json`
//! (`scripts/rust-port/cmd/errtaxgen`); `tests/error_taxonomy.rs` replays it.
//! `ARITY`, `GROUPS` and the output-gate tables are checked against that fixture
//! row by row, and `COMMANDS`/`GROUPS` against `command-tree.json` in both
//! directions, so they cannot drift from the oracle unnoticed.
//!
//! Flag *types* come from the clap tree, never from a side table: pflag consumes
//! the next token for every non-bool flag, so a flag the emulation mistypes turns
//! a value into a positional (or the reverse) and rejects a valid invocation. The
//! unit test `flag_types_match_the_command_tree` compares every flag both trees
//! share against the Go type recorded in `command-tree.json`.
//!
//! Every typed flag of the command tree gets pflag's `invalid argument` wording while
//! the flags are parsed (so before the argument validator, the output gate, the
//! required-flag check and any vault precondition): booleans, the `int`/`int64` flags
//! in `INT_FLAGS`, the `time.Duration` flags in `DURATION_FLAGS` and the
//! `stringSlice` flags in `STRING_SLICE_FLAGS` (a CSV parse error). The unit test
//! `typed_flag_tables_cover_every_typed_flag_of_the_command_tree` fails when the tree
//! has a typed flag no table names.
//!
//! Known limits: a
//! flag that exists only in Go is not reported as unknown by Rust's tree; and the
//! suggestion order of `SUGGESTION_ORDER` is the strict partial order measured
//! from the oracle, not Go's registration order.

use clap::{Arg, Command};

/// Result of the cobra emulation.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing Go would reject: hand the arguments to clap.
    Proceed,
    /// Go fails: print `stderr`, exit with `code`.
    Fail { stderr: String, code: u8 },
    /// Go prints the help of a non-runnable group and exits 0.
    GroupHelp(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    /// cobra::NoArgs reports the first positional as an unknown command.
    NoArgs,
    Exact(usize),
    Min(usize),
    Max(usize),
    Range(usize, usize),
    /// `device join`, validated in Go's `resolveJoinPairing` (`cmd/device.go`): with a
    /// non-empty `--pairing-file` exactly one positional (the token), otherwise exactly
    /// two (`<remote-url> <token>`). Each mode has its own message.
    JoinPair,
    /// `find`: one query, unless `--url` is set; reported as "at most" once more are given.
    QueryOrUrl,
}

const JOIN_SUFFIX: &str = " — either '<remote-url> <token>' or '--pairing-file <path> <token>'";
const JOIN_PAIRING_FILE_MESSAGE: &str =
    "with --pairing-file, pass only the pairing token: 'device join --pairing-file <path> <token>'";

/// Flags Go declares as `int` or `int64`, by command path and long name. pflag parses
/// the value with `strconv.ParseInt(s, 0, 64)` while the flags are parsed, so a
/// malformed one is a usage error even in an uninitialized vault.
const INT_FLAGS: &[(&str, &str)] = &[
    ("add", "length"),
    ("agent audit", "limit"),
    ("audit", "tail"),
    ("file add", "max-size"),
    ("generate", "length"),
    ("intake", "batch-limit"),
    ("intake", "max-files"),
    ("mcp", "port"),
    ("serve", "port"),
    ("startup-profile", "count"),
    ("startup-profile", "top"),
];

/// Flags Go declares as `time.Duration` whose value pflag parses with
/// `time.ParseDuration` before the command runs (so a malformed value is a usage
/// error even in an uninitialized vault).
const DURATION_FLAGS: &[(&str, &str)] = &[
    ("dynamic generate", "ttl"),
    ("file use", "timeout"),
    ("intake watch", "debounce"),
    ("intake watch", "interval"),
    ("run", "timeout"),
    ("unlock", "ttl"),
];

/// Flags Go declares as `stringSlice`: pflag reads every value as one CSV record
/// (`encoding/csv`), so a stray quote is a usage error before the command runs.
/// (`stringArray` flags take the value verbatim and cannot fail.)
const STRING_SLICE_FLAGS: &[(&str, &str)] = &[
    ("agent token new", "tools"),
    ("agent token rotate", "tools"),
    ("broker", "passthrough"),
    ("doctor", "exclude"),
    ("doctor", "only"),
    ("run", "broker-passthrough"),
];

/// Flags cobra's `MarkFlagRequired` makes mandatory, by command path. Cobra
/// reports the unset ones after the argument validator and the root
/// `PersistentPreRunE` (the output-format gate) and before the command body, as
/// `required flag(s) "a", "b" not set`, in flag registration order.
const REQUIRED_FLAGS: &[(&str, &[&str])] = &[
    ("dynamic generate", &["engine", "role"]),
    ("export", &["format"]),
    ("profile add", &["vault"]),
    ("template generate", &["type"]),
];

/// Local bool flags of commands the native CLI parses by hand (no clap
/// definition, so the tree cannot type them). pflag parses them before cobra
/// validates arguments, and a local flag shadows a persistent one of the same
/// name (`update info --json`). Checked against `command-tree.json` by
/// `hand_parsed_bool_flags_match_the_command_tree`.
const HAND_PARSED_BOOLS: &[(&str, &[&str])] = &[
    ("update apply", &["dry-run", "force", "json"]),
    ("update check", &["force", "json", "quiet"]),
    ("update info", &["json"]),
];

/// Go commands with `SilenceErrors`: cobra omits its copy, but the root
/// executor still prints the returned error once.
const SILENCED: &[&str] = &["update apply", "update check", "update info"];

fn hand_parsed_bool(path: &str, name: &str) -> bool {
    HAND_PARSED_BOOLS
        .iter()
        .any(|(command, flags)| *command == path && flags.contains(&name))
}

const SUGGESTION_ORDER: &[&str] = &[
    "audit",
    "auth",
    "backup",
    "broker",
    "config",
    "doctor",
    "export",
    "import",
    "init",
    "add",
    "delete",
    "device",
    "dynamic",
    "edit",
    "find",
    "intake",
    "lock",
    "migrate",
    "restore",
    "setup",
    "startup-profile",
    "get",
    "list",
    "set",
    "agent",
    "file",
    "generate",
    "recipients",
    "remote",
    "share",
    "update",
    "mcp",
    "approval",
    "git",
    "policy",
    "profile",
    "template",
    "unlock",
    "run",
    "sync",
    "version",
    "verify",
    "ui",
    "completion",
];

const ARITY: &[(&str, Rule)] = &[
    ("add", Rule::Exact(1)),
    ("agent audit", Rule::Exact(1)),
    ("agent doctor", Rule::Exact(1)),
    ("agent profile edit", Rule::Exact(1)),
    ("agent profile export", Rule::Exact(1)),
    ("agent profile show", Rule::Exact(1)),
    ("agent skill export", Rule::Exact(1)),
    ("agent skill refresh", Rule::Exact(1)),
    ("agent token list", Rule::Exact(1)),
    ("agent token new", Rule::Exact(1)),
    ("agent token revoke", Rule::Exact(2)),
    ("agent token rotate", Rule::Exact(1)),
    ("agent uninstall", Rule::Exact(1)),
    ("agent upgrade", Rule::Exact(1)),
    ("approval decide", Rule::Exact(1)),
    ("backup", Rule::Exact(1)),
    ("config get", Rule::Exact(1)),
    ("config list", Rule::NoArgs),
    ("config set", Rule::Exact(2)),
    ("config validate", Rule::Max(1)),
    ("delete", Rule::Exact(1)),
    ("device accept", Rule::Exact(1)),
    ("device approval-revoke", Rule::Exact(1)),
    ("device join", Rule::JoinPair),
    ("device revoke", Rule::Exact(1)),
    ("edit", Rule::Exact(1)),
    ("export", Rule::NoArgs),
    ("file add", Rule::Exact(1)),
    ("file get", Rule::Exact(1)),
    ("file use", Rule::Min(2)),
    ("find", Rule::QueryOrUrl),
    ("generate manpages", Rule::Exact(1)),
    ("get", Rule::Exact(1)),
    ("git", Rule::Range(1, 2)),
    ("import", Rule::Exact(1)),
    ("import review list", Rule::NoArgs),
    ("import review promote", Rule::Exact(1)),
    ("init", Rule::Max(1)),
    ("intake", Rule::Min(1)),
    ("intake watch", Rule::Exact(1)),
    ("intake watch disable", Rule::NoArgs),
    ("list", Rule::Max(1)),
    ("migrate paths", Rule::NoArgs),
    ("policy apply", Rule::Exact(1)),
    ("policy remove", Rule::Exact(1)),
    ("policy validate", Rule::Exact(1)),
    ("profile add", Rule::Exact(1)),
    ("profile list", Rule::NoArgs),
    ("profile use", Rule::Exact(1)),
    ("recipients add", Rule::Exact(1)),
    ("recipients remove", Rule::Exact(1)),
    ("remote init", Rule::Exact(1)),
    ("restore", Rule::Exact(1)),
    ("run", Rule::Min(1)),
    ("set", Rule::Exact(1)),
    ("share revoke", Rule::Exact(1)),
    ("sync", Rule::NoArgs),
    ("ui", Rule::NoArgs),
    ("update", Rule::NoArgs),
    ("update apply", Rule::NoArgs),
    ("update check", Rule::NoArgs),
    ("update info", Rule::NoArgs),
];
const GROUPS: &[&str] = &[
    "agent",
    "agent profile",
    "agent skill",
    "agent token",
    "approval",
    "auth",
    "config",
    "device",
    "dynamic",
    "file",
    "import review",
    "migrate",
    "policy",
    "profile",
    "recipients",
    "remote",
    "share",
    "template",
];
/// Every command path of the pinned Go tree (hidden ones included). The native clap
/// tree lacks a few of them, so resolution falls back to this list.
const COMMANDS: &[&str] = &[
    "add",
    "agent",
    "agent audit",
    "agent doctor",
    "agent install",
    "agent list",
    "agent profile",
    "agent profile edit",
    "agent profile export",
    "agent profile show",
    "agent setup",
    "agent skill",
    "agent skill export",
    "agent skill refresh",
    "agent token",
    "agent token list",
    "agent token new",
    "agent token revoke",
    "agent token rotate",
    "agent uninstall",
    "agent upgrade",
    "agent whoami",
    "approval",
    "approval decide",
    "approval list",
    "audit",
    "audit export",
    "audit rotate-key",
    "auth",
    "auth rotate-passphrase",
    "auth set",
    "auth status",
    "backup",
    "broker",
    "config",
    "config get",
    "config list",
    "config set",
    "config validate",
    "delete",
    "device",
    "device accept",
    "device add",
    "device approval-list",
    "device approval-pair",
    "device approval-revoke",
    "device join",
    "device list",
    "device pair",
    "device revoke",
    "doctor",
    "dynamic",
    "dynamic generate",
    "edit",
    "export",
    "file",
    "file add",
    "file get",
    "file use",
    "find",
    "generate",
    "generate manpages",
    "get",
    "git",
    "help",
    "import",
    "import review",
    "import review list",
    "import review promote",
    "init",
    "intake",
    "intake watch",
    "intake watch disable",
    "list",
    "lock",
    "mcp",
    "mcp install",
    "mcp status",
    "mcp token",
    "mcp token create",
    "mcp token list",
    "mcp token revoke",
    "mcp uninstall",
    "mcp-config",
    "mcp-token-rotate",
    "migrate",
    "migrate kdf",
    "migrate paths",
    "migrate pseudonymize",
    "migrate session",
    "migrate v4",
    "policy",
    "policy apply",
    "policy list",
    "policy remove",
    "policy validate",
    "profile",
    "profile add",
    "profile list",
    "profile use",
    "recipients",
    "recipients add",
    "recipients list",
    "recipients remove",
    "remote",
    "remote init",
    "remote status",
    "restore",
    "run",
    "serve",
    "serve install",
    "serve status",
    "serve token",
    "serve token create",
    "serve token list",
    "serve token revoke",
    "serve uninstall",
    "set",
    "setup",
    "share",
    "share list",
    "share revoke",
    "startup-profile",
    "sync",
    "template",
    "template generate",
    "ui",
    "unlock",
    "update",
    "update apply",
    "update check",
    "update info",
    "verify",
    "version",
];

/// Paths where `--json` reaches the gate and is refused (a local `--json` flag shadows the persistent one elsewhere).
const JSON_REFUSED: &[&str] = &[
    "add",
    "agent audit",
    "agent doctor",
    "agent profile edit",
    "agent profile export",
    "agent profile show",
    "agent setup",
    "agent skill export",
    "agent skill refresh",
    "agent token list",
    "agent token new",
    "agent token revoke",
    "agent token rotate",
    "agent uninstall",
    "agent upgrade",
    "agent whoami",
    "audit export",
    "audit rotate-key",
    "auth rotate-passphrase",
    "auth set",
    "backup",
    "broker",
    "dynamic generate",
    "edit",
    "export",
    "file add",
    "file get",
    "file use",
    "git",
    "help",
    "import",
    "import review list",
    "import review promote",
    "init",
    "intake watch disable",
    "lock",
    "mcp",
    "mcp install",
    "mcp status",
    "mcp token",
    "mcp token create",
    "mcp token list",
    "mcp token revoke",
    "mcp uninstall",
    "mcp-config",
    "mcp-token-rotate",
    "migrate kdf",
    "migrate paths",
    "migrate pseudonymize",
    "migrate session",
    "migrate v4",
    "policy apply",
    "policy list",
    "policy remove",
    "policy validate",
    "profile add",
    "profile list",
    "profile use",
    "restore",
    "run",
    "serve",
    "serve install",
    "serve status",
    "serve token",
    "serve token create",
    "serve token list",
    "serve token revoke",
    "serve uninstall",
    "set",
    "setup",
    "startup-profile",
    "sync",
    "ui",
    "unlock",
    "update",
    "verify",
];

/// Paths where `--output <non-text>` reaches the gate and is refused (a local `--output` flag shadows it elsewhere).
const OUTPUT_REFUSED: &[&str] = &[
    "add",
    "agent audit",
    "agent doctor",
    "agent profile edit",
    "agent setup",
    "agent skill refresh",
    "agent token list",
    "agent token new",
    "agent token revoke",
    "agent token rotate",
    "agent uninstall",
    "agent upgrade",
    "audit",
    "audit rotate-key",
    "auth rotate-passphrase",
    "auth set",
    "auth status",
    "backup",
    "broker",
    "doctor",
    "dynamic generate",
    "edit",
    "file add",
    "file get",
    "file use",
    "git",
    "help",
    "import",
    "import review list",
    "import review promote",
    "init",
    "intake",
    "intake watch",
    "intake watch disable",
    "lock",
    "mcp",
    "mcp install",
    "mcp status",
    "mcp token",
    "mcp token create",
    "mcp token list",
    "mcp token revoke",
    "mcp uninstall",
    "mcp-config",
    "mcp-token-rotate",
    "migrate kdf",
    "migrate paths",
    "migrate pseudonymize",
    "migrate session",
    "migrate v4",
    "policy apply",
    "policy list",
    "policy remove",
    "policy validate",
    "profile add",
    "profile list",
    "profile use",
    "restore",
    "run",
    "serve",
    "serve install",
    "serve status",
    "serve token",
    "serve token create",
    "serve token list",
    "serve token revoke",
    "serve uninstall",
    "set",
    "setup",
    "startup-profile",
    "sync",
    "ui",
    "unlock",
    "update",
    "verify",
];

fn rule_for(path: &str) -> Option<Rule> {
    ARITY
        .iter()
        .find(|(candidate, _)| *candidate == path)
        .map(|(_, rule)| *rule)
}

/// The flag values an argument validator reads (`find --url`, `device join --pairing-file`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ValidatorFlags {
    /// `find --url <non-empty>`.
    url_filter: bool,
    /// `device join --pairing-file <non-empty>`.
    pairing_file: bool,
}

/// The message cobra's argument validator reports, if it rejects `count`.
fn arity_message(path: &str, count: usize, flags: ValidatorFlags) -> Option<String> {
    let at_least = |min: usize| format!("requires at least {min} arg(s), only received {count}");
    let exact = |n: usize| format!("accepts {n} arg(s), received {count}");
    let at_most = |n: usize| format!("accepts at most {n} arg(s), received {count}");
    match rule_for(path)? {
        // NoArgs needs the actual first positional; evaluate handles it below.
        Rule::NoArgs => None,
        Rule::Exact(n) => (count != n).then(|| exact(n)),
        Rule::Min(n) => (count < n).then(|| at_least(n)),
        Rule::Max(n) => (count > n).then(|| at_most(n)),
        Rule::Range(min, max) => (count < min || count > max)
            .then(|| format!("accepts between {min} and {max} arg(s), received {count}")),
        Rule::JoinPair if flags.pairing_file => {
            (count != 1).then(|| JOIN_PAIRING_FILE_MESSAGE.to_owned())
        }
        Rule::JoinPair => (count != 2)
            .then(|| format!("accepts between 1 and 2 arg(s), received {count}{JOIN_SUFFIX}")),
        Rule::QueryOrUrl => {
            if count > 1 {
                Some(at_most(1))
            } else if count == 0 && !flags.url_filter {
                Some(exact(1))
            } else {
                None
            }
        }
    }
}

/// The format the gate refuses for this command, if any: `--json` wins over
/// `--output`, exactly like the persistent flags it models.
fn refused_format(path: &str, json_flag: bool, output: Option<&str>) -> Option<String> {
    if json_flag && JSON_REFUSED.contains(&path) {
        return Some("json".to_owned());
    }
    output
        .filter(|value| *value != "text")
        .filter(|_| OUTPUT_REFUSED.contains(&path))
        .map(str::to_owned)
}

/// Cobra's `validateRequiredFlags` message, if a required flag is unset.
fn missing_required_flags(path: &str, set: &[String]) -> Option<String> {
    let (_, required) = REQUIRED_FLAGS
        .iter()
        .find(|(command, _)| *command == path)?;
    let missing: Vec<String> = required
        .iter()
        .filter(|name| !set.iter().any(|seen| seen == **name))
        .map(|name| format!("\"{name}\""))
        .collect();
    (!missing.is_empty()).then(|| format!("required flag(s) {} not set", missing.join(", ")))
}

fn doubled(message: &str) -> String {
    format!("Error: {message}\nError: {message}\n")
}

fn fail(message: &str, code: u8) -> Verdict {
    Verdict::Fail {
        stderr: doubled(message),
        code,
    }
}

/// [`fail`], but printed once for a [`SILENCED`] command.
fn fail_at(path: &str, message: &str, code: u8) -> Verdict {
    if SILENCED.contains(&path) {
        return Verdict::Fail {
            stderr: format!("Error: {message}\n"),
            code,
        };
    }
    fail(message, code)
}

const SUPPORTED_COMMANDS: &str = "admin config get, delete, device list, find, generate, get, list, mcp agent install, mcp agent list, recipients, remote, share, template generate";

/// The gate message for `path` ("symvault <path>").
pub fn gate_message(format: &str, path: &str) -> String {
    let command = if path.is_empty() {
        "symvault".to_owned()
    } else {
        format!("symvault {path}")
    };
    format!(
        "output format {format:?} is not supported by '{command}' (supported commands: {SUPPORTED_COMMANDS})"
    )
}

/// The flags cobra knows on a command: its own plus the root's persistent ones.
/// clap does not propagate a global flag below a command that defines a local
/// flag of the same name (`generate --quiet`), so the root is consulted too.
#[derive(Clone, Copy)]
struct Flags<'a> {
    command: &'a Command,
    root: &'a Command,
}

impl<'a> Flags<'a> {
    fn long(&self, name: &str) -> Option<&'a Arg> {
        let matches = |arg: &&Arg| arg.get_long() == Some(name);
        self.command.get_arguments().find(matches).or_else(|| {
            self.root
                .get_arguments()
                .filter(|arg| arg.is_global_set())
                .find(matches)
        })
    }

    fn short(&self, short: char) -> Option<&'a Arg> {
        let matches = |arg: &&Arg| arg.get_short() == Some(short);
        self.command.get_arguments().find(matches).or_else(|| {
            self.root
                .get_arguments()
                .filter(|arg| arg.is_global_set())
                .find(matches)
        })
    }
}

/// pflag consumes the next token for every flag that is not a bool and has no
/// no-option default (clap: not `require_equals`).
fn eats_next(arg: &Arg) -> bool {
    arg.get_action().takes_values() && !arg.is_require_equals_set()
}

/// A Go bool flag: clap `SetTrue`/`SetFalse`, or the `--flag[=bool]` spelling
/// (`ArgAction::Set` with `require_equals` and an optional value) that
/// accepts Go's `ParseBool` forms with the last occurrence winning.
fn is_bool_arg(arg: &Arg) -> bool {
    !arg.get_action().takes_values()
        || (arg.is_require_equals_set()
            && arg
                .get_num_args()
                .is_some_and(|range| range.min_values() == 0))
}

fn is_help_arg(arg: &Arg) -> bool {
    arg.get_id().as_str() == "help"
}

/// cobra's `stripFlags`: the positional tokens before `--`.
fn strip_flags(tokens: &[String], flags: Flags<'_>, lenient: bool) -> Vec<String> {
    let mut positional = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if token == "--" {
            break;
        }
        if let Some(name) = token.strip_prefix("--") {
            if !token.contains('=') {
                let known = flags.long(name);
                let skip = match known {
                    Some(arg) => eats_next(arg),
                    None => !lenient,
                };
                if skip {
                    index += 1;
                }
            }
        } else if token.starts_with('-') && token.len() > 1 {
            if !token.contains('=') && token.len() == 2 {
                let known = token.chars().nth(1).and_then(|c| flags.short(c));
                let skip = match known {
                    Some(arg) => eats_next(arg),
                    None => !lenient,
                };
                if skip {
                    index += 1;
                }
            }
        } else if !token.starts_with('-') {
            positional.push(token.clone());
        }
        index += 1;
    }
    positional
}

/// cobra's `argsMinusFirstX`: the index of the first occurrence of the command word
/// that is not the value of a flag and comes before `--`.
fn first_word_index(
    tokens: &[String],
    word: &str,
    flags: Flags<'_>,
    lenient: bool,
) -> Option<usize> {
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if token == "--" {
            return None;
        }
        let mut skip_value = false;
        if let Some(name) = token.strip_prefix("--") {
            if !token.contains('=') {
                skip_value = match flags.long(name) {
                    Some(arg) => eats_next(arg),
                    None => !lenient,
                };
            }
        } else if token.starts_with('-') && token.len() == 2 && !token.contains('=') {
            skip_value = match token.chars().nth(1).and_then(|c| flags.short(c)) {
                Some(arg) => eats_next(arg),
                None => !lenient,
            };
        }
        if skip_value {
            index += 2;
            continue;
        }
        if token == word {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// A resolved command: the clap definition when the native tree has it, and its
/// Go path either way.
#[derive(Clone)]
struct Node<'a> {
    command: Option<&'a Command>,
    path: Vec<String>,
}

fn child_path(path: &[String], word: &str) -> String {
    if path.is_empty() {
        word.to_owned()
    } else {
        format!("{} {word}", path.join(" "))
    }
}

fn find_next<'a>(node: &Node<'a>, word: &str) -> Option<Node<'a>> {
    if let Some(sub) = node.command.and_then(|command| {
        command
            .get_subcommands()
            .find(|sub| sub.get_name() == word || sub.get_all_aliases().any(|alias| alias == word))
    }) {
        let mut path = node.path.clone();
        path.push(sub.get_name().to_owned());
        return Some(Node {
            command: Some(sub),
            path,
        });
    }
    let candidate = child_path(&node.path, word);
    COMMANDS.contains(&candidate.as_str()).then(|| {
        let mut path = node.path.clone();
        path.push(word.to_owned());
        Node {
            command: None,
            path,
        }
    })
}

fn go_parse_bool(value: &str) -> bool {
    matches!(
        value,
        "1" | "t" | "T" | "TRUE" | "true" | "True" | "0" | "f" | "F" | "FALSE" | "false" | "False"
    )
}

/// Why Go's `strconv.ParseInt(s, 0, 64)` refuses a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IntError {
    Syntax,
    Range,
}

impl IntError {
    fn text(self) -> &'static str {
        match self {
            Self::Syntax => "invalid syntax",
            Self::Range => "value out of range",
        }
    }
}

/// Go's `strconv.underscoreOK`: underscores may only separate digits (or follow a
/// base prefix). `digits` is the number after its sign.
fn underscore_ok(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    let mut index = 0;
    // `^` before anything, `0` after a digit, `_` after an underscore, `!` otherwise.
    let mut saw = b'^';
    let mut hex = false;
    if bytes.len() >= 2
        && bytes[0] == b'0'
        && matches!(bytes[1].to_ascii_lowercase(), b'b' | b'o' | b'x')
    {
        index = 2;
        saw = b'0';
        hex = bytes[1].eq_ignore_ascii_case(&b'x');
    }
    for &byte in &bytes[index..] {
        if byte.is_ascii_digit() || (hex && matches!(byte.to_ascii_lowercase(), b'a'..=b'f')) {
            saw = b'0';
        } else if byte == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else if saw == b'_' {
            return false;
        } else {
            saw = b'!';
        }
    }
    saw != b'_'
}

/// Go's `strconv.ParseInt(s, 0, 64)`, which is what pflag's int flags call: an optional
/// sign, then a decimal number or a `0x`/`0o`/`0b`/leading-`0` prefixed one, with `_`
/// digit separators. Overflow is reported as soon as it is seen, before a later invalid
/// digit.
fn go_parse_int(value: &str) -> Result<i64, IntError> {
    let (negative, unsigned) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    if unsigned.is_empty() {
        return Err(IntError::Syntax);
    }
    let bytes = unsigned.as_bytes();
    let (base, digits) = if bytes[0] == b'0' {
        match bytes.get(1).map(u8::to_ascii_lowercase) {
            Some(b'b') if bytes.len() >= 3 => (2, &bytes[2..]),
            Some(b'o') if bytes.len() >= 3 => (8, &bytes[2..]),
            Some(b'x') if bytes.len() >= 3 => (16, &bytes[2..]),
            _ => (8, &bytes[1..]),
        }
    } else {
        (10, bytes)
    };
    let mut magnitude: u64 = 0;
    let mut underscores = false;
    for &byte in digits {
        let digit = match byte {
            b'_' => {
                underscores = true;
                continue;
            }
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'z' => byte - b'a' + 10,
            b'A'..=b'Z' => byte - b'A' + 10,
            _ => return Err(IntError::Syntax),
        };
        if u64::from(digit) >= base {
            return Err(IntError::Syntax);
        }
        magnitude = magnitude
            .checked_mul(base)
            .and_then(|scaled| scaled.checked_add(u64::from(digit)))
            .ok_or(IntError::Range)?;
    }
    if underscores && !underscore_ok(unsigned) {
        return Err(IntError::Syntax);
    }
    let limit = if negative {
        1_u64 << 63
    } else {
        (1_u64 << 63) - 1
    };
    if magnitude > limit {
        return Err(IntError::Range);
    }
    Ok(if negative {
        0_i64.wrapping_sub_unsigned(magnitude)
    } else {
        i64::try_from(magnitude).map_err(|_| IntError::Range)?
    })
}

/// clap value parser for flags Go declares as `int` (pflag: `ParseInt(s, 0, 64)`).
pub fn parse_go_int(value: &str) -> Result<i64, String> {
    go_parse_int(value)
        .map_err(|error| format!("strconv.ParseInt: parsing {value:?}: {}", error.text()))
}

/// pflag's `invalid argument` diagnostic for a value of a typed flag (`Set` failed).
fn typed_value_error(path: &str, name: &str, arg: &Arg, value: &str) -> Option<String> {
    let key = (path, name);
    if INT_FLAGS.contains(&key)
        && let Err(error) = go_parse_int(value)
    {
        return Some(invalid_argument(value, arg, "ParseInt", error.text()));
    }
    if DURATION_FLAGS.contains(&key)
        && let Err(reason) = symvault_core::config::parse_go_duration(value)
    {
        return Some(invalid_argument_reason(value, arg, &reason));
    }
    if STRING_SLICE_FLAGS.contains(&key)
        && let Some(reason) = go_csv_error(value)
    {
        return Some(invalid_argument_reason(value, arg, &reason));
    }
    None
}

/// The error pflag's `stringSlice` reports for `value`: `readAsCSV` hands the whole value
/// (unless empty) to a default `encoding/csv` reader and returns its first record, so
/// the message is the reader's own (`ParseError`, or `EOF` for a value of blank
/// lines). `None` means the value is a valid record.
fn go_csv_error(value: &str) -> Option<String> {
    go_csv_record(value).err()
}

/// pflag's `readAsCSV` (`stringSlice.Set`): an empty value is an empty slice, anything
/// else is the first record `csv.NewReader(strings.NewReader(val)).Read()` returns, so
/// `"a,b"` is two elements, `"a,"` has an empty second one, `\"a,b\"` is one, `""` inside
/// quotes is a quote, a record ends at the first line break outside quotes (later lines
/// are ignored) and leading blank lines are skipped. The error is the reader's message.
/// This follows `Reader.readRecord` for the comma separator, strict quotes, no comment
/// character and no space trimming.
pub fn go_csv_record(value: &str) -> Result<Vec<String>, String> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut reader = CsvLines {
        data: value.as_bytes(),
        at: 0,
        num_line: 0,
    };
    // Skip empty lines; running out of input before a record is `io.EOF`.
    let (mut line, mut eof) = reader.read_line();
    while !eof && line.len() == csv_newline_len(&line) {
        (line, eof) = reader.read_line();
    }
    if eof {
        return Err("EOF".to_owned());
    }
    let rec_line = reader.num_line;
    let mut pos_line = reader.num_line;
    let mut pos_col = 1_usize;
    let mut from = 0_usize;
    let parse_error = |line: usize, column: usize, reason: &str| {
        if rec_line == line {
            format!("parse error on line {line}, column {column}: {reason}")
        } else {
            format!(
                "record on line {rec_line}; parse error on line {line}, column {column}: {reason}"
            )
        }
    };
    const BARE_QUOTE: &str = "bare \" in non-quoted-field";
    const QUOTE: &str = "extraneous or missing \" in quoted-field";
    let mut fields: Vec<Vec<u8>> = Vec::new();
    loop {
        let rest = &line[from..];
        if rest.first() != Some(&b'"') {
            let comma = rest.iter().position(|byte| *byte == b',');
            let field = match comma {
                Some(index) => &rest[..index],
                None => &rest[..rest.len() - csv_newline_len(rest)],
            };
            if let Some(quote) = field.iter().position(|byte| *byte == b'"') {
                return Err(parse_error(reader.num_line, pos_col + quote, BARE_QUOTE));
            }
            fields.push(field.to_vec());
            // No comma: this was the last field and the record is complete.
            let Some(index) = comma else { break };
            from += index + 1;
            pos_col += index + 1;
            continue;
        }
        from += 1;
        pos_col += 1;
        let mut field = Vec::new();
        loop {
            let rest = &line[from..];
            if let Some(index) = rest.iter().position(|byte| *byte == b'"') {
                field.extend_from_slice(&rest[..index]);
                from += index + 1;
                pos_col += index + 1;
                let rest = &line[from..];
                match rest.first() {
                    Some(b'"') => {
                        field.push(b'"');
                        from += 1;
                        pos_col += 1;
                    }
                    Some(b',') => {
                        from += 1;
                        pos_col += 1;
                        fields.push(std::mem::take(&mut field));
                        break;
                    }
                    _ if csv_newline_len(rest) == rest.len() => {
                        fields.push(field);
                        return Ok(csv_strings(fields));
                    }
                    _ => return Err(parse_error(reader.num_line, pos_col - 1, QUOTE)),
                }
            } else if !rest.is_empty() {
                // End of line inside the quotes: the field continues on the next line (a
                // following `io.EOF` is not an error by itself, only the missing quote).
                field.extend_from_slice(rest);
                pos_col += rest.len();
                (line, _) = reader.read_line();
                from = 0;
                if !line.is_empty() {
                    pos_line += 1;
                    pos_col = 1;
                }
            } else {
                // Abrupt end of input inside a quoted field.
                return Err(parse_error(pos_line, pos_col, QUOTE));
            }
        }
    }
    Ok(csv_strings(fields))
}

/// The fields of a record as text. Every split point is an ASCII byte of a UTF-8 value,
/// so a field is valid UTF-8 whenever the value was.
fn csv_strings(fields: Vec<Vec<u8>>) -> Vec<String> {
    fields
        .into_iter()
        .map(|field| String::from_utf8_lossy(&field).into_owned())
        .collect()
}

/// The elements of a `stringSlice` flag after pflag parsed every occurrence: the first
/// occurrence replaces the flag's default and later ones append, each as one CSV record
/// (`go_csv_record`), so `--tools ""` is an empty slice, not the default. Without any
/// occurrence the default stays. `evaluate` rejected a malformed occurrence as a usage
/// error before any command runs, so an error cannot reach this point.
pub fn string_slice_flag(occurrences: &[String], default: &[&str]) -> Vec<String> {
    if occurrences.is_empty() {
        return default.iter().map(|value| (*value).to_owned()).collect();
    }
    let mut values = Vec::new();
    for occurrence in occurrences {
        match go_csv_record(occurrence) {
            Ok(record) => values.extend(record),
            Err(_) => debug_assert!(false, "stringSlice value {occurrence:?} passed evaluate"),
        }
    }
    values
}

/// Length of the line terminator (`\n`) that ends `line`, as `encoding/csv`'s `lengthNL`.
fn csv_newline_len(line: &[u8]) -> usize {
    usize::from(line.last() == Some(&b'\n'))
}

/// `encoding/csv`'s `Reader.readLine` over an in-memory value.
struct CsvLines<'a> {
    data: &'a [u8],
    at: usize,
    num_line: usize,
}

impl CsvLines<'_> {
    /// The next line with `\r\n` folded to `\n` and a trailing `\r` before the end of
    /// input dropped, plus whether the input was already exhausted (`io.EOF` with no data).
    fn read_line(&mut self) -> (Vec<u8>, bool) {
        let rest = &self.data[self.at..];
        let size = rest
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(rest.len(), |index| index + 1);
        let mut line = rest[..size].to_vec();
        self.at += size;
        let eof = line.is_empty();
        if !eof && line.last() == Some(&b'\r') {
            line.pop();
        }
        self.num_line += 1;
        let length = line.len();
        if length >= 2 && line[length - 2] == b'\r' && line[length - 1] == b'\n' {
            line[length - 2] = b'\n';
            line.pop();
        }
        (line, eof)
    }
}

fn flag_label(arg: &Arg) -> String {
    let long = arg.get_long().unwrap_or_default();
    match arg.get_short() {
        Some(short) => format!("-{short}, --{long}"),
        None => format!("--{long}"),
    }
}

fn invalid_argument(value: &str, arg: &Arg, parser: &str, reason: &str) -> String {
    format!(
        "invalid argument {value:?} for {label:?} flag: strconv.{parser}: parsing {value:?}: {reason}",
        label = flag_label(arg)
    )
}

fn invalid_argument_reason(value: &str, arg: &Arg, reason: &str) -> String {
    format!(
        "invalid argument {value:?} for {label:?} flag: {reason}",
        label = flag_label(arg)
    )
}

struct Parsed {
    positionals: Vec<String>,
    /// Long names of the flags that appeared on the command line (pflag
    /// `Changed`), whatever their value.
    set: Vec<String>,
    /// The flags an argument validator reads.
    validator: ValidatorFlags,
    json_flag: bool,
    output: Option<String>,
}

/// pflag's parse of the remaining tokens against the command's flag set.
fn parse_flags(
    tokens: &[String],
    flags: Flags<'_>,
    path: &str,
    lenient: bool,
) -> Result<Parsed, String> {
    let mut parsed = Parsed {
        positionals: Vec::new(),
        set: Vec::new(),
        validator: ValidatorFlags::default(),
        json_flag: false,
        output: None,
    };
    let mut index = 0;
    let note = |arg: &Arg, value: Option<&str>, parsed: &mut Parsed| match (arg.get_long(), value) {
        (Some("output"), Some(value)) => parsed.output = Some(value.to_owned()),
        (Some("url"), Some(value)) if path == "find" => {
            parsed.validator.url_filter = !value.is_empty();
        }
        (Some("pairing-file"), Some(value)) if path == "device join" => {
            parsed.validator.pairing_file = !value.is_empty();
        }
        _ => {}
    };
    while index < tokens.len() {
        let token = &tokens[index];
        index += 1;
        if token == "--" {
            parsed.positionals.extend_from_slice(&tokens[index..]);
            break;
        }
        if let Some(rest) = token.strip_prefix("--") {
            let (name, inline) = match rest.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (rest, None),
            };
            if lenient && hand_parsed_bool(path, name) {
                if let Some(value) = inline
                    && !go_parse_bool(value)
                {
                    return Err(format!(
                        "invalid argument {value:?} for \"--{name}\" flag: strconv.ParseBool: parsing {value:?}: invalid syntax"
                    ));
                }
                continue;
            }
            let Some(arg) = flags.long(name) else {
                if lenient {
                    continue;
                }
                return Err(format!("unknown flag: --{name}"));
            };
            if is_help_arg(arg) {
                continue;
            }
            if let Some(long) = arg.get_long() {
                parsed.set.push(long.to_owned());
            }
            if !is_bool_arg(arg) {
                let value = match inline {
                    Some(value) => value.to_owned(),
                    None if arg.is_require_equals_set() => continue,
                    None => match tokens.get(index) {
                        Some(next) => {
                            index += 1;
                            next.clone()
                        }
                        None => return Err(format!("flag needs an argument: --{name}")),
                    },
                };
                if let Some(error) = typed_value_error(path, name, arg, &value) {
                    return Err(error);
                }
                note(arg, Some(&value), &mut parsed);
            } else {
                if let Some(value) = inline
                    && !go_parse_bool(value)
                {
                    return Err(invalid_argument(value, arg, "ParseBool", "invalid syntax"));
                }
                // pflag assigns the parsed value on every occurrence: the last one wins,
                // so `--json --json=false` leaves the flag unset.
                let enabled = inline.is_none_or(|value| {
                    matches!(value, "1" | "t" | "T" | "TRUE" | "true" | "True")
                });
                if arg.get_long() == Some("json") {
                    parsed.json_flag = enabled;
                }
            }
        } else if token.starts_with('-') && token.len() > 1 {
            let cluster: Vec<char> = token[1..].chars().collect();
            let mut at = 0;
            while at < cluster.len() {
                let rest: String = cluster[at..].iter().collect();
                let short = cluster[at];
                let Some(arg) = flags.short(short) else {
                    if lenient {
                        break;
                    }
                    return Err(format!("unknown shorthand flag: {short:?} in -{rest}"));
                };
                at += 1;
                if !is_help_arg(arg)
                    && let Some(long) = arg.get_long()
                {
                    parsed.set.push(long.to_owned());
                }
                if is_help_arg(arg) || is_bool_arg(arg) {
                    // pflag: `-y=value` hands everything after the `=` to the flag, but only
                    // when something follows it; a bare `-y=` leaves `=` as the next shorthand.
                    if at + 1 < cluster.len() && cluster[at] == '=' {
                        let value: String = cluster[at + 1..].iter().collect();
                        if !go_parse_bool(&value) {
                            return Err(invalid_argument(
                                &value,
                                arg,
                                "ParseBool",
                                "invalid syntax",
                            ));
                        }
                        break;
                    }
                    continue;
                }
                let value: String = if at < cluster.len() {
                    let tail: String = cluster[at..].iter().collect();
                    tail.strip_prefix('=').unwrap_or(&tail).to_owned()
                } else {
                    match tokens.get(index) {
                        Some(next) => {
                            index += 1;
                            next.clone()
                        }
                        None => {
                            return Err(format!("flag needs an argument: {short:?} in -{rest}"));
                        }
                    }
                };
                let long = arg.get_long().unwrap_or_default();
                if let Some(error) = typed_value_error(path, long, arg, &value) {
                    return Err(error);
                }
                note(arg, Some(&value), &mut parsed);
                break;
            }
        } else {
            parsed.positionals.push(token.clone());
        }
    }
    Ok(parsed)
}

fn levenshtein(left: &str, right: &str) -> usize {
    let left: Vec<char> = left.to_lowercase().chars().collect();
    let right: Vec<char> = right.to_lowercase().chars().collect();
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    for (i, l) in left.iter().enumerate() {
        let mut current = vec![i + 1];
        for (j, r) in right.iter().enumerate() {
            let cost = usize::from(l != r);
            current.push(
                (previous[j] + cost)
                    .min(previous[j + 1] + 1)
                    .min(current[j] + 1),
            );
        }
        previous = current;
    }
    previous[right.len()]
}

fn unknown_command(word: &str) -> Verdict {
    let lowered = word.to_lowercase();
    let suggestions: Vec<&str> = SUGGESTION_ORDER
        .iter()
        .copied()
        .filter(|name| levenshtein(word, name) <= 2 || name.to_lowercase().starts_with(&lowered))
        .collect();
    let mut message = format!("unknown command {word:?} for \"symvault\"");
    if !suggestions.is_empty() {
        message.push_str("\n\nDid you mean this?\n");
        for name in suggestions {
            message.push('\t');
            message.push_str(name);
            message.push('\n');
        }
    }
    Verdict::Fail {
        stderr: format!("Error: {message}\nRun 'symvault --help' for usage.\nError: {message}\n"),
        code: 1,
    }
}

/// Evaluates `args` (without the program name) the way cobra does: command
/// resolution, flag parsing, the argument validator and the output-format gate.
/// `error_taxonomy`'s fixture rows model exactly that stage, so this entry point
/// stops there; [`evaluate_with_required`] adds the required-flag stage after it.
#[cfg(test)]
pub fn evaluate(args: &[String], root: Command) -> Verdict {
    evaluate_stages(args, root, false)
}

/// [`evaluate`] plus cobra's `validateRequiredFlags`, which runs after the
/// gate and before the command body.
pub fn evaluate_with_required(args: &[String], root: Command) -> Verdict {
    evaluate_stages(args, root, true)
}

/// How cobra's command resolution ended.
enum Stop {
    /// A command was resolved, or none (the root).
    Resolved,
    /// The first positional is `help`: the native help command walks the topic.
    Help,
    /// The first positional is no command of the root.
    Unknown(String),
}

struct Resolution<'a> {
    current: Node<'a>,
    /// The tokens left once the command words are removed.
    tokens: Vec<String>,
    /// Index in the original arguments of the last command word (`help` included).
    last_word: Option<usize>,
    stop: Stop,
}

/// cobra's `Find`: strip the flags, take the first positional as the next command word
/// and repeat on what is left. A lone `-` starts with a dash, so it is skipped here
/// and stays in `tokens` for the flag parser, which counts it as a positional.
fn resolve<'a>(args: &[String], root: &'a Command) -> Resolution<'a> {
    let mut current = Node {
        command: None,
        path: Vec::new(),
    };
    let mut tokens = args.to_vec();
    let mut origin: Vec<usize> = (0..args.len()).collect();
    let mut last_word = None;
    loop {
        let flags = Flags {
            command: current.command.unwrap_or(root),
            root,
        };
        let lenient = current.command.is_none() && !current.path.is_empty();
        let positional = strip_flags(&tokens, flags, lenient);
        let Some(first) = positional.first() else {
            break;
        };
        let lookup = Node {
            command: current.command.or(current.path.is_empty().then_some(root)),
            path: current.path.clone(),
        };
        let index = first_word_index(&tokens, first, flags, lenient);
        match find_next(&lookup, first) {
            Some(next) => {
                if let Some(index) = index {
                    tokens.remove(index);
                    last_word = Some(origin.remove(index));
                }
                current = next;
            }
            None => {
                let stop = if current.path.is_empty() {
                    if first == "help" {
                        last_word = index.map(|index| origin[index]);
                        Stop::Help
                    } else {
                        Stop::Unknown(first.clone())
                    }
                } else {
                    Stop::Resolved
                };
                return Resolution {
                    current,
                    tokens,
                    last_word,
                    stop,
                };
            }
        }
    }
    Resolution {
        current,
        tokens,
        last_word,
        stop: Stop::Resolved,
    }
}

fn evaluate_stages(args: &[String], mut root: Command, required: bool) -> Verdict {
    if args
        .iter()
        .take_while(|token| *token != "--")
        .any(|token| token == "-h" || token == "--help")
    {
        return Verdict::Proceed;
    }
    root.build();
    let Resolution {
        current,
        tokens,
        stop,
        ..
    } = resolve(args, &root);
    match stop {
        Stop::Resolved => {}
        Stop::Help => return Verdict::Proceed,
        Stop::Unknown(word) => return unknown_command(&word),
    }
    let path_text = current.path.join(" ");
    let flags = Flags {
        command: current.command.unwrap_or(&root),
        root: &root,
    };
    let lenient = current.command.is_none() && !current.path.is_empty();
    let parsed = match parse_flags(&tokens, flags, &path_text, lenient) {
        Ok(parsed) => parsed,
        Err(message) => return fail_at(&path_text, &message, 1),
    };
    if current.path.is_empty() {
        // The root is not runnable: whatever is left (a lone `-`, everything after `--`,
        // only persistent flags) is a positional cobra's legacy check never sees, and
        // the root prints its help before the output-format gate runs.
        return Verdict::GroupHelp(String::new());
    }
    if GROUPS.contains(&path_text.as_str()) {
        return Verdict::GroupHelp(path_text);
    }
    if rule_for(&path_text) == Some(Rule::NoArgs)
        && let Some(first) = parsed.positionals.first()
    {
        let message = format!(
            "unknown command {} for {}",
            crate::cli_artifacts::quote_go_string(first),
            crate::cli_artifacts::quote_go_string(&format!("symvault {path_text}"))
        );
        return fail_at(&path_text, &message, 1);
    }
    if let Some(message) = arity_message(&path_text, parsed.positionals.len(), parsed.validator) {
        return fail(&message, 1);
    }
    if let Some(format) = refused_format(&path_text, parsed.json_flag, parsed.output.as_deref()) {
        return fail(&gate_message(&format, &path_text), 9);
    }
    if required && let Some(message) = missing_required_flags(&path_text, &parsed.set) {
        return fail(&message, 1);
    }
    Verdict::Proceed
}

/// The positions of the lone `-` tokens that are positionals of the command (not a flag's
/// value) and precede its last word.
fn bare_dashes_before(tokens: &[String], flags: Flags<'_>, lenient: bool) -> Vec<usize> {
    let mut found = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if token == "--" {
            break;
        }
        let takes_value = if let Some(name) = token.strip_prefix("--") {
            !token.contains('=')
                && match flags.long(name) {
                    Some(arg) => eats_next(arg),
                    None => !lenient,
                }
        } else if token.starts_with('-') && token.len() == 2 && !token.contains('=') {
            match token.chars().nth(1).and_then(|c| flags.short(c)) {
                Some(arg) => eats_next(arg),
                None => !lenient,
            }
        } else {
            false
        };
        if takes_value {
            index += 2;
            continue;
        }
        if token == "-" {
            found.push(index);
        }
        index += 1;
    }
    found
}

/// The arguments clap should parse. cobra skips a lone `-` while it resolves the command
/// and hands it to the resolved command as a positional (`- list`, `share - list`), but
/// clap reads it as the first positional of the parent and never reaches the subcommand.
/// Every lone `-` that precedes the last command word moves right behind that word, which
/// is the position cobra gives it relative to the arguments that follow.
pub fn clap_arguments(args: Vec<std::ffi::OsString>, mut root: Command) -> Vec<std::ffi::OsString> {
    let Some(strings) = args
        .iter()
        .skip(1)
        .map(|arg| arg.to_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()
    else {
        return args;
    };
    if !strings.iter().any(|token| token == "-") {
        return args;
    }
    root.build();
    let resolution = resolve(&strings, &root);
    if matches!(resolution.stop, Stop::Unknown(_)) {
        return args;
    }
    let Some(word) = resolution.last_word else {
        return args;
    };
    let flags = Flags {
        command: resolution.current.command.unwrap_or(&root),
        root: &root,
    };
    let lenient = resolution.current.command.is_none() && !resolution.current.path.is_empty();
    let dashes = bare_dashes_before(&strings[..word], flags, lenient);
    if dashes.is_empty() {
        return args;
    }
    let mut rewritten = Vec::with_capacity(args.len());
    rewritten.push(args[0].clone());
    for (index, token) in args.iter().skip(1).enumerate() {
        if !dashes.contains(&index) {
            rewritten.push(token.clone());
        }
        if index == word {
            rewritten.extend(dashes.iter().map(|_| std::ffi::OsString::from("-")));
        }
    }
    rewritten
}

/// Runs the emulation on the process arguments and prints Go's diagnostic.
/// `Some(code)` means the process must exit with `code`.
pub fn check(args: &[std::ffi::OsString], root: Command) -> Option<std::process::ExitCode> {
    use std::io::Write;
    let strings: Option<Vec<String>> = args
        .iter()
        .skip(1)
        .map(|arg| arg.to_str().map(str::to_owned))
        .collect();
    let strings = strings?;
    match evaluate_with_required(&strings, root) {
        Verdict::Proceed => None,
        Verdict::Fail { stderr, code } => {
            let _ = std::io::stderr().write_all(stderr.as_bytes());
            Some(std::process::ExitCode::from(code))
        }
        Verdict::GroupHelp(path) => {
            let code =
                match crate::help_commands::write_nested(&path, &mut std::io::stdout().lock()) {
                    Ok(()) => 0,
                    Err(error) => {
                        let _ = writeln!(std::io::stderr(), "Error: help: {error}");
                        1
                    }
                };
            Some(std::process::ExitCode::from(code))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levenshtein_is_case_insensitive_edit_distance() {
        assert_eq!(levenshtein("lst", "list"), 1);
        assert_eq!(levenshtein("LIST", "list"), 0);
        assert_eq!(levenshtein("e", "get"), 2);
    }

    #[test]
    fn required_flags_follow_cobra_order_and_wording() {
        let run = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            evaluate_with_required(&args, root())
        };
        let missing = fail("required flag(s) \"format\" not set", 1);
        assert_eq!(run(&["export", "-y"]), missing);
        assert_eq!(run(&["export"]), missing);
        // Any occurrence counts as set, even an empty value or a repeat.
        assert_eq!(run(&["export", "--format", ""]), Verdict::Proceed);
        assert_eq!(
            run(&["export", "--format=csv", "--format=json"]),
            Verdict::Proceed
        );
        // The argument validator and the gate come first.
        assert!(matches!(
            run(&["export", "extra"]),
            Verdict::Fail { ref stderr, .. } if stderr.contains("unknown command \"extra\"")
        ));
        assert!(matches!(
            run(&["export", "--json"]),
            Verdict::Fail { code: 9, .. }
        ));
        // `evaluate` itself stays at the validator/gate stage.
        assert_eq!(evaluate(&["export".to_owned()], root()), Verdict::Proceed);
    }

    #[test]
    fn go_bool_and_int_syntax() {
        assert!(go_parse_bool("T") && go_parse_bool("false") && !go_parse_bool("maybe"));
        assert_eq!(go_parse_int("-12"), Ok(-12));
        assert_eq!(go_parse_int("+3"), Ok(3));
        assert_eq!(go_parse_int("a"), Err(IntError::Syntax));
        assert_eq!(go_parse_int(""), Err(IntError::Syntax));
    }

    /// `strconv.ParseInt(s, 0, 64)`, value by value (Go 1.26 semantics).
    #[test]
    fn go_int_syntax_follows_parse_int_base_zero() {
        let accepted: &[(&str, i64)] = &[
            ("0", 0),
            ("0x10", 16),
            ("0X10", 16),
            ("0o17", 15),
            ("0O17", 15),
            ("0b101", 5),
            ("1_0", 10),
            ("010", 8),
            ("0_7", 7),
            ("-0x10", -16),
            ("+5", 5),
            ("0x_1", 1),
            ("0b_1", 1),
            ("-9223372036854775808", i64::MIN),
            ("9223372036854775807", i64::MAX),
            ("-0x8000000000000000", i64::MIN),
        ];
        for (text, want) in accepted {
            assert_eq!(go_parse_int(text), Ok(*want), "{text:?}");
        }
        let syntax = [
            "", "-", "+", "0x", "0b", "0o", "08", "0b2", "0o8", "0x1G", "1__0", "_10", "10_",
            "0x1_", "0_x1", "1e3", " 5", "5 ", "--5", "+-5", "٣",
        ];
        for text in syntax {
            assert_eq!(go_parse_int(text), Err(IntError::Syntax), "{text:?}");
        }
        let range = [
            "9223372036854775808",
            "-9223372036854775809",
            "99999999999999999999",
            "0x8000000000000000",
            // Overflow is seen before the later invalid digit.
            "99999999999999999999x",
        ];
        for text in range {
            assert_eq!(go_parse_int(text), Err(IntError::Range), "{text:?}");
        }
    }

    #[test]
    fn arity_messages_follow_cobra_validators() {
        assert_eq!(
            arity_message("get", 0, ValidatorFlags::default()).as_deref(),
            Some("accepts 1 arg(s), received 0")
        );
        assert_eq!(arity_message("get", 1, ValidatorFlags::default()), None);
        assert_eq!(
            arity_message("find", 4, ValidatorFlags::default()).as_deref(),
            Some("accepts at most 1 arg(s), received 4")
        );
        assert_eq!(
            arity_message("run", 0, ValidatorFlags::default()).as_deref(),
            Some("requires at least 1 arg(s), only received 0")
        );
        assert_eq!(arity_message("version", 9, ValidatorFlags::default()), None);
    }

    #[derive(serde::Deserialize)]
    struct Observation {
        args: Vec<String>,
        exit_code: i32,
        stdout: String,
        stderr: String,
    }

    #[derive(serde::Deserialize)]
    struct UsageCase {
        name: String,
        observation: Observation,
    }

    #[derive(serde::Deserialize)]
    struct Probe {
        count: usize,
        rejected: bool,
        observation: Option<Observation>,
    }

    #[derive(serde::Deserialize)]
    struct ArityRow {
        path: String,
        probes: Vec<Probe>,
    }

    #[derive(serde::Deserialize)]
    struct GateRow {
        path: String,
        valid_args: usize,
        json_refused: bool,
        output_refused: bool,
        #[serde(default)]
        refusals: Vec<Observation>,
    }

    #[derive(serde::Deserialize)]
    struct ShapeCase {
        name: String,
        observation: Observation,
    }

    #[derive(serde::Deserialize)]
    struct Fixture {
        usage: Vec<UsageCase>,
        arity: Vec<ArityRow>,
        gate: Vec<GateRow>,
        argv_shapes: Vec<ShapeCase>,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!(
            "../../../testdata/port/cli/error-taxonomy.json"
        ))
        .expect("error-taxonomy fixture parses")
    }

    fn root() -> Command {
        use clap::CommandFactory;
        crate::Cli::command()
    }

    fn path_args(path: &str) -> Vec<String> {
        path.split(' ').skip(1).map(str::to_owned).collect()
    }

    /// The Go rejection text of an observation, as `Verdict::Fail` carries it.
    fn expect_fail(observation: &Observation) -> Verdict {
        assert!(observation.stdout.is_empty());
        Verdict::Fail {
            stderr: observation.stderr.clone(),
            code: u8::try_from(observation.exit_code).expect("exit code fits u8"),
        }
    }

    #[test]
    fn evaluation_matches_the_recorded_usage_cases() {
        let fixture = fixture();
        assert!(fixture.usage.len() >= 40);
        let mut failures = Vec::new();
        for case in &fixture.usage {
            let got = evaluate_with_required(&case.observation.args, root());
            let want = if matches!(case.observation.exit_code, 0 | 3) {
                // Group help (stdout), a successful command or the command body's own
                // "vault not initialized" failure (exit 3): never the emulation's verdict.
                if case.observation.stdout.is_empty() {
                    Verdict::Proceed
                } else {
                    continue;
                }
            } else {
                expect_fail(&case.observation)
            };
            if got != want {
                failures.push(format!("{}: {got:?} != {want:?}", case.name));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The emulation answers exactly the diagnostics cobra and the argument validators
    /// give (usage errors, arity, the `device join` messages) and the group help; every
    /// other Go outcome belongs to the command body, which the emulation hands to clap.
    #[test]
    fn every_argv_shape_is_decided_like_the_oracle() {
        let fixture = fixture();
        assert!(fixture.argv_shapes.len() >= 20);
        let mut failures = Vec::new();
        for case in &fixture.argv_shapes {
            let observation = &case.observation;
            let first_line = observation.stderr.lines().next().unwrap_or_default();
            let decided_before_the_body = [
                "Error: accepts ",
                "Error: with --pairing-file, pass only",
                "Error: flag needs an argument",
            ]
            .iter()
            .any(|prefix| first_line.starts_with(prefix));
            let want = if observation.exit_code == 0 {
                assert!(!observation.stdout.is_empty(), "{}", case.name);
                let path = observation.args.join(" ");
                Verdict::GroupHelp(path)
            } else if decided_before_the_body {
                expect_fail(observation)
            } else {
                Verdict::Proceed
            };
            let got = evaluate(&observation.args, root());
            if got != want {
                failures.push(format!("{}: {got:?} != {want:?}", case.name));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn join_arity_depends_on_whether_pairing_file_is_set() {
        let set = ValidatorFlags {
            pairing_file: true,
            ..ValidatorFlags::default()
        };
        let unset = ValidatorFlags::default();
        assert_eq!(arity_message("device join", 1, set), None);
        assert_eq!(
            arity_message("device join", 2, set).as_deref(),
            Some(JOIN_PAIRING_FILE_MESSAGE)
        );
        assert_eq!(
            arity_message("device join", 0, set).as_deref(),
            Some(JOIN_PAIRING_FILE_MESSAGE)
        );
        assert_eq!(arity_message("device join", 2, unset), None);
        assert!(
            arity_message("device join", 1, unset)
                .is_some_and(|message| message.ends_with(JOIN_SUFFIX))
        );
    }

    #[test]
    fn every_arity_probe_matches_the_oracle() {
        let fixture = fixture();
        let mut checked = 0;
        for row in &fixture.arity {
            for probe in &row.probes {
                let mut args = path_args(&row.path);
                args.extend(std::iter::repeat_n("x".to_owned(), probe.count));
                let got = evaluate(&args, root());
                match (&probe.observation, probe.rejected) {
                    (Some(observation), true) => {
                        assert_eq!(
                            got,
                            expect_fail(observation),
                            "{} {}",
                            row.path,
                            probe.count
                        );
                    }
                    _ => assert!(
                        !matches!(&got, Verdict::Fail { .. }),
                        "{} with {} args must pass the validator, got {got:?}",
                        row.path,
                        probe.count
                    ),
                }
                checked += 1;
            }
        }
        assert_eq!(checked, fixture.arity.len() * 5);
    }

    #[test]
    fn every_gate_row_matches_the_oracle() {
        let fixture = fixture();
        let mut refused = 0;
        for row in &fixture.gate {
            let stripped = row.path.trim_start_matches("symvault ");
            if stripped == "auth set" {
                // Go validates `auth set`'s arguments with a custom closure, which
                // the taxonomy probe does not recognise as an arity error, so its
                // row records 0 valid arguments and "not refused". With the one
                // required argument the gate refuses both formats; that refusal is
                // byte-pinned by `output_modes` (auth-set.json/.yaml/.output-json).
                assert!(JSON_REFUSED.contains(&stripped) && OUTPUT_REFUSED.contains(&stripped));
                continue;
            }
            assert_eq!(
                JSON_REFUSED.contains(&stripped),
                row.json_refused,
                "{}",
                row.path
            );
            assert_eq!(
                OUTPUT_REFUSED.contains(&stripped),
                row.output_refused,
                "{}",
                row.path
            );
            let mut base = path_args(&row.path);
            base.extend(std::iter::repeat_n("x".to_owned(), row.valid_args));
            let formats: [&[&str]; 3] = [&["--json"], &["--output", "yaml"], &["--output", "xml"]];
            let mut refusals = row.refusals.iter();
            for format in formats {
                let mut args = base.clone();
                args.extend(format.iter().map(|part| (*part).to_owned()));
                let got = evaluate(&args, root());
                let expected_refusal = if format[0] == "--json" {
                    row.json_refused
                } else {
                    row.output_refused
                };
                if expected_refusal {
                    let observation = refusals.next().expect("recorded refusal");
                    assert_eq!(observation.args, args);
                    assert_eq!(got, expect_fail(observation), "{} {format:?}", row.path);
                    refused += 1;
                } else {
                    assert_eq!(got, Verdict::Proceed, "{} {format:?}", row.path);
                }
            }
            assert!(refusals.next().is_none(), "{}", row.path);
        }
        assert!(refused > 150, "only {refused} refusals replayed");
    }

    /// The pinned Go tree: `(path, runnable, local flags, persistent flags)`.
    fn tree() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../testdata/port/cli/command-tree.json"))
            .expect("command-tree fixture parses")
    }

    /// Walks the clap tree along a Go path ("device join"), like `find_next` does.
    fn clap_command<'a>(root: &'a Command, path: &str) -> Option<&'a Command> {
        path.split(' ')
            .filter(|word| !word.is_empty())
            .try_fold(root, |node, word| {
                node.get_subcommands().find(|sub| {
                    sub.get_name() == word || sub.get_all_aliases().any(|alias| alias == word)
                })
            })
    }

    fn go_path(entry: &serde_json::Value) -> String {
        entry["path"]
            .as_str()
            .expect("path")
            .trim_start_matches("symvault")
            .trim_start()
            .to_owned()
    }

    /// Flags (long and shorthand) that exist in both trees and whose value syntax the two
    /// disagree on, plus the number of flags compared. pflag gives a boolean flag a
    /// no-option default (`--flag` never takes the next token); every other Go flag type
    /// (string, int, duration, slices) consumes the next token. The emulation consumes
    /// it exactly when `eats_next` says so, so that is what has to agree with Go's type:
    /// mixing the two up silently turns a path into a positional (or the reverse).
    fn flag_type_mismatches(root: &Command) -> (Vec<String>, usize) {
        let tree = tree();
        let mut mismatches = Vec::new();
        let mut compared = 0;
        let mut compare = |path: &str, command: &Command, flag: &serde_json::Value| {
            let name = flag["name"].as_str().expect("flag name");
            if name == "help" {
                return;
            }
            let flags = Flags { command, root };
            let go_bool = flag["type"] == "bool";
            let mut check = |label: String, arg: Option<&Arg>| {
                let Some(arg) = arg else {
                    return;
                };
                compared += 1;
                let emulated_bool = !eats_next(arg);
                if go_bool != emulated_bool {
                    mismatches.push(format!(
                        "{path} {label}: Go type {} but the emulation treats it as {}",
                        flag["type"],
                        if emulated_bool {
                            "a boolean"
                        } else {
                            "a value flag"
                        }
                    ));
                }
            };
            check(format!("--{name}"), flags.long(name));
            if let Some(short) = flag["shorthand"].as_str().and_then(|s| s.chars().next()) {
                check(format!("-{short}"), flags.short(short));
            }
        };
        for entry in tree["commands"].as_array().expect("commands") {
            let path = go_path(entry);
            let Some(command) = clap_command(root, &path) else {
                continue;
            };
            for key in ["local_flags", "persistent_flags"] {
                for flag in entry[key].as_array().into_iter().flatten() {
                    compare(&path, command, flag);
                }
            }
        }
        (mismatches, compared)
    }

    fn verdict(args: &[&str]) -> Verdict {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        evaluate(&args, root())
    }

    fn refused(args: &[&str]) -> bool {
        matches!(verdict(args), Verdict::Fail { code: 9, .. })
    }

    /// pflag assigns a bool on every occurrence, so the last one decides the gate.
    #[test]
    fn repeated_json_flag_is_last_value_wins() {
        assert!(refused(&["--json", "lock"]));
        assert!(refused(&["--json=true", "--json", "lock"]));
        assert!(!refused(&["--json", "--json=false", "lock"]));
        assert!(refused(&["--json=false", "--json", "lock"]));
        assert!(!refused(&["--json=F", "lock"]));
        assert!(!refused(&["lock", "--json", "--json=0"]));
        assert!(refused(&["--json=false", "lock", "--json=T"]));
        // The reset hands the decision to `--output`, whose own value then refuses.
        let Verdict::Fail { stderr, code } = verdict(&[
            "--json",
            "--json=false",
            "--output",
            "xml",
            "startup-profile",
        ]) else {
            panic!("--output xml must be refused");
        };
        assert_eq!(code, 9);
        assert!(stderr.contains("output format \"xml\""), "{stderr}");
        // ParseBool accepts no other spelling.
        assert!(matches!(
            verdict(&["--json=maybe", "lock"]),
            Verdict::Fail { code: 1, .. }
        ));
        assert!(matches!(
            verdict(&["--quiet=maybe", "version"]),
            Verdict::Fail { code: 1, .. }
        ));
    }

    #[test]
    fn hand_parsed_bool_flags_match_the_command_tree() {
        let tree = tree();
        for (path, names) in HAND_PARSED_BOOLS {
            let entry = tree["commands"]
                .as_array()
                .expect("commands")
                .iter()
                .find(|entry| go_path(entry) == *path)
                .unwrap_or_else(|| panic!("{path} is not in command-tree.json"));
            let mut go_bools: Vec<&str> = entry["local_flags"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|flag| flag["type"] == "bool" && flag["name"] != "help")
                .map(|flag| flag["name"].as_str().expect("flag name"))
                .collect();
            go_bools.sort_unstable();
            assert_eq!(go_bools, *names, "{path}");
            assert!(
                clap_command(&root(), path).is_none(),
                "{path} now has a clap definition"
            );
        }
    }

    #[test]
    fn flag_types_match_the_command_tree() {
        let (mismatches, compared) = flag_type_mismatches(&root());
        assert!(compared > 150, "only {compared} flags compared");
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    /// Every Go bool flag (local and persistent) is a pflag `BoolVar`, which accepts
    /// `--flag`, `--flag=<ParseBool form>` and repeats with the last value winning.
    /// A clap `SetTrue` flag rejects `--flag=false`, so each one must be the
    /// `--flag[=bool]` spelling (`ArgAction::Set`, optional `require_equals` value).
    /// Returns the bool flags that are not, plus the number of bool flags compared.
    fn bool_flags_without_explicit_value(root: &Command) -> (Vec<String>, usize) {
        let tree = tree();
        let mut offenders = Vec::new();
        let mut compared = 0;
        for entry in tree["commands"].as_array().expect("commands") {
            let path = go_path(entry);
            let Some(command) = clap_command(root, &path) else {
                continue;
            };
            let flags = Flags { command, root };
            for key in ["local_flags", "persistent_flags"] {
                for flag in entry[key].as_array().into_iter().flatten() {
                    let name = flag["name"].as_str().expect("flag name");
                    if flag["type"] != "bool" || name == "help" {
                        continue;
                    }
                    let mut check = |label: String, arg: Option<&Arg>| {
                        let Some(arg) = arg else {
                            return;
                        };
                        compared += 1;
                        let explicit = arg.get_action().takes_values()
                            && arg.is_require_equals_set()
                            && arg
                                .get_num_args()
                                .is_some_and(|range| range.min_values() == 0);
                        if !explicit {
                            offenders.push(format!("{path} {label}"));
                        }
                    };
                    check(format!("--{name}"), flags.long(name));
                    if let Some(short) = flag["shorthand"].as_str().and_then(|s| s.chars().next()) {
                        check(format!("-{short}"), flags.short(short));
                    }
                }
            }
        }
        (offenders, compared)
    }

    #[test]
    fn go_bool_flags_accept_an_explicit_value() {
        let (offenders, compared) = bool_flags_without_explicit_value(&root());
        assert!(compared > 80, "only {compared} bool flags compared");
        assert!(
            offenders.is_empty(),
            "{} of {compared} bool flags reject --flag=<bool>:\n{}",
            offenders.len(),
            offenders.join("\n")
        );
    }

    /// pflag hands everything after `-f=` to the shorthand's flag; only a bare `-f=` leaves
    /// `=` behind as the next (unknown) shorthand.
    #[test]
    fn shorthand_bool_takes_an_equals_value() {
        assert_eq!(verdict(&["sync", "-f=false"]), Verdict::Proceed);
        assert_eq!(verdict(&["sync", "-f", "-f=0"]), Verdict::Proceed);
        let Verdict::Fail { stderr, code } = verdict(&["sync", "-f=maybe"]) else {
            panic!("-f=maybe must be refused");
        };
        assert_eq!(code, 1);
        assert!(
            stderr.starts_with(
                "Error: invalid argument \"maybe\" for \"-f, --force\" flag: strconv.ParseBool: parsing \"maybe\": invalid syntax\n"
            ),
            "{stderr}"
        );
        let Verdict::Fail { stderr, .. } = verdict(&["sync", "-f="]) else {
            panic!("-f= must be refused");
        };
        assert!(
            stderr.starts_with("Error: unknown shorthand flag: '=' in -=\n"),
            "{stderr}"
        );
    }

    /// clap itself must take `--flag=false`, `-x=false` and a repeat in either order for
    /// every Go bool flag (the emulation above runs first, but only clap decides the
    /// accepting cases, e.g. `doctor --fix=false`, whose report is host dependent and so
    /// cannot be replayed from the corpus). Errors about *missing* required arguments are
    /// fine: the flag syntax was already accepted when clap reached them.
    #[test]
    fn clap_parses_explicit_values_of_every_go_bool_flag() {
        use clap::error::ErrorKind;
        let root = root();
        let tree = tree();
        let mut parsed = 0;
        for entry in tree["commands"].as_array().expect("commands") {
            let path = go_path(entry);
            if path.is_empty() || clap_command(&root, &path).is_none() {
                continue;
            }
            for flag in entry["local_flags"].as_array().into_iter().flatten() {
                let name = flag["name"].as_str().expect("flag name");
                if flag["type"] != "bool" || name == "help" {
                    continue;
                }
                let long = format!("--{name}");
                let mut forms = vec![
                    vec![format!("{long}=false")],
                    vec![long.clone(), format!("{long}=false")],
                    vec![format!("{long}=false"), long.clone()],
                    vec![format!("{long}=F"), format!("{long}=1")],
                ];
                if let Some(short) = flag["shorthand"].as_str() {
                    forms.push(vec![format!("-{short}=false")]);
                }
                for form in forms {
                    let mut argv = vec!["symvault".to_owned()];
                    argv.extend(path.split(' ').map(str::to_owned));
                    argv.extend(form);
                    parsed += 1;
                    if let Err(error) = root.clone().try_get_matches_from(&argv) {
                        assert!(
                            matches!(
                                error.kind(),
                                ErrorKind::MissingRequiredArgument
                                    | ErrorKind::MissingSubcommand
                                    | ErrorKind::DisplayHelp
                                    | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                            ),
                            "{}: {:?}: {error}",
                            argv.join(" "),
                            error.kind()
                        );
                    }
                }
            }
        }
        assert!(parsed > 300, "only {parsed} argument vectors parsed");
    }

    #[test]
    fn duration_flag_table_names_duration_flags() {
        let tree = tree();
        for (path, name) in DURATION_FLAGS {
            let entry = tree["commands"]
                .as_array()
                .expect("commands")
                .iter()
                .find(|entry| go_path(entry) == *path)
                .unwrap_or_else(|| panic!("{path} is not in the command tree"));
            let flag = entry["local_flags"]
                .as_array()
                .expect("flags")
                .iter()
                .find(|flag| flag["name"] == *name)
                .unwrap_or_else(|| panic!("{path} has no --{name}"));
            assert_eq!(flag["type"], "duration", "{path} --{name}");
        }
    }

    /// Error texts recorded from the pinned Go binary (`symvault run --timeout
    /// <value>`, which prints `time.ParseDuration`'s error after pflag's `invalid
    /// argument ... flag:` prefix) and values it accepted (a vault error, not a
    /// flag error, follows).
    #[test]
    fn go_duration_errors_match_the_recorded_oracle_texts() {
        for (value, expected) in [
            ("5", Some("time: missing unit in duration \"5\"")),
            ("", Some("time: invalid duration \"\"")),
            ("x", Some("time: invalid duration \"x\"")),
            ("5x", Some("time: unknown unit \"x\" in duration \"5x\"")),
            ("1h30", Some("time: missing unit in duration \"1h30\"")),
            (
                "1é",
                Some("time: unknown unit \"\\xc3\\xa9\" in duration \"1\\xc3\\xa9\""),
            ),
            (
                "9223372036854775807s",
                Some("time: invalid duration \"9223372036854775807s\""),
            ),
            ("0.0.1s", Some("time: missing unit in duration \"0.0.1s\"")),
            (
                "9223372036854775808ns",
                Some("time: invalid duration \"9223372036854775808ns\""),
            ),
            (
                "-9223372036854775809ns",
                Some("time: invalid duration \"-9223372036854775809ns\""),
            ),
            ("9223372036854775807ns", None),
            ("2μs", None),
            ("0.5h", None),
            ("0", None),
            ("-0", None),
            ("+0", None),
            ("+5s", None),
            ("1.5s", None),
            (".5s", None),
            ("1h30m", None),
            ("2µs", None),
            ("-9223372036854775808ns", None),
        ] {
            assert_eq!(
                symvault_core::config::parse_go_duration(value)
                    .err()
                    .as_deref(),
                expected,
                "{value:?}"
            );
        }
    }

    #[test]
    fn integer_flag_table_names_integer_flags() {
        let tree = tree();
        for (path, name) in INT_FLAGS {
            let entry = tree["commands"]
                .as_array()
                .expect("commands")
                .iter()
                .find(|entry| go_path(entry) == *path)
                .unwrap_or_else(|| panic!("{path} is not in the command tree"));
            let flag = entry["local_flags"]
                .as_array()
                .expect("flags")
                .iter()
                .find(|flag| flag["name"] == *name)
                .unwrap_or_else(|| panic!("{path} has no --{name}"));
            assert!(
                matches!(flag["type"].as_str(), Some("int" | "int64")),
                "{path} --{name} is {}",
                flag["type"]
            );
        }
    }

    #[test]
    fn string_slice_flag_table_names_string_slice_flags() {
        let tree = tree();
        for (path, name) in STRING_SLICE_FLAGS {
            let entry = tree["commands"]
                .as_array()
                .expect("commands")
                .iter()
                .find(|entry| go_path(entry) == *path)
                .unwrap_or_else(|| panic!("{path} is not in the command tree"));
            let flag = entry["local_flags"]
                .as_array()
                .expect("flags")
                .iter()
                .find(|flag| flag["name"] == *name)
                .unwrap_or_else(|| panic!("{path} has no --{name}"));
            assert_eq!(flag["type"], "stringSlice", "{path} --{name}");
        }
    }

    /// Every flag of the Go tree whose type is not string or bool (and not a
    /// `stringArray`, which takes any value) must be in exactly the table of its type,
    /// and the required flags must be exactly the `MarkFlagRequired` ones, so a new
    /// typed or required flag cannot ship without Go's diagnostic.
    #[test]
    fn typed_flag_tables_cover_every_typed_flag_of_the_command_tree() {
        let tree = tree();
        let mut problems = Vec::new();
        let mut typed = 0;
        let mut required = Vec::new();
        for entry in tree["commands"].as_array().expect("commands") {
            let path = go_path(entry);
            for key in ["local_flags", "persistent_flags"] {
                for flag in entry[key].as_array().into_iter().flatten() {
                    let name = flag["name"].as_str().expect("flag name");
                    let kind = flag["type"].as_str().expect("flag type");
                    let key = (path.as_str(), name);
                    let tables: [(&str, &[(&str, &str)]); 3] = [
                        ("int", INT_FLAGS),
                        ("duration", DURATION_FLAGS),
                        ("stringSlice", STRING_SLICE_FLAGS),
                    ];
                    for (table_kind, table) in tables {
                        let listed = table.contains(&key);
                        let expected =
                            kind == table_kind || (table_kind == "int" && kind == "int64");
                        if listed != expected {
                            problems.push(format!(
                                "{path} --{name} is {kind}, {table_kind} table lists it: {listed}"
                            ));
                        }
                    }
                    if !matches!(kind, "bool" | "string" | "stringArray") {
                        typed += 1;
                    }
                    if flag["annotations"]["cobra_annotation_bash_completion_one_required_flag"]
                        .is_array()
                    {
                        required.push((path.clone(), name.to_owned()));
                    }
                }
            }
        }
        assert!(typed >= 23, "only {typed} typed flags in the tree");
        let mut table: Vec<(String, String)> = REQUIRED_FLAGS
            .iter()
            .flat_map(|(path, names)| {
                names
                    .iter()
                    .map(move |name| ((*path).to_owned(), (*name).to_owned()))
            })
            .collect();
        table.sort();
        required.sort();
        assert_eq!(
            table, required,
            "REQUIRED_FLAGS vs the tree's required flags"
        );
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    /// Texts recorded from the pinned Go binary (`symvault doctor --only <value>`: the
    /// `encoding/csv` error after pflag's `invalid argument ... flag:` prefix).
    #[test]
    fn go_csv_errors_match_the_recorded_oracle_texts() {
        for (value, expected) in [
            (
                "\"a",
                Some("parse error on line 1, column 3: extraneous or missing \" in quoted-field"),
            ),
            (
                "a\"b",
                Some("parse error on line 1, column 2: bare \" in non-quoted-field"),
            ),
            (
                "a,b\"",
                Some("parse error on line 1, column 4: bare \" in non-quoted-field"),
            ),
            (
                "\"a\"b",
                Some("parse error on line 1, column 3: extraneous or missing \" in quoted-field"),
            ),
            (
                "a,\"b\"c",
                Some("parse error on line 1, column 5: extraneous or missing \" in quoted-field"),
            ),
            ("\n", Some("EOF")),
            (
                "\"a\nb",
                Some(
                    "record on line 1; parse error on line 2, column 2: extraneous or missing \" in quoted-field",
                ),
            ),
            ("a,b", None),
            ("", None),
            ("\"a,b\"", None),
            ("\"a\"\"b\"", None),
            ("\"a\nb\"", None),
            (
                "a\"",
                Some("parse error on line 1, column 2: bare \" in non-quoted-field"),
            ),
            (
                "\n\n\"a",
                Some("parse error on line 3, column 3: extraneous or missing \" in quoted-field"),
            ),
            ("a\nb\"", None),
            (
                "\"a\r\nb",
                Some(
                    "record on line 1; parse error on line 2, column 2: extraneous or missing \" in quoted-field",
                ),
            ),
            ("\r\n", Some("EOF")),
            (
                "\"",
                Some("parse error on line 1, column 2: extraneous or missing \" in quoted-field"),
            ),
            (
                "\"\n",
                Some("parse error on line 1, column 3: extraneous or missing \" in quoted-field"),
            ),
            (
                "\"a\r",
                Some("parse error on line 1, column 3: extraneous or missing \" in quoted-field"),
            ),
            (
                "a\r\"",
                Some("parse error on line 1, column 3: bare \" in non-quoted-field"),
            ),
            (
                "x,\"y\n\"z\"w",
                Some(
                    "record on line 1; parse error on line 2, column 1: extraneous or missing \" in quoted-field",
                ),
            ),
            ("a,\n\"b", None),
            ("a\n\"", None),
            ("a\r\nb\"", None),
        ] {
            assert_eq!(go_csv_error(value).as_deref(), expected, "{value:?}");
        }
    }

    /// `pflag.StringSlice` over real pflag v1.0.10 (`--s=<occurrence>` for each occurrence,
    /// recorded with a Go program that calls `FlagSet.Parse`): the elements, or the
    /// reader's message of the first failing occurrence.
    #[test]
    fn go_csv_record_equals_pflag_string_slice() {
        type Row = (
            &'static [&'static str],
            Result<&'static [&'static str], &'static str>,
        );
        let rows: &[Row] = &[
            (&[""], Ok(&[])),
            (&["a"], Ok(&["a"])),
            (&["a,b"], Ok(&["a", "b"])),
            (&["a,,b"], Ok(&["a", "", "b"])),
            (&[","], Ok(&["", ""])),
            (&["a,"], Ok(&["a", ""])),
            (&[",a"], Ok(&["", "a"])),
            (&["\"a,b\",c"], Ok(&["a,b", "c"])),
            (&["\"a\"\"b\""], Ok(&["a\"b"])),
            (
                &["\"a\"b"],
                Err("parse error on line 1, column 3: extraneous or missing \" in quoted-field"),
            ),
            (
                &["a\"b"],
                Err("parse error on line 1, column 2: bare \" in non-quoted-field"),
            ),
            (
                &["\"a"],
                Err("parse error on line 1, column 3: extraneous or missing \" in quoted-field"),
            ),
            (
                &["\""],
                Err("parse error on line 1, column 2: extraneous or missing \" in quoted-field"),
            ),
            (&["\n"], Err("EOF")),
            (&["\n\na,b"], Ok(&["a", "b"])),
            (&["a,b\nc"], Ok(&["a", "b"])),
            (&["a,b\r\nc"], Ok(&["a", "b"])),
            (&["\"a\nb\",c"], Ok(&["a\nb", "c"])),
            (&["\"a\r\nb\""], Ok(&["a\nb"])),
            (&["a\rb"], Ok(&["a\rb"])),
            (&["a\r"], Ok(&["a"])),
            (&[" a , b"], Ok(&[" a ", " b"])),
            (&["\\,"], Ok(&["\\", ""])),
            (&["a\\,b"], Ok(&["a\\", "b"])),
            (&["\"\""], Ok(&[""])),
            (
                &["\"\"x"],
                Err("parse error on line 1, column 2: extraneous or missing \" in quoted-field"),
            ),
            (&["\"\",a"], Ok(&["", "a"])),
            (&["a,\"\""], Ok(&["a", ""])),
            (&["\"a\",\"b\""], Ok(&["a", "b"])),
            (
                &["\"a\" ,b"],
                Err("parse error on line 1, column 3: extraneous or missing \" in quoted-field"),
            ),
            (&["é,ü"], Ok(&["é", "ü"])),
            (&["\"é\",\"ü\""], Ok(&["é", "ü"])),
            (&["a\n"], Ok(&["a"])),
            (&["a,b\n"], Ok(&["a", "b"])),
            (&["\n"], Err("EOF")),
            (
                &["x,\"y\n\"z\"w"],
                Err(
                    "record on line 1; parse error on line 2, column 1: extraneous or missing \" in quoted-field",
                ),
            ),
            (
                &["\"a,b\",\"c"],
                Err("parse error on line 1, column 9: extraneous or missing \" in quoted-field"),
            ),
            (&["a,\n\"b"], Ok(&["a", ""])),
            (&["\"a\"\r\n"], Ok(&["a"])),
            (&["\"a\"\n\"b\""], Ok(&["a"])),
            (
                &["\"a\nb"],
                Err(
                    "record on line 1; parse error on line 2, column 2: extraneous or missing \" in quoted-field",
                ),
            ),
            (&["a", "b,c"], Ok(&["a", "b", "c"])),
            (&["", "x"], Ok(&["x"])),
            (&["x", ""], Ok(&["x"])),
            (
                &["\"a", "b"],
                Err("parse error on line 1, column 3: extraneous or missing \" in quoted-field"),
            ),
        ];
        assert_eq!(rows.len(), 45);
        let mut errors = 0;
        for (occurrences, expected) in rows {
            let occurrences: Vec<String> = occurrences
                .iter()
                .map(|value| (*value).to_owned())
                .collect();
            let mut actual: Result<Vec<String>, String> = Ok(Vec::new());
            for occurrence in &occurrences {
                match go_csv_record(occurrence) {
                    Ok(record) => {
                        if let Ok(values) = &mut actual {
                            values.extend(record);
                        }
                    }
                    Err(reason) => {
                        actual = Err(reason);
                        break;
                    }
                }
            }
            let expected = expected
                .map(|values| {
                    values
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>()
                })
                .map_err(str::to_owned);
            assert_eq!(actual, expected, "{occurrences:?}");
            if let Err(reason) = &expected {
                errors += 1;
                let first = occurrences.iter().find_map(|value| go_csv_error(value));
                assert_eq!(first.as_ref(), Some(reason), "{occurrences:?}");
            } else {
                // Every accepted occurrence has no error; string_slice_flag appends them.
                assert!(
                    occurrences
                        .iter()
                        .all(|value| go_csv_error(value).is_none())
                );
                assert_eq!(
                    Ok(string_slice_flag(&occurrences, &["*"])),
                    expected,
                    "{occurrences:?}"
                );
            }
        }
        assert_eq!(errors, 12);
    }

    #[test]
    fn string_slice_flag_keeps_the_default_only_without_an_occurrence() {
        let none: Vec<String> = Vec::new();
        assert_eq!(string_slice_flag(&none, &["*"]), ["*"]);
        assert!(string_slice_flag(&none, &[]).is_empty());
        let empty = vec![String::new()];
        assert!(string_slice_flag(&empty, &["*"]).is_empty());
        let two = vec!["a,b".to_owned(), "\"c,d\"".to_owned()];
        assert_eq!(string_slice_flag(&two, &["*"]), ["a", "b", "c,d"]);
    }

    #[test]
    fn command_and_group_tables_equal_the_command_tree() {
        let tree = tree();
        let mut runnable = Vec::new();
        let mut groups = Vec::new();
        let mut all = Vec::new();
        for entry in tree["commands"].as_array().expect("commands") {
            let path = go_path(entry);
            if path.is_empty() {
                continue;
            }
            if entry["runnable"] == true {
                runnable.push(path.clone());
            } else {
                groups.push(path.clone());
            }
            all.push(path);
        }
        let diff = |label: &str, table: &[&str], expected: &[String]| {
            let mut problems = Vec::new();
            for path in expected {
                if !table.contains(&path.as_str()) {
                    problems.push(format!("{label} is missing {path:?}"));
                }
            }
            for path in table {
                if !expected.iter().any(|candidate| candidate == path) {
                    problems.push(format!("{label} has the extra entry {path:?}"));
                }
            }
            problems
        };
        let mut problems = diff("COMMANDS", COMMANDS, &all);
        problems.extend(diff("GROUPS", GROUPS, &groups));
        // An arity rule can only belong to a runnable command (the converse does not
        // hold: commands whose validator accepts anything have no rule).
        for (path, _) in ARITY {
            if !runnable.iter().any(|candidate| candidate == path) {
                problems.push(format!("ARITY names {path:?}, which is not runnable"));
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    #[test]
    fn find_url_replaces_the_query_argument() {
        let run = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            evaluate(&args, root())
        };
        assert_eq!(run(&["find", "--url", "github.com"]), Verdict::Proceed);
        assert_eq!(run(&["find", "--url=github.com"]), Verdict::Proceed);
        assert_eq!(run(&["find", "--url", "x", "q"]), Verdict::Proceed);
        assert!(matches!(run(&["find", "--url", ""]), Verdict::Fail { .. }));
        assert!(matches!(run(&["find", "a", "b"]), Verdict::Fail { .. }));
    }

    #[test]
    fn no_args_reports_the_first_pflag_positional() {
        for args in [
            vec!["config", "list", "--profile", "unused", "other", "x"],
            vec!["config", "list", "--", "other", "x"],
        ] {
            assert_eq!(
                verdict(&args),
                fail("unknown command \"other\" for \"symvault config list\"", 1)
            );
        }
        assert_eq!(verdict(&["get", "-"]), Verdict::Proceed);
        assert_eq!(
            verdict(&["-", "get", "x"]),
            fail("accepts 1 arg(s), received 2", 1)
        );
        assert_eq!(
            verdict(&["config", "-", "get", "x"]),
            fail("accepts 1 arg(s), received 2", 1)
        );
        // Non-root commands with Args == nil use legacyArgs, not NoArgs.
        for args in [
            vec!["lock", "x"],
            vec!["generate", "x"],
            vec!["share", "list", "x"],
        ] {
            assert_eq!(verdict(&args), Verdict::Proceed);
        }
    }

    /// The arguments clap parses for `args` (without the program name).
    fn clap_args(args: &[&str]) -> Vec<String> {
        let mut all = vec![std::ffi::OsString::from("symvault")];
        all.extend(args.iter().map(std::ffi::OsString::from));
        clap_arguments(all, root())
            .into_iter()
            .skip(1)
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn root_without_a_command_prints_its_help_like_cobra() {
        let verdict = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            evaluate_with_required(&args, root())
        };
        let root_help = Verdict::GroupHelp(String::new());
        // No command: a lone dash, `--` and everything after it, persistent flags only.
        for args in [
            vec![],
            vec!["-"],
            vec!["--"],
            vec!["-", "--"],
            vec!["--", "-"],
            vec!["-", "-"],
            vec!["--json"],
            vec!["--output", "xml"],
            vec!["--json", "-"],
            vec!["--", "list"],
            vec!["--", "get", "x"],
            vec!["--", "help"],
            vec!["--", "--json"],
            vec!["--", "--version"],
            vec!["--vault", "somewhere"],
        ] {
            assert_eq!(verdict(&args), root_help, "{args:?}");
        }
        // `help` is a command of the native help handler, not an empty root.
        assert_eq!(verdict(&["help"]), Verdict::Proceed);
        assert_eq!(verdict(&["-", "help"]), Verdict::Proceed);
        // A word before `--` is still resolved (and reported) as before.
        assert!(matches!(
            verdict(&["-", "unknownthing"]),
            Verdict::Fail { code: 1, .. }
        ));
    }

    #[test]
    fn a_lone_dash_moves_behind_the_last_command_word_for_clap() {
        // cobra skips the dash while it resolves the command and counts it as a positional of
        // the command; clap would read it as the parent's first positional.
        assert_eq!(clap_args(&["-", "list"]), ["list", "-"]);
        assert_eq!(clap_args(&["share", "-", "list"]), ["share", "list", "-"]);
        assert_eq!(clap_args(&["-", "share", "list"]), ["share", "list", "-"]);
        assert_eq!(clap_args(&["-", "-", "list"]), ["list", "-", "-"]);
        assert_eq!(
            clap_args(&["-", "share", "-", "list"]),
            ["share", "list", "-", "-"]
        );
        // Flags keep their place; only the positional dash moves.
        assert_eq!(clap_args(&["-", "--json", "list"]), ["--json", "list", "-"]);
        assert_eq!(
            clap_args(&["--vault", "-", "list"]),
            ["--vault", "-", "list"],
            "a flag's value is not a positional"
        );
        assert_eq!(clap_args(&["--vault=-", "list"]), ["--vault=-", "list"]);
        // The dash goes right behind the word, ahead of what cobra passes after it.
        assert_eq!(clap_args(&["-", "list", "foo"]), ["list", "-", "foo"]);
        assert_eq!(
            clap_args(&["-", "version", "--json"]),
            ["version", "-", "--json"]
        );
        // `help` walks its topic itself.
        assert_eq!(clap_args(&["-", "help", "list"]), ["help", "-", "list"]);
        // Nothing to move: unchanged, including a dash behind the word or after `--`.
        for args in [
            vec!["list", "-"],
            vec!["list"],
            vec!["-"],
            vec!["help", "-", "list"],
            vec!["-", "unknownthing"],
            vec!["--", "-"],
            vec!["run", "--", "-"],
        ] {
            assert_eq!(clap_args(&args), args, "{args:?}");
        }
    }

    #[test]
    fn mutated_expectation_is_detected() {
        let fixture = fixture();
        let case = fixture
            .usage
            .iter()
            .find(|case| case.name == "unknown_flag_get")
            .expect("case");
        let mut tampered = expect_fail(&case.observation);
        if let Verdict::Fail { stderr, .. } = &mut tampered {
            stderr.push('x');
        }
        assert_ne!(evaluate(&case.observation.args, root()), tampered);
    }
}
