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
//! `ARITY`, `GROUPS` and `OUTPUT_UNSUPPORTED` are checked against that fixture
//! row by row, so they cannot drift from the oracle unnoticed.
//!
//! Known limits: flag *types* are not introspected, so only booleans and the
//! integer flags in `INT_FLAGS` get Go's `invalid argument` wording; a flag that
//! exists only in Go is not reported as unknown by Rust's tree; and the
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
    Exact(usize),
    Min(usize),
    Max(usize),
    Range(usize, usize),
    /// `device join`: exactly two, reported with a range message and an explanation.
    JoinPair,
    /// `find`: one query, unless `--url` is set; reported as "at most" once more are given.
    QueryOrUrl,
}

const JOIN_SUFFIX: &str = " — either '<remote-url> <token>' or '--pairing-file <path> <token>'";

/// Integer-valued flags, by command path and long name.
const INT_FLAGS: &[(&str, &str)] = &[("generate", "length")];

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
    ("config set", Rule::Exact(2)),
    ("config validate", Rule::Max(1)),
    ("delete", Rule::Exact(1)),
    ("device accept", Rule::Exact(1)),
    ("device approval-revoke", Rule::Exact(1)),
    ("device join", Rule::JoinPair),
    ("device revoke", Rule::Exact(1)),
    ("edit", Rule::Exact(1)),
    ("file add", Rule::Exact(1)),
    ("file get", Rule::Exact(1)),
    ("file use", Rule::Min(2)),
    ("find", Rule::QueryOrUrl),
    ("generate manpages", Rule::Exact(1)),
    ("get", Rule::Exact(1)),
    ("git", Rule::Range(1, 2)),
    ("import", Rule::Exact(1)),
    ("import review promote", Rule::Exact(1)),
    ("init", Rule::Max(1)),
    ("intake", Rule::Min(1)),
    ("intake watch", Rule::Exact(1)),
    ("list", Rule::Max(1)),
    ("policy apply", Rule::Exact(1)),
    ("policy remove", Rule::Exact(1)),
    ("policy validate", Rule::Exact(1)),
    ("profile add", Rule::Exact(1)),
    ("profile use", Rule::Exact(1)),
    ("recipients add", Rule::Exact(1)),
    ("recipients remove", Rule::Exact(1)),
    ("remote init", Rule::Exact(1)),
    ("restore", Rule::Exact(1)),
    ("run", Rule::Min(1)),
    ("set", Rule::Exact(1)),
    ("share revoke", Rule::Exact(1)),
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

/// The message cobra's argument validator reports, if it rejects `count`.
fn arity_message(path: &str, count: usize, url_filter: bool) -> Option<String> {
    let at_least = |min: usize| format!("requires at least {min} arg(s), only received {count}");
    let exact = |n: usize| format!("accepts {n} arg(s), received {count}");
    let at_most = |n: usize| format!("accepts at most {n} arg(s), received {count}");
    match rule_for(path)? {
        Rule::Exact(n) => (count != n).then(|| exact(n)),
        Rule::Min(n) => (count < n).then(|| at_least(n)),
        Rule::Max(n) => (count > n).then(|| at_most(n)),
        Rule::Range(min, max) => (count < min || count > max)
            .then(|| format!("accepts between {min} and {max} arg(s), received {count}")),
        Rule::JoinPair => (count != 2)
            .then(|| format!("accepts between 1 and 2 arg(s), received {count}{JOIN_SUFFIX}")),
        Rule::QueryOrUrl => {
            if count > 1 {
                Some(at_most(1))
            } else if count == 0 && !url_filter {
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

fn doubled(message: &str) -> String {
    format!("Error: {message}\nError: {message}\n")
}

fn fail(message: &str, code: u8) -> Verdict {
    Verdict::Fail {
        stderr: doubled(message),
        code,
    }
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

/// Flags that clap models as taking a value but Go declares as booleans, so the
/// token after them is a positional argument in Go (`device join --pairing-file
/// <path> <token>`).
const GO_BOOL_FLAGS: &[(&str, &str)] = &[("device join", "pairing-file")];

/// pflag consumes the next token for every flag that is not a bool and has no
/// no-option default (clap: not `require_equals`).
fn eats_next(arg: &Arg) -> bool {
    arg.get_action().takes_values() && !arg.is_require_equals_set()
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
        } else {
            // A lone "-" is positional.
            positional.push(token.clone());
        }
        index += 1;
    }
    positional
}

/// cobra's `argsMinusFirstX`: drop the first occurrence of the command word.
fn args_minus_first(tokens: &[String], word: &str, flags: Flags<'_>, lenient: bool) -> Vec<String> {
    let mut kept = Vec::new();
    let mut removed = false;
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if token == "--" {
            kept.extend(tokens[index..].iter().cloned());
            break;
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
            kept.push(token.clone());
            if let Some(next) = tokens.get(index + 1) {
                kept.push(next.clone());
            }
            index += 2;
            continue;
        }
        if !removed && token == word {
            removed = true;
        } else {
            kept.push(token.clone());
        }
        index += 1;
    }
    kept
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

fn go_parse_int(value: &str) -> bool {
    let digits = value
        .strip_prefix('+')
        .or_else(|| value.strip_prefix('-'))
        .unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

fn flag_label(arg: &Arg) -> String {
    let long = arg.get_long().unwrap_or_default();
    match arg.get_short() {
        Some(short) => format!("-{short}, --{long}"),
        None => format!("--{long}"),
    }
}

fn invalid_argument(value: &str, arg: &Arg, parser: &str) -> String {
    format!(
        "invalid argument {value:?} for {label:?} flag: strconv.{parser}: parsing {value:?}: invalid syntax",
        label = flag_label(arg)
    )
}

struct Parsed {
    positionals: usize,
    /// `find --url <non-empty>`: the only flag an argument validator reads.
    url_filter: bool,
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
        positionals: 0,
        url_filter: false,
        json_flag: false,
        output: None,
    };
    let mut index = 0;
    let note = |arg: &Arg, value: Option<&str>, parsed: &mut Parsed| match (arg.get_long(), value) {
        (Some("json"), _) => parsed.json_flag = true,
        (Some("output"), Some(value)) => parsed.output = Some(value.to_owned()),
        (Some("url"), Some(value)) if path == "find" => parsed.url_filter = !value.is_empty(),
        _ => {}
    };
    while index < tokens.len() {
        let token = &tokens[index];
        index += 1;
        if token == "--" {
            parsed.positionals += tokens.len() - index;
            break;
        }
        if let Some(rest) = token.strip_prefix("--") {
            let (name, inline) = match rest.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (rest, None),
            };
            let Some(arg) = flags.long(name) else {
                if lenient {
                    continue;
                }
                return Err(format!("unknown flag: --{name}"));
            };
            if is_help_arg(arg) || GO_BOOL_FLAGS.contains(&(path, name)) {
                continue;
            }
            if arg.get_action().takes_values() {
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
                if INT_FLAGS.contains(&(path, name)) && !go_parse_int(&value) {
                    return Err(invalid_argument(&value, arg, "ParseInt"));
                }
                note(arg, Some(&value), &mut parsed);
            } else {
                if let Some(value) = inline
                    && !go_parse_bool(value)
                {
                    return Err(invalid_argument(value, arg, "ParseBool"));
                }
                let enabled = inline.is_none_or(|value| {
                    matches!(value, "1" | "t" | "T" | "TRUE" | "true" | "True")
                });
                if enabled {
                    note(arg, None, &mut parsed);
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
                if is_help_arg(arg) || !arg.get_action().takes_values() {
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
                if INT_FLAGS.contains(&(path, long)) && !go_parse_int(&value) {
                    return Err(invalid_argument(&value, arg, "ParseInt"));
                }
                note(arg, Some(&value), &mut parsed);
                break;
            }
        } else {
            parsed.positionals += 1;
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

/// Evaluates `args` (without the program name) the way cobra does.
pub fn evaluate(args: &[String], mut root: Command) -> Verdict {
    if args
        .iter()
        .take_while(|token| *token != "--")
        .any(|token| token == "-h" || token == "--help")
    {
        return Verdict::Proceed;
    }
    root.build();
    let mut current = Node {
        command: None,
        path: Vec::new(),
    };
    let mut tokens = args.to_vec();
    loop {
        let flags = Flags {
            command: current.command.unwrap_or(&root),
            root: &root,
        };
        let lenient = current.command.is_none() && !current.path.is_empty();
        let positional = strip_flags(&tokens, flags, lenient);
        let Some(first) = positional.first() else {
            break;
        };
        let lookup = Node {
            command: current.command.or(current.path.is_empty().then_some(&root)),
            path: current.path.clone(),
        };
        match find_next(&lookup, first) {
            Some(next) => {
                tokens = args_minus_first(&tokens, first, flags, lenient);
                current = next;
            }
            None => {
                if current.path.is_empty() {
                    if first == "help" {
                        return Verdict::Proceed;
                    }
                    return unknown_command(first);
                }
                break;
            }
        }
    }
    let path_text = current.path.join(" ");
    let flags = Flags {
        command: current.command.unwrap_or(&root),
        root: &root,
    };
    let lenient = current.command.is_none() && !current.path.is_empty();
    let parsed = match parse_flags(&tokens, flags, &path_text, lenient) {
        Ok(parsed) => parsed,
        Err(message) => return fail(&message, 1),
    };
    if current.path.is_empty() {
        return Verdict::Proceed;
    }
    if GROUPS.contains(&path_text.as_str()) {
        return Verdict::GroupHelp(path_text);
    }
    if let Some(message) = arity_message(&path_text, parsed.positionals, parsed.url_filter) {
        return fail(&message, 1);
    }
    if let Some(format) = refused_format(&path_text, parsed.json_flag, parsed.output.as_deref()) {
        return fail(&gate_message(&format, &path_text), 9);
    }
    Verdict::Proceed
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
    match evaluate(&strings, root) {
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
    fn go_bool_and_int_syntax() {
        assert!(go_parse_bool("T") && go_parse_bool("false") && !go_parse_bool("maybe"));
        assert!(
            go_parse_int("-12") && go_parse_int("+3") && !go_parse_int("a") && !go_parse_int("")
        );
    }

    #[test]
    fn arity_messages_follow_cobra_validators() {
        assert_eq!(
            arity_message("get", 0, false).as_deref(),
            Some("accepts 1 arg(s), received 0")
        );
        assert_eq!(arity_message("get", 1, false), None);
        assert_eq!(
            arity_message("find", 4, false).as_deref(),
            Some("accepts at most 1 arg(s), received 4")
        );
        assert_eq!(
            arity_message("run", 0, false).as_deref(),
            Some("requires at least 1 arg(s), only received 0")
        );
        assert_eq!(arity_message("version", 9, false), None);
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
    struct Fixture {
        usage: Vec<UsageCase>,
        arity: Vec<ArityRow>,
        gate: Vec<GateRow>,
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
            let got = evaluate(&case.observation.args, root());
            let want = if case.observation.exit_code == 0 {
                // Group help (stdout) or a successful command: never a failure.
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
                        !matches!(&got, Verdict::Fail { stderr, .. } if stderr.contains(" arg(s)")),
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
