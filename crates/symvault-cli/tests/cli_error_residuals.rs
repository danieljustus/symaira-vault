//! CLI-005 residuals R1, R2, R3 and R20 of ADR 0037 ("To be recorded from
//! `legacy/go-oracle`"). Each test calls the Go oracle for every input and compares
//! the Rust binary with the answer byte for byte; the Go answers are the
//! recording `testdata/port/cli-transcripts/cli_error_residuals.json`
//! (oracle `legacy/go-oracle`, `ce2390d7`). The same file runs in the oracle
//! worktree, where `SYMVAULT_ORACLE=capture` records and the Rust side is not
//! executed (the Rust tree there is the old one).
//!
//! * R1 `suggestion_order_matches_go_for_every_colliding_input`: cobra's
//!   `Did you mean this?` list for every unknown top-level word with two or more
//!   suggestions: all 1-edit typos of every command name and all one- and
//!   two-letter words. Go lists them in registration order.
//! * R2 `bare_dash_get_matches_go_in_the_go_initialized_vault`: `get -`,
//!   `get - x` and their permutations against a vault `symvault init` of the oracle
//!   created (frozen as a seed).
//! * R3 `not_initialized_shapes_match_go_for_every_runnable_command`: every
//!   runnable path of `command-tree.json` in an empty sandbox, with the flags that
//!   get it past its own pre-checks, plus the approval/file/device variants.
//! * R20 `alias_after_a_redefined_anchor_matches_go`: aliases of a redefined YAML
//!   anchor before and after the redefinition.

#[path = "common/go_oracle.rs"]
mod go_oracle;

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const FILE: &str = "cli_error_residuals";
const PASSPHRASE: &str = "correct horse battery staple";

fn rust_binary() -> PathBuf {
    PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"))
}

fn tree() -> serde_json::Value {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/port/cli/command-tree.json");
    serde_json::from_slice(&fs::read(path).expect("command-tree.json")).expect("command tree")
}

/// `(path words, hidden, runnable, accepted positional counts)` of every command.
fn commands() -> Vec<(Vec<String>, bool, bool, Vec<usize>)> {
    tree()["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .map(|c| {
            let words = c["path"]
                .as_str()
                .expect("path")
                .split_whitespace()
                .skip(1)
                .map(str::to_owned)
                .collect();
            let accepted = c["argument_count_probes"]
                .as_array()
                .map(|probes| {
                    probes
                        .iter()
                        .filter(|p| p["accepted"].as_bool() == Some(true))
                        .map(|p| p["count"].as_u64().expect("count") as usize)
                        .collect()
                })
                .unwrap_or_default();
            (
                words,
                c["hidden"].as_bool().unwrap_or(false),
                c["runnable"].as_bool().unwrap_or(false),
                accepted,
            )
        })
        .collect()
}

/// The environment every call gets. `home` holds the home directory and the XDG
/// trees; `vault` is `SYMVAULT_VAULT` when the call targets a vault.
fn command(
    binary: &Path,
    args: &[&str],
    cwd: &Path,
    home: &Path,
    vault: Option<(&Path, bool)>,
) -> Command {
    let mut command = Command::new(binary);
    command
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .env("TZ", "UTC")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env_remove("SYMVAULT_AGENT")
        .env_remove("EDITOR")
        .env_remove("VISUAL");
    match vault {
        Some((root, unlocked)) => {
            command.env("SYMVAULT_VAULT", root);
            if unlocked {
                command
                    .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
                    .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1");
            } else {
                command
                    .env_remove("SYMVAULT_PASSPHRASE")
                    .env_remove("SYMVAULT_ALLOW_ENV_PASSPHRASE");
            }
        }
        None => {
            command
                .env_remove("SYMVAULT_VAULT")
                .env_remove("SYMVAULT_PASSPHRASE")
                .env_remove("SYMVAULT_ALLOW_ENV_PASSPHRASE");
        }
    }
    command
}

/// Replaces every spelling of `root` so a Go run and a Rust run in different
/// sandboxes compare equal.
fn normalized(bytes: &[u8], roots: &[&Path]) -> String {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    for root in roots {
        let mut spellings = vec![root.to_string_lossy().into_owned()];
        if let Ok(real) = fs::canonicalize(root) {
            spellings.push(real.to_string_lossy().into_owned());
        }
        spellings.sort_by_key(|s| std::cmp::Reverse(s.len()));
        for spelling in spellings {
            text = text.replace(&spelling, "<SANDBOX>");
        }
    }
    mask_temp_suffix(&text)
}

/// Go names the temp file of an atomic registry write `<file>.tmp-<random
/// decimal>` and the recording keeps the one value of that run. A different
/// random suffix is not a behaviour difference, so the digits after `.tmp-` are
/// replaced by `<RANDOM>` on both sides; the recording itself is untouched.
fn mask_temp_suffix(text: &str) -> String {
    const MARKER: &str = ".tmp-";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(MARKER) {
        let (head, tail) = rest.split_at(at + MARKER.len());
        out.push_str(head);
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 {
            out.push_str("<RANDOM>");
        }
        rest = &tail[digits..];
    }
    out.push_str(rest);
    out
}

#[derive(Debug, PartialEq, Eq)]
struct Observed {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn observe(output: &Output, roots: &[&Path]) -> Observed {
    Observed {
        code: output.status.code(),
        stdout: normalized(&output.stdout, roots),
        stderr: normalized(&output.stderr, roots),
    }
}

fn run_go(
    oracle: &go_oracle::GoOracle,
    args: &[&str],
    cwd: &Path,
    home: &Path,
    vault: Option<(&Path, bool)>,
) -> Output {
    go_oracle::output(&mut command(&oracle.binary(), args, cwd, home, vault)).expect("run Go")
}

fn run_rust(args: &[&str], cwd: &Path, home: &Path, vault: Option<(&Path, bool)>) -> Output {
    command(&rust_binary(), args, cwd, home, vault)
        .output()
        .expect("run Rust")
}

// ---------------------------------------------------------------- R1

fn levenshtein(left: &str, right: &str) -> usize {
    let left: Vec<char> = left.to_lowercase().chars().collect();
    let right: Vec<char> = right.to_lowercase().chars().collect();
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    for (i, l) in left.iter().enumerate() {
        let mut current = vec![i + 1];
        for (j, r) in right.iter().enumerate() {
            current.push(
                (previous[j] + usize::from(l != r))
                    .min(previous[j + 1] + 1)
                    .min(current[j] + 1),
            );
        }
        previous = current;
    }
    previous[right.len()]
}

/// Words cobra resolves to a command instead of reporting them unknown.
const ALIASES: [&str; 3] = ["gen", "ls", "rm"];

/// Words of two edits (and prefixes) that name the pairs of commands no 1-edit typo
/// or one- and two-letter word puts in one suggestion list: with them every pair of
/// visible commands that any word within two edits of both can reach (about 275 pairs)
/// has a recorded answer. Found by a greedy cover over the 2-edit neighbours of
/// the command names.
const PAIR_WITNESSES: [&str; 44] = [
    "are", "back", "bcup", "con", "dele", "doc", "dyn", "elet", "emot", "eriy", "etut", "evie",
    "exp", "extore", "fip", "genete", "imp", "inrate", "licy", "loit", "mnerate", "odk", "oek",
    "onig", "rest", "rok", "rostor", "sckup", "sint", "sire", "soc", "stake", "store", "telate",
    "tempte", "tplate", "tup", "udat", "uirate", "upare", "upd", "utp", "vice", "ynd",
];

/// Every unknown word that the model of cobra's `SuggestionsFor` (edit distance
/// of two or less, or a prefix) answers with two or more suggestions. The model
/// only selects the inputs; the order and the exact set are Go's.
fn suggestion_inputs() -> Vec<String> {
    let commands = commands();
    let mut names: BTreeSet<String> = commands
        .iter()
        .filter(|(words, _, _, _)| words.len() == 1)
        .map(|(words, _, _, _)| words[0].clone())
        .collect();
    names.insert("completion".to_owned());
    let visible: Vec<String> = commands
        .iter()
        .filter(|(words, hidden, _, _)| words.len() == 1 && !hidden && words[0] != "help")
        .map(|(words, _, _, _)| words[0].clone())
        .chain(["completion".to_owned()])
        .collect();
    let alphabet: Vec<char> = "abcdefghijklmnopqrstuvwxyz-".chars().collect();
    let mut candidates = BTreeSet::new();
    for name in &names {
        let chars: Vec<char> = name.chars().collect();
        let join = |parts: &[&[char]]| parts.iter().flat_map(|p| p.iter()).collect::<String>();
        for i in 0..chars.len() {
            candidates.insert(join(&[&chars[..i], &chars[i + 1..]]));
            for c in &alphabet {
                candidates.insert(join(&[&chars[..i], &[*c], &chars[i + 1..]]));
            }
            if i + 1 < chars.len() {
                candidates.insert(join(&[
                    &chars[..i],
                    &[chars[i + 1], chars[i]],
                    &chars[i + 2..],
                ]));
            }
        }
        for i in 0..=chars.len() {
            for c in &alphabet {
                candidates.insert(join(&[&chars[..i], &[*c], &chars[i..]]));
            }
        }
    }
    candidates.extend(PAIR_WITNESSES.iter().map(|word| (*word).to_owned()));
    for a in 'a'..='z' {
        candidates.insert(a.to_string());
        for b in 'a'..='z' {
            candidates.insert(format!("{a}{b}"));
        }
    }
    candidates
        .into_iter()
        .filter(|word| !word.is_empty() && !word.starts_with('-'))
        .filter(|word| !names.contains(word) && !ALIASES.contains(&word.as_str()))
        .filter(|word| {
            let lowered = word.to_lowercase();
            visible
                .iter()
                .filter(|name| levenshtein(word, name) <= 2 || name.starts_with(&lowered))
                .count()
                >= 2
        })
        .collect()
}

/// The suggestions of a cobra "unknown command" error, in the order printed.
fn suggestions(stderr: &str) -> Vec<String> {
    stderr
        .split("Did you mean this?\n")
        .nth(1)
        .map(|rest| {
            rest.lines()
                .take_while(|line| line.starts_with('\t'))
                .map(|line| line.trim_start_matches('\t').to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// `Err` names the first pair of commands that two answers list in opposite
/// orders: the answers cannot come from one registration order.
fn order_conflict(lists: &[Vec<String>]) -> Result<usize, String> {
    let mut before: BTreeSet<(String, String)> = BTreeSet::new();
    for list in lists {
        for (i, a) in list.iter().enumerate() {
            for b in &list[i + 1..] {
                if before.contains(&(b.clone(), a.clone())) {
                    return Err(format!("{a} and {b} are listed in both orders"));
                }
                before.insert((a.clone(), b.clone()));
            }
        }
    }
    Ok(before.len())
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn suggestion_order_matches_go_for_every_colliding_input() {
    let oracle = go_oracle::GoOracle::begin(
        FILE,
        "suggestion_order_matches_go_for_every_colliding_input",
        None,
    );
    let sandbox = tempfile::tempdir().expect("sandbox");
    let home = sandbox.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let inputs = suggestion_inputs();
    assert!(inputs.len() > 1900, "corpus shrank to {}", inputs.len());

    let mut lists = Vec::new();
    let mut failures = Vec::new();
    for word in &inputs {
        let args = [word.as_str()];
        let go = observe(
            &run_go(&oracle, &args, sandbox.path(), &home, None),
            &[sandbox.path()],
        );
        assert_eq!(
            go.code,
            Some(1),
            "{word}: Go does not report an unknown command"
        );
        assert!(
            go.stderr.starts_with(&format!(
                "Error: unknown command {word:?} for \"symvault\"\n"
            )),
            "{word}: {:?}",
            go.stderr
        );
        lists.push(suggestions(&go.stderr));
        if oracle.replaying() {
            let rust = observe(
                &run_rust(&args, sandbox.path(), &home, None),
                &[sandbox.path()],
            );
            if rust != go {
                failures.push(format!("{word}:\n  go:   {go:?}\n  rust: {rust:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    // The recording is only evidence of an order if the answers fit one order,
    // and the corpus must exercise many distinct orders and pairs.
    assert!(
        lists.iter().all(|list| list.len() >= 2),
        "a corpus word has fewer than two suggestions"
    );
    let pairs = order_conflict(&lists).expect("one registration order");
    let distinct: BTreeSet<&Vec<String>> = lists.iter().collect();
    assert!(distinct.len() >= 200, "{} distinct lists", distinct.len());
    assert!(pairs >= 270, "{pairs} ordered pairs");

    // Nested groups and `help` suggest nothing: cobra only suggests for the root.
    let nested: [&[&str]; 10] = [
        &["config", "gett"],
        &["agent", "lst"],
        &["file", "ad"],
        &["help", "lst"],
        &["help", "gett"],
        &["completion", "bas"],
        &["device", "lst"],
        &["audit", "expor"],
        &["mcp", "tokn"],
        &["share", "lst", "x"],
    ];
    for args in nested {
        let go = observe(
            &run_go(&oracle, args, sandbox.path(), &home, None),
            &[sandbox.path()],
        );
        assert!(
            suggestions(&go.stderr).is_empty(),
            "{args:?}: {:?}",
            go.stderr
        );
        if oracle.replaying() {
            let rust = observe(
                &run_rust(args, sandbox.path(), &home, None),
                &[sandbox.path()],
            );
            assert_eq!(rust, go, "{args:?}");
        }
    }
    // Upper-case words are lowered before the comparison.
    for word in ["LST", "GE", "Ini", "Sett", "AUDT"] {
        let args = [word];
        let go = observe(
            &run_go(&oracle, &args, sandbox.path(), &home, None),
            &[sandbox.path()],
        );
        if oracle.replaying() {
            let rust = observe(
                &run_rust(&args, sandbox.path(), &home, None),
                &[sandbox.path()],
            );
            assert_eq!(rust, go, "{word}");
        }
    }
    if oracle.replaying() {
        assert_eq!(oracle.calls(), inputs.len() + 10 + 5);
    }
}

#[test]
fn reordered_suggestions_and_contradicting_orders_are_detected() {
    let go = "Error: unknown command \"ait\" for \"symvault\"\n\nDid you mean this?\n\taudit\n\tinit\n\tauth\n\nRun 'symvault --help' for usage.\n";
    assert_eq!(suggestions(go), ["audit", "init", "auth"]);
    let swapped = go.replace("\tinit\n\tauth\n", "\tauth\n\tinit\n");
    assert_ne!(suggestions(&swapped), suggestions(go));
    let lists = [suggestions(go), suggestions(&swapped)];
    assert!(order_conflict(&lists).is_err());
    assert_eq!(order_conflict(&lists[..1]), Ok(3));
    assert!(suggestions("Error: unknown command \"x\" for \"symvault\"\n").is_empty());
}

#[test]
fn suggestion_corpus_is_systematic_and_alias_free() {
    let inputs = suggestion_inputs();
    for alias in ALIASES {
        assert!(!inputs.iter().any(|word| word == alias), "{alias}");
    }
    // Typos that collide with other commands are in, a typo with one candidate is not.
    for word in ["ait", "auit", "int", "seth", "lst", "ge", "g", "co", "sy"] {
        assert!(inputs.iter().any(|w| w == word), "{word} missing");
    }
    assert!(!inputs.iter().any(|w| w == "unlok"), "one suggestion only");
    assert!(
        inputs.windows(2).all(|pair| pair[0] < pair[1]),
        "corpus is sorted and unique"
    );
}

// ---------------------------------------------------------------- R2

/// `(label, entry names, argument lists)` of one frozen vault.
type VaultShape<'a> = (&'a str, &'a [&'a str], &'a [&'a [&'a str]]);

/// Creates a vault with the oracle: `init`, then one entry per name.
fn go_vault(oracle: &go_oracle::GoOracle, root: &Path, home: &Path, entries: &[&str]) {
    let binary = oracle.binary();
    let step = |args: &[&str]| {
        let output = command(&binary, args, root, home, Some((root, true)))
            .output()
            .expect("oracle set-up step");
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    step(&["init", "--auth", "passphrase"]);
    for (index, name) in entries.iter().enumerate() {
        let value = format!("value{index}");
        step(&["set", name, "--value", &value, "--force"]);
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn bare_dash_get_matches_go_in_the_go_initialized_vault() {
    let oracle = go_oracle::GoOracle::begin(
        FILE,
        "bare_dash_get_matches_go_in_the_go_initialized_vault",
        None,
    );
    let mut replayed = 0;
    // `get -` is a substring search over the entry fields (the names carry the
    // dashes, the values do not): several matches list them and fail, one match
    // prints the entry, none is "entry not found".
    let shapes: [VaultShape; 3] = [
        (
            "multiple",
            &["dash-site/login", "dash-two/login", "plain/entry"],
            &[
                &["get", "-"],
                &["get", "-", "x"],
                &["get", "x", "-"],
                &["get", "--", "-"],
                &["get", "--", "-", "x"],
                &["--json", "get", "-"],
                &["get", "-", "--json"],
                &["--output", "yaml", "get", "-"],
                &["-", "get", "-"],
                &["-", "get"],
                &["get", "-", "-"],
                &["get", "zzz-none"],
            ],
        ),
        (
            "single",
            &["only-dash/login", "plain/entry"],
            &[
                &["get", "-"],
                &["get", "-", "x"],
                &["--json", "get", "-"],
                &["get", "--", "-"],
                &["get", "--length", "-"],
                &["get", "-", "--metadata"],
            ],
        ),
        (
            "none",
            &["plain/entry", "other/thing"],
            &[
                &["get", "-"],
                &["get", "-", "x"],
                &["list", "-"],
                &["find", "-"],
            ],
        ),
    ];
    for (label, entries, cases) in shapes {
        let root = tempfile::tempdir().expect("vault root");
        let home = tempfile::tempdir().expect("home");
        // `init` draws fresh keys: the oracle's vault is frozen as a seed.
        oracle.seed(label, &[root.path(), home.path()], || {
            go_vault(&oracle, root.path(), home.path(), entries)
        });
        for args in cases {
            let vault = Some((root.path(), true));
            let go = observe(
                &run_go(&oracle, args, root.path(), home.path(), vault),
                &[root.path(), home.path()],
            );
            if oracle.replaying() {
                let rust = observe(
                    &run_rust(args, root.path(), home.path(), vault),
                    &[root.path(), home.path()],
                );
                assert_eq!(rust, go, "{label}: {args:?}");
            }
            replayed += 1;
        }
    }
    // The three shapes answer as the notes say (guards against a vacuous seed).
    assert!(replayed >= 20);
    if oracle.replaying() {
        assert_eq!(oracle.calls(), replayed);
    }
}

// ---------------------------------------------------------------- R3

/// Files a case needs in its sandbox: `(name, content)`.
type Files = &'static [(&'static str, &'static str)];
/// `(label, argv, files)`.
type Case = (String, Vec<String>, Files);

/// Runnable paths that this test does not run, each with the reason.
const EXCLUDED: &[(&str, &str)] = &[
    (
        "serve",
        "starts a server; the family is the hidden spelling of `mcp`",
    ),
    ("serve install", "service manager (launchd/systemd)"),
    ("serve status", "service manager (launchd/systemd)"),
    ("serve token", "serve family"),
    ("serve token create", "serve family"),
    ("serve token list", "serve family"),
    ("serve token revoke", "serve family"),
    ("serve uninstall", "service manager (launchd/systemd)"),
    ("mcp install", "service manager (launchd/systemd)"),
    ("mcp status", "service manager (launchd/systemd)"),
    ("mcp uninstall", "service manager (launchd/systemd)"),
    ("update", "network; CLI-006 R4"),
    ("update apply", "network; CLI-006 R4"),
    ("update check", "network; CLI-006 R4"),
    ("update info", "network; CLI-006 R4"),
    ("ui", "needs a terminal"),
    ("setup", "needs a terminal"),
    ("doctor", "host probes; replayed by doctor_differential"),
    ("startup-profile", "timings"),
    ("generate", "random output"),
    (
        "generate manpages",
        "writes files; replayed by cli_generate_manpages",
    ),
    ("audit rotate-key", "prints a random key preview"),
    ("intake watch disable", "absolute launchctl path"),
    ("version", "build stamp differs by design"),
    ("help", "replayed by cli_help and cli_help_subcommand"),
    (
        "completion",
        "generated at execute time; replayed by cli_completion_args",
    ),
    (
        "init",
        "creates a vault; its refusals are replayed by error_taxonomy",
    ),
];

/// Flags and values that carry a path past its own pre-checks (`--engine`, a
/// required `--out` ...), appended after the positionals.
fn extra_arguments(path: &str) -> &'static [&'static str] {
    match path {
        "dynamic generate" => &["--engine", "e", "--role", "r"],
        "export" => &["--format", "json"],
        "profile add" => &["--vault", "v"],
        "template generate" => &["--type", "t"],
        "approval decide" => &["--approve"],
        "file add" => &["--field", "f", "--from", "a.bin"],
        "file get" => &["--out", "o"],
        "file use" => &["--", "true"],
        "agent upgrade" => &["--tier", "standard"],
        "device join" => &["--pairing-file", "p.json"],
        "device add" => &["--name", "n", "--pair"],
        _ => &[],
    }
}

/// `(label, args, files)`: the explicit variants of the approval, file and
/// device commands, and the output-format flags in front of them.
fn variants() -> Vec<(&'static str, Vec<&'static str>, Files)> {
    let bin: Files = &[("a.bin", "synthetic attachment bytes")];
    vec![
        (
            "approval decide: neither flag",
            vec!["approval", "decide", "x"],
            &[],
        ),
        (
            "approval decide: deny",
            vec!["approval", "decide", "x", "--deny"],
            &[],
        ),
        (
            "approval decide: both flags",
            vec!["approval", "decide", "x", "--approve", "--deny"],
            &[],
        ),
        (
            "approval decide: approve=false",
            vec!["approval", "decide", "x", "--approve=false"],
            &[],
        ),
        (
            "approval decide: json",
            vec!["--json", "approval", "decide", "x", "--approve"],
            &[],
        ),
        (
            "approval decide: yaml",
            vec!["--output", "yaml", "approval", "decide", "x", "--deny"],
            &[],
        ),
        (
            "approval list: json",
            vec!["approval", "list", "--json"],
            &[],
        ),
        (
            "approval list: yaml",
            vec!["--output", "yaml", "approval", "list"],
            &[],
        ),
        (
            "approval list: quiet",
            vec!["--quiet", "approval", "list"],
            &[],
        ),
        (
            "approval list: explicit vault",
            vec!["--vault", "nowhere", "approval", "list"],
            &[],
        ),
        ("file add: no flags", vec!["file", "add", "x"], &[]),
        (
            "file add: field only",
            vec!["file", "add", "x", "--field", "f"],
            &[],
        ),
        (
            "file add: missing source",
            vec!["file", "add", "x", "--field", "f", "--from", "gone.bin"],
            &[],
        ),
        (
            "file add: source present",
            vec!["file", "add", "x", "--field", "f", "--from", "a.bin"],
            bin,
        ),
        (
            "file add: shred",
            vec![
                "file", "add", "x", "--field", "f", "--from", "a.bin", "--shred",
            ],
            bin,
        ),
        (
            "file add: type",
            vec![
                "file", "add", "x", "--field", "f", "--from", "a.bin", "--type", "cert",
            ],
            bin,
        ),
        (
            "file add: too large",
            vec![
                "file",
                "add",
                "x",
                "--field",
                "f",
                "--from",
                "a.bin",
                "--max-size",
                "3",
            ],
            bin,
        ),
        (
            "file add: json",
            vec![
                "--json", "file", "add", "x", "--field", "f", "--from", "a.bin",
            ],
            bin,
        ),
        ("file get: no out", vec!["file", "get", "x"], &[]),
        (
            "file get: empty out",
            vec!["file", "get", "x", "--out", ""],
            &[],
        ),
        (
            "file get: field in path",
            vec!["file", "get", "x#f", "--out", "o"],
            &[],
        ),
        (
            "file get: field flag",
            vec!["file", "get", "x", "--field", "f", "--out", "o"],
            &[],
        ),
        (
            "file get: field flag without out",
            vec!["file", "get", "x", "--field", "f"],
            &[],
        ),
        (
            "file get: json",
            vec!["--json", "file", "get", "x", "--out", "o"],
            &[],
        ),
        (
            "file get: quiet",
            vec!["--quiet", "file", "get", "x", "--out", "o"],
            &[],
        ),
        ("file use: bare", vec!["file", "use", "x"], &[]),
        (
            "file use: separator",
            vec!["file", "use", "x", "--", "true"],
            &[],
        ),
        (
            "file use: field in path",
            vec!["file", "use", "x#f", "--", "true"],
            &[],
        ),
        (
            "file use: field flag",
            vec!["file", "use", "x", "--field", "f", "--", "true"],
            &[],
        ),
        (
            "file use: as",
            vec!["file", "use", "x", "--as", "A", "--", "true"],
            &[],
        ),
        (
            "file use: timeout",
            vec!["file", "use", "x", "--timeout", "5s", "--", "true"],
            &[],
        ),
        (
            "file use: no separator",
            vec!["file", "use", "x", "true"],
            &[],
        ),
        (
            "device approval-list: json",
            vec!["device", "approval-list", "--json"],
            &[],
        ),
        (
            "device approval-pair: host",
            vec!["device", "approval-pair", "--host", "h"],
            &[],
        ),
        (
            "device approval-revoke",
            vec!["device", "approval-revoke", "x"],
            &[],
        ),
        (
            "device approval-revoke: yes",
            vec!["device", "approval-revoke", "x", "--yes"],
            &[],
        ),
        ("device accept: token", vec!["device", "accept", "x:y"], &[]),
        ("device pair", vec!["device", "pair"], &[]),
        (
            "device revoke: yes",
            vec!["device", "revoke", "x", "--yes"],
            &[],
        ),
        (
            "device join: missing file",
            vec!["device", "join", "--pairing-file", "p.json", "t"],
            &[],
        ),
        ("auth set: touchid", vec!["auth", "set", "touchid"], &[]),
        (
            "auth set: passphrase",
            vec!["auth", "set", "passphrase"],
            &[],
        ),
        ("auth status: json", vec!["auth", "status", "--json"], &[]),
        (
            "auth rotate-passphrase: yes",
            vec!["auth", "rotate-passphrase", "--yes"],
            &[],
        ),
        (
            "auth rotate-passphrase: reencrypt",
            vec!["auth", "rotate-passphrase", "--reencrypt", "--yes"],
            &[],
        ),
    ]
}

struct Sandbox {
    root: tempfile::TempDir,
}

impl Sandbox {
    fn new(files: &[(&str, &str)]) -> Self {
        let root = tempfile::tempdir().expect("sandbox");
        fs::create_dir_all(root.path().join("home")).expect("home");
        for (name, content) in files {
            fs::write(root.path().join(name), content).expect("sandbox file");
        }
        Self { root }
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }
}

/// Cases whose Rust answer differs from Go's outside the not-initialized shape,
/// pinned so a fix is noticed. Empty since ADR 0037 R21 was closed: in a sandbox
/// without the vault directory the token/share registries read as empty, as in
/// Go (`agent token new|rotate|revoke`, `share revoke`).
const OPEN: &[(&str, &str)] = &[];

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn not_initialized_shapes_match_go_for_every_runnable_command() {
    let oracle = go_oracle::GoOracle::begin(
        FILE,
        "not_initialized_shapes_match_go_for_every_runnable_command",
        None,
    );
    let excluded: BTreeMap<&str, &str> = EXCLUDED.iter().copied().collect();
    let mut cases: Vec<Case> = Vec::new();
    let mut covered = BTreeSet::new();
    let mut runnable = BTreeSet::new();
    for (words, _hidden, is_runnable, accepted) in commands() {
        if !is_runnable || words.is_empty() {
            continue;
        }
        let path = words.join(" ");
        runnable.insert(path.clone());
        if excluded.contains_key(path.as_str()) {
            continue;
        }
        // The fewest positionals the validator accepts; `device join
        // --pairing-file p.json` takes one (the token), `file use` needs the
        // entry before its `--`.
        let wanted = match path.as_str() {
            "device join" | "file use" => 1,
            _ => accepted.first().copied().unwrap_or(0),
        };
        let mut args: Vec<String> = words.clone();
        args.extend(std::iter::repeat_n("x".to_owned(), wanted));
        args.extend(extra_arguments(&path).iter().map(|s| (*s).to_owned()));
        covered.insert(path.clone());
        let files: &'static [(&str, &str)] = if path == "file add" {
            &[("a.bin", "synthetic attachment bytes")]
        } else {
            &[]
        };
        cases.push((path, args, files));
    }
    for (label, args, files) in variants() {
        cases.push((
            label.to_owned(),
            args.into_iter().map(str::to_owned).collect(),
            files,
        ));
    }
    // Every runnable path is run or excluded with a reason, and no exclusion is stale.
    for path in &runnable {
        assert!(
            covered.contains(path) || excluded.contains_key(path.as_str()),
            "{path} is neither run nor excluded"
        );
    }
    for path in excluded.keys() {
        assert!(
            runnable.contains(*path) || *path == "completion",
            "excluded path {path} is not in the command tree"
        );
    }
    assert!(
        covered.len() >= 90,
        "{} runnable paths are run",
        covered.len()
    );

    let open: BTreeMap<&str, &str> = OPEN.iter().copied().collect();
    let mut sandboxes = Vec::new();
    let mut failures = Vec::new();
    let mut still_open = BTreeSet::new();
    let mut shapes: BTreeMap<String, usize> = BTreeMap::new();
    for (label, args, files) in &cases {
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let go_box = Sandbox::new(files);
        let go = observe(
            &run_go(&oracle, &argv, go_box.path(), &go_box.home(), None),
            &[go_box.path()],
        );
        let shape = if go.stderr.contains("vault not initialized") {
            "vault not initialized"
        } else {
            "other"
        };
        *shapes.entry(shape.to_owned()).or_default() += 1;
        sandboxes.push(go_box);
        if oracle.replaying() {
            let rust_box = Sandbox::new(files);
            let rust = observe(
                &run_rust(&argv, rust_box.path(), &rust_box.home(), None),
                &[rust_box.path()],
            );
            if rust == go {
                assert!(
                    !open.contains_key(label.as_str()),
                    "{label} matches Go now: remove it from OPEN"
                );
            } else if open.contains_key(label.as_str()) {
                still_open.insert(label.clone());
            } else {
                failures.push(format!(
                    "{label} {argv:?}:\n  go:   {go:?}\n  rust: {rust:?}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    if oracle.replaying() {
        let expected: BTreeSet<String> = open.keys().map(|s| (*s).to_owned()).collect();
        assert_eq!(still_open, expected);
        assert_eq!(oracle.calls(), cases.len());
    }
    // The corpus must contain the shape the item is about.
    assert!(
        shapes.get("vault not initialized").copied().unwrap_or(0) >= 55,
        "{shapes:?}"
    );
    drop(sandboxes);
}

// ---------------------------------------------------------------- R20

/// `(label, config.yaml)`. `x` is defined more than once; the alias under
/// `sessionTimeout` decides whether the file loads (`abc` is not a duration).
const ANCHORS: &[(&str, &str)] = &[
    (
        "alias after the redefinition, second valid",
        "a: &x abc\nb: &x 5m\nsessionTimeout: *x\n",
    ),
    (
        "alias after the redefinition, second invalid",
        "a: &x 5m\nb: &x abc\nsessionTimeout: *x\n",
    ),
    (
        "alias after the last of three definitions",
        "a: &x abc\nb: &x abc\nc: &x 1h\nsessionTimeout: *x\n",
    ),
    (
        "alias after, a further anchor unused",
        "a: &x 5m\nb: &x abc\nsessionTimeout: *x\nc: &y 1\n",
    ),
    (
        "other key aliased after, timeout before",
        "a: &x 5m\nsessionTimeout: *x\nb: &x abc\nc: *x\n",
    ),
    (
        "alias before the redefinition, first valid",
        "a: &x 5m\nsessionTimeout: *x\nb: &x abc\n",
    ),
    (
        "alias before the redefinition, first invalid",
        "a: &x abc\nsessionTimeout: *x\nb: &x 5m\n",
    ),
    (
        "alias between three definitions",
        "a: &x abc\nb: &x 1h\nsessionTimeout: *x\nc: &x abc\n",
    ),
    (
        "one definition, alias after",
        "a: &x 5m\nsessionTimeout: *x\n",
    ),
    (
        "two equal definitions, alias between",
        "a: &x 5m\nsessionTimeout: *x\nb: &x 5m\n",
    ),
];

/// What `sessionTimeout: *x` resolves to: `(Go, Rust)`. Go takes the
/// definition in force at the alias, Rust the last definition of the document.
fn alias_values(config: &str) -> (String, String) {
    let mut current = String::new();
    let mut at_alias = String::new();
    for line in config.lines() {
        if let Some((_, rest)) = line.split_once(": &x ") {
            current = rest.to_owned();
        } else if line == "sessionTimeout: *x" {
            at_alias.clone_from(&current);
        }
    }
    (at_alias, current)
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn alias_after_a_redefined_anchor_matches_go() {
    let oracle =
        go_oracle::GoOracle::begin(FILE, "alias_after_a_redefined_anchor_matches_go", None);
    let commands: [&[&str]; 4] = [
        &["config", "validate"],
        &["config", "validate", "--json"],
        &["config", "get", "sessionTimeout"],
        &["config", "list"],
    ];
    let (mut agreeing, mut diverging) = (0, 0);
    let mut sandboxes = Vec::new();
    for (label, bytes) in ANCHORS {
        let (go_value, rust_value) = alias_values(bytes);
        let (go_loads, rust_loads) = (go_value != "abc", rust_value != "abc");
        for args in commands {
            let place = |sandbox: &Sandbox| {
                let dir = sandbox.home().join(".symvault");
                fs::create_dir_all(&dir).expect("config dir");
                fs::write(dir.join("config.yaml"), bytes).expect("config.yaml");
            };
            let go_box = Sandbox::new(&[]);
            place(&go_box);
            let go = observe(
                &run_go(&oracle, args, go_box.path(), &go_box.home(), None),
                &[go_box.path()],
            );
            sandboxes.push(go_box);
            let resolves = args.contains(&"validate");
            if resolves {
                // Go resolves the alias to the definition in force at the alias.
                assert_eq!(
                    go.code,
                    Some(if go_loads { 0 } else { 6 }),
                    "{label}: {args:?}: {go:?}"
                );
            }
            if !oracle.replaying() {
                continue;
            }
            let rust_box = Sandbox::new(&[]);
            place(&rust_box);
            let rust = observe(
                &run_rust(args, rust_box.path(), &rust_box.home(), None),
                &[rust_box.path()],
            );
            if !resolves {
                // `config get` and `config list` print the document, not the
                // resolved value, and agree whatever the anchors do.
                assert_eq!(rust, go, "{label}: {args:?}");
            } else if go_value == rust_value {
                // An alias after the last definition: both rules coincide.
                assert_eq!(rust, go, "{label}: {args:?}");
                agreeing += 1;
            } else {
                // ADR 0034 item 5 / ADR 0037: Rust resolves to the last definition.
                assert_eq!(
                    rust.code,
                    Some(if rust_loads { 0 } else { 6 }),
                    "{label}: {args:?}: {rust:?}"
                );
                if go_loads != rust_loads {
                    assert_ne!(
                        rust, go,
                        "{label}: {args:?} matches Go now; update ADR 0037"
                    );
                    diverging += 1;
                }
            }
        }
    }
    if oracle.replaying() {
        assert_eq!(oracle.calls(), ANCHORS.len() * commands.len());
        // Aliases at or after the last definition agree (R20); the divergence
        // is confined to aliases that stand before a redefinition whose values
        // differ in validity. Two commands resolve the alias.
        let rows = |keep: &dyn Fn(&str) -> bool| {
            ANCHORS.iter().filter(|(_, bytes)| keep(bytes)).count() * 2
        };
        let same_value = |bytes: &str| {
            let (go, rust) = alias_values(bytes);
            go == rust
        };
        let differs_in_validity = |bytes: &str| {
            let (go, rust) = alias_values(bytes);
            (go != "abc") != (rust != "abc")
        };
        assert_eq!(agreeing, rows(&same_value));
        assert_eq!(diverging, rows(&differs_in_validity));
        assert!(agreeing >= 12 && diverging >= 8, "{agreeing} {diverging}");
    }
    drop(sandboxes);
}
