#![deny(unsafe_code)]

//! CLI-005 / CLI-006: the Go CLI's command-line error taxonomy and output-format
//! gate, replayed against the native binary.
//!
//! `testdata/port/cli/error-taxonomy.json` freezes what the pinned Go CLI prints
//! (exit status, stdout, stderr) for cobra's usage errors, for every command's
//! argument validator, for the output-format gate and for the "vault not
//! initialized" failure. `scripts/rust-port/cmd/errtaxgen` regenerates and
//! re-verifies it against the pinned oracle; nothing here needs a Go toolchain.
//! Only runs whose Go outcome is a rejection before the command body are
//! replayed against the binary, so no replay can touch a real vault or network;
//! the accepting rows are covered by the in-crate `cobra_usage` unit tests.
//! `argv_shapes` adds the shapes an arity sweep cannot reach (flag *types*, such as
//! `device join --pairing-file <path> <token>`) and the group help pages; each row
//! may bring disposable files that are written into the working directory first.
//!
//! `nil_args` lists every cobra command of the pinned tree whose `Args` validator
//! is nil, so cobra accepts any positionals. `extra_positionals` records what Go
//! does when such a command gets extra positionals, in an empty sandbox and in the
//! frozen initialized vault (`vault_seed`, rewritten into the sandbox before each
//! run); `run_file_use_argv` does the same for the argv permutations of `run` and
//! `file use`. The only rewrites applied (to both sides) are the named `normalize`
//! entries of a case; they replace a random password or key fragment.

#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{collections::BTreeMap, fs, process::Command};

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
struct Observation {
    args: Vec<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Deserialize)]
struct UsageCase {
    name: String,
    observation: Observation,
}

#[derive(Debug, Deserialize)]
struct Probe {
    count: usize,
    rejected: bool,
    observation: Option<Observation>,
}

#[derive(Debug, Deserialize)]
struct ArityRow {
    path: String,
    probes: Vec<Probe>,
}

#[derive(Debug, Deserialize)]
struct GateRow {
    path: String,
    #[serde(default)]
    refusals: Vec<Observation>,
}

#[derive(Debug, Deserialize)]
struct ShapeCase {
    name: String,
    #[serde(default)]
    files: BTreeMap<String, String>,
    observation: Observation,
}

#[derive(Debug, Deserialize)]
struct NilArgsEntry {
    path: String,
    runnable: bool,
}

#[derive(Debug, Deserialize)]
struct SeedFile {
    path: String,
    kind: String,
    mode: u32,
    #[serde(default)]
    data: String,
    #[serde(default)]
    base64: String,
}

#[derive(Debug, Deserialize)]
struct ScenarioCase {
    name: String,
    state: String,
    #[serde(default)]
    normalize: Vec<String>,
    observation: Observation,
}

#[derive(Debug, Deserialize)]
struct Exclusion {
    path: String,
    states: Vec<String>,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    release: String,
    source_digest: String,
    generator_digest: String,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    usage: Vec<UsageCase>,
    arity: Vec<ArityRow>,
    gate: Vec<GateRow>,
    not_initialized: Vec<Observation>,
    argv_shapes: Vec<ShapeCase>,
    nil_args: Vec<NilArgsEntry>,
    vault_seed: Vec<SeedFile>,
    extra_positionals: Vec<ScenarioCase>,
    extra_positional_exclusions: Vec<Exclusion>,
    run_file_use_argv: Vec<ScenarioCase>,
}

const USAGE_CASES: usize = 105;
const ARGV_SHAPES: usize = 23;
const ARITY_ROWS: usize = 116;
const REJECTED_ARITY_PROBES: usize = 236;
const GATE_REFUSALS: usize = 223;
const NOT_INITIALIZED_CASES: usize = 29;
const NIL_ARGS_COMMANDS: usize = 64;
const NIL_ARGS_RUNNABLE: usize = 48;
const EXTRA_POSITIONAL_EXCLUSIONS: usize = 7;
const EXTRA_POSITIONALS_UNINITIALIZED: usize = 138;
const EXTRA_POSITIONALS_INITIALIZED: usize = 82;
const RUN_FILE_USE_ARGV_PER_STATE: usize = 82;
const KNOWN_DIVERGENT_UNINITIALIZED: usize = 18;
const KNOWN_DIVERGENT_INITIALIZED: usize = 10;

/// Scenarios whose command body still differs from Go for a reason that has
/// nothing to do with the positionals: the same command without them differs in
/// the same way. Each entry names the scenario slug, the state it applies to and
/// the divergence. The replay does not compare these scenarios with Go; it pins
/// what the native binary prints instead (`error-taxonomy-known-divergences.json`:
/// exit code, stdout and stderr per scenario, recorded by `record_known_divergences`)
/// and fails when the native output moves in any way, when it starts to match
/// Go (so a fix forces the entry out) or when an entry has no pinned observation.
/// A different exit code, lost output or a parser regression therefore cannot hide
/// behind an entry.
const KNOWN_BODY_DIVERGENCES: &[(&str, &str, &str)] = &[
    (
        "agent_list",
        "uninitialized",
        "missing config.yaml is worded `read config: No such file or directory (os error 2)`; Go prints `open <path>: no such file or directory`, twice",
    ),
    (
        "device_pair",
        "uninitialized",
        "Go asks for the passphrase before it checks the vault (exit 4); the native command reports `vault is not initialized` (exit 1)",
    ),
    (
        "migrate_kdf",
        "uninitialized",
        "missing identity.age is worded `file not found`, once; Go prints the `open <path>` error twice",
    ),
    (
        "migrate_v4",
        "uninitialized",
        "missing config.yaml is worded `read config: ...`, once; Go prints the `open <path>` error twice",
    ),
    (
        "dynamic_generate",
        "uninitialized",
        "`dynamic` is not a native subcommand yet (only its help page is frozen)",
    ),
    (
        "dynamic_generate",
        "initialized",
        "`dynamic` is not a native subcommand yet (only its help page is frozen)",
    ),
    (
        "setup",
        "uninitialized",
        "`setup` is not a native subcommand yet (only its help page is frozen)",
    ),
    (
        "setup",
        "initialized",
        "`setup` is not a native subcommand yet (only its help page is frozen)",
    ),
    (
        "auth_rotate-passphrase",
        "initialized",
        "the prompt-read failure says `read passphrase: EOF`; Go keeps the prompt label (`read Current passphrase: EOF`)",
    ),
    (
        "migrate_pseudonymize",
        "initialized",
        "Go prints the SYMVAULT_PASSPHRASE warning before the prompt and the failure twice; the native command prints neither the warning nor the second line",
    ),
    (
        "unlock",
        "initialized",
        "with no OS keyring Go prints the memory-only session error twice and a Touch ID hint; the native command prints it once without the hint",
    ),
];

fn known_divergence(name: &str, state: &str) -> Option<&'static str> {
    KNOWN_BODY_DIVERGENCES
        .iter()
        .find(|(slug, known_state, _)| {
            *known_state == state
                && name
                    .strip_prefix(&format!("extra_{state}_{slug}_"))
                    .is_some_and(|variant| matches!(variant, "x1" | "x2" | "dd1"))
        })
        .map(|(_, _, reason)| *reason)
}

const KNOWN_DIVERGENCES_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/port/cli/error-taxonomy-known-divergences.json"
);

/// What the native binary prints for a known-divergent scenario.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct NativeObservation {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Deserialize)]
struct PinnedDivergence {
    name: String,
    state: String,
    reason: String,
    expected_rust: NativeObservation,
}

#[derive(Debug, Deserialize)]
struct PinnedFile {
    schema_version: u32,
    cases: Vec<PinnedDivergence>,
}

fn pinned_divergences() -> BTreeMap<String, PinnedDivergence> {
    let raw = fs::read_to_string(KNOWN_DIVERGENCES_FILE).expect("read known-divergences file");
    let file: PinnedFile = serde_json::from_str(&raw).expect("parse known-divergences file");
    assert_eq!(file.schema_version, 1);
    let mut by_name = BTreeMap::new();
    for case in file.cases {
        let name = case.name.clone();
        assert!(by_name.insert(name.clone(), case).is_none(), "{name} twice");
    }
    by_name
}

/// The problems of one known-divergent scenario: none while the native output is
/// exactly its pinned observation and still differs from Go.
fn check_known_divergence(
    name: &str,
    go: &Observation,
    pinned: &NativeObservation,
    actual: &(i32, String, String),
) -> Vec<String> {
    let (code, stdout, stderr) = actual;
    let mut problems = Vec::new();
    if *code == go.exit_code && *stdout == go.stdout && *stderr == go.stderr {
        problems.push(format!(
            "{name} now matches Go; remove it from KNOWN_BODY_DIVERGENCES and the pinned file"
        ));
    }
    // The pinned text was recorded on Unix; elsewhere the OS error wording differs,
    // so only the exit code is exact there.
    let same_text = !cfg!(unix) || (*stdout == pinned.stdout && *stderr == pinned.stderr);
    if *code != pinned.exit_code || !same_text {
        problems.push(format!(
            "{name} no longer prints its pinned native observation\n  pinned: {} {:?} {:?}\n  actual: {code} {stdout:?} {stderr:?}",
            pinned.exit_code, pinned.stdout, pinned.stderr
        ));
    }
    problems
}

fn fixture() -> Fixture {
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/cli/error-taxonomy.json"
    ))
    .expect("read error-taxonomy fixture");
    serde_json::from_str(&raw).expect("parse error-taxonomy fixture")
}

/// The fixture was recorded by Go on Unix. Windows renders the same ENOENT errors
/// with the system message table (`main.rs::go_io_reason`, which is also what Go
/// prints on Windows), so map those texts back to the recorded Unix wording. The
/// Unix comparison is untouched: this is a no-op outside Windows.
#[cfg(windows)]
fn windows_errno_to_go_unix(text: String) -> String {
    text.replace(
        "The system cannot find the file specified.",
        "no such file or directory",
    )
    .replace(
        "The system cannot find the path specified.",
        "no such file or directory",
    )
    .replace("Access is denied.", "permission denied")
}

#[cfg(not(windows))]
fn windows_errno_to_go_unix(text: String) -> String {
    text
}

fn run_with_files(args: &[String], files: &BTreeMap<String, String>) -> (i32, String, String) {
    run_scenario(args, files, &[], false)
}

/// Runs the binary in a fresh sandbox. `seed` is the frozen vault tree (text carries
/// the sandbox root as `__ROOT__`); `initialized` adds the passphrase environment
/// the recorded initialized runs had.
fn run_scenario(
    args: &[String],
    files: &BTreeMap<String, String>,
    seed: &[SeedFile],
    initialized: bool,
) -> (i32, String, String) {
    let root = test_temp_root::TempRoot::existing("symvault-error-taxonomy-");
    let home = root.join("home");
    fs::create_dir_all(&home).expect("create isolated home");
    write_seed(&root, seed);
    for (name, content) in files {
        fs::write(root.join(name), content).expect("write disposable file");
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SYMVAULT_") {
            command.env_remove(name);
        }
    }
    if initialized {
        command
            .env("TZ", "UTC")
            .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
            .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1");
    }
    let output = command
        .current_dir(&*root)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CACHE_HOME", root.join("xdg-cache"))
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .expect("run symvault");
    let normalize = |raw: &[u8]| {
        let mut text = String::from_utf8_lossy(raw).into_owned();
        let path = root.to_path_buf();
        let cleaned: std::path::PathBuf = path.components().collect();
        for form in [path.to_string_lossy(), cleaned.to_string_lossy()] {
            text = text.replace(&form.replace('\\', "\\\\"), "__ROOT__");
            text = text.replace(&*form, "__ROOT__");
        }
        windows_errno_to_go_unix(text)
    };
    (
        output.status.code().unwrap_or(-1),
        normalize(&output.stdout),
        normalize(&output.stderr),
    )
}

/// Recreates the frozen vault tree, parents before their contents.
fn write_seed(root: &std::path::Path, seed: &[SeedFile]) {
    use base64::Engine as _;
    let root_text = root.to_string_lossy().into_owned();
    for entry in seed {
        let path = root.join(&entry.path);
        match entry.kind.as_str() {
            "dir" => fs::create_dir_all(&path).expect("create seed directory"),
            "file" => {
                let raw = if entry.base64.is_empty() {
                    entry.data.replace("__ROOT__", &root_text).into_bytes()
                } else {
                    base64::engine::general_purpose::STANDARD
                        .decode(&entry.base64)
                        .expect("decode seed file")
                };
                fs::create_dir_all(path.parent().expect("seed parent")).expect("seed parent");
                fs::write(&path, raw).expect("write seed file");
            }
            other => panic!("seed entry {} has unknown kind {other}", entry.path),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(entry.mode))
                .expect("set seed mode");
        }
        #[cfg(not(unix))]
        let _ = entry.mode;
    }
}

/// The recorded rewrites, applied to the native output exactly as the generator
/// applied them to the oracle's.
fn apply_normalizers(names: &[String], stdout: &mut String, stderr: &mut String) {
    for name in names {
        match name.as_str() {
            "password20" => {
                let body = stdout.strip_suffix('\n').unwrap_or("");
                if body.len() == 20 && body.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                    *stdout = "__PASSWORD__\n".to_string();
                }
            }
            "key_bytes" => *stderr = replace_key_bytes(stderr),
            other => panic!("unknown normalizer {other}"),
        }
    }
}

/// `New key: <8 lowercase hex digits> (first 4 bytes)` -> `New key: __KEY__ (first 4 bytes)`.
fn replace_key_bytes(text: &str) -> String {
    const PREFIX: &str = "New key: ";
    const SUFFIX: &str = " (first 4 bytes)";
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(PREFIX) {
        let (head, tail) = rest.split_at(at + PREFIX.len());
        out.push_str(head);
        let hex = tail.get(..8).unwrap_or("");
        let is_hex = hex.len() == 8 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if is_hex && tail[8..].starts_with(SUFFIX) {
            out.push_str("__KEY__");
            rest = &tail[8..];
        } else {
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

fn compare(label: &str, observation: &Observation, failures: &mut Vec<String>) {
    compare_with_files(label, observation, &BTreeMap::new(), failures);
}

fn compare_with_files(
    label: &str,
    observation: &Observation,
    files: &BTreeMap<String, String>,
    failures: &mut Vec<String>,
) {
    let (code, stdout, stderr) = run_with_files(&observation.args, files);
    record_difference(label, observation, (code, stdout, stderr), failures);
}

fn record_difference(
    label: &str,
    observation: &Observation,
    (code, stdout, stderr): (i32, String, String),
    failures: &mut Vec<String>,
) {
    if code != observation.exit_code || stdout != observation.stdout || stderr != observation.stderr
    {
        failures.push(format!(
            "{label} {:?}\n  go:   {} {:?} {:?}\n  rust: {code} {stdout:?} {stderr:?}",
            observation.args, observation.exit_code, observation.stdout, observation.stderr
        ));
    }
}

/// Runs one recorded scenario in a fresh sandbox, with its normalizers applied.
fn run_case(case: &ScenarioCase, seed: &[SeedFile]) -> (i32, String, String) {
    let initialized = case.state == "initialized";
    let (code, mut stdout, mut stderr) = run_scenario(
        &case.observation.args,
        &BTreeMap::new(),
        if initialized { seed } else { &[] },
        initialized,
    );
    apply_normalizers(&case.normalize, &mut stdout, &mut stderr);
    (code, stdout, stderr)
}

/// Replays the scenarios recorded for `state`; returns how many ran. Known
/// divergences are compared with their pinned native observation instead of Go's.
fn replay_scenarios(
    cases: &[ScenarioCase],
    state: &str,
    seed: &[SeedFile],
    failures: &mut Vec<String>,
) -> usize {
    let pinned = pinned_divergences();
    let mut replayed = 0;
    for case in cases.iter().filter(|case| case.state == state) {
        let actual = run_case(case, seed);
        if known_divergence(&case.name, state).is_some() {
            match pinned.get(&case.name) {
                Some(entry) => failures.extend(check_known_divergence(
                    &case.name,
                    &case.observation,
                    &entry.expected_rust,
                    &actual,
                )),
                None => failures.push(format!("{} has no pinned native observation", case.name)),
            }
        } else {
            record_difference(&case.name, &case.observation, actual, failures);
        }
        replayed += 1;
    }
    replayed
}

#[test]
fn fixture_provenance_and_counts() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle.commit,
        "0cc780626d3275afad14eb64c44abf8adb23d2ce"
    );
    assert_eq!(fixture.oracle.commit_sha, fixture.oracle.commit);
    assert_eq!(fixture.oracle.release, "unreleased");
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert_eq!(fixture.usage.len(), USAGE_CASES);
    assert_eq!(fixture.arity.len(), ARITY_ROWS);
    assert_eq!(fixture.gate.len(), ARITY_ROWS);
    assert_eq!(fixture.not_initialized.len(), NOT_INITIALIZED_CASES);
    assert_eq!(fixture.argv_shapes.len(), ARGV_SHAPES);
    let rejected: usize = fixture
        .arity
        .iter()
        .map(|row| row.probes.iter().filter(|probe| probe.rejected).count())
        .sum();
    assert_eq!(rejected, REJECTED_ARITY_PROBES);
    let refusals: usize = fixture.gate.iter().map(|row| row.refusals.len()).sum();
    assert_eq!(refusals, GATE_REFUSALS);
    assert_eq!(fixture.nil_args.len(), NIL_ARGS_COMMANDS);
    assert_eq!(
        fixture
            .nil_args
            .iter()
            .filter(|entry| entry.runnable)
            .count(),
        NIL_ARGS_RUNNABLE
    );
    assert_eq!(
        fixture.extra_positional_exclusions.len(),
        EXTRA_POSITIONAL_EXCLUSIONS
    );
    let in_state = |cases: &[ScenarioCase], state: &str| {
        cases.iter().filter(|case| case.state == state).count()
    };
    assert_eq!(
        in_state(&fixture.extra_positionals, "uninitialized"),
        EXTRA_POSITIONALS_UNINITIALIZED
    );
    assert_eq!(
        in_state(&fixture.extra_positionals, "initialized"),
        EXTRA_POSITIONALS_INITIALIZED
    );
    for state in ["uninitialized", "initialized"] {
        assert_eq!(
            in_state(&fixture.run_file_use_argv, state),
            RUN_FILE_USE_ARGV_PER_STATE
        );
    }
    assert!(!fixture.vault_seed.is_empty());
}

/// The known divergences name recorded scenarios, and the pinned file holds an
/// observation for exactly those scenarios, with the reason of its table entry.
#[test]
fn known_body_divergences_name_recorded_scenarios() {
    let fixture = fixture();
    for state in ["uninitialized", "initialized"] {
        let known = fixture
            .extra_positionals
            .iter()
            .filter(|case| case.state == state && known_divergence(&case.name, state).is_some())
            .count();
        let expected = if state == "uninitialized" {
            KNOWN_DIVERGENT_UNINITIALIZED
        } else {
            KNOWN_DIVERGENT_INITIALIZED
        };
        assert_eq!(known, expected, "{state}");
    }
    for (slug, state, reason) in KNOWN_BODY_DIVERGENCES {
        assert!(!reason.is_empty());
        assert!(
            fixture
                .extra_positionals
                .iter()
                .any(|case| case.state == *state
                    && case.name == format!("extra_{state}_{slug}_x1")),
            "{slug}/{state} names no recorded scenario"
        );
    }
    let recorded: std::collections::BTreeSet<&str> = fixture
        .extra_positionals
        .iter()
        .chain(&fixture.run_file_use_argv)
        .filter(|case| known_divergence(&case.name, &case.state).is_some())
        .map(|case| case.name.as_str())
        .collect();
    let pinned = pinned_divergences();
    assert_eq!(
        pinned
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        recorded,
        "the pinned file and the known divergences name different scenarios"
    );
    assert_eq!(
        pinned.len(),
        KNOWN_DIVERGENT_UNINITIALIZED + KNOWN_DIVERGENT_INITIALIZED
    );
    for entry in pinned.values() {
        assert_eq!(
            Some(entry.reason.as_str()),
            known_divergence(&entry.name, &entry.state),
            "{} carries another reason than its table entry",
            entry.name
        );
    }
}

/// The positionals must reach the command: a clap rejection of them is the defect
/// this corpus guards, never something a pinned observation may record.
#[test]
fn pinned_divergences_are_not_clap_rejections() {
    for entry in pinned_divergences().values() {
        let stderr = &entry.expected_rust.stderr;
        assert!(
            !stderr.contains("unexpected argument")
                && !stderr.contains("unrecognized subcommand 'x'")
                && !stderr.contains("unrecognized subcommand '--'"),
            "{} pins a parser rejection: {stderr:?}",
            entry.name
        );
    }
}

/// Regenerates `error-taxonomy-known-divergences.json` from the native binary:
/// `cargo test -p symvault-cli --test error_taxonomy -- --ignored record_known_divergences`.
/// Review the diff before committing; an entry may only record a body difference.
#[cfg(unix)]
#[test]
#[ignore = "rewrites testdata/port/cli/error-taxonomy-known-divergences.json"]
fn record_known_divergences() {
    let fixture = fixture();
    let mut cases = Vec::new();
    for case in fixture
        .extra_positionals
        .iter()
        .chain(&fixture.run_file_use_argv)
    {
        let Some(reason) = known_divergence(&case.name, &case.state) else {
            continue;
        };
        let (exit_code, stdout, stderr) = run_case(case, &fixture.vault_seed);
        cases.push(serde_json::json!({
            "name": case.name,
            "state": case.state,
            "reason": reason,
            "expected_rust": {"exit_code": exit_code, "stdout": stdout, "stderr": stderr},
        }));
    }
    cases.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let file = serde_json::json!({
        "schema_version": 1,
        "comment": "What the native CLI prints for the scenarios of error-taxonomy.json whose command body still differs from Go (see KNOWN_BODY_DIVERGENCES in crates/symvault-cli/tests/error_taxonomy.rs). Every entry pins the exact (sandbox-root-normalized) exit code, stdout and stderr: the replay fails when the native output changes in any way and when it starts matching Go, so an entry can neither outlive its cause nor hide another regression. Recorded from the native binary, never hand-edited: run the ignored test record_known_divergences.",
        "cases": cases,
    });
    let mut text = serde_json::to_string_pretty(&file).expect("serialize");
    text.push('\n');
    fs::write(KNOWN_DIVERGENCES_FILE, text).expect("write known-divergences file");
}

#[test]
fn every_runnable_nil_args_command_is_covered_or_excluded() {
    let fixture = fixture();
    let names: std::collections::BTreeSet<&str> = fixture
        .extra_positionals
        .iter()
        .map(|case| case.name.as_str())
        .collect();
    let mut expected = std::collections::BTreeSet::new();
    for entry in fixture.nil_args.iter().filter(|entry| entry.runnable) {
        let slug = entry
            .path
            .strip_prefix("symvault ")
            .expect("path starts with the binary name")
            .replace(' ', "_");
        let excluded = fixture
            .extra_positional_exclusions
            .iter()
            .find(|item| item.path == entry.path);
        for (state, variants) in [
            ("uninitialized", &["x1", "x2", "dd1"][..]),
            ("initialized", &["x1", "x2"][..]),
        ] {
            if excluded.is_some_and(|item| item.states.iter().any(|s| s == state)) {
                continue;
            }
            for variant in variants {
                expected.insert(format!("extra_{state}_{slug}_{variant}"));
            }
        }
    }
    let recorded: std::collections::BTreeSet<String> =
        names.iter().map(|name| (*name).to_string()).collect();
    assert_eq!(recorded, expected);
    for item in &fixture.extra_positional_exclusions {
        assert!(!item.reason.is_empty(), "{} has no reason", item.path);
        assert!(
            fixture.nil_args.iter().any(|entry| entry.path == item.path),
            "exclusion {} is not a nil-Args command",
            item.path
        );
    }
}

#[test]
fn native_cli_matches_go_usage_errors() {
    let fixture = fixture();
    let mut failures = Vec::new();
    for case in &fixture.usage {
        compare(&case.name, &case.observation, &mut failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every shape ends before a vault, a clone or a prompt (the generator refuses any
/// other row), so all of them can be replayed byte for byte.
#[test]
fn native_cli_matches_go_argument_shapes() {
    let fixture = fixture();
    let mut failures = Vec::new();
    for case in &fixture.argv_shapes {
        compare_with_files(&case.name, &case.observation, &case.files, &mut failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `--pairing-file` is a string flag in Go: the three shapes that a bool treatment
/// rejected before the command ran must reach the invitation file.
#[test]
fn pairing_file_shapes_reach_the_invitation_file() {
    let fixture = fixture();
    let reached = |name: &str| {
        let case = fixture
            .argv_shapes
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("shape {name} is missing"));
        assert!(
            case.observation
                .stderr
                .starts_with("Error: pairing file token \"ZZZZ\" does not match"),
            "{name}: Go did not read the file: {:?}",
            case.observation.stderr
        );
        let (code, _, stderr) = run_with_files(&case.observation.args, &case.files);
        assert_eq!(code, 1, "{name}");
        assert_eq!(stderr, case.observation.stderr, "{name}");
    };
    reached("join_pairing_file_equals_token");
    reached("join_pairing_file_separate_token");
    reached("join_pairing_file_equals_double_dash_token");
    reached("join_pairing_file_separate_double_dash_token");
}

#[test]
fn native_cli_matches_go_argument_validators() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let mut replayed = 0;
    for row in &fixture.arity {
        for probe in row.probes.iter().filter(|probe| probe.rejected) {
            let observation = probe.observation.as_ref().expect("rejected probe bytes");
            compare(
                &format!("{} x{}", row.path, probe.count),
                observation,
                &mut failures,
            );
            replayed += 1;
        }
    }
    assert_eq!(replayed, REJECTED_ARITY_PROBES);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn native_cli_matches_go_output_format_gate() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let mut replayed = 0;
    for row in &fixture.gate {
        for observation in &row.refusals {
            compare(&row.path, observation, &mut failures);
            replayed += 1;
        }
    }
    assert_eq!(replayed, GATE_REFUSALS);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn native_cli_matches_go_not_initialized_failures() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let mut replayed = 0;
    for observation in &fixture.not_initialized {
        compare("not initialized", observation, &mut failures);
        replayed += 1;
    }
    assert_eq!(replayed, NOT_INITIALIZED_CASES);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Nil-Args commands accept every positional in cobra, so a call with extra
/// positionals reaches the command body: the empty-sandbox outcome (usually the
/// "vault not initialized" failure, or the command's own output) must match.
#[test]
fn native_cli_matches_go_extra_positionals_uninitialized() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let replayed = replay_scenarios(
        &fixture.extra_positionals,
        "uninitialized",
        &fixture.vault_seed,
        &mut failures,
    );
    assert_eq!(replayed, EXTRA_POSITIONALS_UNINITIALIZED);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The same positionals in the frozen initialized vault. The seed carries Unix
/// permission bits and the recording ran on Unix.
#[cfg(unix)]
#[test]
fn native_cli_matches_go_extra_positionals_initialized() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let replayed = replay_scenarios(
        &fixture.extra_positionals,
        "initialized",
        &fixture.vault_seed,
        &mut failures,
    );
    assert_eq!(replayed, EXTRA_POSITIONALS_INITIALIZED);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `run` and `file use` forward a trailing command line: flags, bare words and
/// `--` in every position must be handled as Go's cobra does.
#[test]
fn native_cli_matches_go_run_file_use_argv_uninitialized() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let replayed = replay_scenarios(
        &fixture.run_file_use_argv,
        "uninitialized",
        &fixture.vault_seed,
        &mut failures,
    );
    assert_eq!(replayed, RUN_FILE_USE_ARGV_PER_STATE);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[cfg(unix)]
#[test]
fn native_cli_matches_go_run_file_use_argv_initialized() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let replayed = replay_scenarios(
        &fixture.run_file_use_argv,
        "initialized",
        &fixture.vault_seed,
        &mut failures,
    );
    assert_eq!(replayed, RUN_FILE_USE_ARGV_PER_STATE);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn key_bytes_normalizer_rewrites_only_the_drawn_key() {
    let mut stdout = String::new();
    let mut stderr =
        "New key: b9e4f8cc (first 4 bytes)\nNew key: nothex!! (first 4 bytes)\n".to_string();
    apply_normalizers(&["key_bytes".to_string()], &mut stdout, &mut stderr);
    assert_eq!(
        stderr,
        "New key: __KEY__ (first 4 bytes)\nNew key: nothex!! (first 4 bytes)\n"
    );
    let mut password = "abcdefghij0123456789\n".to_string();
    let mut none = String::new();
    apply_normalizers(&["password20".to_string()], &mut password, &mut none);
    assert_eq!(password, "__PASSWORD__\n");
    let mut short = "abc\n".to_string();
    apply_normalizers(&["password20".to_string()], &mut short, &mut none);
    assert_eq!(short, "abc\n");
}

/// Negative control: an expectation that differs by one byte must be reported.
#[test]
fn mutated_expectation_is_detected() {
    let fixture = fixture();
    let mut observation = fixture
        .usage
        .iter()
        .find(|case| case.name == "unknown_flag_get")
        .expect("case")
        .observation
        .clone();
    observation.stderr.push('x');
    let mut failures = Vec::new();
    compare("mutated", &observation, &mut failures);
    assert_eq!(failures.len(), 1);
}

/// Negative controls for the known-divergence pin: a changed exit code, lost or
/// unrelated output, a parser-style failure and a native output that now equals Go
/// must each be reported, while the real native output passes.
#[test]
fn known_divergence_pin_detects_unrelated_changes() {
    let fixture = fixture();
    let pinned = pinned_divergences();
    let name = "extra_uninitialized_setup_x1";
    let case = fixture
        .extra_positionals
        .iter()
        .find(|case| case.name == name)
        .expect("recorded scenario");
    let entry = pinned.get(name).expect("pinned scenario");
    let actual = run_case(case, &fixture.vault_seed);
    let check = |actual: &(i32, String, String)| {
        check_known_divergence(name, &case.observation, &entry.expected_rust, actual)
    };
    assert_eq!(
        check(&actual),
        Vec::<String>::new(),
        "the real output passes"
    );

    let (code, stdout, stderr) = actual.clone();
    let mut mutations = vec![
        ("exit code", (code + 1, stdout.clone(), stderr.clone())),
        ("lost stderr", (code, stdout.clone(), String::new())),
        (
            "added stdout",
            (code, format!("{stdout}unrelated\n"), stderr.clone()),
        ),
        (
            "parser regression",
            (
                2,
                String::new(),
                "error: unexpected argument 'x' found\n".to_owned(),
            ),
        ),
        (
            "unrelated stderr",
            (
                code,
                stdout.clone(),
                format!("{stderr}Error: other failure\n"),
            ),
        ),
    ];
    mutations.push((
        "now equal to Go",
        (
            case.observation.exit_code,
            case.observation.stdout.clone(),
            case.observation.stderr.clone(),
        ),
    ));
    for (label, mutated) in mutations {
        assert!(!check(&mutated).is_empty(), "{label} was not detected");
    }

    // A pinned file that was edited the same way is caught by the real output.
    let mut mutated_pin = entry.expected_rust.clone();
    mutated_pin.exit_code += 1;
    assert!(
        !check_known_divergence(name, &case.observation, &mutated_pin, &actual).is_empty(),
        "a mutated pinned exit code was not detected"
    );
}
