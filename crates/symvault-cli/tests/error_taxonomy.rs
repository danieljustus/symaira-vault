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
//!
//! Host tools. Some commands act on the machine they run on: `mcp|serve
//! install|uninstall` register a user service (launchd or systemd), `doctor` and the
//! session code probe the keychain, clipboard and notification helpers. No run reaches
//! the real ones. Every sandbox puts stand-in executables first on `PATH` (the
//! fixture's `host_tools`, installed exactly like the generator's): each logs its argv
//! to a file inside the sandbox and exits 0. Service-manager calls are compared with
//! the recorded `host_tool_calls` on the recording platform (`generated_on`); a call
//! of any other stand-in fails the run. The commands whose output names the
//! platform's service manager carry `platforms: ["darwin"]`: other hosts skip them
//! with a counted, asserted skip. Absolute-path calls (`/bin/launchctl unload` of
//! `intake watch disable`, `/usr/bin/osascript` of the intake notification) cannot be
//! redirected and are reachable only after a LaunchAgent plist or an import exists,
//! which no scenario creates. The session cache stays in memory because the sandbox
//! sets `CI=1`, so no run reads or writes the developer's keychain.

#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{collections::BTreeMap, fs, path::Path, process::Command, sync::OnceLock};

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
    /// Host platforms (Go `GOOS` names) the observation can be compared on; empty
    /// means every platform.
    #[serde(default)]
    platforms: Vec<String>,
    observation: Observation,
    /// Service-manager calls the recording made, valid on `generated_on`.
    #[serde(default)]
    host_tool_calls: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HostDependence {
    path: String,
    platforms: Vec<String>,
    reason: String,
}

#[derive(Clone, Debug, Deserialize)]
struct HostTools {
    service_managers: Vec<String>,
    refused: Vec<String>,
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
    generated_on: String,
    host_tools: HostTools,
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
    host_dependent_commands: Vec<HostDependence>,
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
/// Scenarios of the host-dependent commands (`mcp|serve install|status`, three
/// variants uninitialized and two initialized each), skipped off darwin.
const DARWIN_ONLY_UNINITIALIZED: usize = 12;
const DARWIN_ONLY_INITIALIZED: usize = 8;
const HOST_DEPENDENT_COMMANDS: [&str; 4] = [
    "symvault mcp install",
    "symvault mcp status",
    "symvault serve install",
    "symvault serve status",
];

/// The name the fixture uses for this host (Go's `GOOS`).
fn host_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else {
        std::env::consts::OS
    }
}

/// How many of `darwin_only` scenarios this host skips.
fn expected_skips(darwin_only: usize) -> usize {
    if host_os() == "darwin" {
        0
    } else {
        darwin_only
    }
}

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

/// The stand-in tools of the recording, read once from the fixture.
fn host_tools() -> &'static HostTools {
    static TOOLS: OnceLock<HostTools> = OnceLock::new();
    TOOLS.get_or_init(|| fixture().host_tools)
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

/// What one sandboxed run did, including the calls it made to the host-tool stand-ins.
#[derive(Clone, Debug)]
struct RunOutput {
    code: i32,
    stdout: String,
    stderr: String,
    /// `tool argv...` per call, sandbox root normalized, in call order.
    calls: Vec<String>,
}

const HOST_TOOLS_DIR: &str = ".host-tools";
const HOST_TOOLS_LOG: &str = "calls.log";
/// The rest of the sandbox `PATH`, after the stand-ins (sh, printf, echo, sleep, git).
const SANDBOX_PATH_SYSTEM: &str = "/usr/bin:/bin";

/// Single-quotes text for a POSIX shell.
#[cfg(unix)]
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// Writes the stand-in executables into the sandbox, byte for byte what the
/// generator's `installHostTools` writes. The log path is baked in: a service
/// manager runs with a cleared or filtered environment.
#[cfg(unix)]
fn install_host_tools(root: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = root.join(HOST_TOOLS_DIR);
    fs::create_dir_all(&dir).expect("create host-tool directory");
    let log = dir.join(HOST_TOOLS_LOG);
    let tools = host_tools();
    for name in tools.service_managers.iter().chain(&tools.refused) {
        let script = format!(
            "#!/bin/sh\nprintf '%s %s\\n' {} \"$*\" >> {}\nexit 0\n",
            shell_quote(name),
            shell_quote(&log.to_string_lossy())
        );
        let path = dir.join(name);
        fs::write(&path, script).expect("write host-tool stand-in");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("make the stand-in executable");
    }
}

#[cfg(not(unix))]
fn install_host_tools(_root: &Path) {}

/// The sandbox `PATH`: the stand-ins first, then the system directories only.
#[cfg(unix)]
fn sandbox_path(root: &Path) -> String {
    format!(
        "{}:{SANDBOX_PATH_SYSTEM}",
        root.join(HOST_TOOLS_DIR).display()
    )
}

/// The calls the stand-ins logged, one `tool argv...` line each.
fn read_host_calls(root: &Path) -> Vec<String> {
    let raw =
        fs::read_to_string(root.join(HOST_TOOLS_DIR).join(HOST_TOOLS_LOG)).unwrap_or_default();
    normalize_root(root, &raw)
        .lines()
        .map(|line| line.trim_end().to_owned())
        .collect()
}

/// The calls of `calls` that name a tool no scenario may use.
fn refused_calls(calls: &[String], tools: &HostTools) -> Vec<String> {
    calls
        .iter()
        .filter(|call| {
            let name = call.split(' ').next().unwrap_or("");
            !tools.service_managers.iter().any(|manager| manager == name)
        })
        .cloned()
        .collect()
}

/// Replaces the sandbox root (in the spellings the platform renders) by `__ROOT__`.
fn normalize_root(root: &Path, raw: &str) -> String {
    let mut text = raw.to_owned();
    let path = root.to_path_buf();
    let cleaned: std::path::PathBuf = path.components().collect();
    for form in [path.to_string_lossy(), cleaned.to_string_lossy()] {
        text = text.replace(&form.replace('\\', "\\\\"), "__ROOT__");
        text = text.replace(&*form, "__ROOT__");
    }
    text
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
    let run = run_scenario_full(args, files, seed, initialized);
    (run.code, run.stdout, run.stderr)
}

fn run_scenario_full(
    args: &[String],
    files: &BTreeMap<String, String>,
    seed: &[SeedFile],
    initialized: bool,
) -> RunOutput {
    let root = test_temp_root::TempRoot::existing("symvault-error-taxonomy-");
    let home = root.join("home");
    fs::create_dir_all(&home).expect("create isolated home");
    write_seed(&root, seed);
    for (name, content) in files {
        fs::write(root.join(name), content).expect("write disposable file");
    }
    install_host_tools(&root);
    let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SYMVAULT_") {
            command.env_remove(name);
        }
    }
    #[cfg(unix)]
    command.env("PATH", sandbox_path(&root));
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
    let normalize =
        |raw: &[u8]| windows_errno_to_go_unix(normalize_root(&root, &String::from_utf8_lossy(raw)));
    let calls = read_host_calls(&root);
    let refused = refused_calls(&calls, host_tools());
    assert!(
        refused.is_empty(),
        "{args:?} reached host tools that no scenario may use: {refused:?}"
    );
    RunOutput {
        code: output.status.code().unwrap_or(-1),
        stdout: normalize(&output.stdout),
        stderr: normalize(&output.stderr),
        calls,
    }
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
            // A probe of the machine's biometric hardware, not of the CLI.
            "touch_id_available" => {
                *stdout = stdout
                    .replace(
                        "Touch ID available: true\n",
                        "Touch ID available: __BOOL__\n",
                    )
                    .replace(
                        "Touch ID available: false\n",
                        "Touch ID available: __BOOL__\n",
                    );
            }
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
fn run_case_full(case: &ScenarioCase, seed: &[SeedFile]) -> RunOutput {
    let initialized = case.state == "initialized";
    let mut run = run_scenario_full(
        &case.observation.args,
        &BTreeMap::new(),
        if initialized { seed } else { &[] },
        initialized,
    );
    apply_normalizers(&case.normalize, &mut run.stdout, &mut run.stderr);
    run
}

fn run_case(case: &ScenarioCase, seed: &[SeedFile]) -> (i32, String, String) {
    let run = run_case_full(case, seed);
    (run.code, run.stdout, run.stderr)
}

/// Whether `case` can be compared on this host.
fn runs_on_this_host(case: &ScenarioCase) -> bool {
    case.platforms.is_empty() || case.platforms.iter().any(|platform| platform == host_os())
}

/// How many scenarios a replay compared and how many it skipped on this host.
#[derive(Debug, PartialEq, Eq)]
struct Replay {
    replayed: usize,
    skipped: usize,
}

/// Replays the scenarios recorded for `state`. Known divergences are compared with
/// their pinned native observation instead of Go's. A scenario tagged for other
/// platforms is skipped and counted: its output names the recording platform's
/// service manager. The recorded service-manager calls are compared where they were
/// recorded; everywhere the stand-in guard still holds.
fn replay_scenarios(
    fixture: &Fixture,
    cases: &[ScenarioCase],
    state: &str,
    failures: &mut Vec<String>,
) -> Replay {
    let seed = &fixture.vault_seed;
    let compare_calls = host_os() == fixture.generated_on;
    let pinned = pinned_divergences();
    let mut replayed = 0;
    let mut skipped = 0;
    for case in cases.iter().filter(|case| case.state == state) {
        if !runs_on_this_host(case) {
            skipped += 1;
            continue;
        }
        let run = run_case_full(case, seed);
        if compare_calls && run.calls != case.host_tool_calls {
            failures.push(format!(
                "{} host-tool calls\n  go:   {:?}\n  rust: {:?}",
                case.name, case.host_tool_calls, run.calls
            ));
        }
        let actual = (run.code, run.stdout, run.stderr);
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
    if skipped > 0 {
        eprintln!(
            "SKIP {skipped} {state} scenarios of host-dependent commands (recorded on {}, this host is {})",
            fixture.generated_on,
            host_os()
        );
    }
    Replay { replayed, skipped }
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
    let replay = replay_scenarios(
        &fixture,
        &fixture.extra_positionals,
        "uninitialized",
        &mut failures,
    );
    assert_eq!(
        replay.replayed + replay.skipped,
        EXTRA_POSITIONALS_UNINITIALIZED
    );
    assert_eq!(replay.skipped, expected_skips(DARWIN_ONLY_UNINITIALIZED));
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The same positionals in the frozen initialized vault. The seed carries Unix
/// permission bits and the recording ran on Unix.
#[cfg(unix)]
#[test]
fn native_cli_matches_go_extra_positionals_initialized() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let replay = replay_scenarios(
        &fixture,
        &fixture.extra_positionals,
        "initialized",
        &mut failures,
    );
    assert_eq!(
        replay.replayed + replay.skipped,
        EXTRA_POSITIONALS_INITIALIZED
    );
    assert_eq!(replay.skipped, expected_skips(DARWIN_ONLY_INITIALIZED));
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `run` and `file use` forward a trailing command line: flags, bare words and
/// `--` in every position must be handled as Go's cobra does.
#[test]
fn native_cli_matches_go_run_file_use_argv_uninitialized() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let replay = replay_scenarios(
        &fixture,
        &fixture.run_file_use_argv,
        "uninitialized",
        &mut failures,
    );
    assert_eq!(
        replay,
        Replay {
            replayed: RUN_FILE_USE_ARGV_PER_STATE,
            skipped: 0
        }
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[cfg(unix)]
#[test]
fn native_cli_matches_go_run_file_use_argv_initialized() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let replay = replay_scenarios(
        &fixture,
        &fixture.run_file_use_argv,
        "initialized",
        &mut failures,
    );
    assert_eq!(
        replay,
        Replay {
            replayed: RUN_FILE_USE_ARGV_PER_STATE,
            skipped: 0
        }
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The scenarios of the host-dependent commands, and only those, carry the platform
/// tag; the fixture says where it was recorded and which stand-ins the recording had.
#[test]
fn host_dependent_scenarios_are_tagged_and_counted() {
    let fixture = fixture();
    assert_eq!(fixture.generated_on, "darwin");
    let paths: Vec<&str> = fixture
        .host_dependent_commands
        .iter()
        .map(|item| item.path.as_str())
        .collect();
    assert_eq!(paths, HOST_DEPENDENT_COMMANDS);
    for item in &fixture.host_dependent_commands {
        assert_eq!(item.platforms, ["darwin"], "{}", item.path);
        assert!(!item.reason.is_empty(), "{} has no reason", item.path);
        assert!(
            fixture.nil_args.iter().any(|entry| entry.path == item.path),
            "{} is not a nil-Args command",
            item.path
        );
    }
    let slug = |path: &str| path.trim_start_matches("symvault ").replace(' ', "_");
    for state in ["uninitialized", "initialized"] {
        let tagged = fixture
            .extra_positionals
            .iter()
            .filter(|case| case.state == state && !case.platforms.is_empty())
            .count();
        let expected = if state == "uninitialized" {
            DARWIN_ONLY_UNINITIALIZED
        } else {
            DARWIN_ONLY_INITIALIZED
        };
        assert_eq!(tagged, expected, "{state}");
    }
    for case in &fixture.extra_positionals {
        let dependent = HOST_DEPENDENT_COMMANDS.iter().any(|path| {
            case.name
                .starts_with(&format!("extra_{}_{}_", case.state, slug(path)))
        });
        assert_eq!(
            !case.platforms.is_empty(),
            dependent,
            "{} is tagged inconsistently",
            case.name
        );
        if dependent {
            assert_eq!(case.platforms, ["darwin"], "{}", case.name);
        }
    }
    assert!(
        fixture
            .run_file_use_argv
            .iter()
            .all(|case| case.platforms.is_empty()),
        "run/file-use scenarios compare on every platform"
    );
    let tools = &fixture.host_tools;
    assert_eq!(tools.service_managers, ["launchctl", "systemctl"]);
    for refused in ["security", "osascript", "pbcopy", "pbpaste", "notify-send"] {
        assert!(
            tools.refused.iter().any(|tool| tool == refused),
            "{refused} must be a refused stand-in"
        );
    }
    assert!(
        tools
            .refused
            .iter()
            .all(|tool| !tools.service_managers.contains(tool))
    );
    // Only the service-manager scenarios made host-tool calls, and the install ones
    // ran launchctl unload then load.
    for case in fixture
        .extra_positionals
        .iter()
        .chain(&fixture.run_file_use_argv)
    {
        let service = [
            "mcp_install",
            "mcp_uninstall",
            "serve_install",
            "serve_uninstall",
        ]
        .iter()
        .any(|command| case.name.contains(&format!("_{command}_")));
        assert_eq!(!case.host_tool_calls.is_empty(), service, "{}", case.name);
        assert!(
            refused_calls(&case.host_tool_calls, tools).is_empty(),
            "{} recorded a refused tool",
            case.name
        );
        if case.name.contains("_install_") {
            assert_eq!(case.host_tool_calls.len(), 2, "{}", case.name);
            assert!(case.host_tool_calls[0].starts_with("launchctl unload "));
            assert!(case.host_tool_calls[1].starts_with("launchctl load "));
        }
    }
}

/// Every host tool resolves to its stand-in on the sandbox `PATH`, never to the
/// developer's `launchctl`, `security`, `pbcopy`, ...
#[cfg(unix)]
#[test]
fn sandbox_path_resolves_every_host_tool_to_its_stand_in() {
    let root = test_temp_root::TempRoot::existing("symvault-host-tools-");
    install_host_tools(&root);
    let tools = host_tools();
    for name in tools.service_managers.iter().chain(&tools.refused) {
        let output = Command::new("/bin/sh")
            .args(["-c", &format!("command -v {name}")])
            .env_clear()
            .env("PATH", sandbox_path(&root))
            .output()
            .expect("run sh");
        assert!(output.status.success(), "{name} is not on the sandbox PATH");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            root.join(HOST_TOOLS_DIR).join(name).to_string_lossy(),
            "{name} does not resolve to its stand-in"
        );
    }
}

/// The stand-ins log argv without any environment and succeed silently; the guard
/// flags every tool that is not a service manager (negative control).
#[cfg(unix)]
#[test]
fn stand_ins_log_their_calls_and_the_guard_flags_other_tools() {
    let root = test_temp_root::TempRoot::existing("symvault-host-tools-");
    install_host_tools(&root);
    let run = |name: &str, args: &[&str]| {
        let output = Command::new(root.join(HOST_TOOLS_DIR).join(name))
            .args(args)
            .env_clear()
            .output()
            .expect("run stand-in");
        assert!(output.status.success());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    };
    let plist = root.join("home/LaunchAgents/x.plist");
    run("launchctl", &["unload", &plist.to_string_lossy()]);
    run("systemctl", &["--user", "daemon-reload"]);
    run("security", &[]);
    run("pbcopy", &["-pboard", "general"]);
    let calls = read_host_calls(&root);
    assert_eq!(
        calls,
        [
            "launchctl unload __ROOT__/home/LaunchAgents/x.plist",
            "systemctl --user daemon-reload",
            "security",
            "pbcopy -pboard general",
        ]
    );
    assert_eq!(
        refused_calls(&calls, host_tools()),
        ["security", "pbcopy -pboard general"]
    );
    assert!(refused_calls(&calls[..2], host_tools()).is_empty());
}

/// On the recording platform the native service commands make exactly the
/// launchctl calls Go made, in order, against the stand-in.
#[cfg(target_os = "macos")]
#[test]
fn darwin_service_commands_make_the_recorded_launchctl_calls() {
    let fixture = fixture();
    let mut checked = 0;
    for case in fixture
        .extra_positionals
        .iter()
        .filter(|case| case.name.contains("_install_x1") || case.name.contains("_uninstall_x1"))
    {
        assert!(!case.host_tool_calls.is_empty(), "{}", case.name);
        let run = run_case_full(case, &fixture.vault_seed);
        assert_eq!(run.calls, case.host_tool_calls, "{}", case.name);
        checked += 1;
    }
    assert_eq!(checked, 8);
}

/// Linux has no recording of these commands (the corpus is darwin's), so this is
/// not Go parity: it shows that the skipped scenarios still reach the command, that
/// the native service code talks to systemd's stand-in only, and that the output
/// differs from the darwin recording in nothing but the service-file path.
#[cfg(target_os = "linux")]
#[test]
fn linux_service_commands_use_systemd_through_the_stand_in() {
    const PLIST: &str = "__ROOT__/home/LaunchAgents/com.symvault.mcp.plist";
    const UNIT: &str = "__ROOT__/home/.config/systemd/user/symvault-mcp.service";
    let fixture = fixture();
    let mut checked = 0;
    for case in fixture
        .extra_positionals
        .iter()
        .filter(|case| !case.platforms.is_empty())
    {
        let run = run_case_full(case, &fixture.vault_seed);
        let recorded = &case.observation;
        assert_eq!(run.code, recorded.exit_code, "{}", case.name);
        assert_eq!(run.stderr, recorded.stderr, "{}", case.name);
        assert_eq!(
            run.stdout,
            recorded.stdout.replace(PLIST, UNIT),
            "{}",
            case.name
        );
        let expected: &[&str] = if case.name.contains("_install_") {
            &[
                "systemctl --user daemon-reload",
                "systemctl --user enable symvault-mcp",
                "systemctl --user start symvault-mcp",
            ]
        } else {
            &[]
        };
        assert_eq!(run.calls, expected, "{}", case.name);
        checked += 1;
    }
    assert_eq!(checked, DARWIN_ONLY_UNINITIALIZED + DARWIN_ONLY_INITIALIZED);
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

#[test]
fn touch_id_normalizer_rewrites_only_the_availability_line() {
    let names = ["touch_id_available".to_string()];
    for available in ["true", "false"] {
        let mut stdout = format!(
            "Auth method: passphrase\nTouch ID available: {available}\nKeyring health: unavailable\n"
        );
        let mut stderr = "Touch ID available: true\n".to_string();
        apply_normalizers(&names, &mut stdout, &mut stderr);
        assert_eq!(
            stdout,
            "Auth method: passphrase\nTouch ID available: __BOOL__\nKeyring health: unavailable\n"
        );
        assert_eq!(stderr, "Touch ID available: true\n", "stderr is untouched");
    }
    let mut other = "Touch ID available: maybe\n".to_string();
    apply_normalizers(&names, &mut other, &mut String::new());
    assert_eq!(other, "Touch ID available: maybe\n");
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
