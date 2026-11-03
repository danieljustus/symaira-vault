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

#[derive(Clone, Debug, Deserialize)]
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
    /// Disposable files written into the working directory before the run.
    #[serde(default)]
    files: BTreeMap<String, String>,
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
    service_manager_commands: Vec<String>,
    run_file_use_argv: Vec<ScenarioCase>,
    unlock_states: Vec<ScenarioCase>,
    typed_flags: Vec<ScenarioCase>,
    bare_dash: Vec<ScenarioCase>,
}

const USAGE_CASES: usize = 159;
const ARGV_SHAPES: usize = 24;
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
/// The typed-flag section (CLI-003): values pflag accepts and the command then uses.
const TYPED_FLAGS_UNINITIALIZED: usize = 8;
const TYPED_FLAGS_INITIALIZED: usize = 132;
/// The bare-dash section (CLI-005): a lone `-` that cobra's command resolution skips and
/// pflag counts, `--` and flag-only invocations that leave the root to print its help,
/// and the help topic walk.
const BARE_DASH_UNINITIALIZED: usize = 72;
const BARE_DASH_INITIALIZED: usize = 11;
/// The unlock-state section: commands that unlock the vault, in the settled vault
/// without the environment passphrase (`locked`, EOF at the prompt) and in the
/// vault shapes that miss `config.yaml` or `identity.age`.
const UNLOCK_STATES: [(&str, usize); 9] = [
    ("locked", 18),
    ("identity_only", 7),
    ("config_only", 7),
    ("identity_only_locked", 7),
    ("config_only_locked", 7),
    ("config_only_env_disabled", 7),
    ("env_disabled", 7),
    ("config_clipboard_invalid", 12),
    ("config_syntax_invalid", 12),
];
/// Appended to the seeded `config.yaml` of the `*env_disabled` states.
const ENV_DISABLED_CONFIG_SUFFIX: &str = "security:\n    disable_env_passphrase: true\n";
/// Appended to the seeded `config.yaml` of the config-invalid states (PLATFORM-001): a
/// negative `clipboard.auto_clear_duration` fails the validation, an unterminated flow
/// sequence fails the load. Go refuses both when it resolves the configuration to open
/// the vault.
const CLIPBOARD_INVALID_CONFIG_SUFFIX: &str = "clipboard:\n    auto_clear_duration: -5\n";
const SYNTAX_INVALID_CONFIG_SUFFIX: &str = "clipboard: [\n";
const KNOWN_DIVERGENT_UNINITIALIZED: usize = 0;
const KNOWN_DIVERGENT_INITIALIZED: usize = 0;
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

/// The only commands whose scenarios may call `launchctl` or `systemctl`; every
/// other scenario must make zero host-tool calls on every platform.
const SERVICE_MANAGER_COMMANDS: [&str; 6] = [
    "symvault mcp install",
    "symvault mcp status",
    "symvault mcp uninstall",
    "symvault serve install",
    "symvault serve status",
    "symvault serve uninstall",
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
const KNOWN_BODY_DIVERGENCES: &[(&str, &str, &str)] = &[];

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
    /// Every seeded `config.yaml` as `(path, bytes before the run, bytes after it)`; `None`
    /// is a file that does not exist.
    configs: Vec<ConfigSnapshot>,
}

/// One seeded `config.yaml` around a run.
#[derive(Clone, Debug)]
struct ConfigSnapshot {
    path: String,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
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
        let path = root.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create disposable file directory");
        }
        fs::write(path, content).expect("write disposable file");
    }
    install_host_tools(&root);
    let config_paths: Vec<&str> = seed
        .iter()
        .filter(|entry| entry.kind == "file" && entry.path.ends_with("/config.yaml"))
        .map(|entry| entry.path.as_str())
        .collect();
    let configs_before: Vec<Option<Vec<u8>>> = config_paths
        .iter()
        .map(|path| fs::read(root.join(path)).ok())
        .collect();
    let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SYMVAULT_") {
            command.env_remove(name);
        }
    }
    #[cfg(unix)]
    command.env("PATH", sandbox_path(&root));
    if !seed.is_empty() {
        command.env("TZ", "UTC");
    }
    if initialized {
        command
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
    let configs = config_paths
        .iter()
        .zip(configs_before)
        .map(|(path, before)| ConfigSnapshot {
            path: (*path).to_owned(),
            before,
            after: fs::read(root.join(path)).ok(),
        })
        .collect();
    RunOutput {
        code: output.status.code().unwrap_or(-1),
        stdout: normalize(&output.stdout),
        stderr: normalize(&output.stderr),
        calls,
        configs,
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
            "token_values" => {
                *stdout = normalize_token_text(stdout);
                *stderr = normalize_token_text(stderr);
            }
            other => panic!("unknown normalizer {other}"),
        }
    }
}

/// Mirrors `normalizeTokenText` of the generator: the random id of a minted agent token
/// (`tok-<8 digits>-<8 hex>`, anywhere), and the text after the expiry and raw-token
/// prefixes of a line. A different shape is left alone, so it still differs.
fn normalize_token_text(text: &str) -> String {
    let mut with_ids = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("tok-") {
        let (head, tail) = rest.split_at(at);
        with_ids.push_str(head);
        let id = &tail["tok-".len()..];
        let digits = id.get(..8).unwrap_or("");
        let hex = id.get(9..17).unwrap_or("");
        if digits.len() == 8
            && digits.bytes().all(|byte| byte.is_ascii_digit())
            && id.as_bytes().get(8) == Some(&b'-')
            && hex.len() == 8
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            with_ids.push_str("tok-__ID__");
            rest = &tail["tok-".len() + 17..];
        } else {
            with_ids.push_str("tok-");
            rest = &tail["tok-".len()..];
        }
    }
    with_ids.push_str(rest);
    with_ids
        .split_inclusive('\n')
        .map(|line| {
            let body = line.strip_suffix('\n').unwrap_or(line);
            let newline = &line[body.len()..];
            if body.starts_with("  Expires: ") {
                format!("  Expires: __TIME__{newline}")
            } else if body.starts_with("Raw token (copy now \u{2014} shown once): ") {
                format!("Raw token (copy now \u{2014} shown once): __TOKEN__{newline}")
            } else {
                line.to_owned()
            }
        })
        .collect()
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

/// How a scenario state shapes its sandbox: whether the frozen vault is
/// written, which of its files stay out and whether the environment passphrase
/// is set. Mirrors `specForState` in `errtaxgen/unlockstates.go`.
fn state_shape(state: &str) -> (bool, &'static [&'static str], bool) {
    match state {
        "uninitialized" => (false, &[], false),
        "initialized" => (true, &[], true),
        "locked" => (true, &[], false),
        "identity_only" => (true, &["config.yaml"], true),
        "config_only" => (true, &["identity.age"], true),
        "identity_only_locked" => (true, &["config.yaml"], false),
        "config_only_locked" => (true, &["identity.age"], false),
        "config_only_env_disabled" => (true, &["identity.age"], true),
        "env_disabled" => (true, &[], true),
        "config_clipboard_invalid" | "config_syntax_invalid" => (true, &[], true),
        other => panic!("unknown scenario state {other}"),
    }
}

/// The seed entries of regular files whose base name is not in `omit`.
fn seed_without(seed: &[SeedFile], omit: &[&str]) -> Vec<SeedFile> {
    seed.iter()
        .filter(|entry| {
            !(entry.kind == "file"
                && omit.contains(&entry.path.rsplit('/').next().unwrap_or(&entry.path)))
        })
        .cloned()
        .collect()
}

/// Runs one recorded scenario in a fresh sandbox, with its normalizers applied.
fn run_case_full(case: &ScenarioCase, seed: &[SeedFile]) -> RunOutput {
    let (with_seed, omit, passphrase_env) = state_shape(&case.state);
    let mut seed = if with_seed {
        seed_without(seed, omit)
    } else {
        Vec::new()
    };
    let suffix = match case.state.as_str() {
        "config_only_env_disabled" | "env_disabled" => Some(ENV_DISABLED_CONFIG_SUFFIX),
        "config_clipboard_invalid" => Some(CLIPBOARD_INVALID_CONFIG_SUFFIX),
        "config_syntax_invalid" => Some(SYNTAX_INVALID_CONFIG_SUFFIX),
        _ => None,
    };
    if let Some(suffix) = suffix {
        for entry in &mut seed {
            if entry.kind == "file" && entry.path.ends_with("/config.yaml") {
                entry.data.push_str(suffix);
            }
        }
    }
    let mut run = run_scenario_full(&case.observation.args, &case.files, &seed, passphrase_env);
    apply_normalizers(&case.normalize, &mut run.stdout, &mut run.stderr);
    run
}

fn run_case(case: &ScenarioCase, seed: &[SeedFile]) -> (i32, String, String) {
    let run = run_case_full(case, seed);
    (run.code, run.stdout, run.stderr)
}

/// Whether `case` is a scenario of a service-manager command (the scenario name
/// is `extra_<state>_<command words joined by _>_<variant>`).
fn is_service_manager_case(case: &ScenarioCase) -> bool {
    SERVICE_MANAGER_COMMANDS.iter().any(|path| {
        let slug = path.trim_start_matches("symvault ").replace(' ', "_");
        case.name
            .starts_with(&format!("extra_{}_{slug}_", case.state))
    })
}

/// What is wrong with the host-tool calls of one run, if anything. A scenario of a
/// service-manager command is compared with the recorded calls where they were
/// recorded (`recorded_here`); every other scenario must have made no call on any
/// platform, so a new unrelated `systemctl`/`launchctl` call cannot slip through
/// on the platform that has no recording.
fn host_call_failure(case: &ScenarioCase, calls: &[String], recorded_here: bool) -> Option<String> {
    if is_service_manager_case(case) {
        (recorded_here && calls != case.host_tool_calls).then(|| {
            format!(
                "{} host-tool calls\n  go:   {:?}\n  rust: {:?}",
                case.name, case.host_tool_calls, calls
            )
        })
    } else {
        (!calls.is_empty() || !case.host_tool_calls.is_empty()).then(|| {
            format!(
                "{} is not a service-manager command but made host-tool calls\n  recorded: {:?}\n  rust:     {:?}",
                case.name, case.host_tool_calls, calls
            )
        })
    }
}

/// PLATFORM-001: a configuration Go refuses is reported, never repaired or rewritten, so
/// the refused `config.yaml` must be byte-identical after the run (the interactive repair
/// prompts reach EOF and are declined).
fn config_rewrite_failure(case: &ScenarioCase, run: &RunOutput) -> Option<String> {
    if !matches!(
        case.state.as_str(),
        "config_clipboard_invalid" | "config_syntax_invalid"
    ) {
        return None;
    }
    if run.configs.is_empty() {
        return Some(format!("{} seeded no config.yaml to snapshot", case.name));
    }
    run.configs
        .iter()
        .find(|config| config.before.is_none() || config.before != config.after)
        .map(|config| {
            format!(
                "{} changed {} on a refused configuration\n  before: {:?}\n  after:  {:?}",
                case.name,
                config.path,
                config.before.as_deref().map(String::from_utf8_lossy),
                config.after.as_deref().map(String::from_utf8_lossy)
            )
        })
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
        failures.extend(host_call_failure(case, &run.calls, compare_calls));
        failures.extend(config_rewrite_failure(case, &run));
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
    for (state, count) in [
        ("uninitialized", TYPED_FLAGS_UNINITIALIZED),
        ("initialized", TYPED_FLAGS_INITIALIZED),
    ] {
        assert_eq!(in_state(&fixture.typed_flags, state), count, "{state}");
    }
    assert_eq!(
        fixture.typed_flags.len(),
        TYPED_FLAGS_UNINITIALIZED + TYPED_FLAGS_INITIALIZED
    );
    for (state, count) in [
        ("uninitialized", BARE_DASH_UNINITIALIZED),
        ("initialized", BARE_DASH_INITIALIZED),
    ] {
        assert_eq!(in_state(&fixture.bare_dash, state), count, "{state}");
    }
    assert_eq!(
        fixture.bare_dash.len(),
        BARE_DASH_UNINITIALIZED + BARE_DASH_INITIALIZED
    );
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

/// CLI-003: values of typed flags that pflag accepts and the command then uses.
/// `file add --max-size` is an int64 (hex, octal, binary, `_`, negative limits),
/// `stringSlice` flags are one CSV record per occurrence (`doctor --only|--exclude`,
/// `agent token new|rotate --tools`) and `time.Duration` flags are used by the
/// commands (`run|file use --timeout`, `unlock --ttl`, `intake watch
/// --interval|--debounce`, `dynamic generate --ttl`).
#[test]
fn native_cli_matches_go_typed_flags_uninitialized() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let replay = replay_scenarios(
        &fixture,
        &fixture.typed_flags,
        "uninitialized",
        &mut failures,
    );
    assert_eq!(
        replay,
        Replay {
            replayed: TYPED_FLAGS_UNINITIALIZED,
            skipped: 0
        }
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[cfg(unix)]
#[test]
fn native_cli_matches_go_typed_flags_initialized() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let replay = replay_scenarios(&fixture, &fixture.typed_flags, "initialized", &mut failures);
    assert_eq!(
        replay,
        Replay {
            replayed: TYPED_FLAGS_INITIALIZED,
            skipped: 0
        }
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The recorded typed-flag cases really exercise the residual classes (a generator that
/// silently dropped a class would leave the replay green).
#[test]
fn typed_flag_section_records_every_residual_class() {
    let fixture = fixture();
    let case = |name: &str| {
        fixture
            .typed_flags
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("{name} is not recorded"))
    };
    let names: std::collections::BTreeSet<&str> = fixture
        .typed_flags
        .iter()
        .map(|case| case.name.as_str())
        .collect();
    assert_eq!(names.len(), fixture.typed_flags.len(), "duplicate names");
    for case in &fixture.typed_flags {
        assert!(case.name.starts_with("typed_"), "{}", case.name);
        assert!(
            case.name.ends_with(&format!("_{}", case.state)),
            "{}",
            case.name
        );
        assert!(
            case.platforms.is_empty(),
            "{} compares everywhere",
            case.name
        );
        assert!(case.host_tool_calls.is_empty(), "{}", case.name);
    }
    // int64: a hex limit below the size, a negative limit and the smallest int64.
    let hex = case("typed_max_size_hex_below_size_initialized");
    assert_eq!(hex.observation.exit_code, 9);
    assert!(hex.observation.stderr.contains("exceeds the 16 byte limit"));
    let negative = case("typed_max_size_negative_initialized");
    assert_eq!(negative.observation.exit_code, 9);
    assert!(
        negative
            .observation
            .stderr
            .contains("exceeds the -1 byte limit")
    );
    assert!(
        case("typed_max_size_min_int64_hex_initialized")
            .observation
            .stderr
            .contains("exceeds the -9223372036854775808 byte limit")
    );
    assert_eq!(
        case("typed_max_size_max_int64_initialized")
            .observation
            .exit_code,
        0
    );
    assert_eq!(
        case("typed_max_size_hex_overflow_initialized")
            .observation
            .exit_code,
        1
    );
    // The size and the flag checks come before the vault.
    for name in [
        "typed_max_size_negative_before_vault_uninitialized",
        "typed_file_add_no_flags_uninitialized",
    ] {
        assert_eq!(case(name).observation.exit_code, 9, "{name}");
    }
    assert_eq!(
        case("typed_max_size_fits_vault_check_uninitialized")
            .observation
            .exit_code,
        3
    );
    // stringSlice: an empty value is no filter; quoted commas and empty elements.
    let all = case("typed_slice_doctor_only_empty_value_initialized");
    assert!(all.observation.stdout.matches("\"id\"").count() >= 4);
    let quoted = case("typed_slice_doctor_only_quoted_comma_initialized");
    assert_eq!(quoted.observation.stdout.matches("\"id\"").count(), 0);
    let tools = case("typed_slice_token_new_empty_value_initialized");
    assert_eq!(tools.observation.exit_code, 1);
    assert!(
        tools
            .observation
            .stderr
            .contains("at least one tool must be specified")
    );
    assert!(
        case("typed_slice_token_new_quoted_comma_initialized")
            .observation
            .stdout
            .contains("  Tools: a,b, c\n")
    );
    assert!(
        case("typed_slice_token_new_empty_elements_initialized")
            .observation
            .stdout
            .contains("  Tools: a, , b\n")
    );
    // Durations: a timeout that expired before the start, a negative one and a
    // fractional one.
    assert!(
        case("typed_duration_run_expired_before_start_ns_initialized")
            .observation
            .stderr
            .contains("failed to run command: context deadline exceeded")
    );
    assert!(
        case("typed_duration_run_fraction_initialized")
            .observation
            .stderr
            .contains("command timed out after 250.5ms")
    );
    assert_eq!(
        case("typed_duration_run_negative_initialized")
            .observation
            .exit_code,
        0
    );
    assert_eq!(
        case("typed_duration_run_zero_initialized")
            .observation
            .exit_code,
        0
    );
    assert_eq!(
        case("typed_duration_watch_interval_negative_initialized")
            .observation
            .exit_code,
        0
    );
    // Every case that reads a source file brings it.
    for case in &fixture.typed_flags {
        if case.observation.args.iter().any(|arg| arg == "a.bin") {
            assert_eq!(
                case.files.get("a.bin").map(String::len),
                Some(100),
                "{}",
                case.name
            );
        }
    }
}

/// Negative control: a changed expectation of the typed-flag section is reported.
#[test]
fn mutated_typed_flag_expectation_is_detected() {
    let fixture = fixture();
    let case = fixture
        .typed_flags
        .iter()
        .find(|case| case.name == "typed_max_size_negative_initialized")
        .expect("case");
    let actual = run_case(case, &fixture.vault_seed);
    let mut failures = Vec::new();
    record_difference(&case.name, &case.observation, actual.clone(), &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    let mut tampered = case.observation.clone();
    tampered.stderr = tampered.stderr.replace("-1 byte", "1 byte");
    record_difference(&case.name, &tampered, actual.clone(), &mut failures);
    tampered = case.observation.clone();
    tampered.exit_code = 1;
    record_difference(&case.name, &tampered, actual, &mut failures);
    assert_eq!(failures.len(), 2, "{failures:?}");
}

/// CLI-005: a lone `-` is skipped by cobra's command resolution and counted by pflag
/// (`- list`, `share - list`), `--` ends the resolution so the root prints its help, and a
/// root with only persistent flags prints it too.
#[test]
fn native_cli_matches_go_bare_dash_uninitialized() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let replay = replay_scenarios(&fixture, &fixture.bare_dash, "uninitialized", &mut failures);
    assert_eq!(
        replay,
        Replay {
            replayed: BARE_DASH_UNINITIALIZED,
            skipped: 0
        }
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[cfg(unix)]
#[test]
fn native_cli_matches_go_bare_dash_initialized() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let replay = replay_scenarios(&fixture, &fixture.bare_dash, "initialized", &mut failures);
    assert_eq!(
        replay,
        Replay {
            replayed: BARE_DASH_INITIALIZED,
            skipped: 0
        }
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The recorded bare-dash cases really exercise each class (a generator that silently
/// dropped one would leave the replay green).
#[test]
fn bare_dash_section_records_every_class() {
    let fixture = fixture();
    let case = |name: &str| {
        fixture
            .bare_dash
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("{name} is not recorded"))
    };
    let names: std::collections::BTreeSet<&str> = fixture
        .bare_dash
        .iter()
        .map(|case| case.name.as_str())
        .collect();
    assert_eq!(names.len(), fixture.bare_dash.len(), "duplicate names");
    for case in &fixture.bare_dash {
        assert!(case.name.starts_with("dash_"), "{}", case.name);
        assert!(
            case.name.ends_with(&format!("_{}", case.state)),
            "{}",
            case.name
        );
        assert!(
            case.platforms.is_empty(),
            "{} compares everywhere",
            case.name
        );
        assert!(case.host_tool_calls.is_empty(), "{}", case.name);
    }
    // The root is not runnable: no command, a lone dash or everything after `--` is its help.
    let help = &case("dash_root_no_args_uninitialized").observation;
    assert_eq!(help.exit_code, 0);
    assert!(help.stdout.starts_with("Quick Start:\n"), "{}", help.stdout);
    assert!(help.stderr.is_empty());
    for name in [
        "dash_root_json_only_uninitialized",
        "dash_root_output_xml_only_uninitialized",
        "dash_root_dash_uninitialized",
        "dash_root_double_dash_uninitialized",
        "dash_root_two_dashes_uninitialized",
        "dash_root_output_xml_then_dash_uninitialized",
        "dash_after_double_dash_command_uninitialized",
        "dash_after_double_dash_command_with_arg_uninitialized",
        "dash_after_double_dash_flag_uninitialized",
        "dash_after_double_dash_version_flag_uninitialized",
        "dash_after_double_dash_help_flag_uninitialized",
        "dash_dash_then_double_dash_command_uninitialized",
        "dash_dash_before_help_uninitialized",
        "dash_help_dash_uninitialized",
    ] {
        let observation = &case(name).observation;
        assert_eq!(observation.exit_code, 0, "{name}");
        assert_eq!(observation.stdout, help.stdout, "{name}");
        assert!(observation.stderr.is_empty(), "{name}");
    }
    // A dash before the command does not hide it: list runs and stops at the vault check.
    let list = &case("dash_dash_before_list_uninitialized").observation;
    assert_eq!(list.exit_code, 3);
    assert!(
        list.stderr.contains("vault not initialized"),
        "{}",
        list.stderr
    );
    // ... and pflag counts it: two arguments for get, three for config get.
    for name in [
        "dash_dash_before_get_name_uninitialized",
        "dash_dash_inside_config_get_uninitialized",
        "dash_two_dashes_before_list_uninitialized",
    ] {
        let observation = &case(name).observation;
        assert_eq!(observation.exit_code, 1, "{name}");
        assert!(observation.stderr.contains("arg(s), received 2"), "{name}");
    }
    // The dash is a group's positional only when the group has no such subcommand.
    let group = &case("dash_dash_inside_group_list_initialized").observation;
    assert_eq!(group.stdout, "No share grants found.\n");
    let group_help = &case("dash_dash_inside_group_only_uninitialized").observation;
    assert!(
        group_help
            .stdout
            .starts_with("List and revoke secret share grants")
    );
    // The help topic walk skips the dash; an unknown topic names it.
    let topic = &case("dash_help_dash_command_uninitialized").observation;
    assert!(
        topic.stdout.starts_with("List password entries"),
        "{}",
        topic.stdout
    );
    let unknown = &case("dash_help_unknown_topic_dash_uninitialized").observation;
    assert!(
        unknown.stderr.starts_with("Unknown help topic [`foo` `-`]"),
        "{}",
        unknown.stderr
    );
    // The dash stays out of the way of the flags that follow it.
    let version = &case("dash_dash_after_version_then_json_uninitialized").observation;
    assert!(
        version.stdout.starts_with("{\"tool\":\"symvault\""),
        "{}",
        version.stdout
    );
}

/// Negative control: a changed expectation of the bare-dash section is reported.
#[test]
fn mutated_bare_dash_expectation_is_detected() {
    let fixture = fixture();
    let case = fixture
        .bare_dash
        .iter()
        .find(|case| case.name == "dash_dash_before_list_uninitialized")
        .expect("case");
    let actual = run_case(case, &fixture.vault_seed);
    let mut failures = Vec::new();
    record_difference(&case.name, &case.observation, actual.clone(), &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    let mut tampered = case.observation.clone();
    tampered.exit_code = 1;
    record_difference(&case.name, &tampered, actual.clone(), &mut failures);
    tampered = case.observation.clone();
    tampered.stderr = tampered.stderr.replace("not initialized", "initialized");
    record_difference(&case.name, &tampered, actual, &mut failures);
    assert_eq!(failures.len(), 2, "{failures:?}");
}

#[test]
fn token_value_normalizer_rewrites_only_the_random_parts() {
    let mut stdout = "Token created successfully.\n  ID:    tok-20261103-9dc781fc\n  Expires: 2026-11-04T06:48:37Z\n\nRaw token (copy now \u{2014} shown once): 7cc5ce8b\n  Tools: tok-1-x, tok-20261103-ZZZZZZZZ\n".to_string();
    let mut stderr =
        "WARNING: (id=tok-20261103-ef3b1dc9) revoke legacy tok-20261103-ef3b1dc9\n".to_string();
    apply_normalizers(&["token_values".to_string()], &mut stdout, &mut stderr);
    assert_eq!(
        stdout,
        "Token created successfully.\n  ID:    tok-__ID__\n  Expires: __TIME__\n\nRaw token (copy now \u{2014} shown once): __TOKEN__\n  Tools: tok-1-x, tok-20261103-ZZZZZZZZ\n"
    );
    assert_eq!(
        stderr,
        "WARNING: (id=tok-__ID__) revoke legacy tok-__ID__\n"
    );
}

/// The unlock-state section: Go resolves `config.yaml` (a missing file is the
/// default configuration), obtains the passphrase under that policy and only then
/// opens the vault (reads `identity.age`, loads `config.yaml`); a prompt that reads
/// EOF is an `ExitLocked` error (exit 4 and the locked hint).
#[cfg(unix)]
#[test]
fn native_cli_matches_go_unlock_states() {
    let fixture = fixture();
    let mut summary = Vec::new();
    let mut details = Vec::new();
    for (state, count) in UNLOCK_STATES {
        let mut failures = Vec::new();
        let replay = replay_scenarios(&fixture, &fixture.unlock_states, state, &mut failures);
        assert_eq!(
            replay,
            Replay {
                replayed: count,
                skipped: 0
            },
            "{state}"
        );
        summary.push(format!("{state}: {} of {count} differ", failures.len()));
        details.extend(failures);
    }
    assert!(
        details.is_empty(),
        "{}\n{}",
        summary.join("; "),
        details.join("\n")
    );
}

/// PLATFORM-001: Go resolves the configuration before it opens the vault and refuses one
/// that does not load or validate (`configuration is invalid: ...`, exit 6, the doctor
/// hint). The recorded refusals really name the cause, interactively (the repair prompts
/// reach EOF and abort) and for `get`, which never prompts once stdin is not a terminal.
#[test]
fn config_invalid_states_record_the_refusal() {
    let fixture = fixture();
    let case = |name: &str| {
        fixture
            .unlock_states
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("{name} is not recorded"))
    };
    let hint = "Run 'symvault doctor' to diagnose and fix configuration issues.\n";
    for state in ["config_clipboard_invalid", "config_syntax_invalid"] {
        let in_state: Vec<&ScenarioCase> = fixture
            .unlock_states
            .iter()
            .filter(|case| case.state == state)
            .collect();
        assert_eq!(in_state.len(), 12, "{state}");
        for case in in_state {
            let observation = &case.observation;
            assert_eq!(observation.exit_code, 6, "{}", case.name);
            // Only `import --dry-run` reports before it opens the vault: the format and the
            // CSV mapping of the source it parsed.
            if case.name.ends_with("_import_csv_dry_run") {
                assert_eq!(
                    observation.stdout,
                    "Import format: csv\nCSV mapping: notes=notes, otp=otp, password=password, title=title, url=url, username=username\n",
                    "{}",
                    case.name
                );
            } else {
                assert!(observation.stdout.is_empty(), "{}", case.name);
            }
            assert!(observation.stderr.ends_with(hint), "{}", case.name);
            assert!(
                observation
                    .stderr
                    .contains("Error: configuration is invalid: "),
                "{}",
                case.name
            );
        }
    }
    // A negative auto-clear duration is a validation error; the interactive commands are
    // offered the repair and decline it, `get` reports the validation text.
    let list = &case("unlock_config_clipboard_invalid_list").observation;
    assert!(list.stderr.contains("Field 'clipboard.autoClearDuration' must be non-negative. Suggestion: 30s. Apply this fix? (y/N): "), "{}", list.stderr);
    assert!(
        list.stderr.contains("configuration fix aborted by user"),
        "{}",
        list.stderr
    );
    let get = &case("unlock_config_clipboard_invalid_get").observation;
    assert!(get.stderr.contains("Error: configuration is invalid: clipboard.autoClearDuration: must be non-negative (configure clipboard.autoClearDuration in config.yaml)\n"), "{}", get.stderr);
    assert!(!get.stderr.contains("Apply this fix"), "{}", get.stderr);
    // A syntax error is a load error: the report names it, `get` returns it.
    let list = &case("unlock_config_syntax_invalid_list").observation;
    assert!(
        list.stderr.contains("  \u{2717} Load error: yaml: line "),
        "{}",
        list.stderr
    );
    let get = &case("unlock_config_syntax_invalid_get").observation;
    assert!(
        get.stderr
            .contains("Error: configuration is invalid: yaml: line "),
        "{}",
        get.stderr
    );
    // `dynamic generate` opens through cli.WithVault (interactive repair prompt, declined at
    // EOF); `mcp serve --stdio` resolves non-interactively and reports the cause. Both are
    // ExitConfigError and reach the doctor hint.
    for state in ["config_clipboard_invalid", "config_syntax_invalid"] {
        let dynamic = &case(&format!("unlock_{state}_dynamic_generate")).observation;
        assert!(
            dynamic
                .stderr
                .contains("Error: configuration is invalid: configuration fix aborted by user\n"),
            "{}",
            dynamic.stderr
        );
        let serve = &case(&format!("unlock_{state}_mcp_serve_stdio")).observation;
        assert!(
            !serve.stderr.contains("fix aborted by user")
                && !serve.stderr.contains("Apply this fix"),
            "{}",
            serve.stderr
        );
    }
    // `import <file>` (plain and --dry-run) parses the valid source first and is refused when
    // it opens the vault through cli.WithVault: exit 6 and the doctor hint, like every other
    // command, not a plain exit 1.
    for state in ["config_clipboard_invalid", "config_syntax_invalid"] {
        for name in ["import_csv", "import_csv_dry_run"] {
            let import = case(&format!("unlock_{state}_{name}"));
            assert_eq!(import.observation.args[..2], ["import", "source.csv"]);
            assert_eq!(import.files.len(), 1, "{}", import.name);
            assert!(
                import.files.contains_key("source.csv"),
                "{}: no CSV source file",
                import.name
            );
            assert_eq!(import.observation.exit_code, 6, "{}", import.name);
            assert!(
                import.observation.stderr.ends_with(hint),
                "{}",
                import.observation.stderr
            );
        }
    }
    // The refusal comes before the passphrase policy and the vault check: the locked and
    // identity-less shapes of the same commands are recorded elsewhere with other exits.
    assert_ne!(
        case("unlock_locked_list").observation.exit_code,
        list.exit_code
    );
}

/// Negative control: a replay that stops refusing the configuration is reported.
#[cfg(unix)]
#[test]
fn mutated_config_refusal_is_detected() {
    let fixture = fixture();
    let case = fixture
        .unlock_states
        .iter()
        .find(|case| case.name == "unlock_config_clipboard_invalid_get")
        .expect("case");
    let run = run_case_full(case, &fixture.vault_seed);
    let actual = (run.code, run.stdout.clone(), run.stderr.clone());
    let mut failures = Vec::new();
    record_difference(&case.name, &case.observation, actual.clone(), &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(config_rewrite_failure(case, &run), None);
    // A native open that accepted the configuration would exit 0 without the refusal.
    let mut accepted = actual;
    accepted.0 = 0;
    accepted.2 = String::new();
    record_difference(&case.name, &case.observation, accepted, &mut failures);
    assert_eq!(failures.len(), 1, "{failures:?}");
    // A native open that repaired the refused file in place would change its bytes.
    let mut repaired = run.clone();
    repaired.configs[0].after = Some(b"clipboard:\n    auto_clear_duration: 30s\n".to_vec());
    assert!(
        config_rewrite_failure(case, &repaired).is_some_and(|failure| failure.contains("changed")),
    );
    let mut deleted = run;
    deleted.configs[0].after = None;
    assert!(config_rewrite_failure(case, &deleted).is_some());
}

/// The partial vault shapes really miss their file, and the scenarios only name
/// states the section knows (a typo would silently replay an empty sandbox).
#[test]
fn unlock_state_shapes_drop_exactly_their_file() {
    let fixture = fixture();
    let names: Vec<&str> = fixture
        .vault_seed
        .iter()
        .map(|entry| entry.path.rsplit('/').next().unwrap_or(&entry.path))
        .collect();
    for file in ["config.yaml", "identity.age"] {
        assert_eq!(
            names.iter().filter(|name| **name == file).count(),
            1,
            "{file}"
        );
    }
    let count_of = |omit: &[&str]| seed_without(&fixture.vault_seed, omit).len();
    assert_eq!(count_of(&[]), fixture.vault_seed.len());
    assert_eq!(count_of(&["config.yaml"]), fixture.vault_seed.len() - 1);
    assert_eq!(count_of(&["identity.age"]), fixture.vault_seed.len() - 1);
    let known: Vec<&str> = UNLOCK_STATES.iter().map(|(state, _)| *state).collect();
    for case in &fixture.unlock_states {
        assert!(known.contains(&case.state.as_str()), "{}", case.name);
        assert!(case.name.starts_with(&format!("unlock_{}_", case.state)));
    }
    let total: usize = UNLOCK_STATES.iter().map(|(_, count)| count).sum();
    assert_eq!(fixture.unlock_states.len(), total);
    // The locked shapes record the locked exit class, not a plain failure.
    for case in fixture
        .unlock_states
        .iter()
        .filter(|case| case.state == "locked" && case.name.ends_with("_migrate_pseudonymize"))
    {
        assert_eq!(case.observation.exit_code, 4, "{}", case.name);
        assert!(
            case.observation
                .stderr
                .contains("Unlock with 'symvault unlock'")
        );
    }
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
    assert_eq!(fixture.service_manager_commands, SERVICE_MANAGER_COMMANDS);
    for path in HOST_DEPENDENT_COMMANDS {
        assert!(
            SERVICE_MANAGER_COMMANDS.contains(&path),
            "{path} is host dependent but not a service-manager command"
        );
    }
    for path in &fixture.service_manager_commands {
        assert!(
            fixture.nil_args.iter().any(|entry| &entry.path == path),
            "{path} is not a nil-Args command"
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
        // Calls come from install and uninstall only (`status` makes none on
        // darwin); no other scenario made one.
        let service = is_service_manager_case(case)
            && (case.name.contains("_install_") || case.name.contains("_uninstall_"));
        assert_eq!(!case.host_tool_calls.is_empty(), service, "{}", case.name);
        assert_eq!(
            host_call_failure(case, &case.host_tool_calls, true),
            None,
            "{}",
            case.name
        );
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

fn scenario(name: &str, args: &[&str], calls: &[&str]) -> ScenarioCase {
    ScenarioCase {
        name: name.to_string(),
        state: "uninitialized".to_string(),
        normalize: Vec::new(),
        platforms: Vec::new(),
        files: BTreeMap::new(),
        observation: Observation {
            args: args.iter().map(|arg| arg.to_string()).collect(),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
        host_tool_calls: calls.iter().map(|call| call.to_string()).collect(),
    }
}

/// Negative control for the host-call rule: a service-manager scenario is compared
/// only where it was recorded, every other scenario must make no call anywhere.
#[test]
fn host_call_rule_flags_unrelated_and_changed_calls() {
    let calls =
        |items: &[&str]| -> Vec<String> { items.iter().map(|item| item.to_string()).collect() };
    let install = scenario(
        "extra_uninitialized_mcp_install_x1",
        &["mcp", "install", "x"],
        &["launchctl load p"],
    );
    assert!(is_service_manager_case(&install));
    // Recording platform: the calls must repeat exactly.
    assert_eq!(
        host_call_failure(&install, &calls(&["launchctl load p"]), true),
        None
    );
    assert!(host_call_failure(&install, &calls(&["launchctl load q"]), true).is_some());
    assert!(host_call_failure(&install, &[], true).is_some());
    // Another platform: the service manager differs and is not compared.
    assert_eq!(
        host_call_failure(&install, &calls(&["systemctl --user start x"]), false),
        None
    );

    let unrelated = scenario("extra_uninitialized_lock_x1", &["lock", "x"], &[]);
    assert!(!is_service_manager_case(&unrelated));
    assert_eq!(host_call_failure(&unrelated, &[], true), None);
    assert_eq!(host_call_failure(&unrelated, &[], false), None);
    for recorded_here in [true, false] {
        let failure = host_call_failure(
            &unrelated,
            &calls(&["systemctl --user daemon-reload"]),
            recorded_here,
        );
        assert!(
            failure
                .as_deref()
                .is_some_and(|text| text.contains("not a service-manager command")),
            "{recorded_here}: {failure:?}"
        );
    }
    // A run/file-use scenario (no `extra_` prefix) is never a service-manager one.
    let run_case = scenario("run_uninitialized_echo", &["run", "x"], &[]);
    assert!(!is_service_manager_case(&run_case));
    assert!(host_call_failure(&run_case, &calls(&["launchctl list"]), false).is_some());
    // A recorded call list on a scenario that is not a service-manager command is stale.
    let stale = scenario(
        "extra_uninitialized_lock_x2",
        &["lock", "x", "y"],
        &["launchctl list"],
    );
    assert!(host_call_failure(&stale, &[], false).is_some());
}

/// End to end through the replay: an unrelated scenario that really reaches the
/// service manager (`mcp install`, whatever the platform's tool is) is reported.
#[cfg(unix)]
#[test]
fn replay_reports_service_manager_calls_of_unrelated_scenarios() {
    let fixture = fixture();
    let unrelated = scenario(
        "extra_uninitialized_unrelated",
        &["mcp", "install", "x"],
        &[],
    );
    let mut failures = Vec::new();
    let replay = replay_scenarios(&fixture, &[unrelated], "uninitialized", &mut failures);
    assert_eq!(
        replay,
        Replay {
            replayed: 1,
            skipped: 0
        }
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("not a service-manager command")),
        "{failures:?}"
    );
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
    // No scenario is a known divergence any more, so the mechanism is exercised on a
    // synthetic one: a real scenario whose Go observation is declared to differ from
    // what the native binary prints (it is pinned to the real native output).
    let fixture = fixture();
    let name = "extra_uninitialized_lock_x1";
    let case = fixture
        .extra_positionals
        .iter()
        .find(|case| case.name == name)
        .expect("recorded scenario");
    let actual = run_case(case, &fixture.vault_seed);
    let entry = PinnedDivergence {
        name: name.to_owned(),
        state: "uninitialized".to_owned(),
        reason: "synthetic".to_owned(),
        expected_rust: NativeObservation {
            exit_code: actual.0,
            stdout: actual.1.clone(),
            stderr: actual.2.clone(),
        },
    };
    let go = Observation {
        args: case.observation.args.clone(),
        exit_code: case.observation.exit_code,
        stdout: case.observation.stdout.clone(),
        stderr: format!("{}Error: only Go prints this\n", case.observation.stderr),
    };
    let check = |actual: &(i32, String, String)| {
        check_known_divergence(name, &go, &entry.expected_rust, actual)
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
        (go.exit_code, go.stdout.clone(), go.stderr.clone()),
    ));
    for (label, mutated) in mutations {
        assert!(!check(&mutated).is_empty(), "{label} was not detected");
    }

    // A pinned file that was edited the same way is caught by the real output.
    let mut mutated_pin = entry.expected_rust.clone();
    mutated_pin.exit_code += 1;
    assert!(
        !check_known_divergence(name, &go, &mutated_pin, &actual).is_empty(),
        "a mutated pinned exit code was not detected"
    );
}
