#![deny(unsafe_code)]

//! CLI-005: the go-yaml scanner/parser/reader error dialect of config.yaml.
//!
//! `testdata/port/cli/config-yaml-syntax.json` freezes what the pinned Go CLI
//! prints (exit status, stdout, stderr, and whether `config set` left the file
//! alone) for a corpus of malformed and control configs across
//! `config validate`, `config validate --json`, `config get`, `config set` and
//! the five `doctor` checks that load the config. This test replays every one
//! of them against the native CLI and compares the bytes. Nothing here needs a
//! Go toolchain; the fixture is regenerated and re-verified against the pinned
//! oracle by `scripts/rust-port/cmd/yamlsyntaxgen` (see
//! `scripts/rust-port/check_yaml_syntax_cli.sh`).
//!
//! The corpus is not a parity claim for YAML in general. The fixture's
//! `open_divergences` list records the inputs on which the native CLI is known
//! to differ from Go, with the Go bytes of the commands the difference shows
//! on; `recorded_open_divergences_are_still_open` keeps every one honest.

#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Observation {
    command: String,
    args: Vec<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
    #[serde(default)]
    config_unchanged: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct DoctorResult {
    id: String,
    name: String,
    status: String,
    message: String,
    hint: String,
    fixable: bool,
}

#[derive(Debug, Deserialize)]
struct DoctorObservation {
    args: Vec<String>,
    exit_code: i32,
    results: Vec<DoctorResult>,
}

#[derive(Debug, Deserialize)]
struct AuthObservation {
    args: Vec<String>,
    exit_code: i32,
    method: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    class: String,
    config_hex: String,
    observations: Vec<Observation>,
    doctor: DoctorObservation,
    #[serde(default)]
    agent_list: Option<Observation>,
    #[serde(default)]
    auth_method: Option<AuthObservation>,
}

#[derive(Debug, Deserialize)]
struct OpenDivergence {
    name: String,
    kind: String,
    reason: String,
    config_hex: String,
    observations: Vec<Observation>,
    #[serde(default)]
    doctor: Option<DoctorObservation>,
    #[serde(default)]
    agent_list: Option<Observation>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    doctor_ids: Vec<String>,
    cases: Vec<Case>,
    open_divergences: Vec<OpenDivergence>,
    loader_warning_counts: LoaderWarningCounts,
}

/// Cases whose Go output the native CLI must reproduce byte for byte.
const MATCHING_CASES: usize = 276;
/// Comparisons the replay executes: every recorded config observation, one
/// `doctor` run per case and the `agent list` runs.
const REPLAYED_COMPARISONS: usize = 1062;
/// The `load_*` cases (CONFIG-LOAD-001): what the loader and validator accept
/// or reject once the bytes parse as YAML.
const LOAD_CASES: usize = 90;
/// The CONFIG-SECTIONS-001 cases among them: what the typed decode makes of
/// each kind of scalar and how the section merge treats it.
const SECTION_CASES: usize = 58;
/// Inputs on which the native CLI is known to differ from Go.
const OPEN_DIVERGENCES: usize = 34;
/// The `nest_*` cases (ADR 0034 item 6): yaml.v3's two scanner limits of 10000.
const NEST_CASES: usize = 26;

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/cli/config-yaml-syntax.json");
    serde_json::from_slice(CONTENT).expect("config YAML syntax fixture parses")
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex fixture has odd length");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex digit pair"))
        .collect()
}

/// One disposable HOME/XDG tree, the way the generator builds it.
struct Sandbox {
    root: test_temp_root::TempRoot,
}

impl Sandbox {
    fn new() -> Self {
        Self {
            root: test_temp_root::TempRoot::existing("symvault-yaml-syntax-"),
        }
    }

    fn config_path(&self) -> PathBuf {
        self.root.join("config.yaml")
    }

    fn vault_dir(&self) -> PathBuf {
        self.root.join("vault")
    }

    fn run(&self, args: &[String]) -> Output {
        let home = self.root.join("home");
        fs::create_dir_all(&home).expect("create isolated home");
        let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("SYMVAULT_") {
                command.env_remove(name);
            }
        }
        command
            .current_dir(&*self.root)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", self.root.join("xdg-config"))
            .env("XDG_DATA_HOME", self.root.join("xdg-data"))
            .env("XDG_CACHE_HOME", self.root.join("xdg-cache"))
            .env("CI", "1")
            .env("NO_COLOR", "1")
            .args(args)
            .output()
            .expect("run symvault")
    }

    /// Makes recorded and live text comparable: the sandbox root becomes
    /// `__ROOT__`, the config and vault paths their markers. The paths are
    /// replaced as joined strings, so Windows separators do not matter. JSON
    /// output escapes each `\` of a Windows path as `\\`, so the escaped form
    /// is replaced first; on Unix paths it equals the plain form.
    fn normalize(&self, raw: &[u8]) -> String {
        let mut text = String::from_utf8_lossy(raw).into_owned();
        let vault_config = self.vault_dir().join("config.yaml");
        let replacements = [
            (vault_config, "__VAULT__/config.yaml"),
            (self.vault_dir(), "__VAULT__"),
            (self.config_path(), "__CONFIG__"),
            (self.root.to_path_buf(), "__ROOT__"),
        ];
        for (path, marker) in &replacements {
            // The CLI prints cleaned paths, so a root under a TMPDIR with a
            // trailing separator (macOS `.../T/` joined to `.../T//x`) also
            // appears with the duplicate separator collapsed.
            let cleaned: PathBuf = path.components().collect();
            for form in [path.to_string_lossy(), cleaned.to_string_lossy()] {
                text = text.replace(&form.replace('\\', "\\\\"), marker);
                text = text.replace(&*form, marker);
            }
        }
        text
    }
}

fn substitute(args: &[String], marker: &str, value: &Path) -> Vec<String> {
    args.iter()
        .map(|arg| arg.replace(marker, &value.to_string_lossy()))
        .collect()
}

/// How a live run differs from the recorded Go run.
#[derive(Debug)]
struct Difference {
    /// The exit status or the effect on the config file differs, not only the
    /// text.
    effect: bool,
    message: String,
}

impl Difference {
    fn effect(message: String) -> Self {
        Self {
            effect: true,
            message,
        }
    }

    fn text(message: String) -> Self {
        Self {
            effect: false,
            message,
        }
    }
}

/// Compares one live run of a config command with the recorded Go output.
/// Returns the first difference, or `None` when every byte agrees.
fn compare_observation(
    expected: &Observation,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
    unchanged: Option<bool>,
) -> Option<Difference> {
    if exit_code != expected.exit_code {
        return Some(Difference::effect(format!(
            "exit {exit_code}, Go {}; stderr={stderr:?}",
            expected.exit_code
        )));
    }
    if expected.config_unchanged.is_some() && unchanged != expected.config_unchanged {
        return Some(Difference::effect(format!(
            "config unchanged {unchanged:?}, Go {:?}",
            expected.config_unchanged
        )));
    }
    if stdout != expected.stdout {
        return Some(Difference::text(format!(
            "stdout {stdout:?}, Go {:?}",
            expected.stdout
        )));
    }
    if stderr != expected.stderr {
        return Some(Difference::text(format!(
            "stderr {stderr:?}, Go {:?}",
            expected.stderr
        )));
    }
    None
}

fn run_config_observation(case_bytes: &[u8], expected: &Observation) -> Option<String> {
    config_observation_difference(case_bytes, expected).map(|difference| difference.message)
}

fn config_observation_difference(case_bytes: &[u8], expected: &Observation) -> Option<Difference> {
    let sandbox = Sandbox::new();
    let config = sandbox.config_path();
    fs::write(&config, case_bytes).expect("write isolated config");
    let args = substitute(&expected.args, "__CONFIG__", &config);
    let output = sandbox.run(&args);
    let unchanged = expected
        .config_unchanged
        .map(|_| fs::read(&config).expect("read config after run") == case_bytes);
    compare_observation(
        expected,
        output.status.code().unwrap_or(255),
        &sandbox.normalize(&output.stdout),
        &sandbox.normalize(&output.stderr),
        unchanged,
    )
}

/// `agent list` against a vault directory holding the case's config.yaml.
fn run_agent_list_observation(case_bytes: &[u8], expected: &Observation) -> Option<String> {
    agent_list_observation_difference(case_bytes, expected).map(|difference| difference.message)
}

fn agent_list_observation_difference(
    case_bytes: &[u8],
    expected: &Observation,
) -> Option<Difference> {
    let sandbox = Sandbox::new();
    let vault = sandbox.vault_dir();
    fs::create_dir_all(&vault).expect("create isolated vault directory");
    fs::write(vault.join("config.yaml"), case_bytes).expect("write isolated vault config");
    let args = substitute(&expected.args, "__VAULT__", &vault);
    let output = sandbox.run(&args);
    compare_observation(
        expected,
        output.status.code().unwrap_or(255),
        &sandbox.normalize(&output.stdout),
        &sandbox.normalize(&output.stderr),
        None,
    )
}

/// `auth status` against a vault directory holding the case's config.yaml:
/// the resolved top-level method it reports.
fn run_auth_method_observation(case_bytes: &[u8], expected: &AuthObservation) -> Option<String> {
    let sandbox = Sandbox::new();
    let vault = sandbox.vault_dir();
    fs::create_dir_all(&vault).expect("create isolated vault directory");
    fs::write(vault.join("config.yaml"), case_bytes).expect("write isolated vault config");
    fs::write(vault.join("identity.age"), b"").expect("write isolated vault identity");
    let args = substitute(&expected.args, "__VAULT__", &vault);
    let output = sandbox.run(&args);
    let code = output.status.code().unwrap_or(255);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let method = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("Auth method: "))
        .next_back()
        .unwrap_or_default();
    (code != expected.exit_code || method != expected.method).then(|| {
        format!(
            "exit {code} method {method:?}, Go exit {} method {:?}",
            expected.exit_code, expected.method
        )
    })
}

fn run_doctor_observation(
    case_bytes: &[u8],
    expected: &DoctorObservation,
    ids: &[String],
) -> Option<String> {
    doctor_observation_difference(case_bytes, expected, ids).map(|difference| difference.message)
}

fn doctor_observation_difference(
    case_bytes: &[u8],
    expected: &DoctorObservation,
    ids: &[String],
) -> Option<Difference> {
    let sandbox = Sandbox::new();
    let vault = sandbox.vault_dir();
    fs::create_dir_all(&vault).expect("create isolated vault directory");
    fs::write(vault.join("config.yaml"), case_bytes).expect("write isolated vault config");
    let args = substitute(&expected.args, "__VAULT__", &vault);
    let output = sandbox.run(&args);
    let code = output.status.code().unwrap_or(255);
    if code != expected.exit_code {
        return Some(Difference::effect(format!(
            "doctor exit {code}, Go {}; stderr={:?}",
            expected.exit_code,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let payload: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(payload) => payload,
        Err(error) => return Some(Difference::effect(format!("doctor JSON: {error}"))),
    };
    let results = payload["results"].as_array().cloned().unwrap_or_default();
    let mut live = Vec::new();
    for id in ids {
        let Some(result) = results.iter().find(|result| result["id"] == id.as_str()) else {
            return Some(Difference::effect(format!("doctor did not report {id}")));
        };
        let text =
            |field: &str| sandbox.normalize(result[field].as_str().unwrap_or_default().as_bytes());
        live.push(DoctorResult {
            id: id.clone(),
            name: text("name"),
            status: text("status"),
            message: text("message"),
            hint: text("hint"),
            fixable: result["fixable"].as_bool().unwrap_or(false),
        });
    }
    (live != expected.results).then(|| {
        Difference::text(format!(
            "doctor results {live:#?}, Go {:#?}",
            expected.results
        ))
    })
}

#[test]
fn fixture_pins_go_oracle_and_covers_every_libyaml_stage() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle.commit,
        "0cc780626d3275afad14eb64c44abf8adb23d2ce"
    );
    assert_eq!(fixture.oracle.commit_sha, fixture.oracle.commit);
    assert_eq!(fixture.oracle.release, "unreleased");
    assert_eq!(
        fixture.oracle.source_files,
        [
            "cmd/admin/config.go",
            "go.mod",
            "go.sum",
            "internal/cli/cli.go",
            "internal/config/config_load.go",
            "internal/config/config_merge.go",
            "internal/config/config_validate.go",
            "internal/config/dottedpath.go",
            "internal/errors/errors.go",
            "internal/health/doctor_mcp.go",
            "internal/health/doctor_session.go",
            "internal/health/doctor_vault.go",
        ]
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert_eq!(
        fixture.doctor_ids,
        [
            "vault.config.parses",
            "vault.config.validates",
            "auth.passphrase.rotation",
            "mcp.dynamic.engines",
            "mcp.agents",
        ]
    );

    let mut classes = BTreeSet::new();
    let mut problems = BTreeSet::new();
    for case in &fixture.cases {
        classes.insert(case.class.as_str());
        assert_eq!(case.doctor.results.len(), fixture.doctor_ids.len());
        let validate = case
            .observations
            .iter()
            .find(|observation| observation.command == "validate")
            .unwrap_or_else(|| panic!("{} has no validate observation", case.name));
        match case.class.as_str() {
            "accepted" => assert_eq!(validate.exit_code, 0, "{}", case.name),
            _ => assert_eq!(validate.exit_code, 6, "{}", case.name),
        }
        if matches!(
            case.class.as_str(),
            "scanner" | "parser" | "reader" | "node"
        ) {
            let get = case
                .observations
                .iter()
                .find(|observation| observation.command == "get")
                .unwrap_or_else(|| panic!("{} has no get observation", case.name));
            assert_eq!(get.exit_code, 6, "{}", case.name);
            let set = case
                .observations
                .iter()
                .find(|observation| observation.command == "set")
                .unwrap_or_else(|| panic!("{} has no set observation", case.name));
            // Go loads the node tree before it writes anything, so a failing
            // load must leave the file alone.
            assert_eq!(set.config_unchanged, Some(true), "{}", case.name);
            assert_eq!(set.exit_code, 6, "{}", case.name);
            // "yaml: line N: <problem>" or "yaml: <problem>": keep the problem.
            let message = validate
                .stderr
                .lines()
                .next()
                .and_then(|line| line.split("yaml: ").nth(1))
                .unwrap_or_else(|| panic!("{}: no yaml error in {:?}", case.name, validate.stderr));
            let problem = message
                .strip_prefix("line ")
                .and_then(|rest| rest.split_once(": "))
                .map_or(message, |(_, problem)| problem);
            problems.insert(problem.split(": yaml").next().unwrap_or(problem).to_owned());
        }
    }
    assert_eq!(
        classes,
        BTreeSet::from([
            "accepted", "decode", "loader", "node", "parser", "reader", "scanner"
        ])
    );
    assert!(
        problems.len() >= 38,
        "corpus covers only {} distinct go-yaml problem strings: {problems:#?}",
        problems.len()
    );
    // Documented in cli-gap-inventory.md and contract-matrix.md: change the
    // count there together with this one.
    assert_eq!(fixture.open_divergences.len(), OPEN_DIVERGENCES);
    for divergence in &fixture.open_divergences {
        assert!(!divergence.reason.is_empty(), "{}", divergence.name);
        assert!(
            matches!(divergence.kind.as_str(), "wording" | "behavior"),
            "{}: kind {:?}",
            divergence.name,
            divergence.kind
        );
        assert!(
            !divergence.observations.is_empty()
                || divergence.doctor.is_some()
                || divergence.agent_list.is_some(),
            "{} records no Go output",
            divergence.name
        );
    }
}

#[test]
fn native_cli_matches_go_recorded_yaml_syntax_failures() {
    let fixture = fixture();
    let expected_runs: usize = fixture
        .cases
        .iter()
        .map(|case| {
            case.observations.len()
                + 1
                + usize::from(case.agent_list.is_some())
                + usize::from(case.auth_method.is_some())
        })
        .sum();
    assert_eq!(fixture.cases.len(), MATCHING_CASES);
    assert_eq!(
        expected_runs, REPLAYED_COMPARISONS,
        "fixture and the pinned comparison count disagree"
    );
    let mut compared = 0_usize;
    let mut failures = Vec::new();
    for case in &fixture.cases {
        let bytes = decode_hex(&case.config_hex);
        for observation in &case.observations {
            compared += 1;
            if let Some(difference) = run_config_observation(&bytes, observation) {
                failures.push(format!(
                    "{} {}: {difference}",
                    case.name, observation.command
                ));
            }
        }
        compared += 1;
        if let Some(difference) = run_doctor_observation(&bytes, &case.doctor, &fixture.doctor_ids)
        {
            failures.push(format!("{} doctor: {difference}", case.name));
        }
        if let Some(agent_list) = &case.agent_list {
            compared += 1;
            if let Some(difference) = run_agent_list_observation(&bytes, agent_list) {
                failures.push(format!("{} agent list: {difference}", case.name));
            }
        }
        if let Some(auth) = &case.auth_method {
            compared += 1;
            if let Some(difference) = run_auth_method_observation(&bytes, auth) {
                failures.push(format!("{} auth status: {difference}", case.name));
            }
        }
    }
    assert_eq!(
        compared, expected_runs,
        "every recorded Go observation must be replayed"
    );
    assert!(
        failures.is_empty(),
        "{} of {compared} comparisons differ from the Go oracle:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Negative control: the comparison must notice a changed expectation. Without
/// this, an always-passing comparator would let the replay above go green.
#[test]
fn mutated_expectation_is_detected() {
    let fixture = fixture();
    let case = fixture
        .cases
        .iter()
        .find(|case| case.name == "mapping_value_nested")
        .expect("mapping_value_nested is part of the corpus");
    let bytes = decode_hex(&case.config_hex);
    let validate = case
        .observations
        .iter()
        .find(|observation| observation.command == "validate")
        .expect("validate observation");
    assert_eq!(
        run_config_observation(&bytes, validate),
        None,
        "the unmutated expectation must match"
    );

    let mut wrong_line = validate.clone();
    wrong_line.stderr = wrong_line.stderr.replace("yaml: line 3:", "yaml: line 4:");
    assert_ne!(
        wrong_line.stderr, validate.stderr,
        "mutation changed nothing"
    );
    assert!(
        run_config_observation(&bytes, &wrong_line).is_some(),
        "a one-line shift in the expected go-yaml error must fail the replay"
    );

    let mut wrong_exit = validate.clone();
    wrong_exit.exit_code = 1;
    assert!(run_config_observation(&bytes, &wrong_exit).is_some());

    let mut wrong_doctor = case.doctor.results.clone();
    wrong_doctor[0].message = wrong_doctor[0].message.replace("line 3", "line 2");
    assert_ne!(wrong_doctor[0].message, case.doctor.results[0].message);
    let mutated = DoctorObservation {
        args: case.doctor.args.clone(),
        exit_code: case.doctor.exit_code,
        results: wrong_doctor,
    };
    assert!(run_doctor_observation(&bytes, &mutated, &fixture.doctor_ids).is_some());

    // The `auth status` observation must also be able to fail: the merged
    // useTouchID case resolves to touchid, so expecting passphrase is a diff.
    let merge = fixture
        .cases
        .iter()
        .find(|case| case.name == "load_vault_use_touch_id_via_merge")
        .expect("load_vault_use_touch_id_via_merge is part of the corpus");
    let merge_bytes = decode_hex(&merge.config_hex);
    let auth = merge
        .auth_method
        .as_ref()
        .expect("the merge case records an auth_method observation");
    assert_eq!(auth.method, "touchid");
    assert_eq!(run_auth_method_observation(&merge_bytes, auth), None);
    let wrong_method = AuthObservation {
        args: auth.args.clone(),
        exit_code: auth.exit_code,
        method: "passphrase".into(),
    };
    assert!(
        run_auth_method_observation(&merge_bytes, &wrong_method).is_some(),
        "a wrong resolved auth method must fail the replay"
    );
}

/// Commands recorded against the global config of the sandbox HOME
/// (`~/.symvault/config.yaml`) instead of a `--file` or a vault directory.
fn is_home_command(command: &str) -> bool {
    matches!(command, "complete_get" | "completion_bash")
}

/// What a live run of an open-divergence observation produced.
struct LiveObservation {
    exit_code: i32,
    stdout: String,
    stderr: String,
    unchanged: Option<bool>,
}

/// Runs the command of `expected` the way the generator did and returns the raw
/// live values. `completion bash` prints a generated script: like the
/// generator, the stdout is replaced by its `sha256:` digest.
fn live_open_observation(case_bytes: &[u8], expected: &Observation) -> LiveObservation {
    let sandbox = Sandbox::new();
    if is_home_command(&expected.command) {
        let global = sandbox.root.join("home").join(".symvault");
        fs::create_dir_all(&global).expect("create global config directory");
        fs::write(global.join("config.yaml"), case_bytes).expect("write global config");
        let output = sandbox.run(&expected.args);
        let stdout = if expected.command == "completion_bash" {
            format!("sha256:{}", hex::encode(Sha256::digest(&output.stdout)))
        } else {
            sandbox.normalize(&output.stdout)
        };
        return LiveObservation {
            exit_code: output.status.code().unwrap_or(255),
            stdout,
            stderr: sandbox.normalize(&output.stderr),
            unchanged: None,
        };
    }
    let config = sandbox.config_path();
    fs::write(&config, case_bytes).expect("write isolated config");
    let args = substitute(&expected.args, "__CONFIG__", &config);
    let output = sandbox.run(&args);
    let unchanged = expected
        .config_unchanged
        .map(|_| fs::read(&config).expect("read config after run") == case_bytes);
    LiveObservation {
        exit_code: output.status.code().unwrap_or(255),
        stdout: sandbox.normalize(&output.stdout),
        stderr: sandbox.normalize(&output.stderr),
        unchanged,
    }
}

fn home_observation_difference(case_bytes: &[u8], expected: &Observation) -> Option<Difference> {
    let live = live_open_observation(case_bytes, expected);
    compare_observation(
        expected,
        live.exit_code,
        &live.stdout,
        &live.stderr,
        live.unchanged,
    )
}

/// Runs every command recorded for an open divergence and returns, per command,
/// how the native CLI differs from Go. Empty means the input now matches.
fn open_divergence_differences(
    divergence: &OpenDivergence,
    doctor_ids: &[String],
) -> Vec<(String, Difference)> {
    let bytes = decode_hex(&divergence.config_hex);
    let mut differences = Vec::new();
    for observation in &divergence.observations {
        let difference = if is_home_command(&observation.command) {
            home_observation_difference(&bytes, observation)
        } else {
            config_observation_difference(&bytes, observation)
        };
        if let Some(difference) = difference {
            differences.push((observation.command.clone(), difference));
        }
    }
    if let Some(expected) = &divergence.doctor
        && let Some(difference) = doctor_observation_difference(&bytes, expected, doctor_ids)
    {
        differences.push(("doctor".to_owned(), difference));
    }
    if let Some(expected) = &divergence.agent_list
        && let Some(difference) = agent_list_observation_difference(&bytes, expected)
    {
        differences.push(("agent_list".to_owned(), difference));
    }
    differences
}

/// Inputs on which the native CLI differs from Go stay in the fixture with the
/// Go bytes of the commands the difference shows on. Each must still differ
/// here, and in the way its `kind` says: `wording` keeps exit status and the
/// effect on the file identical and differs in text only, `behavior` differs in
/// exit status or file effect. The day one matches, move it from
/// `open_divergences` into `cases`.
#[test]
fn recorded_open_divergences_are_still_open() {
    let fixture = fixture();
    for divergence in &fixture.open_divergences {
        let differences = open_divergence_differences(divergence, &fixture.doctor_ids);
        assert!(
            !differences.is_empty(),
            "{} now matches Go ({}); promote it to a regular case",
            divergence.name,
            divergence.reason
        );
        match divergence.kind.as_str() {
            "wording" => assert!(
                differences.iter().all(|(_, difference)| !difference.effect),
                "{} is recorded as a wording gap but exit status or file effect differs: {differences:#?}",
                divergence.name
            ),
            "behavior" => assert!(
                differences.iter().any(|(_, difference)| difference.effect),
                "{} is recorded as a behavior gap but only wording differs: {differences:#?}",
                divergence.name
            ),
            other => panic!("{}: unknown kind {other}", divergence.name),
        }
    }
}

/// Negative control for the check above: an input that does match Go must come
/// back without a difference, and a recorded divergence must come back with one.
#[test]
fn open_divergence_check_tells_a_match_from_a_gap() {
    let fixture = fixture();
    let matching = fixture
        .cases
        .iter()
        .find(|case| case.name == "unknown_anchor_value")
        .expect("unknown_anchor_value is part of the corpus");
    let as_divergence = OpenDivergence {
        name: matching.name.clone(),
        kind: "wording".to_owned(),
        reason: String::new(),
        config_hex: matching.config_hex.clone(),
        observations: matching.observations.clone(),
        doctor: None,
        agent_list: matching.agent_list.clone(),
    };
    assert!(
        open_divergence_differences(&as_divergence, &fixture.doctor_ids).is_empty(),
        "a regular case must not register as an open divergence"
    );
    let gap = fixture
        .open_divergences
        .iter()
        .find(|divergence| divergence.name == "trailing_token_after_double_quoted")
        .expect("trailing_token_after_double_quoted is recorded");
    assert!(!open_divergence_differences(gap, &fixture.doctor_ids).is_empty());
}

/// CONFIG-LOAD-001: the six inputs on which the native loader used to differ
/// from `config.Load` / `Config.Validate`, by the name of the recorded case.
/// Each is replayed with the rest of the corpus above; this keeps the list
/// honest by naming them and by pinning what Go prints for them.
#[test]
fn config_load_divergences_are_recorded_and_replay_as_go_prints_them() {
    let fixture = fixture();
    let load_cases: Vec<&Case> = fixture
        .cases
        .iter()
        .filter(|case| case.name.starts_with("load_"))
        .collect();
    assert_eq!(load_cases.len(), LOAD_CASES);
    let find = |name: &str| -> &Case {
        load_cases
            .iter()
            .copied()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("{name} is not part of the corpus"))
    };
    let validate = |case: &Case| -> Observation {
        case.observations
            .iter()
            .find(|observation| observation.command == "validate")
            .expect("validate observation")
            .clone()
    };

    // 1. `vaultDir: ''` is valid.
    assert_eq!(validate(find("load_vault_dir_empty")).exit_code, 0);
    // 2. An unknown promptInjectionMode is rejected while the file loads.
    let observation = validate(find("load_prompt_injection_mode_invalid"));
    assert_eq!(observation.exit_code, 6);
    assert!(
        observation
            .stderr
            .contains("invalid promptInjectionMode \"weird\" (valid: off, log-only, wrap, deny)")
    );
    // 3 and 4. A value of the wrong shape in a section the port does not model.
    for (name, shape) in [
        ("load_audit_max_size_mb_string", "!!str `abc` into int64"),
        ("load_logging_level_sequence", "!!seq into string"),
    ] {
        let observation = validate(find(name));
        assert_eq!(observation.exit_code, 6, "{name}");
        assert!(observation.stderr.contains(shape), "{name}");
    }
    // 5. An unknown authMethod loads and validates.
    assert_eq!(validate(find("load_auth_method_unknown")).exit_code, 0);
    // 6. The session duration rejection names the parsed value.
    let observation = validate(find("load_session_timeout_zero"));
    assert_eq!(observation.exit_code, 6);
    assert!(observation.stderr.contains(
        "sessionTimeout: must be greater than 0, got 0s (default: 15m, configure sessionTimeout in config.yaml)"
    ));

    // Go returns the loader's errors bare: not one recorded byte of any
    // command carries the native loader's former prefixes.
    for case in &load_cases {
        let mut texts: Vec<&str> = case
            .observations
            .iter()
            .flat_map(|observation| [observation.stdout.as_str(), observation.stderr.as_str()])
            .collect();
        texts.extend(
            case.doctor
                .results
                .iter()
                .map(|result| result.message.as_str()),
        );
        if let Some(agent_list) = &case.agent_list {
            texts.extend([agent_list.stdout.as_str(), agent_list.stderr.as_str()]);
        }
        for text in texts {
            assert!(
                !text.contains("parse config:") && !text.contains("invalid config:"),
                "{}: {text:?}",
                case.name
            );
        }
    }
}

/// Negative control for the `load_*` replay: an expectation that differs from
/// Go in the one detail this packet fixed (`, got 0s`) must fail the replay.
#[test]
fn mutated_load_expectation_is_detected() {
    let fixture = fixture();
    let case = fixture
        .cases
        .iter()
        .find(|case| case.name == "load_session_timeout_zero")
        .expect("load_session_timeout_zero is part of the corpus");
    let bytes = decode_hex(&case.config_hex);
    let validate = case
        .observations
        .iter()
        .find(|observation| observation.command == "validate")
        .expect("validate observation");
    assert_eq!(run_config_observation(&bytes, validate), None);

    let mut without_value = validate.clone();
    without_value.stderr = without_value.stderr.replace(", got 0s", "");
    assert_ne!(
        without_value.stderr, validate.stderr,
        "mutation changed nothing"
    );
    assert!(run_config_observation(&bytes, &without_value).is_some());

    let mut prefixed = validate.clone();
    prefixed.stderr = prefixed
        .stderr
        .replace("__CONFIG__: ", "__CONFIG__: parse config: ");
    assert_ne!(prefixed.stderr, validate.stderr, "mutation changed nothing");
    assert!(run_config_observation(&bytes, &prefixed).is_some());
}

/// CONFIG-SECTIONS-001: the Go-coerced values the section parsers read. The
/// replay above already compares every byte; this names the classes, pins the
/// Go outcome the coercion decides (a message that quotes the coerced text, a
/// range check on the coerced number, an index shifted by a dropped null) and
/// proves a replay notices a wrong coercion.
#[test]
fn section_coercions_are_pinned_to_what_go_prints() {
    let fixture = fixture();
    let sections: Vec<&Case> = fixture
        .cases
        .iter()
        .filter(|case| {
            case.name.starts_with("load_")
                && !fixture.cases[..128]
                    .iter()
                    .any(|earlier| earlier.name == case.name)
        })
        .collect();
    assert_eq!(sections.len(), SECTION_CASES);
    let validate = |name: &str| -> Observation {
        sections
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("{name} is not a section case"))
            .observations
            .iter()
            .find(|observation| observation.command == "validate")
            .expect("validate observation")
            .clone()
    };
    for (name, exit_code, text) in [
        // Strings keep their source text.
        (
            "load_vault_auth_method_hex",
            6,
            "invalid authMethod \"0x10\"",
        ),
        (
            "load_approval_mode_integer",
            6,
            "invalid approvalMode \"5\"",
        ),
        (
            "load_approval_mode_bool",
            6,
            "invalid approvalMode \"true\"",
        ),
        (
            "load_prompt_injection_mode_hex",
            6,
            "invalid promptInjectionMode \"0x10\"",
        ),
        // Ints truncate floats and read YAML 1.1 spellings.
        (
            "load_vault_argon2id_time_float",
            6,
            "argon2id_time: 1 is below",
        ),
        (
            "load_vault_argon2id_time_exponent",
            6,
            "argon2id_time: 1000 exceeds",
        ),
        (
            "load_vault_argon2id_time_underscore",
            6,
            "argon2id_time: 1000 exceeds",
        ),
        (
            "load_vault_argon2id_time_old_octal",
            6,
            "argon2id_time: 64 exceeds",
        ),
        (
            "load_vault_argon2id_time_octal_prefix",
            0,
            "Configuration is valid",
        ),
        (
            "load_clipboard_auto_clear_negative_float",
            6,
            "must be non-negative",
        ),
        (
            "load_clipboard_auto_clear_truncates_to_zero",
            0,
            "Configuration is valid",
        ),
        // A null list item is dropped; other scalars are kept as text.
        (
            "load_agent_null_items_dropped",
            6,
            "allowedPaths[0]: invalid glob",
        ),
        (
            "load_agent_non_string_items_index",
            6,
            "allowedPaths[2]: invalid glob",
        ),
        // Pointer fields, durations and nulls.
        ("load_agent_null_pointers", 0, "Configuration is valid"),
        ("load_agents_null", 0, "Configuration is valid"),
        (
            "load_section_negative_durations",
            0,
            "Configuration is valid",
        ),
        (
            "load_agent_approval_timeout_integer",
            6,
            "into time.Duration",
        ),
        // The merge gates.
        (
            "load_agent_merged_prompt_injection_mode",
            6,
            "invalid promptInjectionMode \"weird\"",
        ),
        (
            "load_agent_merged_approval_mode_ignored",
            0,
            "Configuration is valid",
        ),
        (
            "load_mcp_section_alias_ignored",
            0,
            "Configuration is valid",
        ),
        (
            "load_session_timeout_zero_via_merge",
            0,
            "Configuration is valid",
        ),
    ] {
        let observation = validate(name);
        assert_eq!(observation.exit_code, exit_code, "{name}");
        assert!(
            observation.stdout.contains(text) || observation.stderr.contains(text),
            "{name}: {observation:?}"
        );
    }

    // Negative control: the one detail a wrong coercion would change must
    // fail the replay (`0x10` read as the number 16, a float rejected, a null
    // item kept).
    for (name, from, to) in [
        ("load_vault_auth_method_hex", "0x10", "16"),
        (
            "load_vault_argon2id_time_float",
            "1 is below",
            "1.5 is below",
        ),
        (
            "load_agent_null_items_dropped",
            "allowedPaths[0]",
            "allowedPaths[1]",
        ),
    ] {
        let case = sections
            .iter()
            .find(|case| case.name == name)
            .expect("section case");
        let bytes = decode_hex(&case.config_hex);
        let mut expected = validate(name);
        assert_eq!(run_config_observation(&bytes, &expected), None, "{name}");
        expected.stdout = expected.stdout.replace(from, to);
        expected.stderr = expected.stderr.replace(from, to);
        assert!(
            run_config_observation(&bytes, &expected).is_some(),
            "{name}: a wrong coercion went unnoticed"
        );
    }
}

/// CONFIG-RESID: the `Config.Validate` checks on `audit` and `paymentPolicies`
/// and the deprecation warnings. The replay above compares every byte; this
/// names the Go outcomes the packet closed (a refusal where the native CLI used
/// to accept, a warning on stderr where it used to print nothing), including a
/// Go quirk that is easy to "fix" by mistake (`--quiet` does not silence the
/// warnings), and proves a replay notices their absence.
#[test]
fn config_resid_outcomes_are_pinned_to_what_go_prints() {
    let fixture = fixture();
    let find = |name: &str| -> &Case {
        fixture
            .cases
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("{name} is not part of the corpus"))
    };
    let observation = |name: &str, command: &str| -> Observation {
        find(name)
            .observations
            .iter()
            .find(|observation| observation.command == command)
            .unwrap_or_else(|| panic!("{name} has no {command} observation"))
            .clone()
    };

    // Refusals: exit 6 with Go's text on stdout.
    for (name, text) in [
        (
            "load_audit_max_size_mb_null",
            "audit.maxFileSize: must be greater than 0",
        ),
        (
            "resid_audit_max_size_mb_wraps_negative",
            "audit.maxFileSize: must be greater than 0",
        ),
        (
            "load_payment_policy_without_instrument",
            "paymentPolicies.p.instrument: must not be empty",
        ),
        (
            "resid_payment_policy_no_limits",
            "paymentPolicies.p: must have at least one allowed_merchant or max_amount limit",
        ),
        (
            "resid_payment_policy_limit_without_currency",
            "paymentPolicies.p.currency: required when max_amount limits are set",
        ),
        (
            "resid_payment_per_transaction_only_minus",
            "paymentPolicies.p.max_amount.per_transaction: \"-\" is not a valid decimal amount (no digits)",
        ),
        (
            "resid_payment_per_transaction_exponent_scalar",
            "paymentPolicies.p.max_amount.per_transaction: \"1e3\" is not a valid decimal amount",
        ),
        (
            "load_agent_payment_policy_unknown",
            "agents.x.paymentPolicy: policy \"abc\" not found in paymentPolicies",
        ),
        (
            "resid_agent_payment_policy_integer_unknown",
            "agents.x.paymentPolicy: policy \"5\" not found in paymentPolicies",
        ),
    ] {
        let validate = observation(name, "validate");
        assert_eq!(validate.exit_code, 6, "{name}");
        assert!(validate.stdout.contains(text), "{name}: {validate:?}");
    }
    // Go's Validate order: the audit, clipboard, payment and Argon2id errors,
    // each after the agent ones, and the policy error before the agent's.
    let order = observation("resid_validate_error_order", "validate").stdout;
    let positions: Vec<usize> = [
        "vaultDir: must not be empty",
        "agents.x.allowedPaths[0]",
        "audit.maxFileSize",
        "clipboard.autoClearDuration",
        "paymentPolicies.p.instrument",
        "agents.x.paymentPolicy",
        "vault.argon2id_time",
    ]
    .iter()
    .map(|text| {
        order
            .find(text)
            .unwrap_or_else(|| panic!("{text} is missing from {order:?}"))
    })
    .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "{order:?}"
    );

    // Acceptances the checks must not turn into refusals.
    for name in [
        "resid_audit_max_size_mb_via_merge",
        "resid_payment_policy_decimal_forms",
        "resid_payment_policy_float_scalar_amount",
        "resid_agent_payment_policy_integer_defined",
        "resid_agent_payment_policy_empty",
    ] {
        assert_eq!(observation(name, "validate").exit_code, 0, "{name}");
    }

    // Warnings: on stderr of a successful load, once per Load, in load order,
    // and not silenced by `--quiet` (Go hands the flag to cliout before cobra
    // has parsed it). `agent list` loads the config too.
    let three = observation("resid_warn_all_three", "validate");
    assert_eq!(three.exit_code, 0);
    assert_eq!(
        three.stderr,
        "envWhitelist is deprecated and will be removed in a future version; use envAllowlist instead\n\
         approval_required is deprecated and will be removed in a future version\n\
         clipboard.printByDefault is deprecated; use clipboard.copyByDefault instead\n"
    );
    assert_eq!(
        observation("resid_warn_all_three", "validate_quiet").stderr,
        three.stderr
    );
    let agent_list = find("resid_warn_env_whitelist")
        .agent_list
        .clone()
        .expect("agent list observation");
    assert!(agent_list.stderr.starts_with("envWhitelist is deprecated"));
    for name in [
        "resid_warn_env_whitelist_null",
        "resid_warn_mcp_approval_required_false",
        "resid_warn_clipboard_copy_by_default_wins",
        "resid_warn_not_when_decode_fails",
    ] {
        assert!(
            !observation(name, "validate").stderr.contains("deprecated"),
            "{name}"
        );
    }
    // Go prints the warning and then rejects the document.
    let rejected = observation("resid_warn_then_loader_rejection", "validate");
    assert_eq!(rejected.exit_code, 6);
    assert!(rejected.stderr.starts_with("envWhitelist is deprecated"));

    // Negative control: dropping what the packet added from the expectation
    // must fail the replay.
    let replay = |name: &str, command: &str, mutate: &dyn Fn(&mut Observation)| {
        let case = find(name);
        let bytes = decode_hex(&case.config_hex);
        let mut expected = observation(name, command);
        assert_eq!(run_config_observation(&bytes, &expected), None, "{name}");
        mutate(&mut expected);
        assert!(
            run_config_observation(&bytes, &expected).is_some(),
            "{name}: a missing check went unnoticed"
        );
    };
    replay(
        "load_payment_policy_without_instrument",
        "validate",
        &|expected| {
            expected.exit_code = 0;
            expected.stdout = "Configuration is valid (__CONFIG__)\n".to_owned();
            expected.stderr.clear();
        },
    );
    replay(
        "load_audit_max_size_mb_null",
        "validate_json",
        &|expected| {
            expected.exit_code = 0;
            expected.stdout = "{\"path\":\"__CONFIG__\",\"valid\":true}\n".to_owned();
            expected.stderr.clear();
        },
    );
    replay("resid_warn_env_whitelist", "validate", &|expected| {
        expected.stderr.clear();
    });
    replay(
        "resid_warn_then_loader_rejection",
        "validate",
        &|expected| {
            expected.stderr = expected.stderr.replacen(
                "envWhitelist is deprecated and will be removed in a future version; use envAllowlist instead\n",
                "",
                1,
            );
        },
    );
}

// --- ADR 0034 items 6 and 9: the ratified native behaviour, pinned exactly -----------

/// What the native CLI must print for one observation of an open divergence that
/// ADR 0034 ratified. `None` means equal to Go's recording; a given value must
/// differ from it. The Go side is the fixture, recorded by `yamlsyntaxgen`.
struct Ratified {
    name: &'static str,
    item: &'static str,
    command: &'static str,
    exit_code: Option<i32>,
    stdout: Option<&'static str>,
    stderr: Option<&'static str>,
    config_unchanged: Option<bool>,
}

const NESTING_REFUSAL: &str = "Error: cannot load config: Parse error at line 1, column 260: Collection nested too deeply (limit 256)\n";

const RATIFIED: &[Ratified] = &[
    // Item 6: the native config get/set refuse beyond 256 nested collections
    // (yaml_edit MAX_FLOW_DEPTH), yaml.v3 accepts 10000.
    Ratified {
        name: "nesting_depth_257",
        item: "ADR 0034 item 6",
        command: "get_nested",
        exit_code: Some(6),
        stdout: Some(""),
        stderr: Some(NESTING_REFUSAL),
        config_unchanged: None,
    },
    Ratified {
        name: "nesting_depth_257",
        item: "ADR 0034 item 6",
        command: "set",
        exit_code: Some(6),
        stdout: Some(""),
        stderr: Some(NESTING_REFUSAL),
        config_unchanged: Some(true),
    },
    Ratified {
        name: "nesting_depth_10000",
        item: "ADR 0034 item 6",
        command: "get_nested",
        exit_code: Some(6),
        stdout: Some(""),
        stderr: Some(NESTING_REFUSAL),
        config_unchanged: None,
    },
    Ratified {
        name: "nesting_depth_10000",
        item: "ADR 0034 item 6",
        command: "set",
        exit_code: Some(6),
        stdout: Some(""),
        stderr: Some(NESTING_REFUSAL),
        config_unchanged: Some(true),
    },
    // Go's own limit (10001 levels) is no longer a divergence: the loader enforces
    // it with Go's wording, pinned by the `nest_flow_sequence_10001` cases.
    // Item 9: shell completion loads the global config fewer times.
    Ratified {
        name: "completion_loader_warnings",
        item: "ADR 0034 item 9",
        command: "complete_get",
        exit_code: None,
        stdout: None,
        stderr: Some(concat!(
            "envWhitelist is deprecated and will be removed in a future version; use envAllowlist instead\n",
            "Completion ended with directive: ShellCompDirectiveNoFileComp\n"
        )),
        config_unchanged: None,
    },
    Ratified {
        name: "completion_loader_warnings",
        item: "ADR 0034 item 9",
        command: "completion_bash",
        exit_code: None,
        stdout: None,
        stderr: Some(""),
        config_unchanged: None,
    },
];

/// Compares a live run with the ratified native values and rejects a declaration
/// that does not differ from Go. Pure, so the negative controls need no binary.
fn ratified_problems(ratified: &Ratified, go: &Observation, live: &LiveObservation) -> Vec<String> {
    let mut problems = Vec::new();
    let want_exit = ratified.exit_code.unwrap_or(go.exit_code);
    let want_stdout = ratified.stdout.unwrap_or(&go.stdout);
    let want_stderr = ratified.stderr.unwrap_or(&go.stderr);
    let want_unchanged = ratified.config_unchanged.or(go.config_unchanged);
    for (what, declared_equals_go) in [
        ("exit", ratified.exit_code == Some(go.exit_code)),
        ("stdout", ratified.stdout == Some(go.stdout.as_str())),
        ("stderr", ratified.stderr == Some(go.stderr.as_str())),
        (
            "config_unchanged",
            ratified.config_unchanged.is_some() && ratified.config_unchanged == go.config_unchanged,
        ),
    ] {
        if declared_equals_go {
            problems.push(format!("declared {what} equals Go's"));
        }
    }
    if want_exit == go.exit_code
        && want_stdout == go.stdout
        && want_stderr == go.stderr
        && want_unchanged == go.config_unchanged
    {
        problems.push("no declared difference from Go".to_owned());
    }
    if live.exit_code != want_exit {
        problems.push(format!("exit {}, declared {want_exit}", live.exit_code));
    }
    if live.stdout != want_stdout {
        problems.push(format!(
            "stdout {:?}, declared {want_stdout:?}",
            live.stdout
        ));
    }
    if live.stderr != want_stderr {
        problems.push(format!(
            "stderr {:?}, declared {want_stderr:?}",
            live.stderr
        ));
    }
    if want_unchanged.is_some() && live.unchanged != want_unchanged {
        problems.push(format!(
            "config unchanged {:?}, declared {want_unchanged:?}",
            live.unchanged
        ));
    }
    problems
}

fn ratified_go<'a>(
    fixture: &'a Fixture,
    ratified: &Ratified,
) -> (&'a OpenDivergence, &'a Observation) {
    let divergence = fixture
        .open_divergences
        .iter()
        .find(|divergence| divergence.name == ratified.name)
        .unwrap_or_else(|| panic!("{} is not an open divergence", ratified.name));
    let observation = divergence
        .observations
        .iter()
        .find(|observation| observation.command == ratified.command)
        .unwrap_or_else(|| panic!("{}: no {} observation", ratified.name, ratified.command));
    (divergence, observation)
}

/// The native CLI does exactly what ADR 0034 items 6 and 9 ratified, on the same
/// inputs Go's behaviour is recorded for, and the declarations cover every
/// observation of those entries.
#[test]
fn ratified_native_behaviour_of_adr_0034_items_6_and_9_is_pinned() {
    let fixture = fixture();
    let mut covered = BTreeSet::new();
    for ratified in RATIFIED {
        let (divergence, go) = ratified_go(&fixture, ratified);
        covered.insert((ratified.name, ratified.command));
        assert!(
            ratified.item.starts_with("ADR 0034 item "),
            "{}: {}",
            ratified.name,
            ratified.item
        );
        let live = live_open_observation(&decode_hex(&divergence.config_hex), go);
        assert_eq!(
            ratified_problems(ratified, go, &live),
            Vec::<String>::new(),
            "{} {}",
            ratified.name,
            ratified.command
        );
    }
    for name in [
        "nesting_depth_257",
        "nesting_depth_10000",
        "completion_loader_warnings",
    ] {
        let divergence = fixture
            .open_divergences
            .iter()
            .find(|divergence| divergence.name == name)
            .unwrap_or_else(|| panic!("{name} is recorded"));
        for observation in &divergence.observations {
            assert!(
                covered.contains(&(name, observation.command.as_str())),
                "{name} {} has no ratified declaration",
                observation.command
            );
        }
    }
    // Go's side of the nesting limit: 10000 levels are read and written (the
    // refusal one level further is pinned by the `nest_*` cases).
    for (name, exit) in [("nesting_depth_257", 0), ("nesting_depth_10000", 0)] {
        let divergence = fixture
            .open_divergences
            .iter()
            .find(|divergence| divergence.name == name)
            .expect("nesting entry");
        for observation in &divergence.observations {
            assert_eq!(
                observation.exit_code, exit,
                "{name} {}",
                observation.command
            );
        }
    }
    let complete = fixture
        .open_divergences
        .iter()
        .find(|divergence| divergence.name == "completion_loader_warnings")
        .expect("completion entry");
    let counts: Vec<(String, usize)> = complete
        .observations
        .iter()
        .map(|observation| {
            (
                observation.command.clone(),
                observation
                    .stderr
                    .matches("envWhitelist is deprecated")
                    .count(),
            )
        })
        .collect();
    assert_eq!(
        counts,
        [
            ("complete_get".to_owned(), 2),
            ("completion_bash".to_owned(), 1)
        ],
        "Go prints the warning twice for __complete and once for completion"
    );
}

/// Negative control per pin: Go's own behaviour is rejected as a closed
/// divergence, and a one-field mutation of the live values is detected.
#[test]
fn ratified_pins_reject_go_behaviour_and_mutations() {
    let fixture = fixture();
    for ratified in RATIFIED {
        let (_, go) = ratified_go(&fixture, ratified);
        let go_live = LiveObservation {
            exit_code: go.exit_code,
            stdout: go.stdout.clone(),
            stderr: go.stderr.clone(),
            unchanged: go.config_unchanged,
        };
        assert!(
            !ratified_problems(ratified, go, &go_live).is_empty(),
            "{} {}: Go's behaviour must not satisfy the declaration",
            ratified.name,
            ratified.command
        );
        let good = LiveObservation {
            exit_code: ratified.exit_code.unwrap_or(go.exit_code),
            stdout: ratified.stdout.unwrap_or(&go.stdout).to_owned(),
            stderr: ratified.stderr.unwrap_or(&go.stderr).to_owned(),
            unchanged: ratified.config_unchanged.or(go.config_unchanged),
        };
        assert_eq!(
            ratified_problems(ratified, go, &good),
            Vec::<String>::new(),
            "{} {}: the declared values satisfy it",
            ratified.name,
            ratified.command
        );
        for (what, mutated) in [
            (
                "exit",
                LiveObservation {
                    exit_code: good.exit_code + 1,
                    stdout: good.stdout.clone(),
                    stderr: good.stderr.clone(),
                    unchanged: good.unchanged,
                },
            ),
            (
                "stdout",
                LiveObservation {
                    exit_code: good.exit_code,
                    stdout: format!("{}x", good.stdout),
                    stderr: good.stderr.clone(),
                    unchanged: good.unchanged,
                },
            ),
            (
                "stderr",
                LiveObservation {
                    exit_code: good.exit_code,
                    stdout: good.stdout.clone(),
                    stderr: format!("{}x", good.stderr),
                    unchanged: good.unchanged,
                },
            ),
        ] {
            assert!(
                !ratified_problems(ratified, go, &mutated).is_empty(),
                "{} {}: a mutated {what} must be detected",
                ratified.name,
                ratified.command
            );
        }
        if good.unchanged.is_some() {
            let mutated = LiveObservation {
                unchanged: good.unchanged.map(|value| !value),
                exit_code: good.exit_code,
                stdout: good.stdout.clone(),
                stderr: good.stderr.clone(),
            };
            assert!(
                !ratified_problems(ratified, go, &mutated).is_empty(),
                "{} {}: a mutated file effect must be detected",
                ratified.name,
                ratified.command
            );
        }
    }
}

/// The 256/257 boundary of the native limit, on the native binary alone: 256
/// nested sequences are read and rewritten, 257 are refused (Go accepts both;
/// the 257 entry above records Go).
#[test]
fn native_nesting_limit_is_256_levels() {
    for (depth, accepted) in [(256usize, true), (257, false)] {
        let mut bytes = b"a: ".to_vec();
        bytes.extend(std::iter::repeat_n(b'[', depth));
        bytes.extend(std::iter::repeat_n(b']', depth));
        bytes.push(b'\n');
        for args in [
            vec!["config", "get", "a", "--file", "__CONFIG__"],
            vec![
                "config",
                "set",
                "vaultDir",
                "changed",
                "--file",
                "__CONFIG__",
            ],
        ] {
            let sandbox = Sandbox::new();
            let config = sandbox.config_path();
            fs::write(&config, &bytes).expect("write config");
            let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            let output = sandbox.run(&substitute(&args, "__CONFIG__", &config));
            assert_eq!(
                output.status.code(),
                Some(if accepted { 0 } else { 6 }),
                "depth {depth} {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let rewritten = fs::read(&config).expect("read config") != bytes;
            assert_eq!(
                rewritten,
                accepted && args[1] == "set",
                "depth {depth} {args:?}"
            );
        }
    }
}

#[derive(Debug, Deserialize)]
struct LoaderWarningCounts {
    runs_per_case: usize,
    config: String,
    cases: Vec<LoaderWarningRun>,
}

#[derive(Debug, Deserialize)]
struct LoaderWarningRun {
    command: String,
    args: Vec<String>,
    layout: String,
    go_min: usize,
    go_max: usize,
    #[serde(default)]
    go_race: String,
    go_sites: Vec<String>,
}

/// What the native CLI prints for the same runs: `(command, layout) -> count`.
///
/// Go re-reads `config.yaml` at several seams that Rust does not repeat (see
/// `go_sites` in the fixture): the root `PersistentPreRunE` and the command's
/// own `VaultPath` both load the global config (so a default-location vault
/// warns twice more), and every vault operation (`List`, `ReadEntry`,
/// `FindWithOptions`, `VerifyManifestIntegrity`) loads the vault config once
/// again, in addition to a background index build. Rust loads the global
/// config once (`resolve_vault`) and the vault config twice (`config::fix` and
/// the unlock), exactly Go's `resolveConfig` and `vault.Open`; only `get`
/// reads the vault config a third time, like Go's `ReadEntry`.
const NATIVE_WARNING_COUNTS: &[(&str, &str, usize)] = &[
    ("list", "vault_env", 2),
    ("list", "legacy_default", 3),
    ("get", "vault_env", 3),
    ("get", "legacy_default", 4),
    ("find", "vault_env", 2),
    ("find", "legacy_default", 3),
    ("verify", "vault_env", 2),
    ("verify", "legacy_default", 3),
    ("recipients list", "vault_env", 0),
    ("recipients list", "legacy_default", 1),
    ("lock", "vault_env", 0),
    ("lock", "legacy_default", 1),
    ("generate", "vault_env", 0),
    ("generate", "legacy_default", 0),
    ("agent list", "vault_env", 1),
    ("agent list", "legacy_default", 2),
];

const ENV_WHITELIST_WARNING: &str = "envWhitelist is deprecated and will be removed in a future version; use envAllowlist instead\n";

/// Runs `symvault` in a throw-away HOME (no real keychain: the session cache is
/// in memory under `CI=1`) and returns `(exit code, stderr)`.
fn run_isolated(root: &Path, vault_env: Option<&Path>, args: &[&str]) -> (i32, String) {
    let home = root.join("home");
    fs::create_dir_all(&home).expect("create isolated home");
    let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SYMVAULT_") {
            command.env_remove(name);
        }
    }
    command
        .current_dir(root)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CACHE_HOME", root.join("xdg-cache"))
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .env("SYMVAULT_PASSPHRASE", "loader-warning-count")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .stdin(std::process::Stdio::null())
        .args(args);
    if let Some(vault) = vault_env {
        command.env("SYMVAULT_VAULT", vault);
    }
    let output = command.output().expect("run symvault");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn native_warning_count(row: &LoaderWarningRun, config: &str) -> usize {
    let sandbox = Sandbox::new();
    let root: &Path = &sandbox.root;
    let home = root.join("home");
    let (vault, vault_env) = match row.layout.as_str() {
        "vault_env" => (home.join("vault"), Some(home.join("vault"))),
        "legacy_default" => {
            let vault = home.join(".symvault");
            fs::create_dir_all(&vault).expect("legacy vault directory");
            (vault, None)
        }
        other => panic!("unknown layout {other}"),
    };
    let init_dir = vault.to_string_lossy().into_owned();
    let init: Vec<&str> = if vault_env.is_some() {
        vec!["init", &init_dir]
    } else {
        vec!["init"]
    };
    for step in [
        init,
        vec!["add", "demo/entry", "--value", "demo-value-1234"],
    ] {
        let (code, stderr) = run_isolated(root, vault_env.as_deref(), &step);
        assert_eq!(code, 0, "setup {step:?}: {stderr}");
    }
    let config_path = vault.join("config.yaml");
    let mut text = fs::read_to_string(&config_path).expect("read vault config");
    text.push_str(config);
    fs::write(&config_path, text).expect("append the deprecated key");
    let args: Vec<&str> = row.args.iter().map(String::as_str).collect();
    let (code, stderr) = run_isolated(root, vault_env.as_deref(), &args);
    assert_eq!(code, 0, "{} ({}): {stderr}", row.command, row.layout);
    stderr.matches(ENV_WHITELIST_WARNING).count()
}

/// ADR 0034 item 9 says ordinary commands print the loader warning as often as
/// Go. They do not, and this pins what is true. Go's recorded bounds
/// (`loader_warning_counts`, from the pinned oracle) come from re-reading the
/// config at seams Rust does not repeat; the native counts are pinned exactly,
/// the rows where Go and Rust agree must lie inside Go's bounds, and every
/// other row must stay below Go's minimum (an open divergence: fewer
/// duplicate deprecation lines, no other output differs). A native change that
/// closes or widens a gap fails here and must update the table and the
/// matrix row together.
#[test]
fn native_loader_warning_counts_are_pinned_against_go() {
    let fixture = fixture();
    let counts = &fixture.loader_warning_counts;
    assert_eq!(counts.config, "envWhitelist: [a]\n");
    assert_eq!(counts.runs_per_case, 8);
    assert_eq!(counts.cases.len(), NATIVE_WARNING_COUNTS.len());
    let (mut equal, mut fewer) = (0, 0);
    for (row, (command, layout, native_expected)) in counts.cases.iter().zip(NATIVE_WARNING_COUNTS)
    {
        assert_eq!(
            (row.command.as_str(), row.layout.as_str()),
            (*command, *layout)
        );
        assert!(row.go_min <= row.go_max);
        assert_eq!(
            row.go_race.is_empty(),
            row.go_min == row.go_max,
            "{command}/{layout}: a range exists only where a goroutine read races the exit"
        );
        assert_eq!(
            row.go_sites.len(),
            row.go_min,
            "{command}/{layout}: every certain site prints once; the race adds at most one"
        );
        let native = native_warning_count(row, &counts.config);
        assert_eq!(native, *native_expected, "{command}/{layout}: native count");
        if (row.go_min..=row.go_max).contains(&native) {
            equal += 1;
        } else {
            assert!(
                native < row.go_min,
                "{command}/{layout}: native {native} must stay below Go's {}..={}",
                row.go_min,
                row.go_max
            );
            fewer += 1;
        }
    }
    // `get` with the vault given explicitly (Rust's own entry read is the
    // operation-level load), recipients list, lock and generate with the vault
    // given explicitly, and both agent list rows, agree; the other ten print
    // fewer duplicates.
    assert_eq!((equal, fewer), (6, 10));
}

#[test]
fn warning_count_pin_tells_a_match_from_a_gap() {
    // The comparison used above: inside Go's bounds is a match, below is the
    // recorded gap, above would be a new divergence.
    let gap = |native: usize, min: usize, max: usize| {
        if (min..=max).contains(&native) {
            "match"
        } else if native < min {
            "fewer"
        } else {
            "more"
        }
    };
    assert_eq!(gap(2, 3, 4), "fewer");
    assert_eq!(gap(3, 3, 4), "match");
    assert_eq!(gap(5, 3, 4), "more");
    assert_eq!(gap(1, 1, 1), "match");
}

/// ADR 0034 item 6 / ADR 0035: yaml.v3's scanner stops at 10000 open flow
/// collections and at 10000 nested block collections (two separate counters),
/// with the scanner problem `exceeded max depth of 10000`. The native loader
/// used to read 10001 levels in full. The replay above compares every
/// `nest_*` command byte for byte; this test pins what that comparison has to
/// show, so a corpus that quietly lost its boundary pairs cannot pass.
#[test]
fn nesting_limit_boundaries_are_pinned_to_go() {
    let fixture = fixture();
    let nest: Vec<&Case> = fixture
        .cases
        .iter()
        .filter(|case| case.name.starts_with("nest_"))
        .collect();
    assert_eq!(nest.len(), NEST_CASES);
    let case = |name: &str| -> &Case {
        nest.iter()
            .copied()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("{name} is not part of the corpus"))
    };
    let validate = |name: &str| -> &Observation {
        case(name)
            .observations
            .iter()
            .find(|observation| observation.command == "validate")
            .unwrap_or_else(|| panic!("{name} records no validate run"))
    };
    const LIMIT: &str = "exceeded max depth of 10000";

    // Exactly on the limit: the scan passes (flow documents validate; the block
    // ones are rejected by the typed decode, not by the scanner).
    for name in ["nest_flow_sequence_257", "nest_flow_sequence_10000"] {
        assert_eq!(validate(name).exit_code, 0, "{name}");
    }
    for name in [
        "nest_block_sequence_10000",
        "nest_block_explicit_key_10000",
        "nest_block_mapping_after_9999_dashes",
        "nest_counters_are_independent",
    ] {
        let observation = validate(name);
        assert_eq!(observation.exit_code, 6, "{name}");
        assert!(!observation.stderr.contains(LIMIT), "{name}");
        assert!(observation.stderr.contains("unmarshal"), "{name}");
    }
    // One past it: the scanner problem, with the line only past the first.
    for (name, line) in [
        ("nest_flow_sequence_10001", None),
        ("nest_flow_sequence_20000", None),
        ("nest_flow_mapping_10001", None),
        ("nest_flow_sequence_10001_unterminated", None),
        ("nest_depth_before_error", None),
        ("nest_block_sequence_10001", None),
        ("nest_block_explicit_key_10001", None),
        ("nest_block_mapping_after_10000_dashes", None),
        ("nest_block_over_with_flow_inside", None),
        ("nest_flow_sequence_10001_on_line_three", Some(3)),
        ("nest_flow_sequence_after_document_start", Some(2)),
    ] {
        let observation = validate(name);
        assert_eq!(observation.exit_code, 6, "{name}");
        let wording = match line {
            None => format!("yaml: {LIMIT}"),
            Some(line) => format!("yaml: line {line}: {LIMIT}"),
        };
        assert!(
            observation.stderr.contains(&wording),
            "{name}: {:?}",
            observation.stderr
        );
        // Go's own `get` and `set` stop at the same scanner failure.
        for command in ["get", "set"] {
            let run = case(name)
                .observations
                .iter()
                .find(|observation| observation.command == command)
                .unwrap_or_else(|| panic!("{name} records no {command} run"));
            assert_eq!(run.exit_code, 6, "{name} {command}");
            assert!(run.stderr.contains(&wording), "{name} {command}");
        }
    }
    // The failure that comes first in the stream wins.
    assert!(
        validate("nest_error_before_depth")
            .stderr
            .contains("line 2: mapping values are not allowed")
    );
    // Brackets that are text, flat documents and a trailing document that fails
    // to scan are not nesting.
    for name in [
        "nest_brackets_in_double_quotes",
        "nest_brackets_in_single_quotes",
        "nest_brackets_in_comment",
        "nest_brackets_in_block_scalar",
        "nest_brackets_in_plain_scalar",
        "nest_many_sequence_entries",
        "nest_second_document_too_deep",
    ] {
        assert_eq!(validate(name).exit_code, 0, "{name}");
    }
    assert!(
        validate("nest_second_document_at_limit")
            .stderr
            .contains("more than one YAML document")
    );

    // The native CLI reproduces the refusals (the full replay above runs every
    // recorded command of every `nest_*` case, the 10000-level acceptances
    // included; they take seconds each in a debug build, so only the cheap
    // rejections are repeated here).
    for name in [
        "nest_flow_sequence_10001",
        "nest_flow_sequence_10001_on_line_three",
        "nest_block_sequence_10001",
        "nest_error_before_depth",
    ] {
        let case = case(name);
        let bytes = decode_hex(&case.config_hex);
        for observation in &case.observations {
            assert!(
                run_config_observation(&bytes, observation).is_none(),
                "{} {}",
                case.name,
                observation.command
            );
        }
    }
}

/// The 257..10000 flow range is open only for `config get` and `config set`:
/// both read the node tree with yaml_edit (256 levels), while the loader
/// accepts those documents. The divergence is recorded with Go's bytes.
#[test]
fn nesting_between_256_and_10000_is_open_only_for_get_and_set() {
    let fixture = fixture();
    let names: Vec<&str> = fixture
        .open_divergences
        .iter()
        .map(|divergence| divergence.name.as_str())
        .filter(|name| name.starts_with("nest_"))
        .collect();
    assert_eq!(
        names,
        [
            "nest_get_set_flow_sequence_257",
            "nest_get_set_flow_sequence_10000"
        ]
    );
    for divergence in fixture
        .open_divergences
        .iter()
        .filter(|divergence| divergence.name.starts_with("nest_"))
    {
        assert_eq!(divergence.kind, "behavior");
        let commands: Vec<&str> = divergence
            .observations
            .iter()
            .map(|observation| observation.command.as_str())
            .collect();
        assert_eq!(commands, ["get", "set"]);
        let set = &divergence.observations[1];
        assert_eq!(set.exit_code, 0, "Go rewrites the nested document");
        assert_eq!(set.config_unchanged, Some(false));
        let bytes = decode_hex(&divergence.config_hex);
        let difference = open_divergence_differences(divergence, &fixture.doctor_ids);
        assert!(
            difference.iter().any(|(command, _)| command == "set"),
            "{}: set now matches Go; promote the case",
            divergence.name
        );
        // The loader side of the same document is part of the matching corpus.
        assert!(bytes.starts_with(b"a: ["));
    }
}

/// Runs `config validate` on `config` and fails when it has not exited after
/// `seconds`; returns `(exit code, normalised stdout, normalised stderr)`.
///
/// The bound is independent of the build profile: it sits an order of magnitude
/// above what a debug build needs and well below what the quadratic or
/// whole-document behaviour it guards against needs.
fn validate_within(seconds: u64, config: &[u8]) -> (i32, String, String) {
    use std::{
        io::Read,
        process::Stdio,
        time::{Duration, Instant},
    };
    let sandbox = Sandbox::new();
    let path = sandbox.config_path();
    fs::write(&path, config).expect("write isolated config");
    let home = sandbox.root.join("home");
    fs::create_dir_all(&home).expect("create isolated home");
    let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SYMVAULT_") {
            command.env_remove(name);
        }
    }
    let mut child = command
        .current_dir(&*sandbox.root)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", sandbox.root.join("xdg-config"))
        .env("XDG_DATA_HOME", sandbox.root.join("xdg-data"))
        .env("XDG_CACHE_HOME", sandbox.root.join("xdg-cache"))
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .args(["config", "validate"])
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run symvault");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let out = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stdout.read_to_end(&mut buffer);
        buffer
    });
    let err = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stderr.read_to_end(&mut buffer);
        buffer
    });
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll symvault") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("config validate was still running after {seconds} s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = sandbox.normalize(&out.join().expect("stdout reader"));
    let stderr = sandbox.normalize(&err.join().expect("stderr reader"));
    (status.code().unwrap_or(255), stdout, stderr)
}

/// A long run of blanks inside a plain scalar of a document big enough to be
/// depth-scanned used to be rescanned from every blank (quadratic): a 400 KB
/// config took over two minutes. Go reads it in well under a second.
#[test]
fn a_long_run_of_blanks_in_a_deep_config_validates_in_linear_time() {
    let mut config = String::new();
    for index in 0..11_000 {
        config.push_str(&format!("k{index}: 1\n"));
    }
    config.push_str("last: x");
    config.push_str(&" ".repeat(300_000));
    config.push_str("y\n");
    let (code, stdout, stderr) = validate_within(60, config.as_bytes());
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, "Configuration is valid (__CONFIG__)\n");
}

/// A depth violation ends the read: libyaml (and so `serde_yaml_ng`) used to
/// parse the rest of the stream in full, which took half a minute for 100000
/// opening brackets in a debug build; Go stops at level 10001 in 0.02 s.
#[test]
fn a_depth_violation_does_not_make_the_rest_of_the_stream_expensive() {
    let config = format!("a: {}\n", "[".repeat(100_000));
    let (code, stdout, stderr) = validate_within(15, config.as_bytes());
    assert_eq!(code, 6, "{stderr}");
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "Error: cannot load config from __CONFIG__: yaml: exceeded max depth of 10000: yaml: exceeded max depth of 10000\n\
         Error: cannot load config from __CONFIG__: yaml: exceeded max depth of 10000: yaml: exceeded max depth of 10000\n\
         Run 'symvault doctor' to diagnose and fix configuration issues.\n"
    );
}
