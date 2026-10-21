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
struct Case {
    name: String,
    class: String,
    config_hex: String,
    observations: Vec<Observation>,
    doctor: DoctorObservation,
    #[serde(default)]
    agent_list: Option<Observation>,
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
}

/// Cases whose Go output the native CLI must reproduce byte for byte.
const MATCHING_CASES: usize = 93;
/// Comparisons the replay executes: every recorded config observation, one
/// `doctor` run per case and the five `agent list` runs.
const REPLAYED_COMPARISONS: usize = 438;
/// Inputs on which the native CLI is known to differ from Go.
const OPEN_DIVERGENCES: usize = 33;

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
    /// replaced as joined strings, so Windows separators do not matter.
    fn normalize(&self, raw: &[u8]) -> String {
        let mut text = String::from_utf8_lossy(raw).into_owned();
        let root = self.root.to_string_lossy().into_owned();
        let vault_config = self.vault_dir().join("config.yaml");
        text = text.replace(&*vault_config.to_string_lossy(), "__VAULT__/config.yaml");
        text = text.replace(&*self.vault_dir().to_string_lossy(), "__VAULT__");
        text = text.replace(&*self.config_path().to_string_lossy(), "__CONFIG__");
        text.replace(&root, "__ROOT__")
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
        BTreeSet::from(["accepted", "loader", "node", "parser", "reader", "scanner"])
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
        .map(|case| case.observations.len() + 1 + usize::from(case.agent_list.is_some()))
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
        if let Some(difference) = config_observation_difference(&bytes, observation) {
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
