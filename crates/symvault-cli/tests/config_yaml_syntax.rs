#![deny(unsafe_code)]

//! CLI-005: the go-yaml scanner/parser/reader error dialect of config.yaml.
//!
//! `testdata/port/cli/config-yaml-syntax.json` freezes what the pinned Go CLI
//! prints (exit status, stdout, stderr, and whether `config set` left the file
//! alone) for 72 configs across `config validate`, `config validate --json`,
//! `config get`, `config set` and the five `doctor` checks that load the
//! config. This test replays every one of them against the native CLI and
//! compares the bytes. Nothing here needs a Go toolchain; the fixture is
//! regenerated and re-verified against the pinned oracle by
//! `scripts/rust-port/cmd/yamlsyntaxgen` (see
//! `scripts/rust-port/check_yaml_syntax_cli.sh`).

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
}

#[derive(Debug, Deserialize)]
struct OpenDivergence {
    name: String,
    reason: String,
    config_hex: String,
    validate: Observation,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    doctor_ids: Vec<String>,
    cases: Vec<Case>,
    open_divergences: Vec<OpenDivergence>,
}

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

/// Compares one live run of a config command with the recorded Go output.
/// Returns a description of the first difference, or `None` when every byte
/// agrees.
fn compare_observation(
    expected: &Observation,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
    unchanged: Option<bool>,
) -> Option<String> {
    if exit_code != expected.exit_code {
        return Some(format!(
            "exit {exit_code}, Go {}; stderr={stderr:?}",
            expected.exit_code
        ));
    }
    if stdout != expected.stdout {
        return Some(format!("stdout {stdout:?}, Go {:?}", expected.stdout));
    }
    if stderr != expected.stderr {
        return Some(format!("stderr {stderr:?}, Go {:?}", expected.stderr));
    }
    if expected.config_unchanged.is_some() && unchanged != expected.config_unchanged {
        return Some(format!(
            "config unchanged {unchanged:?}, Go {:?}",
            expected.config_unchanged
        ));
    }
    None
}

fn run_config_observation(case_bytes: &[u8], expected: &Observation) -> Option<String> {
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

fn run_doctor_observation(
    case_bytes: &[u8],
    expected: &DoctorObservation,
    ids: &[String],
) -> Option<String> {
    let sandbox = Sandbox::new();
    let vault = sandbox.vault_dir();
    fs::create_dir_all(&vault).expect("create isolated vault directory");
    fs::write(vault.join("config.yaml"), case_bytes).expect("write isolated vault config");
    let args = substitute(&expected.args, "__VAULT__", &vault);
    let output = sandbox.run(&args);
    let code = output.status.code().unwrap_or(255);
    if code != expected.exit_code {
        return Some(format!(
            "doctor exit {code}, Go {}; stderr={:?}",
            expected.exit_code,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let payload: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(payload) => payload,
        Err(error) => return Some(format!("doctor JSON: {error}")),
    };
    let results = payload["results"].as_array().cloned().unwrap_or_default();
    let mut live = Vec::new();
    for id in ids {
        let Some(result) = results.iter().find(|result| result["id"] == id.as_str()) else {
            return Some(format!("doctor did not report {id}"));
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
    (live != expected.results)
        .then(|| format!("doctor results {live:#?}, Go {:#?}", expected.results))
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
        if matches!(case.class.as_str(), "scanner" | "parser" | "reader") {
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
            assert_eq!(set.config_unchanged, Some(true), "{}", case.name);
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
        BTreeSet::from(["accepted", "loader", "parser", "reader", "scanner"])
    );
    assert!(
        problems.len() >= 38,
        "corpus covers only {} distinct go-yaml problem strings: {problems:#?}",
        problems.len()
    );
    assert!(fixture.open_divergences.len() >= 5);
    for divergence in &fixture.open_divergences {
        assert!(!divergence.reason.is_empty(), "{}", divergence.name);
    }
}

#[test]
fn native_cli_matches_go_recorded_yaml_syntax_failures() {
    let fixture = fixture();
    let expected_runs: usize = fixture
        .cases
        .iter()
        .map(|case| case.observations.len() + 1)
        .sum();
    assert!(
        expected_runs >= 300,
        "fixture shrank to {expected_runs} comparisons"
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

/// Inputs on which the two YAML front ends differ in more than wording stay in
/// the fixture with the Go bytes. Each must still differ here; the day one
/// matches, move it from `open_divergences` into `cases`.
#[test]
fn recorded_open_divergences_are_still_open() {
    let fixture = fixture();
    for divergence in &fixture.open_divergences {
        let bytes = decode_hex(&divergence.config_hex);
        assert!(
            run_config_observation(&bytes, &divergence.validate).is_some(),
            "{} now matches Go ({}); promote it to a regular case",
            divergence.name,
            divergence.reason
        );
    }
}
