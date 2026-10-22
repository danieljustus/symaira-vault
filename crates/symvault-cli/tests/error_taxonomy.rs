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

#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{fs, process::Command};

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
}

const USAGE_CASES: usize = 40;
const ARITY_ROWS: usize = 116;
const REJECTED_ARITY_PROBES: usize = 188;
const GATE_REFUSALS: usize = 223;
const NOT_INITIALIZED_CASES: usize = 29;

fn fixture() -> Fixture {
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/cli/error-taxonomy.json"
    ))
    .expect("read error-taxonomy fixture");
    serde_json::from_str(&raw).expect("parse error-taxonomy fixture")
}

fn run(args: &[String]) -> (i32, String, String) {
    let root = test_temp_root::TempRoot::existing("symvault-error-taxonomy-");
    let home = root.join("home");
    fs::create_dir_all(&home).expect("create isolated home");
    let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SYMVAULT_") {
            command.env_remove(name);
        }
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
        text
    };
    (
        output.status.code().unwrap_or(-1),
        normalize(&output.stdout),
        normalize(&output.stderr),
    )
}

fn compare(label: &str, observation: &Observation, failures: &mut Vec<String>) {
    let (code, stdout, stderr) = run(&observation.args);
    if code != observation.exit_code || stdout != observation.stdout || stderr != observation.stderr
    {
        failures.push(format!(
            "{label} {:?}\n  go:   {} {:?} {:?}\n  rust: {code} {stdout:?} {stderr:?}",
            observation.args, observation.exit_code, observation.stdout, observation.stderr
        ));
    }
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
    let rejected: usize = fixture
        .arity
        .iter()
        .map(|row| row.probes.iter().filter(|probe| probe.rejected).count())
        .sum();
    assert_eq!(rejected, REJECTED_ARITY_PROBES);
    let refusals: usize = fixture.gate.iter().map(|row| row.refusals.len()).sum();
    assert_eq!(refusals, GATE_REFUSALS);
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

/// Commands whose "vault not initialized" failure is still not Go's. Each entry
/// is the full argument vector of a recorded case; `open_not_initialized_cases_
/// are_still_open` fails when one starts to match so the list cannot go stale.
///
/// - `delete x`: the native command prompts before it checks the vault (exit 0).
/// - `device approval-pair`, `device revoke x`: single-line / different wording.
/// - `file use x x`, `run x`: clap requires the `--` separator before the
///   command, Go takes positional arguments (a CLI-002 parser difference).
const OPEN_NOT_INITIALIZED: &[&[&str]] = &[
    &["delete", "x"],
    &["device", "approval-pair"],
    &["device", "revoke", "x"],
    &["file", "use", "x", "x"],
    &["run", "x"],
];

fn is_open(observation: &Observation) -> bool {
    OPEN_NOT_INITIALIZED.iter().any(|open| {
        observation
            .args
            .iter()
            .map(String::as_str)
            .eq(open.iter().copied())
    })
}

#[test]
fn native_cli_matches_go_not_initialized_failures() {
    let fixture = fixture();
    let mut failures = Vec::new();
    let mut replayed = 0;
    for observation in fixture.not_initialized.iter().filter(|o| !is_open(o)) {
        compare("not initialized", observation, &mut failures);
        replayed += 1;
    }
    assert_eq!(replayed, NOT_INITIALIZED_CASES - OPEN_NOT_INITIALIZED.len());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn open_not_initialized_cases_are_still_open() {
    let fixture = fixture();
    let open: Vec<&Observation> = fixture
        .not_initialized
        .iter()
        .filter(|observation| is_open(observation))
        .collect();
    assert_eq!(open.len(), OPEN_NOT_INITIALIZED.len());
    for observation in open {
        let mut failures = Vec::new();
        compare("open", observation, &mut failures);
        assert_eq!(
            failures.len(),
            1,
            "{:?} now matches Go; remove it from OPEN_NOT_INITIALIZED",
            observation.args
        );
    }
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
