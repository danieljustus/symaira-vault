//! CFG-003: the config-bytes contract, against the Go oracle.
//!
//! Error text is deliberately not part of the contract — Go's yaml.v3 and
//! Rust's serde_yaml_ng word their failures differently. What is pinned is
//! whether an input is rejected at all, what an accepted input resolves to,
//! and the permissions the writer leaves behind.

use serde::Deserialize;
use symvault_core::config::Config;

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Snapshot {
    default_agent: String,
    session_timeout: String,
    session_max_lifetime: String,
    auth_method: String,
    agent_names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    #[allow(dead_code)]
    description: String,
    input: String,
    rejected: bool,
    snapshot: Option<Snapshot>,
    #[serde(default)]
    warnings: Vec<String>,
    #[serde(default)]
    saved_yaml: String,
    #[serde(default)]
    round_trips_to: String,
}

/// Only the unix build reads the mode fields; Windows does not carry these
/// bits and the fixture records that instead of asserting them.
#[derive(Debug, Deserialize)]
#[cfg_attr(not(unix), allow(dead_code))]
struct Modes {
    #[serde(default)]
    directory: String,
    #[serde(default)]
    file: String,
    platform: String,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    cases: Vec<Case>,
    #[cfg_attr(not(unix), allow(dead_code))]
    modes: Modes,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/config/bytes.json");
    serde_json::from_slice(CONTENT).expect("CFG-003 fixture parses")
}

fn snapshot_of(config: &Config) -> Snapshot {
    Snapshot {
        default_agent: config.default_agent.clone(),
        session_timeout: go_duration(config.session_timeout.as_secs()),
        session_max_lifetime: go_duration(config.session_max_lifetime.as_secs()),
        auth_method: config.auth_method.as_str().to_owned(),
        agent_names: {
            let mut names: Vec<String> = config.agents.keys().cloned().collect();
            names.sort();
            names
        },
    }
}

/// Renders seconds the way Go's time.Duration.String() does, so the snapshot
/// is comparable without carrying a Go-specific format into production code.
fn go_duration(total: u64) -> String {
    if total == 0 {
        return "0s".to_owned();
    }
    let (hours, minutes, seconds) = (total / 3600, (total % 3600) / 60, total % 60);
    let mut out = String::new();
    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if hours > 0 || minutes > 0 {
        out.push_str(&format!("{minutes}m"));
    }
    out.push_str(&format!("{seconds}s"));
    out
}

#[test]
fn fixture_has_pinned_provenance_and_schema() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "0daaaa91");
    assert_eq!(fixture.oracle.release, "unreleased");
    assert_eq!(fixture.oracle.commit_sha.len(), 40);
    assert!(
        fixture
            .oracle
            .commit_sha
            .starts_with(&fixture.oracle.commit)
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert!(fixture.oracle.source_files.len() >= 5);
    assert!(fixture.cases.len() >= 20, "fixture lost cases");
    assert!(fixture.cases.iter().any(|case| case.rejected));
    assert!(fixture.cases.iter().any(|case| !case.rejected));
}

/// Inputs where the two implementations disagree on acceptance.
///
/// Empty since the step-one alignment: Rust adopted Go's YAML 1.1 booleans and
/// its treatment of an explicit `null`, and both sides now warn-and-accept a
/// non-positive duration and a multi-document stream rather than one rejecting
/// what the other takes. Step two flips the latter two to rejection in both,
/// deliberately and together; see `docs/rust-port/cfg-003-acceptance-adjudication.md`.
///
/// The set is asserted exactly, so it can neither grow nor shrink unnoticed.
const ACCEPTANCE_PENDING_ADJUDICATION: [&str; 0] = [];

/// The decisive property: an input one implementation rejects must not be
/// silently accepted by the other, except for the adjudication set above,
/// whose membership is itself asserted.
#[test]
fn acceptance_matches_go_oracle() {
    let mut unexpected = Vec::new();
    let mut diverging = Vec::new();
    for case in &fixture().cases {
        let result = Config::load_from_bytes(case.input.as_bytes());
        let rejected = result.is_err();
        if rejected == case.rejected {
            continue;
        }
        diverging.push(case.name.clone());
        if !ACCEPTANCE_PENDING_ADJUDICATION.contains(&case.name.as_str()) {
            unexpected.push(format!(
                "{}: Go rejected={}, Rust rejected={} ({:?})",
                case.name,
                case.rejected,
                rejected,
                result.err().map(|error| error.to_string())
            ));
        }
    }
    assert!(
        unexpected.is_empty(),
        "acceptance diverges outside the adjudication set:\n  {}",
        unexpected.join("\n  ")
    );

    diverging.sort();
    let mut expected: Vec<String> = ACCEPTANCE_PENDING_ADJUDICATION
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    expected.sort();
    assert_eq!(
        diverging, expected,
        "the pending-adjudication set drifted; update it deliberately, with the contract decision"
    );
}

#[test]
fn accepted_inputs_resolve_to_the_go_snapshot() {
    for case in &fixture().cases {
        let Some(expected) = &case.snapshot else {
            continue;
        };
        if ACCEPTANCE_PENDING_ADJUDICATION.contains(&case.name.as_str()) {
            continue;
        }
        let config = Config::load_from_bytes(case.input.as_bytes()).unwrap_or_else(|error| {
            panic!(
                "{}: Go accepted this input, Rust failed: {error}",
                case.name
            )
        });
        assert_eq!(
            &snapshot_of(&config),
            expected,
            "snapshot for {}",
            case.name
        );
    }
}

/// Re-loading the writer's canonical output must reproduce the same snapshot.
#[test]
fn canonical_output_round_trips() {
    for case in &fixture().cases {
        let Some(expected) = &case.snapshot else {
            continue;
        };
        assert_eq!(case.round_trips_to, "identical_snapshot", "{}", case.name);
        if ACCEPTANCE_PENDING_ADJUDICATION.contains(&case.name.as_str()) {
            continue;
        }
        assert!(
            !case.saved_yaml.is_empty(),
            "{} has no canonical output",
            case.name
        );
        let reloaded =
            Config::load_from_bytes(case.saved_yaml.as_bytes()).unwrap_or_else(|error| {
                panic!(
                    "{}: Rust cannot reload Go's canonical output: {error}",
                    case.name
                )
            });
        assert_eq!(
            &snapshot_of(&reloaded),
            expected,
            "round-trip snapshot for {}",
            case.name
        );
    }
}

/// The writer must leave the same permissions behind. Unix only: Windows does
/// not carry these bits, and the fixture records that rather than pretending.
#[cfg(unix)]
#[test]
fn writer_modes_match_go_oracle() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = fixture();
    if fixture.modes.platform != "unix" {
        return;
    }
    // The repository's test convention is a uniquely named directory under the
    // system temp dir rather than a tempfile dev-dependency.
    let root = std::env::temp_dir().join(format!("sv-cfg003-modes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let nested = root.join("modes").join("nested");
    let path = nested.join("config.yaml");
    Config::default().save_to(&path).expect("save config");

    let dir_mode = format!(
        "0{:o}",
        std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777
    );
    let file_mode = format!(
        "0{:o}",
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777
    );
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(dir_mode, fixture.modes.directory, "directory mode");
    assert_eq!(file_mode, fixture.modes.file, "config file mode");
}

/// The warning texts are ours on both sides, so unlike error messages they are
/// part of the contract. A warning that stops being emitted would otherwise
/// return the loader to silently discarding what the operator wrote.
#[test]
fn warnings_match_go_oracle() {
    for case in &fixture().cases {
        if case.rejected {
            continue;
        }
        let (_, warnings) = Config::load_from_bytes_with_warnings(case.input.as_bytes())
            .unwrap_or_else(|error| {
                panic!(
                    "{}: Go accepted this input, Rust failed: {error}",
                    case.name
                )
            });
        assert_eq!(warnings, case.warnings, "warnings for {}", case.name);
    }
}

/// CFG-003 step two turned the loader's two warnings into rejections, in both
/// implementations at once. These are the inputs that changed, and they must
/// stay rejected: a regression on either side reopens the silent discard that
/// motivated the change — an operator believing a restriction is in force when
/// the loader threw it away.
#[test]
fn the_fixture_pins_the_step_two_rejections() {
    let cases = fixture().cases;
    for name in [
        "multiple_documents",
        "negative_duration",
        "zero_duration",
        "negative_max_lifetime",
    ] {
        let case = cases
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("fixture no longer carries the {name} case"));
        assert!(case.rejected, "{name} must be rejected by the Go oracle");
        assert!(
            Config::load_from_bytes(case.input.as_bytes()).is_err(),
            "{name} must be rejected here too"
        );
    }
}
