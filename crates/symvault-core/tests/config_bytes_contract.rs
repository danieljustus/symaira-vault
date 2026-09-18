//! CFG-003: the config-bytes contract, against the Go oracle.
//!
//! Error text is deliberately not part of the contract — Go's yaml.v3 and
//! Rust's serde_yaml_ng word their failures differently. What is pinned is
//! whether an input is rejected at all, what an accepted input resolves to,
//! and the permissions the writer leaves behind.

use serde::Deserialize;
use symvault_core::config::Config;
use symvault_core::test_support::corpus_limit;

/// The fixture cases a run executes: the full corpus natively, a bounded prefix
/// under Miri, where interpreter time scales with corpus size while UB coverage
/// scales with code paths. See `symvault_core::test_support`.
fn cases_for_run() -> Vec<Case> {
    let all = fixture().cases;
    let limit = corpus_limit(all.len());
    all.into_iter().take(limit).collect()
}

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

#[derive(Debug, Deserialize)]
struct WriterCase {
    name: String,
    #[allow(dead_code)]
    description: String,
    requested: WriterSnapshot,
    saved_yaml: String,
    loaded: WriterSnapshot,
    #[serde(default)]
    omitted_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WriterSnapshot {
    vault: Option<WriterVaultSnapshot>,
    git: Option<WriterGitSnapshot>,
    clipboard: Option<WriterClipboardSnapshot>,
}

#[derive(Debug, Deserialize)]
struct WriterVaultSnapshot {
    path: String,
    default_recipients: Vec<String>,
    confirm_remove: bool,
    auth_method: String,
    use_touch_id: bool,
    legacy_mode: Option<bool>,
    search_index: bool,
    search_workers: i64,
    search_index_cache: bool,
    config_cache_entries: i64,
    pseudonymize_paths: bool,
    scrypt_work_factor: i64,
    auto_migrate_kdf: bool,
    auto_heal_zero_key: bool,
    last_rotated: String,
    format_version: i64,
    argon2id_time: i64,
    argon2id_memory: i64,
    argon2id_threads: i64,
    listing_cache_ttl: String,
    manifest_generation: i64,
    sync_method: String,
}

#[derive(Debug, Deserialize)]
struct WriterGitSnapshot {
    auto_push: bool,
    auto_pull: bool,
    auto_pull_interval: String,
    commit_template: String,
}

#[derive(Debug, Deserialize)]
struct WriterClipboardSnapshot {
    auto_clear_duration: i64,
    copy_by_default: bool,
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
    #[serde(default)]
    writer_cases: Vec<WriterCase>,
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
    assert_eq!(fixture.oracle.commit, "aa21ec4e");
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
    assert!(fixture.cases.len() >= 22, "fixture lost cases");
    assert!(fixture.cases.iter().any(|case| case.rejected));
    assert!(fixture.cases.iter().any(|case| !case.rejected));
}

/// Inputs where the two implementations disagree on acceptance.
///
/// Empty since the step-one alignment, and still empty after step two: Rust
/// adopted Go's YAML 1.1 booleans and its treatment of an explicit `null`, and
/// both sides now reject a non-positive session duration and a multi-document
/// stream instead of silently discarding what the operator wrote. The staged
/// migration is complete; see `docs/rust-port/cfg-003-acceptance-adjudication.md`.
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
    for case in &cases_for_run() {
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
    for case in &cases_for_run() {
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
    for case in &cases_for_run() {
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

/// The writer cases execute Go's Config.SaveTo and then Go's Load. Re-load the
/// exact saved bytes here and compare every modeled vault field, including the
/// KDF settings. Fields in omitted_fields are intentionally visible evidence
/// of production Go's current raw-copy omission, rather than silently treated
/// as Rust-only data.
#[test]
fn go_writer_cases_reload_with_rust_semantics() {
    let fixture = fixture();
    assert_eq!(fixture.writer_cases.len(), 2);
    for case in &fixture.writer_cases {
        let config = Config::load_from_bytes(case.saved_yaml.as_bytes()).unwrap_or_else(|error| {
            panic!("{}: Rust cannot reload Go SaveTo bytes: {error}", case.name)
        });
        if let Some(expected) = &case.loaded.vault {
            let actual = config
                .vault
                .as_ref()
                .unwrap_or_else(|| panic!("{}: Go loaded vault section is missing", case.name));
            assert_eq!(actual.path, expected.path, "{} vault.path", case.name);
            assert_eq!(
                actual.default_recipients, expected.default_recipients,
                "{} vault.default_recipients",
                case.name
            );
            assert_eq!(
                actual.confirm_remove, expected.confirm_remove,
                "{} vault.confirm_remove",
                case.name
            );
            assert_eq!(
                actual.auth_method.as_str(),
                expected.auth_method,
                "{} vault.auth_method",
                case.name
            );
            assert_eq!(
                actual.use_touch_id, expected.use_touch_id,
                "{} vault.use_touch_id",
                case.name
            );
            assert_eq!(
                actual.legacy_mode, expected.legacy_mode,
                "{} vault.legacy_mode",
                case.name
            );
            assert_eq!(
                actual.search_index, expected.search_index,
                "{} vault.search_index",
                case.name
            );
            assert_eq!(
                actual.search_workers, expected.search_workers,
                "{} vault.search_workers",
                case.name
            );
            assert_eq!(
                actual.search_index_cache, expected.search_index_cache,
                "{} vault.search_index_cache",
                case.name
            );
            assert_eq!(
                actual.config_cache_entries, expected.config_cache_entries,
                "{} vault.config_cache_entries",
                case.name
            );
            assert_eq!(
                actual.pseudonymize_paths, expected.pseudonymize_paths,
                "{} vault.pseudonymize_paths",
                case.name
            );
            assert_eq!(
                actual.scrypt_work_factor, expected.scrypt_work_factor,
                "{} vault.scrypt_work_factor",
                case.name
            );
            assert_eq!(
                actual.auto_migrate_kdf, expected.auto_migrate_kdf,
                "{} vault.auto_migrate_kdf",
                case.name
            );
            assert_eq!(
                actual.auto_heal_zero_key, expected.auto_heal_zero_key,
                "{} vault.auto_heal_zero_key",
                case.name
            );
            assert_eq!(
                actual.last_rotated.as_deref().unwrap_or_default(),
                expected.last_rotated,
                "{} vault.last_rotated",
                case.name
            );
            assert_eq!(
                actual.format_version, expected.format_version,
                "{} vault.format_version",
                case.name
            );
            assert_eq!(
                actual.argon2id_time, expected.argon2id_time,
                "{} vault.argon2id_time",
                case.name
            );
            assert_eq!(
                actual.argon2id_memory, expected.argon2id_memory,
                "{} vault.argon2id_memory",
                case.name
            );
            assert_eq!(
                actual.argon2id_threads, expected.argon2id_threads,
                "{} vault.argon2id_threads",
                case.name
            );
            assert_eq!(
                go_duration(actual.listing_cache_ttl.as_secs()),
                expected.listing_cache_ttl,
                "{} vault.listing_cache_ttl",
                case.name
            );
            assert_eq!(
                actual.manifest_generation, expected.manifest_generation,
                "{} vault.manifest_generation",
                case.name
            );
            assert_eq!(
                actual
                    .sync
                    .as_ref()
                    .map(|sync| sync.method.as_str())
                    .unwrap_or_default(),
                expected.sync_method,
                "{} vault.sync",
                case.name
            );
        }
        if let Some(expected) = &case.loaded.git {
            let actual = config
                .git
                .as_ref()
                .unwrap_or_else(|| panic!("{}: Go loaded git section is missing", case.name));
            assert_eq!(
                actual.auto_push, expected.auto_push,
                "{} git.auto_push",
                case.name
            );
            assert_eq!(
                actual.auto_pull, expected.auto_pull,
                "{} git.auto_pull",
                case.name
            );
            assert_eq!(
                go_duration(actual.auto_pull_interval.as_secs()),
                expected.auto_pull_interval,
                "{} git.auto_pull_interval",
                case.name
            );
            assert_eq!(
                actual.commit_template, expected.commit_template,
                "{} git.commit_template",
                case.name
            );
        }
        if let Some(expected) = &case.loaded.clipboard {
            let actual = config
                .clipboard
                .as_ref()
                .unwrap_or_else(|| panic!("{}: Go loaded clipboard section is missing", case.name));
            assert_eq!(
                actual.auto_clear_duration, expected.auto_clear_duration,
                "{} clipboard.auto_clear_duration",
                case.name
            );
            assert_eq!(
                actual.copy_by_default, expected.copy_by_default,
                "{} clipboard.copy_by_default",
                case.name
            );
        }
        for field in &case.omitted_fields {
            let key = field.rsplit('.').next().unwrap_or(field);
            assert!(
                !case.saved_yaml.contains(key),
                "{} unexpectedly wrote omitted field {field}",
                case.name
            );
        }
        if case.name == "explicit_false_sections" {
            let requested_git = case
                .requested
                .git
                .as_ref()
                .expect("false-section case must request a git section");
            assert!(!requested_git.auto_push);
            assert!(!requested_git.auto_pull);
            let loaded_git = case
                .loaded
                .git
                .as_ref()
                .expect("false-section case must reload a git section");
            assert!(
                loaded_git.auto_push,
                "Go's empty git section applies its true default"
            );
            assert!(
                loaded_git.auto_pull,
                "Go's empty git section applies its true default"
            );
            let requested_clipboard = case
                .requested
                .clipboard
                .as_ref()
                .expect("false-section case must request a clipboard section");
            assert!(!requested_clipboard.copy_by_default);
            let loaded_clipboard = case
                .loaded
                .clipboard
                .as_ref()
                .expect("false-section case must reload a clipboard section");
            assert!(
                loaded_clipboard.copy_by_default,
                "Go's empty clipboard section applies its true default"
            );
            assert!(case.saved_yaml.contains("git: {}\n"));
            assert!(case.saved_yaml.contains("clipboard: {}\n"));

            // Rust deliberately retains these explicit safety opt-outs in its
            // own writer, even though the Go `omitempty` writer loses them.
            // This is the one documented writer-byte divergence in this slice.
            let rust = Config {
                git: Some(symvault_core::config::GitConfig {
                    auto_push: false,
                    auto_pull: false,
                    auto_pull_interval: std::time::Duration::ZERO,
                    commit_template: String::new(),
                }),
                clipboard: Some(symvault_core::config::ClipboardConfig {
                    auto_clear_duration: 0,
                    copy_by_default: false,
                }),
                ..Config::default()
            };
            let rust_yaml = String::from_utf8(rust.to_yaml_bytes().expect("Rust writer"))
                .expect("Rust writer emits UTF-8");
            assert!(rust_yaml.contains("auto_push: false"));
            assert!(rust_yaml.contains("auto_pull: false"));
            assert!(rust_yaml.contains("copyByDefault: false"));
            let rust_reload = Config::load_from_bytes(rust_yaml.as_bytes()).expect("Rust reload");
            assert!(!rust_reload.git.expect("Rust git section").auto_push);
            assert!(
                !rust_reload
                    .clipboard
                    .expect("Rust clipboard section")
                    .copy_by_default
            );
        }
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
    for case in &cases_for_run() {
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
