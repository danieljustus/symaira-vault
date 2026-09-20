//! CFG-001: the path-resolution contract, against the Go oracle.
//!
//! The fixture pins slash-separated logical paths. The contract is the
//! resolution logic, not the host separator, so both sides normalise to
//! slashes before comparing and the fixture stays comparable on every
//! platform.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use symvault_core::config::{PathEnvironment, PathResolver, resolve_paths};

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
}

#[derive(Debug, Deserialize)]
struct Environment {
    #[serde(default)]
    home: String,
    #[serde(default)]
    xdg_config_home: String,
    #[serde(default)]
    xdg_data_home: String,
    #[serde(default)]
    xdg_cache_home: String,
    #[serde(default)]
    vault_override: String,
    #[serde(default)]
    legacy_dir_exists: bool,
    #[serde(default)]
    xdg_data_dir_exists: bool,
}

#[derive(Debug, Deserialize)]
struct Expected {
    config_dir: String,
    data_dir: String,
    cache_dir: String,
    legacy_dir: String,
    migrated: bool,
    config_path: String,
    audit_dir: String,
    cache_path: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    #[allow(dead_code)]
    description: String,
    environment: Environment,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    cases: Vec<Case>,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/config/paths.json");
    serde_json::from_slice(CONTENT).expect("CFG-001 fixture parses")
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn to_environment(input: &Environment) -> PathEnvironment {
    PathEnvironment {
        home: input.home.clone(),
        xdg_config_home: input.xdg_config_home.clone(),
        xdg_data_home: input.xdg_data_home.clone(),
        xdg_cache_home: input.xdg_cache_home.clone(),
        vault_override: input.vault_override.clone(),
        legacy_dir_exists: input.legacy_dir_exists,
        xdg_data_dir_exists: input.xdg_data_dir_exists,
    }
}

#[test]
fn fixture_has_pinned_provenance_and_schema() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "fc9eddc0");
    assert_eq!(fixture.oracle.release, "unreleased");
    assert_eq!(fixture.oracle.commit_sha.len(), 40);
    assert!(
        fixture
            .oracle
            .commit_sha
            .starts_with(&fixture.oracle.commit),
        "commit_sha {} does not match commit {}",
        fixture.oracle.commit_sha,
        fixture.oracle.commit
    );
    assert_eq!(
        fixture.oracle.source_files,
        ["internal/config/config.go", "internal/config/paths.go"]
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert!(
        fixture.cases.len() >= 14,
        "fixture lost cases: {}",
        fixture.cases.len()
    );
}

#[test]
fn path_resolution_matches_go_oracle() {
    for case in &fixture().cases {
        let resolved = resolve_paths(&to_environment(&case.environment));
        let expected = &case.expected;

        assert_eq!(
            slash(&resolved.config_dir),
            expected.config_dir,
            "config_dir in {}",
            case.name
        );
        assert_eq!(
            slash(&resolved.data_dir),
            expected.data_dir,
            "data_dir in {}",
            case.name
        );
        assert_eq!(
            slash(&resolved.cache_dir),
            expected.cache_dir,
            "cache_dir in {}",
            case.name
        );
        assert_eq!(
            resolved
                .legacy_dir
                .as_deref()
                .map(slash)
                .unwrap_or_default(),
            expected.legacy_dir,
            "legacy_dir in {}",
            case.name
        );
        assert_eq!(
            resolved.migrated, expected.migrated,
            "migrated in {}",
            case.name
        );
        assert_eq!(
            slash(&resolved.config_path()),
            expected.config_path,
            "config_path in {}",
            case.name
        );
        assert_eq!(
            slash(&resolved.audit_dir()),
            expected.audit_dir,
            "audit_dir in {}",
            case.name
        );
        assert_eq!(
            slash(&resolved.cache_path()),
            expected.cache_path,
            "cache_path in {}",
            case.name
        );
    }
}

/// The fixture must keep exercising both polarities of each decision, or a
/// regression in one branch could pass unnoticed.
#[test]
fn fixture_covers_every_install_state_and_override_shape() {
    let cases = fixture().cases;
    let names: Vec<&str> = cases.iter().map(|case| case.name.as_str()).collect();
    for required in [
        "new_install_xdg_only",
        "legacy_install_reads_legacy",
        "post_migration_prefers_xdg",
        "xdg_data_without_legacy",
        "empty_xdg_values_fall_back",
        "vault_override_tilde_expands",
        "vault_override_blank_is_ignored",
        "no_home_yields_zero_resolver",
    ] {
        assert!(names.contains(&required), "fixture lost case {required}");
    }
    assert!(cases.iter().any(|case| case.expected.migrated));
    assert!(cases.iter().any(|case| !case.expected.migrated));
    assert!(
        cases
            .iter()
            .any(|case| !case.expected.legacy_dir.is_empty())
    );
    assert!(cases.iter().any(|case| case.expected.legacy_dir.is_empty()));
}

/// Go builds the XDG defaults with one `filepath.Join` component per segment
/// (`filepath.Join(home, ".local", "share")`), so the resolved path renders with
/// host separators throughout. Preparing `.local/share` as a single literal
/// segment instead keeps `/` inside the middle of the path on Windows, which is
/// invisible to `PathBuf` equality (Windows parses both separators) but visible
/// in the bytes the CLI prints, so compare rendered strings against the same
/// component-wise join.
#[test]
fn xdg_defaults_render_with_host_separators_throughout() {
    let home = "/fixture/home/probe";
    let resolved = resolve_paths(&PathEnvironment {
        home: home.to_owned(),
        ..PathEnvironment::default()
    });
    for (actual, expected) in [
        (
            &resolved.config_dir,
            Path::new(home).join(".config").join("symaira-vault"),
        ),
        (
            &resolved.data_dir,
            Path::new(home)
                .join(".local")
                .join("share")
                .join("symaira-vault"),
        ),
        (
            &resolved.cache_dir,
            Path::new(home).join(".cache").join("symaira-vault"),
        ),
    ] {
        assert_eq!(
            actual.to_string_lossy(),
            expected.to_string_lossy(),
            "resolved XDG default must join one component at a time"
        );
    }
}

/// A legacy install must read its config from the legacy directory. Resolving
/// config_path against the XDG directory instead would silently miss an
/// existing user's configuration.
#[test]
fn config_path_follows_the_resolved_config_dir() {
    let resolved = resolve_paths(&PathEnvironment {
        home: "/fixture/home/probe".to_owned(),
        legacy_dir_exists: true,
        ..PathEnvironment::default()
    });
    assert_eq!(
        slash(&resolved.config_path()),
        "/fixture/home/probe/.symvault/config.yaml"
    );
    let _: PathBuf = resolved.config_path();
    let _: &PathResolver = &resolved;
}
