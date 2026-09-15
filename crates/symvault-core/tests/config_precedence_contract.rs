//! CFG-002: the config-loading precedence contract, against the Go oracle.
//!
//! The ladder is: built-in defaults, then the tier preset when `tier` is
//! present, then every explicitly present field. The subtle part is presence
//! rather than value — an explicitly written `false` must beat what the tier
//! grants, and an absent field must not.
//!
//! Permissions are compared in effective terms. Go models them as `*bool` and
//! every consumer resolves them as `p != nil && *p`, so an unset permission is
//! observably false; that is also the shape Rust carries.

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
struct Profile {
    present: bool,
    tier: Option<String>,
    approval_mode: Option<String>,
    allowed_paths: Vec<String>,
    can_write: bool,
    can_run_commands: bool,
    can_manage_config: bool,
    can_use_clipboard: bool,
    can_use_autotype: bool,
    can_read_values: bool,
    expose_value_tools: bool,
    auto_unseal: bool,
    require_approval: bool,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    #[allow(dead_code)]
    description: String,
    input: String,
    profile: Profile,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    cases: Vec<Case>,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/config/precedence.json");
    serde_json::from_slice(CONTENT).expect("CFG-002 fixture parses")
}

fn resolve(config: &Config) -> Profile {
    match config.agents.get("probe") {
        None => Profile {
            present: false,
            tier: None,
            approval_mode: None,
            allowed_paths: Vec::new(),
            can_write: false,
            can_run_commands: false,
            can_manage_config: false,
            can_use_clipboard: false,
            can_use_autotype: false,
            can_read_values: false,
            expose_value_tools: false,
            auto_unseal: false,
            require_approval: false,
        },
        Some(agent) => Profile {
            present: true,
            tier: agent.tier.clone(),
            approval_mode: agent.approval_mode.clone(),
            allowed_paths: agent.allowed_paths.clone(),
            can_write: agent.can_write,
            can_run_commands: agent.can_run_commands,
            can_manage_config: agent.can_manage_config,
            can_use_clipboard: agent.can_use_clipboard,
            can_use_autotype: agent.can_use_autotype,
            can_read_values: agent.can_read_values,
            expose_value_tools: agent.expose_value_tools,
            auto_unseal: agent.auto_unseal,
            require_approval: agent.require_approval,
        },
    }
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
    assert!(
        fixture
            .oracle
            .source_files
            .contains(&"internal/config/presets.go".to_owned())
    );
    assert!(fixture.cases.len() >= 23, "fixture lost cases");
}

#[test]
fn precedence_matches_go_oracle() {
    for case in &fixture().cases {
        let config = Config::load_from_bytes(case.input.as_bytes())
            .unwrap_or_else(|error| panic!("{}: {error}", case.name));
        assert_eq!(resolve(&config), case.profile, "profile for {}", case.name);
    }
}

/// The tier layer must actually take effect, not merely be recorded. Rust
/// stored the tier name and applied nothing, so a `tier: standard` agent ran
/// without requiring approval.
#[test]
fn a_tier_applies_its_preset() {
    let cases = fixture().cases;
    let by_name = |name: &str| {
        cases
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("fixture lost case {name}"))
    };

    let admin = &by_name("tier_admin").profile;
    assert!(admin.can_write && admin.can_run_commands && admin.can_read_values);
    assert!(admin.require_approval, "admin must still require approval");

    let standard = &by_name("tier_standard").profile;
    assert!(standard.require_approval, "standard must require approval");
    assert!(!standard.can_write);

    let read_only = &by_name("tier_read_only").profile;
    assert!(!read_only.can_write && !read_only.can_read_values);

    // An unrecognized tier grants nothing but is still recorded.
    let unknown = &by_name("tier_unknown").profile;
    assert_eq!(unknown.tier.as_deref(), Some("not-a-tier"));
    assert!(!unknown.can_write && !unknown.require_approval);
}

/// Presence beats value: an explicitly written permission overrides the tier
/// in both directions, which is what makes this a precedence contract rather
/// than a defaults one.
#[test]
fn an_explicit_field_overrides_the_tier() {
    let cases = fixture().cases;
    let by_name = |name: &str| {
        cases
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("fixture lost case {name}"))
    };

    assert!(!by_name("tier_admin_denies_write").profile.can_write);
    assert!(by_name("tier_read_only_grants_write").profile.can_write);
    assert!(
        !by_name("tier_admin_drops_approval")
            .profile
            .require_approval
    );
}
