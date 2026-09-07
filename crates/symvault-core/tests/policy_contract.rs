#![deny(unsafe_code)]

use serde::Deserialize;
use symvault_core::policy::{Engine, EvalContext, Policy, TimeRange, UtcTime};
use symvault_core::tier::{AgentProfile, apply_tier_preset, get_preset};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    oracle: Oracle,
    validation_cases: Vec<ValidationCase>,
    time_range_cases: Vec<TimeRangeCase>,
    evaluation_policy: Policy,
    evaluation_cases: Vec<EvaluationCase>,
    tier_preset_cases: Vec<TierPresetCase>,
    tier_copy_cases: Vec<TierCopyCase>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
}

#[derive(Debug, Deserialize)]
struct ValidationCase {
    name: String,
    policy: Policy,
    valid: bool,
    #[serde(default)]
    error: String,
}

#[derive(Debug, Deserialize)]
struct TimeRangeCase {
    name: String,
    range: TimeRange,
    now: String,
    valid: bool,
    matches: bool,
}

#[derive(Debug, Deserialize)]
struct EvaluationCase {
    name: String,
    context: FixtureContext,
    expected: FixtureResult,
}

#[derive(Debug, Deserialize)]
struct FixtureContext {
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    working_dir: String,
    #[serde(default)]
    env_vars: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    action_type: String,
    #[serde(default)]
    tool_name: String,
    now: String,
    #[serde(default)]
    secrets_accessed: i32,
}

#[derive(Debug, Deserialize)]
struct FixtureResult {
    action: String,
    rule_name: String,
    matched: bool,
}

#[derive(Debug, Deserialize)]
struct TierPresetCase {
    tier: String,
    found: bool,
    preset: ProfileSnapshot,
    apply_input: ProfileSnapshot,
    apply_expected: ProfileSnapshot,
}

#[derive(Debug, Deserialize)]
struct TierCopyCase {
    tier: String,
    mutated_can_write: bool,
    second_can_write: bool,
}

#[derive(Debug, Deserialize)]
struct ProfileSnapshot {
    name: String,
    #[serde(default)]
    approval_mode: Option<String>,
    allowed_paths: Vec<String>,
    #[serde(default)]
    can_write: Option<bool>,
    #[serde(default)]
    can_run_commands: Option<bool>,
    #[serde(default)]
    can_manage_config: Option<bool>,
    #[serde(default)]
    can_use_clipboard: Option<bool>,
    #[serde(default)]
    can_use_autotype: Option<bool>,
    #[serde(default)]
    can_read_values: Option<bool>,
    #[serde(default)]
    expose_value_tools: Option<bool>,
    #[serde(default)]
    auto_unseal: Option<bool>,
    #[serde(default)]
    require_approval: Option<bool>,
    #[serde(default)]
    allowed_executables: Option<Vec<String>>,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/core/policy-contract.json");
    serde_json::from_slice(CONTENT).expect("decode Go-generated policy fixture")
}

#[test]
fn fixture_has_provenance_and_schema() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "caadd5e");
    assert_eq!(fixture.oracle.release, "v0.22.1");
    assert_eq!(
        fixture.oracle.source_files,
        [
            "internal/config/config.go",
            "internal/config/presets.go",
            "internal/policy/engine.go",
            "internal/policy/types.go",
        ]
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
}

#[test]
fn policy_validation_cases_match_go_oracle() {
    for case in fixture().validation_cases {
        let actual = case.policy.validate();
        assert_eq!(actual.is_ok(), case.valid, "case {}", case.name);
        if !case.valid {
            let error = actual.expect_err("invalid fixture case");
            assert!(
                !case.error.is_empty(),
                "case {} missing oracle error",
                case.name
            );
            assert_eq!(error.to_string(), case.error, "case {}", case.name);
        }
    }
}

#[test]
fn time_range_cases_match_go_oracle() {
    for case in fixture().time_range_cases {
        let now = UtcTime::parse_rfc3339(&case.now).expect("fixture UTC timestamp");
        assert_eq!(case.range.parse().is_ok(), case.valid, "case {}", case.name);
        assert_eq!(case.range.contains(now), case.matches, "case {}", case.name);
    }
}

#[test]
fn evaluation_cases_match_go_oracle() {
    let fixture = fixture();
    let engine = Engine::new([&fixture.evaluation_policy]);
    for case in fixture.evaluation_cases {
        let actual = engine.evaluate(to_context(case.context));
        assert_eq!(
            actual.action.as_str(),
            case.expected.action,
            "case {} action",
            case.name
        );
        assert_eq!(
            actual.rule_name, case.expected.rule_name,
            "case {} rule",
            case.name
        );
        assert_eq!(
            actual.matched, case.expected.matched,
            "case {} matched",
            case.name
        );
    }
}

#[test]
fn tier_presets_and_apply_match_go_oracle() {
    for case in fixture().tier_preset_cases {
        let actual = get_preset(&case.tier);
        assert_eq!(actual.is_some(), case.found, "tier {} found", case.tier);
        if case.found {
            assert_profile(&actual.expect("known tier"), &case.preset, &case.tier);
        }

        let mut target = to_profile(&case.apply_input);
        let applied = apply_tier_preset(&mut target, &case.tier);
        assert_eq!(applied, case.found, "tier {} apply result", case.tier);
        assert_profile(&target, &case.apply_expected, &case.tier);
    }
}

#[test]
fn get_preset_field_mutation_matches_copy_contract() {
    for case in fixture().tier_copy_cases {
        let mut first = get_preset(&case.tier).expect("known copy tier");
        let second = get_preset(&case.tier).expect("known copy tier");
        first.can_write = Some(case.mutated_can_write);
        assert_eq!(
            first.can_write,
            Some(case.mutated_can_write),
            "tier {}",
            case.tier
        );
        assert_eq!(
            second.can_write,
            Some(case.second_can_write),
            "tier {}",
            case.tier
        );
    }
}

fn to_context(context: FixtureContext) -> EvalContext {
    EvalContext {
        agent_id: context.agent_id,
        path: context.path,
        tags: context.tags,
        working_dir: context.working_dir,
        env_vars: context.env_vars,
        action_type: context.action_type,
        tool_name: context.tool_name,
        now: UtcTime::parse_rfc3339(&context.now).expect("fixture UTC timestamp"),
        secrets_accessed: context.secrets_accessed,
    }
}

fn to_profile(snapshot: &ProfileSnapshot) -> AgentProfile {
    AgentProfile {
        name: snapshot.name.clone(),
        approval_mode: snapshot.approval_mode.clone(),
        allowed_paths: snapshot.allowed_paths.clone(),
        can_write: snapshot.can_write,
        can_run_commands: snapshot.can_run_commands,
        can_manage_config: snapshot.can_manage_config,
        can_use_clipboard: snapshot.can_use_clipboard,
        can_use_autotype: snapshot.can_use_autotype,
        can_read_values: snapshot.can_read_values,
        expose_value_tools: snapshot.expose_value_tools,
        auto_unseal: snapshot.auto_unseal,
        require_approval: snapshot.require_approval,
        allowed_executables: snapshot.allowed_executables.clone(),
        ..AgentProfile::default()
    }
}

fn assert_profile(actual: &AgentProfile, expected: &ProfileSnapshot, label: &str) {
    assert_eq!(actual.name, expected.name, "{label} name");
    assert_eq!(
        actual.approval_mode, expected.approval_mode,
        "{label} approval mode"
    );
    assert_eq!(
        actual.allowed_paths, expected.allowed_paths,
        "{label} allowed paths"
    );
    assert_eq!(actual.can_write, expected.can_write, "{label} can write");
    assert_eq!(
        actual.can_run_commands, expected.can_run_commands,
        "{label} can run commands"
    );
    assert_eq!(
        actual.can_manage_config, expected.can_manage_config,
        "{label} can manage config"
    );
    assert_eq!(
        actual.can_use_clipboard, expected.can_use_clipboard,
        "{label} clipboard"
    );
    assert_eq!(
        actual.can_use_autotype, expected.can_use_autotype,
        "{label} autotype"
    );
    assert_eq!(
        actual.can_read_values, expected.can_read_values,
        "{label} read values"
    );
    assert_eq!(
        actual.expose_value_tools, expected.expose_value_tools,
        "{label} value tools"
    );
    assert_eq!(
        actual.auto_unseal, expected.auto_unseal,
        "{label} auto unseal"
    );
    assert_eq!(
        actual.require_approval, expected.require_approval,
        "{label} require approval"
    );
    assert_eq!(
        actual.allowed_executables, expected.allowed_executables,
        "{label} allowed executables"
    );
}
