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
    empty_engine_cases: Vec<EvaluationCase>,
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
    rule_name: String,
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
    for case in &fixture.evaluation_cases {
        let rule = fixture
            .evaluation_policy
            .rules
            .iter()
            .find(|rule| rule.name == case.rule_name)
            .unwrap_or_else(|| panic!("missing isolated rule {}", case.rule_name));
        let isolated_policy = Policy {
            version: fixture.evaluation_policy.version.clone(),
            description: fixture.evaluation_policy.description.clone(),
            rules: vec![rule.clone()],
        };
        let engine = Engine::new([&isolated_policy]);
        let actual = engine.evaluate(to_context(&case.context));
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
fn empty_engine_cases_match_genuine_default_result() {
    let fixture = fixture();
    for case in &fixture.empty_engine_cases {
        let engine = Engine::new(std::iter::empty::<&Policy>());
        let actual = engine.evaluate(to_context(&case.context));
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
fn evaluation_fixture_covers_each_rule_action_and_branch() {
    let fixture = fixture();
    let required_rules = [
        "allow openclaw dev",
        "allow project child",
        "allow project recursive",
        "allow working tree",
        "allow ci read",
        "allow safe tool",
        "biometry at night",
        "prompt production",
        "allow limited secrets",
        "deny all",
    ];
    assert_eq!(fixture.evaluation_policy.rules.len(), required_rules.len());
    for name in required_rules {
        assert!(
            fixture
                .evaluation_policy
                .rules
                .iter()
                .any(|rule| rule.name == name),
            "missing evaluation rule {name}"
        );
        assert!(
            fixture
                .evaluation_cases
                .iter()
                .any(|case| case.rule_name == name
                    && case.expected.rule_name == name
                    && case.expected.matched),
            "rule {name} lacks an isolated positive case"
        );
    }
    for action in ["allow", "deny", "prompt", "require_biometry"] {
        assert!(
            fixture
                .evaluation_policy
                .rules
                .iter()
                .any(|rule| rule.action.as_str() == action),
            "action {action} is not covered"
        );
    }
    let required_cases = [
        "agent_tags_match",
        "agent_tags_rejects_tag",
        "path_child_match",
        "path_child_rejects_grandchild",
        "path_recursive_match",
        "path_recursive_rejects_child",
        "working_dir_match",
        "working_dir_rejects_sibling",
        "env_action_match",
        "env_rejects_value",
        "action_rejects_value",
        "allowed_tool_match",
        "allowed_tool_rejects_name",
        "allowed_tool_empty_name",
        "biometry_night_match",
        "biometry_day_reject",
        "prompt_prod_match",
        "prompt_nonprod_reject",
        "limited_below_secret_limit",
        "limited_at_secret_limit",
        "default_deny",
    ];
    for name in required_cases {
        assert!(
            fixture
                .evaluation_cases
                .iter()
                .any(|case| case.name == name),
            "missing branch case {name}"
        );
    }
    let rejected_cases = [
        "agent_tags_rejects_tag",
        "path_child_rejects_grandchild",
        "path_recursive_rejects_child",
        "working_dir_rejects_sibling",
        "env_rejects_value",
        "action_rejects_value",
        "allowed_tool_rejects_name",
        "biometry_day_reject",
        "prompt_nonprod_reject",
        "limited_at_secret_limit",
    ];
    for name in rejected_cases {
        let case = fixture
            .evaluation_cases
            .iter()
            .find(|case| case.name == name)
            .expect("required rejected case");
        assert_eq!(case.expected.action, "deny", "case {name} action");
        assert!(case.expected.rule_name.is_empty(), "case {name} rule");
        assert!(!case.expected.matched, "case {name} matched unexpectedly");
    }
    let empty_tool = fixture
        .evaluation_cases
        .iter()
        .find(|case| case.name == "allowed_tool_empty_name")
        .expect("explicit empty tool case");
    assert_eq!(empty_tool.context.tool_name, "");
    assert_eq!(empty_tool.expected.rule_name, "allow safe tool");
    assert!(empty_tool.expected.matched);
    assert_eq!(empty_tool.expected.action, "allow");
    assert_eq!(fixture.empty_engine_cases.len(), 1);
    let empty = &fixture.empty_engine_cases[0].expected;
    assert_eq!(empty.action, "deny");
    assert!(empty.rule_name.is_empty());
    assert!(!empty.matched);
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

fn to_context(context: &FixtureContext) -> EvalContext {
    EvalContext {
        agent_id: context.agent_id.clone(),
        path: context.path.clone(),
        tags: context.tags.clone(),
        working_dir: context.working_dir.clone(),
        env_vars: context.env_vars.clone(),
        action_type: context.action_type.clone(),
        tool_name: context.tool_name.clone(),
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
