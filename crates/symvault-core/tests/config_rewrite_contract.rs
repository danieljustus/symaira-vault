//! CONFIG-WRITER: the bytes a config rewrite leaves behind, against Go's
//! `Config.SaveTo`.
//!
//! Every case is a real Go `Load` -> mutation -> `SaveTo` recorded by
//! `scripts/rust-port/cmd/configrewritegen`. The Rust writer must produce the
//! same bytes for everything Go writes. The declared differences are the two
//! top-level sections Go drops on rewrite (`paymentPolicies`, `security`) and
//! the line-level ones in `declared_line_differences` (`mcp.oauth`); all are
//! upstream bugs recorded in `docs/rust-port/upstream-go-bugs.md` that Rust
//! keeps data across. A case whose Go bytes yaml.v3 cannot read back
//! (`go_saved_faithful: false`) must instead be written as a file that loads
//! and reloads equal.

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

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    input: String,
    mutation: String,
    saved_yaml: String,
    go_saved_faithful: bool,
}

#[derive(Debug, Deserialize)]
struct LineDifference {
    side: String,
    #[serde(default)]
    cases: Vec<String>,
    #[serde(default)]
    agents: Vec<String>,
    keys: Vec<String>,
    #[serde(default)]
    values: Vec<String>,
    #[serde(default)]
    block: bool,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    declared_differences: Vec<String>,
    declared_line_differences: Vec<LineDifference>,
    fields: Vec<String>,
    dropped_by_save_to: Vec<String>,
    cases: Vec<Case>,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/config/rewrite.json");
    serde_json::from_slice(CONTENT).expect("CONFIG-WRITER fixture parses")
}

fn rewrite(case: &Case) -> Config {
    let mut config = Config::load_from_bytes(case.input.as_bytes())
        .unwrap_or_else(|error| panic!("{}: load: {error}", case.name));
    if let Some(agent) = case.mutation.strip_prefix("remove_agent:") {
        config.agents.remove(agent);
    } else {
        assert_eq!(case.mutation, "none", "{}: unknown mutation", case.name);
    }
    config
}

fn rust_bytes(case: &Case) -> String {
    String::from_utf8(rewrite(case).to_yaml_bytes().expect("Rust writer")).expect("utf-8")
}

/// Removes the named top-level blocks (the key line and everything indented
/// beneath it).
fn without_sections(yaml: &str, sections: &[String]) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in yaml.split_inclusive('\n') {
        let top_level = !line.starts_with([' ', '\t', '-']) && !line.trim().is_empty();
        if top_level {
            skipping = sections
                .iter()
                .any(|section| line.starts_with(&format!("{section}:")));
        }
        if !skipping {
            out.push_str(line);
        }
    }
    out
}

fn has_section(yaml: &str, section: &str) -> bool {
    yaml.lines()
        .any(|line| line.starts_with(&format!("{section}:")))
}

/// Removes the lines the declared differences of `side` allow for `case`.
fn without_lines(yaml: &str, fixture: &Fixture, case: &Case, side: &str) -> String {
    let applies = |difference: &&LineDifference| {
        difference.side == side
            && (difference.cases.is_empty() || difference.cases.contains(&case.name))
    };
    let differences: Vec<_> = fixture
        .declared_line_differences
        .iter()
        .filter(applies)
        .collect();
    let mut out = String::new();
    let mut skip_deeper_than: Option<usize> = None;
    let mut agent = String::new();
    for line in yaml.split_inclusive('\n') {
        let indent = line.len() - line.trim_start().len();
        if indent == 4 {
            agent = line.trim().trim_end_matches(':').to_owned();
        } else if indent == 0 {
            agent.clear();
        }
        if let Some(depth) = skip_deeper_than {
            if indent > depth {
                continue;
            }
            skip_deeper_than = None;
        }
        let trimmed = line.trim_end();
        let hit = differences.iter().find(|difference| {
            (difference.agents.is_empty() || difference.agents.contains(&agent))
                && difference.keys.iter().any(|key| {
                    trimmed.trim_start().starts_with(&format!("{key}:"))
                        && (difference.values.is_empty()
                            || difference
                                .values
                                .iter()
                                .any(|value| trimmed.ends_with(&format!(": {value}"))))
                })
        });
        if let Some(difference) = hit {
            assert!(
                !difference.reason.is_empty(),
                "a declared difference needs a reason"
            );
            if difference.block {
                skip_deeper_than = Some(indent);
            }
            continue;
        }
        out.push_str(line);
    }
    out
}

/// What the Rust writer must share with Go: the bytes minus the declared
/// sections and lines.
fn comparable(fixture: &Fixture, case: &Case, rust: &str) -> String {
    without_lines(
        &without_sections(rust, &fixture.declared_differences),
        fixture,
        case,
        "rust_adds",
    )
}

/// Go's bytes minus the lines Go writes and Rust deliberately omits.
fn go_comparable(fixture: &Fixture, case: &Case) -> String {
    without_lines(&case.saved_yaml, fixture, case, "go_only")
}

/// The contract: Rust bytes minus the declared differences are Go's bytes.
fn matches_go(fixture: &Fixture, case: &Case, rust: &str) -> bool {
    comparable(fixture, case, rust) == go_comparable(fixture, case)
}

#[test]
fn fixture_has_pinned_provenance_and_schema() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, fixture.oracle.commit_sha);
    assert_eq!(fixture.oracle.commit_sha.len(), 40);
    assert!(
        fixture
            .oracle
            .commit_sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    );
    assert_eq!(fixture.oracle.release, "unreleased");
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert!(
        fixture
            .oracle
            .source_files
            .iter()
            .any(|f| f == "internal/config/config_save.go")
    );
    assert_eq!(
        fixture.declared_differences,
        ["paymentPolicies", "security"]
    );
    assert!(fixture.cases.len() >= 30, "{} cases", fixture.cases.len());
    assert!(
        fixture
            .declared_line_differences
            .iter()
            .all(
                |difference| matches!(difference.side.as_str(), "rust_adds" | "go_only")
                    && !difference.reason.is_empty()
            )
    );
    assert_eq!(fixture.declared_line_differences.len(), 10);
}

/// The field-coverage probe: the generator proves that every yaml field of
/// Go's `Config` is set in some case and records which ones `SaveTo` does not
/// write back. Rust must not drop anything else.
#[test]
fn every_go_field_is_exercised_and_only_the_dropped_ones_are_lost() {
    let fixture = fixture();
    assert!(
        fixture.fields.len() > 100,
        "{} fields",
        fixture.fields.len()
    );
    for dropped in &fixture.dropped_by_save_to {
        assert!(fixture.fields.contains(dropped), "{dropped}");
    }
    let key_of = |path: &str| path.rsplit(['.', ']']).next().unwrap_or(path).to_owned();
    let kept: Vec<_> = fixture
        .fields
        .iter()
        .filter(|path| !fixture.dropped_by_save_to.contains(path))
        .collect();
    assert!(kept.len() > 90, "{} kept fields", kept.len());
    let probe = fixture
        .cases
        .iter()
        .find(|case| case.name == "all_fields_non_zero")
        .expect("the field-coverage case");
    let rust = rust_bytes(probe);
    let rust_keys: std::collections::BTreeSet<_> = rust
        .lines()
        .filter_map(|line| line.trim_start().trim_start_matches("- ").split_once(':'))
        .map(|(key, _)| key.trim().to_owned())
        .collect();
    let missing: Vec<_> = kept
        .iter()
        .map(|path| (path, key_of(path)))
        .filter(|(_, key)| !rust_keys.contains(key))
        .collect();
    assert!(
        missing.is_empty(),
        "the Rust writer drops fields Go keeps: {missing:?}\n{rust}"
    );
    // The declared line differences: Rust keeps what Go drops (entry 10).
    for kept in [
        "    perplexity:\n",
        "        api_key: k\n",
        "        allow_private: true\n",
        "    approval_required: true\n",
        "    author: Ann\n",
        "    email: ann@example.test\n",
        "    printByDefault: true\n",
    ] {
        assert!(rust.contains(kept), "{kept:?} survives:\n{rust}");
    }
    let oauth = fixture
        .cases
        .iter()
        .find(|case| case.name == "mcp_oauth")
        .expect("mcp_oauth case");
    assert!(
        rust_bytes(oauth).contains("    oauth:\n"),
        "mcp.oauth survives"
    );
}

#[test]
fn rewrite_bytes_match_go_save_to() {
    let fixture = fixture();
    let mut failures = Vec::new();
    for case in fixture.cases.iter().filter(|case| case.go_saved_faithful) {
        let rust = rust_bytes(case);
        if !matches_go(&fixture, case, &rust) {
            failures.push(format!(
                "{}:\n--- go\n{}--- rust (declared sections removed)\n{}",
                case.name,
                go_comparable(&fixture, case),
                comparable(&fixture, case, &rust)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Go loses these two sections on rewrite; Rust must not.
#[test]
fn declared_sections_survive_a_rewrite_that_go_loses() {
    let fixture = fixture();
    let mut exercised = [0usize; 2];
    for case in &fixture.cases {
        let rust = rust_bytes(case);
        for (index, section) in fixture.declared_differences.iter().enumerate() {
            assert!(
                !has_section(&case.saved_yaml, section),
                "{}: the Go oracle kept {section}; the declared difference is stale",
                case.name
            );
            let written = has_section(&case.input, section);
            assert_eq!(
                has_section(&rust, section),
                written,
                "{}: {section}",
                case.name
            );
            if written {
                exercised[index] += 1;
                // The kept section reloads to what the operator wrote.
                let reloaded = Config::load_from_bytes(rust.as_bytes()).expect("reload");
                let original = rewrite(case);
                assert_eq!(reloaded.payment_policies, original.payment_policies);
                assert_eq!(reloaded.security, original.security);
            }
        }
    }
    assert!(exercised.iter().all(|count| *count >= 2), "{exercised:?}");
}

/// A rewrite followed by a load reproduces every section the writer owns.
#[test]
fn rewritten_files_reload_to_the_same_sections() {
    let fixture = fixture();
    for case in &fixture.cases {
        let original = rewrite(case);
        let rust = rust_bytes(case);
        let reloaded = Config::load_from_bytes(rust.as_bytes())
            .unwrap_or_else(|error| panic!("{}: reload: {error}\n{rust}", case.name));
        // Go omits a zero `maxSizeMb` (`omitempty`), so a zero size reloads as
        // the 100 MiB default: the byte contract above pins that, and the
        // round trip follows it.
        let mut expected_audit = original.audit;
        if let Some(audit) = expected_audit.as_mut()
            && audit.max_file_size == 0
        {
            audit.max_file_size = 100 * 1024 * 1024;
        }
        assert_eq!(reloaded.audit, expected_audit, "{}: audit", case.name);
        // Likewise a blank logging value is omitted (`omitempty`) and reloads
        // as its default.
        let mut expected_logging = original.logging.clone();
        if let Some(logging) = expected_logging.as_mut() {
            if logging.level.is_empty() {
                logging.level = "warn".into();
            }
            if logging.format.is_empty() {
                logging.format = "text".into();
            }
        }
        assert_eq!(reloaded.logging, expected_logging, "{}: logging", case.name);
        assert_eq!(reloaded.mcp, original.mcp, "{}: mcp", case.name);
        // Go's SaveTo never writes these three vault fields (upstream-go-bugs.md 4).
        let mut expected_vault = original.vault.clone();
        if let Some(vault) = expected_vault.as_mut() {
            vault.listing_cache_ttl = Default::default();
            vault.manifest_generation = 0;
            vault.sync = None;
            // Go prints a timestamp as RFC3339Nano, so Go's own file holds the
            // normalised form of whatever shape the operator wrote.
            if case.go_saved_faithful {
                vault.last_rotated = Config::load_from_bytes(case.saved_yaml.as_bytes())
                    .expect("Go's bytes load")
                    .vault
                    .and_then(|go| go.last_rotated);
            }
        }
        assert_eq!(reloaded.vault, expected_vault, "{}: vault", case.name);
        assert_eq!(reloaded.git, original.git, "{}: git", case.name);
        assert_eq!(reloaded.update, original.update, "{}: update", case.name);
        assert_eq!(
            reloaded.clipboard, original.clipboard,
            "{}: clipboard",
            case.name
        );
        assert_eq!(reloaded.vault_dir, original.vault_dir, "{}", case.name);
        assert_eq!(
            reloaded.default_agent, original.default_agent,
            "{}",
            case.name
        );
        assert_eq!(
            reloaded.session_timeout, original.session_timeout,
            "{}",
            case.name
        );
        assert_eq!(
            reloaded.session_max_lifetime, original.session_max_lifetime,
            "{}",
            case.name
        );
        assert_eq!(reloaded.profiles, original.profiles, "{}", case.name);
        assert_eq!(reloaded.agents, original.agents, "{}: agents", case.name);
        assert_eq!(
            reloaded.security, original.security,
            "{}: security",
            case.name
        );
        assert_eq!(
            reloaded.scan_patterns, original.scan_patterns,
            "{}: scan_patterns",
            case.name
        );
        assert_eq!(
            reloaded.payment_policies, original.payment_policies,
            "{}: paymentPolicies",
            case.name
        );
        for (name, agent) in &original.agents {
            let again = &reloaded.agents[name];
            assert_eq!(
                again.payment_policy, agent.payment_policy,
                "{}: {name}",
                case.name
            );
            assert_eq!(
                again.skill_version, agent.skill_version,
                "{}: {name}",
                case.name
            );
            assert_eq!(
                again.allowed_tools, agent.allowed_tools,
                "{}: {name}",
                case.name
            );
            assert_eq!(
                again.dynamic_providers, agent.dynamic_providers,
                "{}: {name}",
                case.name
            );
            assert_eq!(
                again.per_tool_redact_fields, agent.per_tool_redact_fields,
                "{}: {name}",
                case.name
            );
        }
    }
}

/// yaml.v3 writes a value that starts with a line break (or, inside a
/// sequence item, with a space) as a literal block that no parser reads back
/// or that loses the break; Rust must not copy those bytes.
#[test]
fn go_bytes_that_do_not_round_trip_are_written_double_quoted() {
    let fixture = fixture();
    let unfaithful: Vec<_> = fixture
        .cases
        .iter()
        .filter(|case| !case.go_saved_faithful)
        .collect();
    let names: Vec<_> = unfaithful.iter().map(|case| case.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "leading_break_list_item",
            "leading_break_scan_pattern",
            "leading_break_map_value",
            "leading_break_map_key"
        ]
    );
    for case in unfaithful {
        let original = rewrite(case);
        // Go's bytes are broken: they do not load, or load as another config.
        let go = Config::load_from_bytes(case.saved_yaml.as_bytes());
        assert!(
            go.as_ref().map_or(true, |go| {
                go.agents != original.agents
                    || go.scan_patterns != original.scan_patterns
                    || go.vault != original.vault
            }),
            "{}: Go's bytes round-trip, the case is stale\n{}",
            case.name,
            case.saved_yaml
        );
        let rust = rust_bytes(case);
        assert!(rust.contains("\\n"), "{}: {rust}", case.name);
        let reloaded = Config::load_from_bytes(rust.as_bytes()).expect("Rust output reloads");
        assert_eq!(reloaded.scan_patterns, original.scan_patterns);
        assert_eq!(reloaded.agents, original.agents);
        assert_eq!(reloaded.vault, original.vault);
    }
}

const TIERS: [&str; 3] = ["read-only", "standard", "admin"];
const PRESET_BOOLS: [&str; 9] = [
    "canWrite",
    "canRunCommands",
    "canManageConfig",
    "canUseClipboard",
    "canUseAutotype",
    "canReadValues",
    "exposeValueTools",
    "autoUnseal",
    "requireApproval",
];

/// Every tier crossed with every preset-backed field (and the other fields a
/// preset or a builtin default can refill) written explicitly as an
/// empty / false / zero / null value, plus the all-explicit-empty profile.
fn effective_matrix() -> Vec<(String, String)> {
    let mut cases = Vec::new();
    for tier in TIERS {
        let mut push = |label: String, body: String| {
            cases.push((
                format!("{tier}: {label}"),
                format!("vaultDir: /fixture/vault\nagents:\n  bot:\n    tier: {tier}\n{body}  other:\n    canWrite: true\n"),
            ));
        };
        for key in PRESET_BOOLS {
            for value in ["true", "false", "null"] {
                push(format!("{key}={value}"), format!("    {key}: {value}\n"));
            }
        }
        for (key, value) in [
            ("allowedExecutables", "[]"),
            ("allowedExecutables", "null"),
            ("allowedExecutables", "[git]"),
            ("approvalMode", "null"),
            ("approvalMode", "''"),
            ("approvalMode", "none"),
            ("approvalMode", "deny"),
            ("approvalMode", "prompt"),
            ("approvalTimeout", "0s"),
            ("approvalTimeout", "90s"),
            ("max_reads_per_hour", "0"),
            ("max_reads_per_day", "0"),
            ("max_secrets_in_session", "0"),
            ("allowedPaths", "[]"),
            ("allowed_tools", "[]"),
            ("allowedEnvVars", "[]"),
            ("redactFields", "[]"),
            ("promptInjectionMode", "''"),
            ("skillPath", "''"),
            ("skillVersion", "''"),
            ("exposePaymentValues", "false"),
        ] {
            push(format!("{key}={value}"), format!("    {key}: {value}\n"));
        }
        let all_empty: String = PRESET_BOOLS
            .iter()
            .map(|key| format!("    {key}: false\n"))
            .chain([
                "    approvalMode: null\n".to_owned(),
                "    allowedExecutables: []\n".to_owned(),
            ])
            .collect();
        push("every preset-backed field explicit".to_owned(), all_empty);
    }
    cases
}

fn reloaded_bot(yaml: &str) -> symvault_core::config::AgentProfile {
    Config::load_from_bytes(yaml.as_bytes())
        .unwrap_or_else(|error| panic!("load: {error}\n{yaml}"))
        .agents
        .remove("bot")
        .expect("bot profile")
}

/// CONFIG-WRITER fix round 3 (HIGH): a rewrite (`agent uninstall other`) must
/// leave the *effective* profile of every other agent untouched. Go's
/// omitempty writer drops an explicit empty `allowedExecutables`, and the next
/// load re-applies the tier preset: `tier: standard` gains curl, git,
/// terraform, npm, node, python, python3, docker and kubectl.
#[test]
fn a_rewrite_never_changes_the_effective_profile() {
    let mut failures = Vec::new();
    for (label, input) in effective_matrix() {
        let mut config = Config::load_from_bytes(input.as_bytes()).expect("load");
        let before = config.agents.get("bot").cloned().expect("bot");
        config.agents.remove("other");
        let rewritten = String::from_utf8(config.to_yaml_bytes().expect("write")).expect("utf-8");
        let after = reloaded_bot(&rewritten);
        if before != after {
            failures.push(format!("{label}:\n  before {before:?}\n  after  {after:?}"));
        }
        // And the rewrite is a fixed point.
        let again = String::from_utf8(
            Config::load_from_bytes(rewritten.as_bytes())
                .expect("reload")
                .to_yaml_bytes()
                .expect("write"),
        )
        .expect("utf-8");
        assert_eq!(again, rewritten, "{label}: second rewrite differs");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The control for the test above: without the presence writes the same
/// detector fires, and the standard tier really does gain nine executables.
#[test]
fn negative_control_dropping_the_presence_writes_widens_the_profile() {
    let input = "vaultDir: /fixture/vault\nagents:\n  bot:\n    tier: standard\n    allowedExecutables: []\n    approvalMode: null\n  other:\n    canWrite: true\n";
    let mut config = Config::load_from_bytes(input.as_bytes()).expect("load");
    let before = config.agents["bot"].clone();
    assert!(before.allowed_executables.is_empty());
    assert_eq!(before.approval_mode, None);
    config.agents.remove("other");
    let written = String::from_utf8(config.to_yaml_bytes().expect("write")).expect("utf-8");
    assert!(
        written.contains("        allowedExecutables: []\n"),
        "{written}"
    );
    assert!(
        written.contains("        approvalMode: null\n"),
        "{written}"
    );
    assert_eq!(reloaded_bot(&written), before);

    let widened = written.replace("        allowedExecutables: []\n", "");
    assert_ne!(widened, written);
    let after = reloaded_bot(&widened);
    assert_ne!(after, before, "the detector must see the widening");
    assert_eq!(
        after.allowed_executables,
        [
            "curl",
            "git",
            "terraform",
            "npm",
            "node",
            "python",
            "python3",
            "docker",
            "kubectl"
        ]
    );
    let refilled = written.replace("        approvalMode: null\n", "");
    assert_ne!(reloaded_bot(&refilled), before);
}

fn case<'a>(fixture: &'a Fixture, name: &str) -> &'a Case {
    fixture
        .cases
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

/// Each mutation of a correct writer output must be rejected by the contract.
#[test]
fn negative_controls_are_rejected() {
    let fixture = fixture();

    // The review's data-loss finding: the agent's paymentPolicy line is gone.
    let pp = case(&fixture, "payment_policy_agent");
    let rust = rust_bytes(pp);
    assert!(matches_go(&fixture, pp, &rust), "control baseline");
    let dropped: String = rust
        .split_inclusive('\n')
        .filter(|line| !line.trim_start().starts_with("paymentPolicy:"))
        .collect();
    assert_ne!(dropped, rust, "the control must change the bytes");
    assert!(!matches_go(&fixture, pp, &dropped), "dropped paymentPolicy");

    // Go order: skillVersion before exposePaymentValues, not after.
    let swapped = rust.replace(
        "        skillVersion: 1.2.3\n        exposePaymentValues: true\n",
        "        exposePaymentValues: true\n        skillVersion: 1.2.3\n",
    );
    assert_ne!(swapped, rust, "the control must change the bytes");
    assert!(!matches_go(&fixture, pp, &swapped), "swapped field order");

    // Dropping skillVersion, or a whole audit section, is also a mismatch.
    let no_version: String = rust
        .split_inclusive('\n')
        .filter(|line| !line.trim_start().starts_with("skillVersion:"))
        .collect();
    assert!(
        !matches_go(&fixture, pp, &no_version),
        "dropped skillVersion"
    );
    let all = case(&fixture, "all_sections");
    let rust = rust_bytes(all);
    assert!(matches_go(&fixture, all, &rust), "control baseline");
    let no_audit = rust.replace(
        "audit:\n    maxSizeMb: 50\n    maxBackups: 3\n    maxAgeDays: 7\n",
        "",
    );
    assert_ne!(no_audit, rust);
    assert!(!matches_go(&fixture, all, &no_audit), "dropped audit");

    // The multi-line finding: a block scalar whose continuation lines are
    // indented two columns (what the old writer left behind) is not Go's
    // bytes, and the file no longer loads as what the operator wrote.
    let multiline = case(&fixture, "multiline_scan_description_remove_agent_other");
    let rust = rust_bytes(multiline);
    assert!(matches_go(&fixture, multiline, &rust), "control baseline");
    assert!(
        rust.contains("      description: |\n        Matches AWS keys.\n        Second line.\n")
    );
    let broken = rust.replace(
        "      description: |\n        Matches AWS keys.\n        Second line.\n",
        "      description: |\n  Matches AWS keys.\n  Second line.\n",
    );
    assert!(
        !matches_go(&fixture, multiline, &broken),
        "wrong block indent"
    );
    assert!(
        Config::load_from_bytes(broken.as_bytes()).map_or(true, |loaded| loaded.scan_patterns
            != rewrite(multiline).scan_patterns),
        "the broken file must not reload equal"
    );

    // The MCP findings: a dropped approval mTLS key or trusted-proxy entry,
    // and a wrong field order, are mismatches.
    let mcp = case(&fixture, "mcp_full_fields");
    let rust = rust_bytes(mcp);
    assert!(matches_go(&fixture, mcp, &rust), "control baseline");
    for line in [
        "    approval_tls_cert_file: certs/approval-client.pem\n",
        "    approval_tls_key_file: certs/approval-client.key\n",
        "    trusted_proxy_ips:\n        - 10.0.0.1\n        - 192.168.0.0/24\n",
        "    otlp_endpoint: http://otel:4318\n",
    ] {
        assert!(rust.contains(line), "{line}");
        assert!(
            !matches_go(&fixture, mcp, &rust.replace(line, "")),
            "dropped {line}"
        );
    }
    let stdio = case(&fixture, "mcp_stdio_http_token_file");
    let rust = rust_bytes(stdio);
    assert!(matches_go(&fixture, stdio, &rust), "control baseline");
    let reordered = rust.replace(
        "    httpTokenFile: /tmp/mcp-token\n",
        "    stdio: true\n    httpTokenFile: /tmp/mcp-token\n",
    );
    assert!(
        !matches_go(&fixture, stdio, &reordered),
        "stdio before httpTokenFile"
    );
    // Durations are Duration.String(): 90s is 1m30s.
    let durations = case(&fixture, "durations_go_string");
    let rust = rust_bytes(durations);
    assert!(rust.contains("sessionTimeout: 1m30s\n"));
    assert!(!matches_go(
        &fixture,
        durations,
        &rust.replace("1m30s", "90s")
    ));

    // Dropping a declared section is NOT a mismatch for the byte comparison
    // (that is the declared difference) but IS caught by the preservation
    // check, which asserts the section is present whenever the input has it.
    let pol = case(&fixture, "payment_policies_only");
    let rust = rust_bytes(pol);
    assert!(has_section(&rust, "paymentPolicies"));
    let lost = without_sections(&rust, &["paymentPolicies".to_owned()]);
    assert!(matches_go(&fixture, pol, &lost));
    assert!(!has_section(&lost, "paymentPolicies"));
}
