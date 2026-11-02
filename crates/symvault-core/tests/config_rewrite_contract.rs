//! CONFIG-WRITER: the bytes a config rewrite leaves behind, against Go's
//! `Config.SaveTo`.
//!
//! Every case is a real Go `Load` -> mutation -> `SaveTo` recorded by
//! `scripts/rust-port/cmd/configrewritegen`. The Rust writer must produce the
//! same bytes for everything Go writes. Exactly two top-level sections are the
//! declared difference: Go drops `paymentPolicies` and `security` on rewrite
//! (an upstream bug, `docs/rust-port/upstream-go-bugs.md`), Rust keeps them.

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
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    declared_differences: Vec<String>,
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

/// The contract: Rust bytes minus the declared sections are Go's bytes.
fn matches_go(fixture: &Fixture, case: &Case, rust: &str) -> bool {
    without_sections(rust, &fixture.declared_differences) == case.saved_yaml
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
    assert!(fixture.cases.len() >= 20, "{} cases", fixture.cases.len());
}

#[test]
fn rewrite_bytes_match_go_save_to() {
    let fixture = fixture();
    let mut failures = Vec::new();
    for case in &fixture.cases {
        let rust = rust_bytes(case);
        if !matches_go(&fixture, case, &rust) {
            failures.push(format!(
                "{}:\n--- go\n{}--- rust (declared sections removed)\n{}",
                case.name,
                case.saved_yaml,
                without_sections(&rust, &fixture.declared_differences)
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
