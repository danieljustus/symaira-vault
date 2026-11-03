//! PLATFORM-002 / ADR 0034 item 29: replays `testdata/port/mcp/anomaly-detector.json`,
//! recorded by `scripts/rust-port/cmd/anomalygen` from the real Go
//! `internal/anomaly` detector at the ordered reference `mcp-anomaly-ordered-v1`
//! (`24acdb08`), against the Rust detector with explicit event timestamps.
//! No Go and no wall clock are involved.

use serde::Deserialize;
use std::time::Duration;
use symvault_mcp::anomaly::{AnomalyAlert, AnomalyDetector, DetectorConfig, ToolCallEvent};
use time::{OffsetDateTime, UtcOffset};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    dispatch: Dispatch,
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    contract: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
}

#[derive(Debug, Deserialize)]
struct Dispatch {
    audit_action_prefix: String,
    audit_path: String,
    audit_ok: bool,
    audit_context_background: bool,
    cache_invalidated_after_audit: bool,
    cache_invalidated_for_any_alert: bool,
    notify_min_severity: String,
    skips_empty_agent: bool,
    observes_failed_calls: bool,
    field_length_tools: Vec<String>,
    warn_message: String,
    warn_attributes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    config: Config,
    events: Vec<Entry>,
}

#[derive(Debug, Default, Deserialize)]
struct Config {
    window_size: Option<usize>,
    sweep_threshold: Option<usize>,
    sweep_window_seconds: Option<u64>,
    rate_limit: Option<usize>,
    rate_window_seconds: Option<u64>,
    off_hours_start: Option<u8>,
    off_hours_end: Option<u8>,
    tool_chain_window_seconds: Option<u64>,
    tool_chain_field_threshold: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    event: EventIn,
    hooks: Vec<AlertOut>,
    returned: Option<AlertOut>,
    window_len: usize,
}

#[derive(Debug, Deserialize)]
struct EventIn {
    unix_nanos: i128,
    utc_offset_seconds: i32,
    agent: String,
    tool: String,
    path: String,
    ok: bool,
    #[serde(default)]
    is_canary: bool,
    request_id: String,
    #[serde(default)]
    field_length: usize,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct AlertOut {
    #[serde(rename = "type")]
    kind: String,
    severity: String,
    description: String,
    agent: String,
    path: String,
    tool: String,
    request_id: String,
    unix_nanos: i128,
}

impl From<&AnomalyAlert> for AlertOut {
    fn from(alert: &AnomalyAlert) -> Self {
        Self {
            kind: alert.alert_type.as_str().into(),
            severity: alert.severity.as_str().into(),
            description: alert.description.clone(),
            agent: alert.agent.clone(),
            path: alert.path.clone(),
            tool: alert.tool.clone(),
            request_id: alert.request_id.clone(),
            unix_nanos: alert.timestamp.unix_timestamp_nanos(),
        }
    }
}

fn load() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/anomaly-detector.json"
    ))
    .expect("decode actual Go anomaly fixture")
}

fn detector_config(config: &Config) -> DetectorConfig {
    let mut out = DetectorConfig::default();
    if let Some(value) = config.window_size {
        out.max_events = value;
    }
    if let Some(value) = config.sweep_threshold {
        out.sweep_threshold = value;
    }
    if let Some(value) = config.sweep_window_seconds {
        out.sweep_window = Duration::from_secs(value);
    }
    if let Some(value) = config.rate_limit {
        out.rate_limit = value;
    }
    if let Some(value) = config.rate_window_seconds {
        out.rate_window = Duration::from_secs(value);
    }
    if let Some(value) = config.off_hours_start {
        out.off_hours_start = value;
    }
    if let Some(value) = config.off_hours_end {
        out.off_hours_end = value;
    }
    if let Some(value) = config.tool_chain_window_seconds {
        out.tool_chain_window = Duration::from_secs(value);
    }
    if let Some(value) = config.tool_chain_field_threshold {
        out.tool_chain_threshold = value;
    }
    out
}

/// Replays every scenario and returns one line per divergence from Go.
fn replay(fixture: &Fixture, tweak: impl Fn(&mut DetectorConfig)) -> (usize, Vec<String>) {
    let mut divergences = Vec::new();
    let mut checked = 0;
    for scenario in &fixture.scenarios {
        let mut config = detector_config(&scenario.config);
        tweak(&mut config);
        let mut detector = AnomalyDetector::new(config);
        for (index, entry) in scenario.events.iter().enumerate() {
            let e = &entry.event;
            let timestamp = OffsetDateTime::from_unix_timestamp_nanos(e.unix_nanos)
                .expect("event instant")
                .to_offset(UtcOffset::from_whole_seconds(e.utc_offset_seconds).expect("offset"));
            let alerts = detector.check(ToolCallEvent {
                timestamp,
                agent: e.agent.clone(),
                tool: e.tool.clone(),
                path: e.path.clone(),
                duration: Duration::ZERO,
                ok: e.ok,
                is_canary: e.is_canary,
                request_id: e.request_id.clone(),
                field_length: e.field_length,
            });
            let hooks: Vec<AlertOut> = alerts.iter().map(AlertOut::from).collect();
            let returned = alerts.first().map(AlertOut::from);
            checked += 1;
            let label = format!("{}[{index}]", scenario.name);
            if hooks != entry.hooks {
                divergences.push(format!("{label} hooks: {hooks:?} != {:?}", entry.hooks));
            }
            if returned != entry.returned {
                divergences.push(format!(
                    "{label} returned: {returned:?} != {:?}",
                    entry.returned
                ));
            }
            if detector.window_len() != entry.window_len {
                divergences.push(format!(
                    "{label} window: {} != {}",
                    detector.window_len(),
                    entry.window_len
                ));
            }
        }
    }
    (checked, divergences)
}

#[test]
fn rust_detector_matches_every_recorded_go_decision() {
    let fixture = load();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.contract, "mcp-anomaly-ordered-v1");
    assert_eq!(
        fixture.oracle.commit,
        "24acdb08fcc7021262717aa803d72eb8d151c66a"
    );
    assert_eq!(fixture.oracle.commit_sha, fixture.oracle.commit);
    assert_eq!(
        fixture.oracle.source_files,
        [
            "internal/anomaly/detector.go",
            "internal/anomaly/rules.go",
            "internal/mcp/server/server_dispatch.go"
        ]
    );
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    assert_eq!(fixture.scenarios.len(), 14);

    let (checked, divergences) = replay(&fixture, |_| {});
    assert_eq!(checked, 104, "every recorded event must execute");
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));

    // Every rule fired somewhere, at every severity, with and without a path.
    let kinds: std::collections::BTreeSet<_> = fixture
        .scenarios
        .iter()
        .flat_map(|s| &s.events)
        .flat_map(|e| &e.hooks)
        .map(|a| a.kind.as_str())
        .collect();
    assert_eq!(
        kinds.into_iter().collect::<Vec<_>>(),
        [
            "canary_access",
            "off_hours",
            "rate_anomaly",
            "sweep",
            "tool_chain"
        ]
    );
}

/// Negative controls: the comparison is not vacuous. Each altered detector must
/// diverge from the recorded Go behavior.
#[test]
fn altered_detectors_diverge_from_the_recorded_go_behavior() {
    let fixture = load();
    type Tweak = fn(&mut DetectorConfig);
    let controls: [(&str, Tweak); 6] = [
        ("off-hours end 7", |c| c.off_hours_end = 7),
        ("default rate limit 31", |c| c.rate_limit = 31),
        ("default sweep threshold 11", |c| c.sweep_threshold = 11),
        ("tool-chain threshold 501", |c| c.tool_chain_threshold = 501),
        ("tool-chain window 29 s", |c| {
            c.tool_chain_window = Duration::from_secs(29)
        }),
        ("window of one event", |c| c.max_events = 1),
    ];
    for (name, tweak) in controls {
        let (_, divergences) = replay(&fixture, tweak);
        assert!(!divergences.is_empty(), "control {name:?} matched Go");
    }
}

/// The source-bound dispatch facts Rust's runtime implements (asserted
/// behaviorally in `anomaly_dispatch.rs`).
#[test]
fn recorded_dispatch_facts_are_the_ones_the_rust_runtime_implements() {
    let facts = load().dispatch;
    assert_eq!(facts.audit_action_prefix, "anomaly_");
    assert_eq!(facts.audit_path, "alert.Path");
    assert!(!facts.audit_ok, "anomaly rows are failure rows");
    assert!(
        facts.audit_context_background,
        "anomaly rows carry the session id only (no request or token id)"
    );
    assert!(facts.cache_invalidated_after_audit);
    assert!(facts.cache_invalidated_for_any_alert);
    assert_eq!(facts.notify_min_severity, "SeverityHigh");
    assert!(facts.skips_empty_agent);
    assert!(facts.observes_failed_calls);
    assert_eq!(facts.field_length_tools, ["get_entry", "get_entry_value"]);
    assert_eq!(facts.warn_message, "anomaly detected");
    assert_eq!(
        facts.warn_attributes,
        [
            "type",
            "severity",
            "agent",
            "path",
            "request_id",
            "description"
        ]
    );
}
