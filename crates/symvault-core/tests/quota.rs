#![deny(unsafe_code)]

use serde::Deserialize;
use symvault_core::quota::{
    RateLimitEvent, RateLimitLimits, RateLimitResult, RateLimitState, transition_rate_limit,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    cases: Vec<QuotaCase>,
}

#[derive(Debug, Deserialize)]
struct QuotaCase {
    name: String,
    initial_state: RateLimitState,
    limits: RateLimitLimits,
    transitions: Vec<QuotaTransition>,
}

#[derive(Debug, Deserialize)]
struct QuotaTransition {
    event: QuotaEvent,
    state: RateLimitState,
    result: RateLimitResult,
}

#[derive(Debug, Deserialize)]
struct QuotaEvent {
    kind: RateLimitEvent,
    at_unix_nanos: i64,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/core/quota-contract.json");
    serde_json::from_slice(CONTENT).expect("decode Go-generated quota fixture")
}

fn assert_state(actual: RateLimitState, expected: RateLimitState, case: &str, step: usize) {
    const EPSILON: f64 = 1e-12;
    assert!(
        (actual.tokens - expected.tokens).abs() <= EPSILON,
        "{case} step {step}: tokens {actual:?} != {expected:?}"
    );
    assert!(
        (actual.capacity - expected.capacity).abs() <= EPSILON,
        "{case} step {step}: capacity {actual:?} != {expected:?}"
    );
    assert!(
        (actual.refill_rate - expected.refill_rate).abs() <= EPSILON,
        "{case} step {step}: refill rate {actual:?} != {expected:?}"
    );
    assert_eq!(
        actual.last_refill_unix_nanos, expected.last_refill_unix_nanos,
        "{case} step {step}: last refill"
    );
    assert_eq!(
        actual.daily_count, expected.daily_count,
        "{case} step {step}: daily count"
    );
    assert_eq!(
        actual.daily_window_start_unix_nanos, expected.daily_window_start_unix_nanos,
        "{case} step {step}: daily window"
    );
    assert_eq!(
        actual.max_per_day, expected.max_per_day,
        "{case} step {step}: max per day"
    );
}

#[test]
fn generated_go_vectors_match_every_rust_transition() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.cases.len(), 5);

    for case in fixture.cases {
        let mut state = case.initial_state;
        for (step, expected) in case.transitions.iter().enumerate() {
            let (actual_state, actual_result) = transition_rate_limit(
                state,
                case.limits,
                expected.event.at_unix_nanos,
                expected.event.kind,
            );
            assert_state(actual_state, expected.state, &case.name, step);
            assert_eq!(
                actual_result, expected.result,
                "{} step {step}: result",
                case.name
            );
            state = actual_state;
        }
    }
}

#[test]
fn fixture_includes_each_boundary_family() {
    let fixture = fixture();
    let names: Vec<&str> = fixture
        .cases
        .iter()
        .map(|case| case.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "refill_fractional",
            "daily_rollover",
            "capacity_clamp",
            "rejection",
            "boundaries",
        ]
    );
}
