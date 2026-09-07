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

const DAY_NANOS: i64 = 86_400_000_000_000;
const HOUR_NANOS: i64 = 3_600_000_000_000;
const BASE_TIME: i64 = 1_700_000_000_000_000_000;
const EPSILON: f64 = 1e-12;

fn assert_quota_invariants(state: RateLimitState) {
    assert!(
        state.tokens.is_finite(),
        "tokens must remain finite: {state:?}"
    );
    assert!(
        state.capacity.is_finite() && state.capacity >= 0.0,
        "capacity must be finite and non-negative: {state:?}"
    );
    assert!(
        state.tokens >= -EPSILON,
        "tokens must remain non-negative: {state:?}"
    );
    assert!(
        state.tokens <= state.capacity + EPSILON,
        "tokens must remain capped: {state:?}"
    );
    assert!(
        state.refill_rate.is_finite(),
        "refill rate must be finite: {state:?}"
    );
    assert!(
        state.daily_count >= 0,
        "daily count must be non-negative: {state:?}"
    );
}

#[test]
fn bounded_generated_transitions_preserve_quota_properties() {
    let capacities = [0_u32, 1, 2];
    let refill_rates = [0.0, 1.0 / 3_600.0, 10.0];
    let timestamps = [
        BASE_TIME - 1,
        BASE_TIME,
        BASE_TIME + DAY_NANOS - 1,
        BASE_TIME + DAY_NANOS,
    ];
    let timestamp_pairs = [
        (BASE_TIME, BASE_TIME),
        (BASE_TIME, BASE_TIME + DAY_NANOS),
        (BASE_TIME + DAY_NANOS, BASE_TIME),
        (BASE_TIME + DAY_NANOS, BASE_TIME + DAY_NANOS),
    ];

    let events = [RateLimitEvent::SetLimits, RateLimitEvent::Allow];

    for capacity in capacities {
        for token_step in 0..=capacity * 2 {
            let tokens = f64::from(token_step) / 2.0;
            for refill_rate in refill_rates {
                for (last_refill, daily_window_start) in timestamp_pairs {
                    for daily_count in 0..=3 {
                        for max_per_day in 0..=3 {
                            let state = RateLimitState {
                                tokens,
                                capacity: f64::from(capacity),
                                refill_rate,
                                last_refill_unix_nanos: last_refill,
                                daily_count,
                                daily_window_start_unix_nanos: daily_window_start,
                                max_per_day,
                            };
                            for max_per_hour in capacities {
                                let limits = RateLimitLimits {
                                    max_per_hour: max_per_hour as i32,
                                    max_per_day,
                                };
                                for now in timestamps {
                                    for event in events {
                                        let (next, result) =
                                            transition_rate_limit(state, limits, now, event);
                                        let (repeat, repeat_result) =
                                            transition_rate_limit(state, limits, now, event);

                                        assert_eq!(
                                            (next, result),
                                            (repeat, repeat_result),
                                            "transition is not deterministic: state={state:?}, limits={limits:?}, now={now}, event={event:?}"
                                        );
                                        assert_quota_invariants(next);

                                        if event == RateLimitEvent::SetLimits {
                                            assert_eq!(next.daily_count, 0);
                                            assert_eq!(next.daily_window_start_unix_nanos, now);
                                            continue;
                                        }

                                        let rolled_over = max_per_day > 0
                                            && now.saturating_sub(daily_window_start) >= DAY_NANOS;
                                        if rolled_over {
                                            assert!(
                                                next.daily_count == 0 || next.daily_count == 1,
                                                "rollover may reset or consume once: before={state:?}, after={next:?}"
                                            );
                                        } else if max_per_day == 0 {
                                            assert_eq!(next.daily_count, daily_count);
                                        } else {
                                            assert!(
                                                next.daily_count == daily_count
                                                    || next.daily_count == daily_count + 1,
                                                "daily count must be monotonic except rollover: before={state:?}, after={next:?}"
                                            );
                                        }

                                        if !result.allowed {
                                            assert!(
                                                next.tokens + EPSILON >= state.tokens,
                                                "rejection must not consume tokens: before={state:?}, after={next:?}"
                                            );
                                            let (again, again_result) = transition_rate_limit(
                                                next,
                                                limits,
                                                now,
                                                RateLimitEvent::Allow,
                                            );
                                            assert_eq!(
                                                again, next,
                                                "repeated rejection consumed state: {next:?} -> {again:?}"
                                            );
                                            assert_eq!(again_result, result);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn boundary_arithmetic_observes_exact_refill_and_daily_rollover() {
    let limits = RateLimitLimits {
        max_per_hour: 1,
        max_per_day: 1,
    };
    let (state, result) = transition_rate_limit(
        RateLimitState::default(),
        limits,
        BASE_TIME,
        RateLimitEvent::SetLimits,
    );
    assert!(!result.allowed);

    let (state, result) = transition_rate_limit(state, limits, BASE_TIME, RateLimitEvent::Allow);
    assert!(result.allowed);
    assert_eq!(state.tokens, 0.0);
    assert_eq!(state.daily_count, 1);

    let (before_day, result) = transition_rate_limit(
        state,
        limits,
        BASE_TIME + DAY_NANOS - 1,
        RateLimitEvent::Allow,
    );
    assert!(!result.allowed);
    assert_eq!(before_day.daily_count, 1);
    assert_eq!(before_day.daily_window_start_unix_nanos, BASE_TIME);
    assert_eq!(before_day.last_refill_unix_nanos, BASE_TIME + DAY_NANOS - 1);

    let (after_day, result) =
        transition_rate_limit(state, limits, BASE_TIME + DAY_NANOS, RateLimitEvent::Allow);
    assert!(result.allowed);
    assert_eq!(after_day.daily_count, 1);
    assert_eq!(
        after_day.daily_window_start_unix_nanos,
        BASE_TIME + DAY_NANOS
    );

    let (full, _) = transition_rate_limit(
        RateLimitState::default(),
        RateLimitLimits {
            max_per_hour: 1,
            max_per_day: 0,
        },
        BASE_TIME,
        RateLimitEvent::SetLimits,
    );
    let (consumed, result) = transition_rate_limit(
        full,
        RateLimitLimits {
            max_per_hour: 0,
            max_per_day: 0,
        },
        BASE_TIME,
        RateLimitEvent::Allow,
    );
    assert!(result.allowed);
    for (elapsed, allowed) in [
        (0, false),
        (1, false),
        (HOUR_NANOS - 1, false),
        (HOUR_NANOS, true),
        (HOUR_NANOS + 1, true),
    ] {
        let (next, result) = transition_rate_limit(
            consumed,
            RateLimitLimits {
                max_per_hour: 0,
                max_per_day: 0,
            },
            BASE_TIME + elapsed,
            RateLimitEvent::Allow,
        );
        assert_eq!(result.allowed, allowed, "elapsed={elapsed}, state={next:?}");
        assert_quota_invariants(next);
    }
}

#[test]
fn timestamp_extremes_use_saturating_elapsed_arithmetic() {
    let limits = RateLimitLimits {
        max_per_hour: 2,
        max_per_day: 2,
    };
    for last_refill in [i64::MIN, i64::MAX] {
        for daily_window_start in [i64::MIN, i64::MAX] {
            for now in [
                i64::MIN,
                i64::MIN + DAY_NANOS,
                i64::MAX - DAY_NANOS,
                i64::MAX,
            ] {
                let state = RateLimitState {
                    tokens: 0.5,
                    capacity: 2.0,
                    refill_rate: 1.0,
                    last_refill_unix_nanos: last_refill,
                    daily_count: 1,
                    daily_window_start_unix_nanos: daily_window_start,
                    max_per_day: 2,
                };
                let (next, result) =
                    transition_rate_limit(state, limits, now, RateLimitEvent::Allow);
                assert_quota_invariants(next);
                if !result.allowed {
                    assert!(next.tokens + EPSILON >= state.tokens);
                }
            }
        }
    }
}
