use serde::{Deserialize, Serialize};

/// The explicit state of one quota/rate-limit bucket.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
pub struct RateLimitState {
    pub tokens: f64,
    pub capacity: f64,
    pub refill_rate: f64,
    pub last_refill_unix_nanos: i64,
    pub daily_count: i64,
    pub daily_window_start_unix_nanos: i64,
    pub max_per_day: i64,
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self {
            tokens: 0.0,
            capacity: 0.0,
            refill_rate: 0.0,
            last_refill_unix_nanos: 0,
            daily_count: 0,
            daily_window_start_unix_nanos: 0,
            max_per_day: 0,
        }
    }
}

/// The limits applied by a `set_limits` event.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
pub struct RateLimitLimits {
    pub max_per_hour: i64,
    pub max_per_day: i64,
}

/// A supported pure bucket transition event.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitEvent {
    SetLimits,
    Allow,
}

/// The decision returned by an `allow` event.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
pub struct RateLimitResult {
    pub allowed: bool,
}

/// Applies one deterministic quota/rate-limit state transition.
///
/// No clock, lock, registry, filesystem, or process state is accessed here.
#[must_use]
pub fn transition_rate_limit(
    state: RateLimitState,
    limits: RateLimitLimits,
    now_unix_nanos: i64,
    event: RateLimitEvent,
) -> (RateLimitState, RateLimitResult) {
    if event == RateLimitEvent::SetLimits {
        let hour = limits.max_per_hour as f64;
        return (
            RateLimitState {
                tokens: hour,
                capacity: hour,
                refill_rate: hour / 3_600.0,
                last_refill_unix_nanos: now_unix_nanos,
                daily_count: 0,
                daily_window_start_unix_nanos: now_unix_nanos,
                max_per_day: limits.max_per_day,
            },
            RateLimitResult { allowed: false },
        );
    }

    let mut next = state;
    let elapsed_nanos = now_unix_nanos.saturating_sub(next.last_refill_unix_nanos);
    if elapsed_nanos > 0 {
        let elapsed_seconds = elapsed_nanos as f64 / 1_000_000_000.0;
        next.tokens = (next.tokens + elapsed_seconds * next.refill_rate).min(next.capacity);
        next.last_refill_unix_nanos = now_unix_nanos;
    }

    if next.max_per_day > 0 {
        let daily_elapsed = now_unix_nanos.saturating_sub(next.daily_window_start_unix_nanos);
        if daily_elapsed >= 86_400_000_000_000 {
            next.daily_count = 0;
            next.daily_window_start_unix_nanos = now_unix_nanos;
        }
        if next.daily_count >= next.max_per_day {
            return (next, RateLimitResult { allowed: false });
        }
    }

    if next.tokens < 1.0 {
        return (next, RateLimitResult { allowed: false });
    }

    next.tokens -= 1.0;
    if next.max_per_day > 0 {
        next.daily_count += 1;
    }
    (next, RateLimitResult { allowed: true })
}

/// Public registry wrapper matching the Go `AgentRateLimiter` surface.
///
/// Unknown agents are intentionally unlimited. Configured agents use the same
/// pure transition function as `transition_rate_limit`; the wrapper only owns
/// registry lookup, locking, and the wall-clock adapter.
pub struct AgentRateLimiter {
    buckets: std::sync::Mutex<std::collections::BTreeMap<String, RateLimitState>>,
}

impl Default for AgentRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentRateLimiter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    pub fn set_limits(&self, agent_id: impl Into<String>, max_per_hour: i64, max_per_day: i64) {
        let now = unix_now_nanos();
        let (state, _) = transition_rate_limit(
            RateLimitState::default(),
            RateLimitLimits {
                max_per_hour,
                max_per_day,
            },
            now,
            RateLimitEvent::SetLimits,
        );
        if let Ok(mut buckets) = self.buckets.lock() {
            buckets.insert(agent_id.into(), state);
        }
    }

    #[must_use]
    pub fn allow(&self, agent_id: &str) -> bool {
        let Ok(mut buckets) = self.buckets.lock() else {
            return false;
        };
        let Some(state) = buckets.get_mut(agent_id) else {
            return true;
        };
        let (next, result) = transition_rate_limit(
            *state,
            RateLimitLimits {
                max_per_hour: 0,
                max_per_day: 0,
            },
            unix_now_nanos(),
            RateLimitEvent::Allow,
        );
        *state = next;
        result.allowed
    }

    #[must_use]
    pub fn has_limits(&self, agent_id: &str) -> bool {
        self.buckets
            .lock()
            .map(|buckets| buckets.contains_key(agent_id))
            .unwrap_or(false)
    }

    pub fn cleanup(&self) {
        if let Ok(mut buckets) = self.buckets.lock() {
            buckets.clear();
        }
    }
}

fn unix_now_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{RateLimitEvent, RateLimitLimits, RateLimitState, transition_rate_limit};

    #[test]
    fn set_limits_initializes_a_bucket_without_allowing_a_request() {
        let (state, result) = transition_rate_limit(
            RateLimitState::default(),
            RateLimitLimits {
                max_per_hour: 4,
                max_per_day: 9,
            },
            1_700_000_000_000_000_000,
            RateLimitEvent::SetLimits,
        );

        assert_eq!(state.tokens, 4.0);
        assert_eq!(state.capacity, 4.0);
        assert_eq!(state.daily_count, 0);
        assert!(!result.allowed);
    }

    #[test]
    fn allow_refills_only_after_elapsed_time_and_clamps_to_capacity() {
        let start = 1_700_000_000_000_000_000;
        let (mut state, _) = transition_rate_limit(
            RateLimitState::default(),
            RateLimitLimits {
                max_per_hour: 2,
                max_per_day: 0,
            },
            start,
            RateLimitEvent::SetLimits,
        );
        let (next, result) = transition_rate_limit(
            state,
            RateLimitLimits {
                max_per_hour: 0,
                max_per_day: 0,
            },
            start,
            RateLimitEvent::Allow,
        );
        state = next;
        assert!(result.allowed);
        let (state, result) = transition_rate_limit(
            state,
            RateLimitLimits {
                max_per_hour: 0,
                max_per_day: 0,
            },
            start + 7_200_000_000_000,
            RateLimitEvent::Allow,
        );
        assert!(result.allowed);
        assert_eq!(state.tokens, 1.0);
    }
}
