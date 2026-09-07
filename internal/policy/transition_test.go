package policy

import (
	"testing"
	"time"
)

func TestTransitionRateLimitSetLimitsInitializesState(t *testing.T) {
	now := time.Unix(1_700_000_000, 123).UTC()

	next, result := TransitionRateLimit(RateLimitState{}, RateLimitLimits{
		MaxPerHour: 4,
		MaxPerDay:  9,
	}, now, RateLimitEventSetLimits)

	if result.Allowed {
		t.Fatal("set_limits result.Allowed = true, want false")
	}
	if next.Tokens != 4 || next.Capacity != 4 || next.RefillRate != 4.0/3600.0 {
		t.Fatalf("set_limits state = %+v, want four-token bucket", next)
	}
	if !next.LastRefill.Equal(now) || !next.DailyWindowStart.Equal(now) {
		t.Fatalf("set_limits timestamps = %+v, want %v", next, now)
	}
	if next.MaxPerDay != 9 || next.DailyCount != 0 {
		t.Fatalf("set_limits daily state = %+v", next)
	}
}

func TestTransitionRateLimitRefillsAndClampsCapacity(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC()
	state, _ := TransitionRateLimit(RateLimitState{}, RateLimitLimits{MaxPerHour: 4}, start, RateLimitEventSetLimits)

	for i := 0; i < 4; i++ {
		var result RateLimitResult
		state, result = TransitionRateLimit(state, RateLimitLimits{}, start, RateLimitEventAllow)
		if !result.Allowed {
			t.Fatalf("allow %d = false, want true", i+1)
		}
	}

	state, result := TransitionRateLimit(state, RateLimitLimits{}, start.Add(30*time.Minute), RateLimitEventAllow)
	if !result.Allowed || state.Tokens != 1 {
		t.Fatalf("half-hour refill = state %+v, result %+v; want one token and allow", state, result)
	}

	state, result = TransitionRateLimit(state, RateLimitLimits{}, start.Add(2*time.Hour), RateLimitEventAllow)
	if !result.Allowed || state.Tokens != 3 {
		t.Fatalf("capacity clamp = state %+v, result %+v; want three tokens after allow", state, result)
	}
}

func TestTransitionRateLimitDailyRolloverAndRejection(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC()
	state, _ := TransitionRateLimit(RateLimitState{}, RateLimitLimits{MaxPerHour: 10, MaxPerDay: 2}, start, RateLimitEventSetLimits)

	var result RateLimitResult
	for i := 0; i < 2; i++ {
		state, result = TransitionRateLimit(state, RateLimitLimits{}, start, RateLimitEventAllow)
		if !result.Allowed {
			t.Fatalf("initial allow %d = false, want true", i+1)
		}
	}
	beforeReject := state
	state, result = TransitionRateLimit(state, RateLimitLimits{}, start, RateLimitEventAllow)
	if result.Allowed {
		t.Fatal("daily limit rejection Allowed = true, want false")
	}
	if state.DailyCount != beforeReject.DailyCount || state.Tokens != beforeReject.Tokens {
		t.Fatalf("daily rejection changed state from %+v to %+v", beforeReject, state)
	}

	state, result = TransitionRateLimit(state, RateLimitLimits{}, start.Add(24*time.Hour), RateLimitEventAllow)
	if !result.Allowed || state.DailyCount != 1 || !state.DailyWindowStart.Equal(start.Add(24*time.Hour)) {
		t.Fatalf("daily rollover = state %+v, result %+v", state, result)
	}
}

func TestTransitionRateLimitBoundaryNeedsAFullToken(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC()
	state, _ := TransitionRateLimit(RateLimitState{}, RateLimitLimits{MaxPerHour: 1}, start, RateLimitEventSetLimits)
	var result RateLimitResult
	state, result = TransitionRateLimit(state, RateLimitLimits{}, start, RateLimitEventAllow)
	if !result.Allowed {
		t.Fatal("initial allow = false, want true")
	}

	state, result = TransitionRateLimit(state, RateLimitLimits{}, start.Add(3599*time.Second), RateLimitEventAllow)
	if result.Allowed {
		t.Fatal("allow before a full refill hour = true, want false")
	}
	if state.Tokens >= 1 {
		t.Fatalf("boundary tokens = %v, want less than one", state.Tokens)
	}

	state, result = TransitionRateLimit(state, RateLimitLimits{}, start.Add(3600*time.Second), RateLimitEventAllow)
	if !result.Allowed || state.Tokens != 0 {
		t.Fatalf("allow at exact refill boundary = state %+v, result %+v", state, result)
	}
}
