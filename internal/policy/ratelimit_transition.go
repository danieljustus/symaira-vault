package policy

import "time"

// RateLimitState is the language-neutral in-memory state of one rate-limit bucket.
// The timestamps are explicit so callers can evaluate transitions without wall-clock I/O.
type RateLimitState struct {
	Tokens           float64   `json:"tokens"`
	Capacity         float64   `json:"capacity"`
	RefillRate       float64   `json:"refill_rate"`
	LastRefill       time.Time `json:"last_refill"`
	DailyCount       int       `json:"daily_count"`
	DailyWindowStart time.Time `json:"daily_window_start"`
	MaxPerDay        int       `json:"max_per_day"`
}

// RateLimitLimits contains the limits applied by a set_limits transition.
type RateLimitLimits struct {
	MaxPerHour int `json:"max_per_hour"`
	MaxPerDay  int `json:"max_per_day"`
}

// RateLimitEvent identifies one supported pure bucket transition.
type RateLimitEvent string

const (
	// RateLimitEventSetLimits initializes or replaces the bucket limits.
	RateLimitEventSetLimits RateLimitEvent = "set_limits"
	// RateLimitEventAllow attempts to consume one token from the bucket.
	RateLimitEventAllow RateLimitEvent = "allow"
)

// RateLimitResult is the result of an allow transition. set_limits returns the
// zero result because it does not represent a request decision.
type RateLimitResult struct {
	Allowed bool `json:"allowed"`
}

// TransitionRateLimit applies one deterministic rate-limit transition.
//
// The function is deliberately pure over its state and arguments: it never
// reads the clock, locks, accesses a registry, or performs filesystem I/O.
func TransitionRateLimit(state RateLimitState, limits RateLimitLimits, now time.Time, event RateLimitEvent) (RateLimitState, RateLimitResult) {
	if event == RateLimitEventSetLimits {
		hour := float64(limits.MaxPerHour)
		return RateLimitState{
			Tokens:           hour,
			Capacity:         hour,
			RefillRate:       hour / 3600.0,
			LastRefill:       now,
			DailyWindowStart: now,
			MaxPerDay:        limits.MaxPerDay,
		}, RateLimitResult{}
	}

	if event != RateLimitEventAllow {
		return state, RateLimitResult{}
	}

	next := state
	elapsed := now.Sub(next.LastRefill).Seconds()
	if elapsed > 0 {
		next.Tokens = min(next.Capacity, next.Tokens+elapsed*next.RefillRate)
		next.LastRefill = now
	}

	if next.MaxPerDay > 0 {
		if now.Sub(next.DailyWindowStart) >= 24*time.Hour {
			next.DailyCount = 0
			next.DailyWindowStart = now
		}
		if next.DailyCount >= next.MaxPerDay {
			return next, RateLimitResult{}
		}
	}

	if next.Tokens < 1 {
		return next, RateLimitResult{}
	}

	next.Tokens--
	if next.MaxPerDay > 0 {
		next.DailyCount++
	}
	return next, RateLimitResult{Allowed: true}
}
