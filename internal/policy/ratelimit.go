package policy

import (
	"sync"
	"time"
)

type bucket struct {
	tokens           float64
	capacity         float64
	refillRate       float64
	lastRefill       time.Time
	dailyCount       int
	dailyWindowStart time.Time
	maxPerDay        int
	mu               sync.Mutex
}

type AgentRateLimiter struct {
	buckets map[string]*bucket
	mu      sync.RWMutex
}

func NewAgentRateLimiter() *AgentRateLimiter {
	return &AgentRateLimiter{
		buckets: make(map[string]*bucket),
	}
}

func (rl *AgentRateLimiter) Allow(agentID string) bool {
	rl.mu.RLock()
	b, ok := rl.buckets[agentID]
	rl.mu.RUnlock()

	if !ok {
		return true
	}

	return b.allow()
}

func (rl *AgentRateLimiter) SetLimits(agentID string, hour, day int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	state, _ := TransitionRateLimit(RateLimitState{}, RateLimitLimits{
		MaxPerHour: hour,
		MaxPerDay:  day,
	}, now, RateLimitEventSetLimits)
	rl.buckets[agentID] = &bucket{
		tokens:           state.Tokens,
		capacity:         state.Capacity,
		refillRate:       state.RefillRate,
		lastRefill:       state.LastRefill,
		maxPerDay:        state.MaxPerDay,
		dailyWindowStart: state.DailyWindowStart,
	}
}

// HasLimits returns whether rate limits have been configured for the given agent.
func (rl *AgentRateLimiter) HasLimits(agentID string) bool {
	rl.mu.RLock()
	_, ok := rl.buckets[agentID]
	rl.mu.RUnlock()
	return ok
}

func (rl *AgentRateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.buckets = make(map[string]*bucket)
}

func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	next, result := TransitionRateLimit(RateLimitState{
		Tokens:           b.tokens,
		Capacity:         b.capacity,
		RefillRate:       b.refillRate,
		LastRefill:       b.lastRefill,
		DailyCount:       b.dailyCount,
		DailyWindowStart: b.dailyWindowStart,
		MaxPerDay:        b.maxPerDay,
	}, RateLimitLimits{}, time.Now(), RateLimitEventAllow)
	b.tokens = next.Tokens
	b.capacity = next.Capacity
	b.refillRate = next.RefillRate
	b.lastRefill = next.LastRefill
	b.dailyCount = next.DailyCount
	b.dailyWindowStart = next.DailyWindowStart
	b.maxPerDay = next.MaxPerDay
	return result.Allowed
}
