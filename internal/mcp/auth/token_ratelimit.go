package auth

import (
	"sync"
	"time"
)

type tokenBucket struct {
	failures int
	lockedAt time.Time
	lastFail time.Time
}

type TokenRateLimiter struct {
	buckets     map[string]*tokenBucket
	mu          sync.RWMutex
	maxAttempts int
	lockout     time.Duration
}

func NewTokenRateLimiter(maxAttempts int, lockout time.Duration) *TokenRateLimiter {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if lockout <= 0 {
		lockout = 30 * time.Second
	}
	return &TokenRateLimiter{
		buckets:     make(map[string]*tokenBucket),
		maxAttempts: maxAttempts,
		lockout:     lockout,
	}
}

func (rl *TokenRateLimiter) RecordFailure(agentID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[agentID]
	if !ok {
		b = &tokenBucket{failures: 1, lastFail: time.Now()}
		rl.buckets[agentID] = b
	} else if !b.lockedAt.IsZero() && time.Since(b.lockedAt) > rl.lockout {
		b.failures = 1
		b.lockedAt = time.Time{}
	} else if b.lockedAt.IsZero() {
		b.failures++
	}
	b.lastFail = time.Now()

	if b.failures >= rl.maxAttempts && b.lockedAt.IsZero() {
		b.lockedAt = time.Now()
	}
}

func (rl *TokenRateLimiter) RecordSuccess(agentID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, agentID)
}

func (rl *TokenRateLimiter) IsLocked(agentID string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	b, ok := rl.buckets[agentID]
	if !ok {
		return false
	}

	if !b.lockedAt.IsZero() && time.Since(b.lockedAt) <= rl.lockout {
		return true
	}

	if !b.lockedAt.IsZero() && time.Since(b.lockedAt) > rl.lockout {
		return false
	}

	return b.failures >= rl.maxAttempts
}

func (rl *TokenRateLimiter) RemainingLockout(agentID string) time.Duration {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	b, ok := rl.buckets[agentID]
	if !ok || b.lockedAt.IsZero() {
		return 0
	}

	elapsed := time.Since(b.lockedAt)
	if elapsed >= rl.lockout {
		return 0
	}
	return rl.lockout - elapsed
}

func (rl *TokenRateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.buckets = make(map[string]*tokenBucket)
}
