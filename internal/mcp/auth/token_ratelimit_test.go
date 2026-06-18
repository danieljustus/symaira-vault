package auth

import (
	"testing"
	"time"
)

func TestTokenRateLimiter_LockoutAfterMaxAttempts(t *testing.T) {
	rl := NewTokenRateLimiter(3, 5*time.Second)

	agentID := "test-agent"

	for i := 0; i < 3; i++ {
		if rl.IsLocked(agentID) {
			t.Fatalf("IsLocked() = true after %d failures, want false", i+1)
		}
		rl.RecordFailure(agentID)
	}

	if !rl.IsLocked(agentID) {
		t.Fatal("IsLocked() = false after max attempts, want true")
	}
}

func TestTokenRateLimiter_LockoutExpires(t *testing.T) {
	rl := NewTokenRateLimiter(2, 50*time.Millisecond)

	agentID := "test-agent"
	rl.RecordFailure(agentID)
	rl.RecordFailure(agentID)

	if !rl.IsLocked(agentID) {
		t.Fatal("IsLocked() = false after 2 failures, want true")
	}

	time.Sleep(100 * time.Millisecond)

	if rl.IsLocked(agentID) {
		t.Fatal("IsLocked() = true after lockout expired, want false")
	}
}

func TestTokenRateLimiter_SuccessResetsCount(t *testing.T) {
	rl := NewTokenRateLimiter(3, 5*time.Second)

	agentID := "test-agent"
	rl.RecordFailure(agentID)
	rl.RecordFailure(agentID)
	rl.RecordSuccess(agentID)

	if rl.IsLocked(agentID) {
		t.Fatal("IsLocked() = true after success reset, want false")
	}

	rl.RecordFailure(agentID)
	rl.RecordFailure(agentID)
	rl.RecordFailure(agentID)

	if !rl.IsLocked(agentID) {
		t.Fatal("IsLocked() = false after re-locking, want true")
	}
}

func TestTokenRateLimiter_RemainingLockout(t *testing.T) {
	rl := NewTokenRateLimiter(1, 100*time.Millisecond)

	agentID := "test-agent"
	rl.RecordFailure(agentID)

	remaining := rl.RemainingLockout(agentID)
	if remaining <= 0 || remaining > 100*time.Millisecond {
		t.Fatalf("RemainingLockout() = %v, want (0, 100ms]", remaining)
	}

	time.Sleep(150 * time.Millisecond)

	remaining = rl.RemainingLockout(agentID)
	if remaining != 0 {
		t.Fatalf("RemainingLockout() = %v after expiry, want 0", remaining)
	}
}

func TestTokenRateLimiter_Cleanup(t *testing.T) {
	rl := NewTokenRateLimiter(1, 5*time.Second)
	rl.RecordFailure("agent-a")
	rl.RecordFailure("agent-b")

	rl.Cleanup()

	if rl.IsLocked("agent-a") {
		t.Fatal("IsLocked() = true after cleanup, want false")
	}
	if rl.IsLocked("agent-b") {
		t.Fatal("IsLocked() = true after cleanup, want false")
	}
}

func TestTokenRateLimiter_DefaultValues(t *testing.T) {
	rl := NewTokenRateLimiter(0, 0)

	if rl.maxAttempts != 5 {
		t.Fatalf("maxAttempts = %d, want 5", rl.maxAttempts)
	}
	if rl.lockout != 30*time.Second {
		t.Fatalf("lockout = %v, want 30s", rl.lockout)
	}
}

func TestTokenRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewTokenRateLimiter(100, 5*time.Second)

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			agentID := "concurrent-agent"
			for j := 0; j < 50; j++ {
				rl.RecordFailure(agentID)
				_ = rl.IsLocked(agentID)
				rl.RecordSuccess(agentID)
			}
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
