package clipboard

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func pollWithTimeout(t *testing.T, condition func() bool, timeout time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestStartAutoClear_NormalFlow(t *testing.T) {
	var called atomic.Bool
	done := make(chan struct{})

	go StartAutoClear(1, func() {
		called.Store(true)
		close(done)
	}, nil)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("clearFn was not called within timeout")
	}

	if !called.Load() {
		t.Fatal("clearFn was not called")
	}
}

func TestStartAutoClear_Cancel(t *testing.T) {
	var called atomic.Bool
	cancelCh := make(chan struct{})

	go StartAutoClear(10, func() {
		called.Store(true)
	}, cancelCh)

	close(cancelCh)

	pollWithTimeout(t, func() bool {
		return !called.Load()
	}, 500*time.Millisecond, "clearFn should not have been called after cancel")
}

func TestStartAutoClear_DurationZero(t *testing.T) {
	var called atomic.Bool

	go StartAutoClear(0, func() {
		called.Store(true)
	}, nil)

	pollWithTimeout(t, func() bool {
		return !called.Load()
	}, 200*time.Millisecond, "clearFn should not have been called with duration 0")
}

func TestStartAutoClear_NilClearFn(t *testing.T) {
	// This should not panic and return immediately
	StartAutoClear(1, nil, nil)
	time.Sleep(10 * time.Millisecond)
}

func TestCountdown_NormalFlow(t *testing.T) {
	updates := make([]int, 0, 4)
	done := make(chan struct{})

	go Countdown(2, func(remaining int) {
		updates = append(updates, remaining)
		if remaining == 0 {
			close(done)
		}
	}, nil)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("countdown did not complete within timeout")
	}

	if len(updates) < 3 {
		t.Fatalf("expected at least 3 updates, got %d: %v", len(updates), updates)
	}
	if updates[0] != 2 {
		t.Fatalf("expected first update to be 2, got %d", updates[0])
	}
	if updates[len(updates)-1] != 0 {
		t.Fatalf("expected last update to be 0, got %d", updates[len(updates)-1])
	}
}

func TestCountdown_Cancel(t *testing.T) {
	cancelCh := make(chan struct{})
	var updates atomic.Int32

	//nolint:unparam
	go Countdown(10, func(remaining int) {
		updates.Add(1)
	}, cancelCh)

	close(cancelCh)

	pollWithTimeout(t, func() bool {
		return updates.Load() > 0
	}, 500*time.Millisecond, "expected at least one update before cancel")
}

func TestCountdown_DurationZero(t *testing.T) {
	var called atomic.Bool

	//nolint:unparam
	go Countdown(0, func(remaining int) {
		called.Store(true)
	}, nil)

	pollWithTimeout(t, func() bool {
		return !called.Load()
	}, 200*time.Millisecond, "updateFn should not have been called with duration 0")
}

func TestCountdown_NilUpdateFn(t *testing.T) {
	// This should not panic and return immediately
	Countdown(1, nil, nil)
	time.Sleep(10 * time.Millisecond)
}

func TestVerifyCleared_StillContainsSecret(t *testing.T) {
	err := VerifyCleared("topsecret", func() (string, error) { return "topsecret", nil })
	if err == nil {
		t.Fatal("expected ErrClipboardNotCleared, got nil")
	}
}

func TestVerifyCleared_Cleared(t *testing.T) {
	err := VerifyCleared("topsecret", func() (string, error) { return "", nil })
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestVerifyCleared_NilReadFn(t *testing.T) {
	if err := VerifyCleared("x", nil); err != nil {
		t.Errorf("expected nil with nil readFn, got %v", err)
	}
}

func TestVerifyCleared_EmptyExpected(t *testing.T) {
	if err := VerifyCleared("", func() (string, error) { return "anything", nil }); err != nil {
		t.Errorf("expected nil with empty expectedAbsent, got %v", err)
	}
}

func TestVerifyCleared_ReadError(t *testing.T) {
	readErr := errors.New("read failed")
	if err := VerifyCleared("x", func() (string, error) { return "", readErr }); err != readErr {
		t.Errorf("got %v, want %v", err, readErr)
	}
}
