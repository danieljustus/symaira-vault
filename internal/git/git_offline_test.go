package git

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIsOfflineError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"ssh operation timed out", errors.New("ssh: connect to host github.com port 22: Operation timed out"), true},
		{"connection refused", errors.New("dial tcp 127.0.0.1:1: connect: connection refused"), true},
		{"no route to host", errors.New("dial tcp: no route to host"), true},
		{"connection timed out", errors.New("dial tcp: connection timed out"), true},
		{"i/o timeout", errors.New("dial tcp: i/o timeout"), true},
		{"no such host", errors.New("dial tcp: lookup github.com: no such host"), true},
		{"could not resolve hostname", errors.New("ssh: Could not resolve hostname github.com: nodename nor servname provided"), true},
		{"name or service not known", errors.New("ssh: connect to host github.com port 22: Name or service not known"), true},
		{"network unreachable", errors.New("connect: network is unreachable"), true},
		{"push timed out", errors.New("push timed out after 20s"), true},
		{"generic network", errors.New("network error - please check your connection"), true},
		{"wrapped push error", &PushError{Message: "network error - please check your connection", Cause: errors.New("connection refused")}, true},
		{"permission denied", errors.New("permission denied"), false},
		{"authentication failed", errors.New("authentication failed: invalid credentials"), false},
		{"repository not found", errors.New("repository not found"), false},
		{"empty message", errors.New(""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsOfflineError(tc.err); got != tc.want {
				t.Errorf("IsOfflineError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestPushWithTimeoutBoundsSlowPush(t *testing.T) {
	start := time.Now()
	err := pushWithTimeout(100*time.Millisecond, func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return nil
		}
	})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("push with timeout took too long: %v", elapsed)
	}
}

func TestPushWithTimeoutReturnsUnderlyingError(t *testing.T) {
	want := errors.New("boom")
	err := pushWithTimeout(time.Second, func(context.Context) error {
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("expected underlying error, got: %v", err)
	}
}

func TestPushWithTimeoutAllowsContextCancellation(t *testing.T) {
	cancelled := false
	err := pushWithTimeout(100*time.Millisecond, func(ctx context.Context) error {
		<-ctx.Done()
		cancelled = true
		return ctx.Err()
	})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
	if !cancelled {
		t.Error("expected push function to observe context cancellation")
	}
}
