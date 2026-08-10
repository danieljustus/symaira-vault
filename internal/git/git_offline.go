package git

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// pushTimeout bounds a single push attempt so an unreachable remote cannot
// stall vault writes for minutes (the default OpenSSH connect timeout alone
// can block for 10-75s per attempt).
const pushTimeout = 20 * time.Second

// offlineErrorMarkers are substrings that indicate the git remote is
// unreachable (a connectivity problem), as opposed to a configuration or
// authentication problem. Matching is case-insensitive.
var offlineErrorMarkers = []string{
	// Real-world ssh / net / git error strings (see issue #798).
	"no route to host",
	"connection refused",
	"connection timed out",
	"operation timed out",
	"i/o timeout",
	"no such host",
	"could not resolve hostname",
	"name or service not known",
	"network is unreachable",
	"host is unreachable",
	"connection reset by peer",
	"timed out",
	"timeout",
	// Generic markers kept for parity with the previous per-package
	// classifiers (git_pull.go / internal/cli / cmd/sync).
	"connection",
	"refused",
	"network",
	"tls",
	"eof",
}

// IsOfflineError reports whether err indicates that the git remote is
// unreachable (offline/network problem) rather than a configuration or
// authentication problem. It is the single shared offline classifier used
// by all push and pull call sites.
func IsOfflineError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range offlineErrorMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// pushWithTimeout runs fn and returns an error if it does not complete within
// timeout. Replication is best-effort: a dead remote must never stall a vault
// write beyond the bounded window.
func pushWithTimeout(timeout time.Duration, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- fn(ctx)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("push timed out after %s", timeout)
	}
}
