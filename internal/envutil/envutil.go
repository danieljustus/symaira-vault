// Package envutil provides helpers for reading environment variables with
// backward-compatible fallback names.
//
// Deprecated env var names (OPENPASS_*) trigger a one-shot stderr warning
// per process and are scheduled for removal 3 releases after 2026-05-26.
package envutil

import (
	"fmt"
	"os"
	"sync/atomic"
)

var deprecateWarn atomic.Uint32

// Getenv checks the primary environment variable first, then falls back to the
// legacy variable. Prints a one-shot deprecation warning when a legacy
// OPENPASS_* variable is consumed. Returns the value (may be empty).
func Getenv(primary, legacy string) string {
	if v := os.Getenv(primary); v != "" {
		return v
	}
	if v := os.Getenv(legacy); v != "" {
		if deprecateWarn.CompareAndSwap(0, 1) {
			fmt.Fprintf(os.Stderr,
				"WARNING: %[1]s is deprecated and will be removed in a future release. "+
					"Use %[2]s instead.\n", legacy, primary)
		}
		return v
	}
	return ""
}

// ResetDeprecationWarning resets the one-shot deprecation warning so that
// the next legacy-var lookup prints it again. Intended for testing only.
func ResetDeprecationWarning() {
	deprecateWarn.Store(0)
}

// Unsetenv unsets both the primary and legacy environment variable names.
func Unsetenv(primary, legacy string) {
	_ = os.Unsetenv(primary)
	_ = os.Unsetenv(legacy)
}
