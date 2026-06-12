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

	corekitenvutil "github.com/danieljustus/symaira-corekit/envutil"
	"golang.org/x/term"
)

var deprecateWarn atomic.Uint32

// ForceDeprecationWarning forces the deprecation warning to print even when
// stderr is not a terminal. Used in tests.
var ForceDeprecationWarning bool

// Getenv checks the primary environment variable first, then falls back to the
// legacy variable. Prints a one-shot deprecation warning when a legacy
// OPENPASS_* variable is consumed. Returns the value (may be empty).
func Getenv(primary, legacy string) string {
	v := corekitenvutil.Getenv(primary, legacy)
	if v == "" {
		return ""
	}
	// If the value came from the primary variable, no warning is needed.
	if p := os.Getenv(primary); p != "" {
		return v
	}
	// Value came from legacy — fire deprecation warning.
	if deprecateWarn.CompareAndSwap(0, 1) && len(legacy) > 8 && legacy[:8] == "OPENPASS" {
		if ForceDeprecationWarning || term.IsTerminal(int(os.Stderr.Fd())) {
			fmt.Fprintf(os.Stderr,
				"WARNING: %[1]s is deprecated and will be removed 3 releases after 2026-05-26. "+
					"Use %[2]s instead.\n", legacy, primary)
		}
	}
	return v
}

// resetDeprecationWarning resets the one-shot deprecation warning so that
// the next legacy-var lookup prints it again. Intended for testing only.
func resetDeprecationWarning() {
	deprecateWarn.Store(0)
}

// Unsetenv unsets both the primary and legacy environment variable names.
func Unsetenv(primary, legacy string) {
	_ = corekitenvutil.Unsetenv(primary)
	_ = corekitenvutil.Unsetenv(legacy)
}
