package wizard

import (
	"fmt"
	"os"
	"testing"
)

// TestMain redirects the environment variables that os.UserCacheDir and
// os.UserHomeDir resolve from so wizard tests never write into the
// developer's real cache or home directory. Without this, every
// SaveResumeState call in the suite leaves a stale YAML file behind in
// ~/Library/Caches/symaira/wizard (macOS) or $XDG_CACHE_HOME/symaira/wizard,
// keyed by a hash of the per-test temp vault dir so it is never reused or
// cleaned up.
func TestMain(m *testing.M) {
	tmpHome, err := os.MkdirTemp("", "symvault-wizard-home")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp home: %v\n", err)
		os.Exit(1)
	}

	// HOME covers macOS ($HOME/Library/Caches) and the Linux fallback
	// ($HOME/.cache); XDG_CACHE_HOME takes precedence on Linux when the
	// developer has it set, so pin it too.
	os.Setenv("HOME", tmpHome)
	os.Setenv("XDG_CACHE_HOME", tmpHome+"/.cache")

	code := m.Run()
	os.RemoveAll(tmpHome)
	os.Exit(code)
}
