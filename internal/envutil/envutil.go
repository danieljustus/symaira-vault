// Package envutil provides helpers for reading environment variables with
// backward-compatible fallback names.
package envutil

import "os"

// Getenv checks the primary environment variable first, then falls back to the
// legacy variable. Returns the value (which may be empty if neither is set).
func Getenv(primary, legacy string) string {
	if v := os.Getenv(primary); v != "" {
		return v
	}
	return os.Getenv(legacy)
}

// Unsetenv unsets both the primary and legacy environment variable names.
func Unsetenv(primary, legacy string) {
	_ = os.Unsetenv(primary)
	_ = os.Unsetenv(legacy)
}
