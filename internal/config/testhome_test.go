package config

import "testing"

// setTestHome points HOME (and the XDG overrides that take precedence over
// it) at a fresh temp dir so path resolution is hermetic regardless of the
// runner's environment.
func setTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	return home
}
