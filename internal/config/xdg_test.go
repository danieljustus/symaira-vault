package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestXDGConfigHome_defaults(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	got := XDGConfigHome()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir failed: %v", err)
	}
	want := filepath.Join(home, ".config")
	if got != want {
		t.Errorf("XDGConfigHome() = %q, want %q", got, want)
	}
}

func TestXDGDataHome_defaults(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	got := XDGDataHome()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir failed: %v", err)
	}
	want := filepath.Join(home, ".local", "share")
	if got != want {
		t.Errorf("XDGDataHome() = %q, want %q", got, want)
	}
}

func TestXDGCacheHome_defaults(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "")
	got := XDGCacheHome()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir failed: %v", err)
	}
	want := filepath.Join(home, ".cache")
	if got != want {
		t.Errorf("XDGCacheHome() = %q, want %q", got, want)
	}
}

func TestDefaultConfigDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	got := DefaultConfigDir()
	want := filepath.Join(XDGConfigHome(), ConfigSubdir)
	if got != want {
		t.Errorf("DefaultConfigDir() = %q, want %q", got, want)
	}
}

func TestDefaultDataDir(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	got := DefaultDataDir()
	want := filepath.Join(XDGDataHome(), DataSubdir)
	if got != want {
		t.Errorf("DefaultDataDir() = %q, want %q", got, want)
	}
}

func TestDefaultCacheDir(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "")
	got := DefaultCacheDir()
	want := filepath.Join(XDGCacheHome(), CacheSubdir)
	if got != want {
		t.Errorf("DefaultCacheDir() = %q, want %q", got, want)
	}
}

func TestXDGConfigHome_respectsEnv(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tempDir)

	got := XDGConfigHome()
	if got != tempDir {
		t.Errorf("XDGConfigHome() = %q, want %q (XDG_CONFIG_HOME)", got, tempDir)
	}
}

func TestXDGDataHome_respectsEnv(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempDir)

	got := XDGDataHome()
	if got != tempDir {
		t.Errorf("XDGDataHome() = %q, want %q (XDG_DATA_HOME)", got, tempDir)
	}
}

func TestXDGCacheHome_respectsEnv(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tempDir)

	got := XDGCacheHome()
	if got != tempDir {
		t.Errorf("XDGCacheHome() = %q, want %q (XDG_CACHE_HOME)", got, tempDir)
	}
}

func TestDefaultConfigDir_respectsXDGConfigHome(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tempDir)

	got := DefaultConfigDir()
	want := filepath.Join(tempDir, ConfigSubdir)
	if got != want {
		t.Errorf("DefaultConfigDir() = %q, want %q", got, want)
	}
}

func TestDefaultDataDir_respectsXDGDataHome(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempDir)

	got := DefaultDataDir()
	want := filepath.Join(tempDir, DataSubdir)
	if got != want {
		t.Errorf("DefaultDataDir() = %q, want %q", got, want)
	}
}

func TestDefaultCacheDir_respectsXDGCacheHome(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tempDir)

	got := DefaultCacheDir()
	want := filepath.Join(tempDir, CacheSubdir)
	if got != want {
		t.Errorf("DefaultCacheDir() = %q, want %q", got, want)
	}
}
