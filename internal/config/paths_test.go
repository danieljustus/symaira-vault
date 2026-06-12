package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPathResolver_FreshInstall_UsesXDG(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	r := NewPathResolver()

	wantConfig := filepath.Join(home, ".config", "symaira-vault")
	wantData := filepath.Join(home, ".local", "share", "symaira-vault")
	wantCache := filepath.Join(home, ".cache", "symaira-vault")

	if r.ConfigDir != wantConfig {
		t.Errorf("ConfigDir = %q, want %q", r.ConfigDir, wantConfig)
	}
	if r.DataDir != wantData {
		t.Errorf("DataDir = %q, want %q", r.DataDir, wantData)
	}
	if r.CacheDir != wantCache {
		t.Errorf("CacheDir = %q, want %q", r.CacheDir, wantCache)
	}
	if r.LegacyDir != "" {
		t.Errorf("LegacyDir = %q, want empty", r.LegacyDir)
	}
	if r.Migrated {
		t.Error("Migrated should be false for fresh install")
	}
}

func TestPathResolver_ExistingInstall_ReadsFromLegacy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	legacyDir := filepath.Join(home, LegacyVaultSubdir)
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	r := NewPathResolver()

	wantCache := filepath.Join(home, ".cache", "symaira-vault")

	if r.ConfigDir != legacyDir {
		t.Errorf("ConfigDir = %q, want %q (legacy)", r.ConfigDir, legacyDir)
	}
	if r.DataDir != legacyDir {
		t.Errorf("DataDir = %q, want %q (legacy)", r.DataDir, legacyDir)
	}
	if r.CacheDir != wantCache {
		t.Errorf("CacheDir = %q, want %q", r.CacheDir, wantCache)
	}
	if r.LegacyDir != legacyDir {
		t.Errorf("LegacyDir = %q, want %q", r.LegacyDir, legacyDir)
	}
	if r.Migrated {
		t.Error("Migrated should be false when only legacy exists")
	}
}

func TestPathResolver_BothExist_PostMigration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	legacyDir := filepath.Join(home, LegacyVaultSubdir)
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	xdgDataDir := filepath.Join(home, ".local", "share", "symaira-vault")
	if err := os.MkdirAll(xdgDataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	r := NewPathResolver()

	wantConfig := filepath.Join(home, ".config", "symaira-vault")

	if r.ConfigDir != wantConfig {
		t.Errorf("ConfigDir = %q, want %q (XDG)", r.ConfigDir, wantConfig)
	}
	if r.DataDir != xdgDataDir {
		t.Errorf("DataDir = %q, want %q (XDG)", r.DataDir, xdgDataDir)
	}
	if r.LegacyDir != legacyDir {
		t.Errorf("LegacyDir = %q, want %q", r.LegacyDir, legacyDir)
	}
	if !r.Migrated {
		t.Error("Migrated should be true when both legacy and XDG exist")
	}
}

func TestPathResolver_SymvaultVaultEnvOverride(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SYMVAULT_VAULT", filepath.Join(home, "custom-vault"))

	r := NewPathResolver()

	wantData := filepath.Join(home, "custom-vault")
	if r.DataDir != wantData {
		t.Errorf("DataDir = %q, want %q (env override)", r.DataDir, wantData)
	}
}

func TestPathResolver_SymvaultVaultEnvTildeExpansion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SYMVAULT_VAULT", "~/my-vault")

	r := NewPathResolver()

	wantData := filepath.Join(home, "my-vault")
	if r.DataDir != wantData {
		t.Errorf("DataDir = %q, want %q (tilde expanded)", r.DataDir, wantData)
	}
}

func TestPathResolver_ConfigPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	r := NewPathResolver()

	want := filepath.Join(home, ".config", "symaira-vault", "config.yaml")
	if got := r.ConfigPath(); got != want {
		t.Errorf("ConfigPath() = %q, want %q", got, want)
	}
}

func TestPathResolver_VaultDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	r := NewPathResolver()

	want := filepath.Join(home, ".local", "share", "symaira-vault")
	if got := r.VaultDataDir(); got != want {
		t.Errorf("VaultDataDir() = %q, want %q", got, want)
	}
}

func TestPathResolver_AuditDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	r := NewPathResolver()

	want := filepath.Join(home, ".local", "share", "symaira-vault", "audit")
	if got := r.AuditDir(); got != want {
		t.Errorf("AuditDir() = %q, want %q", got, want)
	}
}

func TestPathResolver_CachePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	r := NewPathResolver()

	want := filepath.Join(home, ".cache", "symaira-vault", "update-cache.json")
	if got := r.CachePath(); got != want {
		t.Errorf("CachePath() = %q, want %q", got, want)
	}
}

func TestPathResolver_LegacyInstall_VaultDataDirEqualsDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	legacyDir := filepath.Join(home, LegacyVaultSubdir)
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	r := NewPathResolver()

	if r.VaultDataDir() != r.DataDir {
		t.Errorf("VaultDataDir() = %q, want DataDir = %q", r.VaultDataDir(), r.DataDir)
	}
}

func TestPathResolver_IsDir_Helper(t *testing.T) {
	dir := t.TempDir()
	if !isDir(dir) {
		t.Error("isDir(tempDir) = false, want true")
	}
	if isDir(filepath.Join(dir, "nonexistent")) {
		t.Error("isDir(nonexistent) = true, want false")
	}
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if isDir(file) {
		t.Error("isDir(regular file) = true, want false")
	}
}

func TestPathResolver_ExpandTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir")
	}

	tests := []struct {
		input string
		want  string
	}{
		{"~", home},
		{"~/Documents", filepath.Join(home, "Documents")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}
	for _, tt := range tests {
		got, err := expandTilde(tt.input)
		if err != nil {
			t.Errorf("expandTilde(%q) error = %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("expandTilde(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
