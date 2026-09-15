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
	home := setTestHome(t)

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
	home := setTestHome(t)

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
	home := setTestHome(t)

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
	home := setTestHome(t)
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
	home := setTestHome(t)
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
	home := setTestHome(t)

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
	home := setTestHome(t)

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
	home := setTestHome(t)

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
	home := setTestHome(t)

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
	home := setTestHome(t)

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

func TestExpandTildeAgainstSuppliedHome(t *testing.T) {
	// The home directory is supplied rather than discovered, so this table is
	// deterministic and never reads the operating user's real home.
	const home = "/fixture/home/probe"

	tests := []struct {
		input string
		want  string
	}{
		{"~", home},
		{"~/Documents", filepath.Join(home, "Documents")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
		{"~notatilde", "~notatilde"},
	}
	for _, tt := range tests {
		if got := expandTildeAgainst(tt.input, home); got != tt.want {
			t.Errorf("expandTildeAgainst(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ResolvePaths is the pure CFG-001 seam: the same inputs must always produce
// the same resolution, with no filesystem or environment access.
func TestResolvePathsContract(t *testing.T) {
	const home = "/fixture/home/probe"
	base := PathEnvironment{Home: home}

	tests := []struct {
		name                        string
		env                         PathEnvironment
		config, data, cache, legacy string
		migrated                    bool
	}{
		{
			name:   "new install uses xdg exclusively",
			env:    base,
			config: home + "/.config/symaira-vault",
			data:   home + "/.local/share/symaira-vault",
			cache:  home + "/.cache/symaira-vault",
		},
		{
			name:     "existing legacy install reads from legacy",
			env:      PathEnvironment{Home: home, LegacyDirExists: true},
			config:   home + "/.symvault",
			data:     home + "/.symvault",
			cache:    home + "/.cache/symaira-vault",
			legacy:   home + "/.symvault",
			migrated: false,
		},
		{
			name:     "post migration prefers xdg and reports migrated",
			env:      PathEnvironment{Home: home, LegacyDirExists: true, XDGDataDirExists: true},
			config:   home + "/.config/symaira-vault",
			data:     home + "/.local/share/symaira-vault",
			cache:    home + "/.cache/symaira-vault",
			legacy:   home + "/.symvault",
			migrated: true,
		},
		{
			name:   "explicit xdg values win over the defaults",
			env:    PathEnvironment{Home: home, XDGConfigHome: "/x/cfg", XDGDataHome: "/x/data", XDGCacheHome: "/x/cache"},
			config: "/x/cfg/symaira-vault",
			data:   "/x/data/symaira-vault",
			cache:  "/x/cache/symaira-vault",
		},
		{
			// A variable that is set but empty must fall back exactly like an
			// unset one, or the resolved path becomes relative.
			name:   "empty xdg values fall back to the defaults",
			env:    PathEnvironment{Home: home, XDGConfigHome: "", XDGDataHome: "", XDGCacheHome: ""},
			config: home + "/.config/symaira-vault",
			data:   home + "/.local/share/symaira-vault",
			cache:  home + "/.cache/symaira-vault",
		},
		{
			name:   "vault override replaces only the data directory",
			env:    PathEnvironment{Home: home, VaultOverride: "  /elsewhere/vault  "},
			config: home + "/.config/symaira-vault",
			data:   "/elsewhere/vault",
			cache:  home + "/.cache/symaira-vault",
		},
		{
			name:   "vault override expands a leading tilde against home",
			env:    PathEnvironment{Home: home, VaultOverride: "~/vaults/work"},
			config: home + "/.config/symaira-vault",
			data:   home + "/vaults/work",
			cache:  home + "/.cache/symaira-vault",
		},
		{
			name: "no home yields a zero resolver",
			env:  PathEnvironment{XDGConfigHome: "/x/cfg"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolvePaths(tt.env)
			if got.ConfigDir != filepath.FromSlash(tt.config) {
				t.Errorf("ConfigDir = %q, want %q", got.ConfigDir, tt.config)
			}
			if got.DataDir != filepath.FromSlash(tt.data) {
				t.Errorf("DataDir = %q, want %q", got.DataDir, tt.data)
			}
			if got.CacheDir != filepath.FromSlash(tt.cache) {
				t.Errorf("CacheDir = %q, want %q", got.CacheDir, tt.cache)
			}
			if got.LegacyDir != filepath.FromSlash(tt.legacy) {
				t.Errorf("LegacyDir = %q, want %q", got.LegacyDir, tt.legacy)
			}
			if got.Migrated != tt.migrated {
				t.Errorf("Migrated = %v, want %v", got.Migrated, tt.migrated)
			}
		})
	}
}

// ConfigPath must follow the resolved config directory. For a legacy install
// that is the legacy directory, not the XDG one.
func TestConfigPathFollowsResolvedConfigDir(t *testing.T) {
	const home = "/fixture/home/probe"
	legacy := ResolvePaths(PathEnvironment{Home: home, LegacyDirExists: true})
	want := filepath.Join(home, ".symvault", "config.yaml")
	if got := legacy.ConfigPath(); got != want {
		t.Fatalf("legacy install ConfigPath() = %q, want %q", got, want)
	}
}
