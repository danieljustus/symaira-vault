package config

import (
	"os"
	"path/filepath"
	"strings"
)

// PathResolver handles XDG path resolution with legacy ~/.symvault/ fallback.
// For existing installs: reads from legacy, writes to XDG.
// For new installs: uses XDG exclusively.
type PathResolver struct {
	// ConfigDir is the resolved config directory (XDG or legacy).
	// Contains config.yaml.
	ConfigDir string
	// DataDir is the resolved data directory (XDG or legacy).
	// Contains vault entries, identity.age, and vault config.
	DataDir string
	// CacheDir is the resolved cache directory (XDG).
	CacheDir string
	// LegacyDir is the old ~/.symvault/ path if it exists.
	LegacyDir string
	// Migrated indicates whether both legacy and XDG data dirs exist
	// (i.e., migration from legacy has completed).
	Migrated bool
}

// PathEnvironment is the discovered environment that path resolution is
// computed from. Keeping the inputs explicit makes resolution deterministic and
// lets the CFG-001 contract pin it without touching the filesystem or the
// process environment.
type PathEnvironment struct {
	// Home is the user's home directory. An empty Home yields a zero
	// PathResolver, matching the behavior when the home directory cannot be
	// determined at all.
	Home string
	// XDGConfigHome, XDGDataHome and XDGCacheHome are the raw environment
	// values. An empty value falls back to the XDG default beneath Home.
	XDGConfigHome string
	XDGDataHome   string
	XDGCacheHome  string
	// VaultOverride is the raw SYMVAULT_VAULT value. It is trimmed, and a
	// leading "~" is expanded against Home.
	VaultOverride string
	// LegacyDirExists and XDGDataDirExists are the two filesystem probes the
	// resolution depends on. The caller performs them; the resolution itself
	// touches no filesystem.
	LegacyDirExists  bool
	XDGDataDirExists bool
}

// ResolvePaths is the pure path-resolution contract.
// For existing installs: reads from legacy, writes to XDG.
// For new installs: uses XDG exclusively.
func ResolvePaths(env PathEnvironment) PathResolver {
	if env.Home == "" {
		return PathResolver{}
	}

	legacyDir := filepath.Join(env.Home, LegacyVaultSubdir)
	resolver := PathResolver{
		CacheDir: filepath.Join(xdgBase(env.XDGCacheHome, env.Home, ".cache"), CacheSubdir),
	}
	xdgConfigDir := filepath.Join(xdgBase(env.XDGConfigHome, env.Home, ".config"), ConfigSubdir)
	xdgDataDir := filepath.Join(xdgBase(env.XDGDataHome, env.Home, ".local", "share"), DataSubdir)

	if env.LegacyDirExists {
		resolver.LegacyDir = legacyDir
	}

	switch {
	case env.LegacyDirExists && !env.XDGDataDirExists:
		// Existing install: read from legacy, write target is XDG.
		resolver.ConfigDir = legacyDir
		resolver.DataDir = legacyDir
		resolver.Migrated = false
	case env.LegacyDirExists && env.XDGDataDirExists:
		// Post-migration: both exist, prefer XDG.
		resolver.ConfigDir = xdgConfigDir
		resolver.DataDir = xdgDataDir
		resolver.Migrated = true
	default:
		// New install: XDG exclusively.
		resolver.ConfigDir = xdgConfigDir
		resolver.DataDir = xdgDataDir
		resolver.Migrated = false
	}

	if override := strings.TrimSpace(env.VaultOverride); override != "" {
		resolver.DataDir = expandTildeAgainst(override, env.Home)
	}

	return resolver
}

// xdgBase returns the raw XDG value when set, and otherwise the XDG default
// beneath home. An environment variable that is set but empty falls back, the
// same as an unset one.
func xdgBase(value, home string, fallback ...string) string {
	if value != "" {
		return value
	}
	return filepath.Join(append([]string{home}, fallback...)...)
}

// expandTildeAgainst expands a leading "~" against the supplied home rather
// than discovering it, so the resolution stays pure.
func expandTildeAgainst(path, home string) string {
	if path == "~" {
		return home
	}
	if rest, found := strings.CutPrefix(path, "~/"); found {
		return filepath.Join(home, rest)
	}
	return path
}

// NewPathResolver discovers the environment and resolves the paths from it.
// The resolution itself lives in ResolvePaths; this is the discovery wrapper.
func NewPathResolver() *PathResolver {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	env := PathEnvironment{
		Home:          home,
		XDGConfigHome: os.Getenv("XDG_CONFIG_HOME"),
		XDGDataHome:   os.Getenv("XDG_DATA_HOME"),
		XDGCacheHome:  os.Getenv("XDG_CACHE_HOME"),
		VaultOverride: os.Getenv("SYMVAULT_VAULT"),
	}
	if home != "" {
		env.LegacyDirExists = isDir(filepath.Join(home, LegacyVaultSubdir))
		env.XDGDataDirExists = isDir(filepath.Join(xdgBase(env.XDGDataHome, home, ".local", "share"), DataSubdir))
	}
	resolver := ResolvePaths(env)
	return &resolver
}

// ConfigPath returns the path to config.yaml.
func (r *PathResolver) ConfigPath() string {
	return filepath.Join(r.ConfigDir, "config.yaml")
}

// VaultDataDir returns the directory containing encrypted vault entries,
// identity.age, and vault-level config.yaml. This is the same as DataDir
// because the vault layout is flat (entries/ subdirectory is within this dir).
func (r *PathResolver) VaultDataDir() string {
	return r.DataDir
}

// AuditDir returns the directory for audit logs.
func (r *PathResolver) AuditDir() string {
	return filepath.Join(r.DataDir, "audit")
}

// CachePath returns the path to the update cache file.
func (r *PathResolver) CachePath() string {
	return filepath.Join(r.CacheDir, "update-cache.json")
}

// isDir reports whether path exists and is a directory.
func isDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
