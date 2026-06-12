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

// NewPathResolver creates a PathResolver that detects existing paths and resolves XDG.
// For existing installs: reads from legacy, writes to XDG.
// For new installs: uses XDG exclusively.
func NewPathResolver() *PathResolver {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return &PathResolver{}
	}

	legacyDir := filepath.Join(home, LegacyVaultSubdir)
	legacyExists := isDir(legacyDir)

	xdgDataDir := DefaultDataDir()
	xdgDataExists := isDir(xdgDataDir)

	r := &PathResolver{
		CacheDir: DefaultCacheDir(),
	}

	if legacyExists {
		r.LegacyDir = legacyDir
	}

	switch {
	case legacyExists && !xdgDataExists:
		// Existing install: read from legacy, write target is XDG.
		// config.yaml and vault data live in the legacy directory.
		r.ConfigDir = legacyDir
		r.DataDir = legacyDir
		r.Migrated = false
	case legacyExists && xdgDataExists:
		// Post-migration: both exist, prefer XDG.
		r.ConfigDir = DefaultConfigDir()
		r.DataDir = xdgDataDir
		r.Migrated = true
	default:
		// New install: XDG exclusively.
		r.ConfigDir = DefaultConfigDir()
		r.DataDir = DefaultDataDir()
		r.Migrated = false
	}

	// SYMVAULT_VAULT env var overrides the resolved data directory.
	if envVault := strings.TrimSpace(os.Getenv("SYMVAULT_VAULT")); envVault != "" {
		if expanded, err := expandTilde(envVault); err == nil {
			r.DataDir = expanded
		}
	}

	return r
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

// expandTilde expands a leading ~ in a path to the user's home directory.
func expandTilde(path string) (string, error) {
	if path == "~" {
		return os.UserHomeDir()
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	}
	return filepath.Clean(path), nil
}
