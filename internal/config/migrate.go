package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const migrationMarker = ".migrated"

// MigrateLegacyToXDG migrates data from legacy ~/.symvault/ to XDG paths.
// It is a no-op if:
//   - Legacy dir doesn't exist
//   - XDG data dir already exists (migration already done)
//   - SYMVAULT_NO_PATH_MIGRATION=1 is set
//
// Returns true if migration was performed.
func MigrateLegacyToXDG() (bool, error) {
	if os.Getenv("SYMVAULT_NO_PATH_MIGRATION") == "1" {
		return false, nil
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false, nil
	}

	legacyDir := filepath.Join(home, LegacyVaultSubdir)
	xdgDataDir := DefaultDataDir()
	xdgConfigDir := DefaultConfigDir()
	xdgCacheDir := DefaultCacheDir()

	// Check if legacy exists.
	legacyInfo, err := os.Stat(legacyDir)
	if err != nil || !legacyInfo.IsDir() {
		return false, nil // No legacy dir, nothing to migrate.
	}

	// Check if migration marker exists.
	markerPath := filepath.Join(legacyDir, migrationMarker)
	if _, err := os.Stat(markerPath); err == nil {
		return false, nil // Already migrated.
	}

	// Check if XDG data dir already exists (someone manually migrated).
	if _, err := os.Stat(xdgDataDir); err == nil {
		// XDG exists — leave marker and return.
		writeMarker(legacyDir)
		return false, nil
	}

	// Perform migration.
	// 1. Create XDG directories.
	for _, dir := range []string{xdgConfigDir, xdgDataDir, xdgCacheDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return false, fmt.Errorf("create XDG dir %s: %w", dir, err)
		}
	}

	// 2. Migrate config.
	if err := migrateFile(filepath.Join(legacyDir, "config.yaml"), filepath.Join(xdgConfigDir, "config.yaml")); err != nil {
		return false, fmt.Errorf("migrate config.yaml: %w", err)
	}

	// 3. Migrate vault data (entire directory).
	if err := migrateDir(filepath.Join(legacyDir, "vault"), filepath.Join(xdgDataDir, "vault")); err != nil {
		return false, fmt.Errorf("migrate vault/: %w", err)
	}

	// 4. Migrate audit.
	if err := migrateDir(filepath.Join(legacyDir, "audit"), filepath.Join(xdgDataDir, "audit")); err != nil {
		return false, fmt.Errorf("migrate audit/: %w", err)
	}

	// 5. Migrate devices.json.
	if err := migrateFile(filepath.Join(legacyDir, "devices.json"), filepath.Join(xdgDataDir, "devices.json")); err != nil {
		return false, fmt.Errorf("migrate devices.json: %w", err)
	}

	// 6. Migrate pairing.
	if err := migrateDir(filepath.Join(legacyDir, "pairing"), filepath.Join(xdgDataDir, "pairing")); err != nil {
		return false, fmt.Errorf("migrate pairing/: %w", err)
	}

	// 7. Migrate update cache.
	if err := migrateFile(filepath.Join(legacyDir, "update-cache.json"), filepath.Join(xdgCacheDir, "update-cache.json")); err != nil {
		return false, fmt.Errorf("migrate update-cache.json: %w", err)
	}

	// 8. Leave marker.
	writeMarker(legacyDir)

	fmt.Fprintf(os.Stderr, "Migrated symvault data from %s to XDG paths.\n", legacyDir)

	return true, nil
}

func migrateFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // Source doesn't exist, skip.
		}
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

func migrateDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := migrateDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := migrateFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeMarker(legacyDir string) {
	markerPath := filepath.Join(legacyDir, migrationMarker)
	content := fmt.Sprintf("migrated at %s\n", time.Now().Format(time.RFC3339))
	_ = os.WriteFile(markerPath, []byte(content), 0o600) // Best-effort; caller continues regardless.
}
