package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	migrationMarker        = ".migrated"
	migrationStateFile     = ".migration-state.json"
	migrationBackupDir     = ".migration-backup"
	migrationKindDirectory = "directory"
)

// MigrationItem describes one source/destination pair without exposing data.
type MigrationItem struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Kind        string `json:"kind"`
	Bytes       int64  `json:"bytes"`
}

// MigrationPlan is the complete, non-mutating description of a migration.
type MigrationPlan struct {
	LegacyDir      string          `json:"legacy_dir"`
	Items          []MigrationItem `json:"items"`
	NeedsMigration bool            `json:"needs_migration"`
}

type migrationState struct {
	Version   int      `json:"version"`
	BackupDir string   `json:"backup_dir"`
	Published []string `json:"published"`
}

// MigrationPhaseHook is used by tests to inject an interruption between phases.
// Production callers should leave it nil.
var MigrationPhaseHook func(string) error

// PreviewLegacyToXDG returns a complete migration summary and never writes.
func PreviewLegacyToXDG() (MigrationPlan, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return MigrationPlan{}, nil
	}
	legacy := filepath.Join(home, LegacyVaultSubdir)
	info, err := os.Lstat(legacy)
	if errors.Is(err, os.ErrNotExist) {
		return MigrationPlan{LegacyDir: legacy}, nil
	}
	if err != nil {
		return MigrationPlan{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return MigrationPlan{}, fmt.Errorf("legacy path is not a directory: %s", legacy)
	}
	if _, err := os.Lstat(filepath.Join(legacy, migrationMarker)); err == nil {
		return MigrationPlan{LegacyDir: legacy}, nil
	}

	plan := MigrationPlan{LegacyDir: legacy, NeedsMigration: true}
	groups := []struct{ src, dst string }{
		{"config.yaml", filepath.Join(DefaultConfigDir(), "config.yaml")},
		{"vault", filepath.Join(DefaultDataDir(), "vault")},
		{"audit", filepath.Join(DefaultDataDir(), "audit")},
		{"devices.json", filepath.Join(DefaultDataDir(), "devices.json")},
		{"pairing", filepath.Join(DefaultDataDir(), "pairing")},
		{"update-cache.json", filepath.Join(DefaultCacheDir(), "update-cache.json")},
	}
	for _, g := range groups {
		if err := appendMigrationItems(&plan, legacy, g.src, g.dst); err != nil {
			return MigrationPlan{}, err
		}
	}
	sort.Slice(plan.Items, func(i, j int) bool { return plan.Items[i].Destination < plan.Items[j].Destination })
	return plan, nil
}

func appendMigrationItems(plan *MigrationPlan, base, rel, dst string) error {
	src := filepath.Join(base, rel)
	cleanBase, _ := filepath.Abs(base)
	cleanSrc, _ := filepath.Abs(src)
	if cleanSrc != cleanBase && !strings.HasPrefix(cleanSrc, cleanBase+string(filepath.Separator)) {
		return fmt.Errorf("path traversal: %s", rel)
	}
	info, err := os.Lstat(src)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink: %s", rel)
	}
	if info.IsDir() {
		plan.Items = append(plan.Items, MigrationItem{Source: src, Destination: dst, Kind: migrationKindDirectory})
		return filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path == src {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing symlink: %s", path)
			}
			relPath, err := filepath.Rel(src, path)
			if err != nil {
				return err
			}
			target := filepath.Join(dst, relPath)
			kind := "file"
			var size int64
			if entry.IsDir() {
				kind = migrationKindDirectory
			} else {
				fi, err := entry.Info()
				if err != nil {
					return err
				}
				size = fi.Size()
			}
			plan.Items = append(plan.Items, MigrationItem{Source: path, Destination: target, Kind: kind, Bytes: size})
			return nil
		})
	}
	return appendFileItem(plan, src, dst, info)
}

func appendFileItem(plan *MigrationPlan, src, dst string, info os.FileInfo) error {
	return func() error {
		plan.Items = append(plan.Items, MigrationItem{Source: src, Destination: dst, Kind: "file", Bytes: info.Size()})
		return nil
	}()
}

// MigrateLegacyToXDG performs a verified, recoverable migration. Source data is retained.
func MigrateLegacyToXDG() (bool, error) {
	if os.Getenv("SYMVAULT_NO_PATH_MIGRATION") == "1" {
		return false, nil
	}
	plan, err := PreviewLegacyToXDG()
	if err != nil || !plan.NeedsMigration {
		return false, err
	}
	statePath := filepath.Join(plan.LegacyDir, migrationStateFile)
	if _, err := os.Lstat(statePath); err == nil {
		if err := RecoverLegacyToXDGMigration(); err != nil {
			return false, err
		}
	}
	if err := migrationPhase("previewed"); err != nil {
		return false, err
	}
	backup := filepath.Join(plan.LegacyDir, migrationBackupDir)
	if err := os.MkdirAll(backup, 0o700); err != nil {
		return false, fmt.Errorf("create backup: %w", err)
	}
	for _, item := range plan.Items {
		if item.Source == filepath.Join(plan.LegacyDir, migrationMarker) {
			continue
		}
		rel, _ := filepath.Rel(plan.LegacyDir, item.Source)
		if err := copyEntry(item.Source, filepath.Join(backup, rel)); err != nil {
			return false, fmt.Errorf("backup %s: %w", rel, err)
		}
	}
	if err := migrationPhase("backed-up"); err != nil {
		return false, err
	}
	state := migrationState{Version: 1, BackupDir: backup}
	if err := writeJSONAtomic(statePath, state, 0o600); err != nil {
		return false, err
	}
	if err := migrationPhase("state-published"); err != nil {
		return false, err
	}
	for _, item := range plan.Items {
		if !isTopLevelMigrationItem(plan.Items, item) {
			continue
		}
		if item.Kind == migrationKindDirectory {
			if _, err := os.Lstat(item.Destination); err == nil {
				return false, fmt.Errorf("destination collision: %s", item.Destination)
			}
			if err := copyEntry(item.Source, item.Destination); err != nil {
				return false, err
			}
		} else if _, err := os.Lstat(item.Destination); errors.Is(err, os.ErrNotExist) {
			if err := copyEntry(item.Source, item.Destination); err != nil {
				return false, err
			}
		} else {
			return false, fmt.Errorf("destination collision: %s", item.Destination)
		}
		state.Published = append(state.Published, item.Destination)
		if err := writeJSONAtomic(statePath, state, 0o600); err != nil {
			return false, err
		}
		if err := migrationPhase("published"); err != nil {
			return false, err
		}
	}
	if err := migrationPhase("verified"); err != nil {
		return false, err
	}
	if err := writeJSONAtomic(filepath.Join(plan.LegacyDir, migrationMarker), []byte("migration complete\n"), 0o600); err != nil {
		return false, err
	}
	if err := os.Remove(statePath); err != nil {
		return false, fmt.Errorf("remove migration state: %w", err)
	}
	return true, nil
}

func isTopLevelMigrationItem(items []MigrationItem, candidate MigrationItem) bool {
	for _, item := range items {
		if item.Kind == migrationKindDirectory && item.Source != candidate.Source && strings.HasPrefix(candidate.Source, item.Source+string(filepath.Separator)) {
			return false
		}
	}
	return true
}

// RecoverLegacyToXDGMigration removes only destinations recorded as published by an incomplete run.
func RecoverLegacyToXDGMigration() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	statePath := filepath.Join(home, LegacyVaultSubdir, migrationStateFile)
	data, err := os.ReadFile(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var state migrationState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("invalid migration state: %w", err)
	}
	for i := len(state.Published) - 1; i >= 0; i-- {
		if err := os.RemoveAll(state.Published[i]); err != nil {
			return err
		}
	}
	return os.Remove(statePath)
}

func migrationPhase(phase string) error {
	if MigrationPhaseHook != nil {
		return MigrationPhaseHook(phase)
	}
	return nil
}

func copyEntry(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink: %s", src)
	}
	if info.IsDir() {
		if mkdirErr := os.MkdirAll(dst, 0o700); mkdirErr != nil {
			return mkdirErr
		}
		_ = os.Chmod(dst, 0o700)
		entries, readErr := os.ReadDir(src)
		if readErr != nil {
			return readErr
		}
		for _, e := range entries {
			if copyErr := copyEntry(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); copyErr != nil {
				return copyErr
			}
		}
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if mkdirErr := os.MkdirAll(filepath.Dir(dst), 0o700); mkdirErr != nil {
		return mkdirErr
	}
	if writeErr := os.WriteFile(dst, data, 0o600); writeErr != nil {
		return writeErr
	}
	_ = os.Chmod(dst, 0o600)
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, data) {
		return fmt.Errorf("verification failed for %s", dst)
	}
	return nil
}

func writeJSONAtomic(path string, value any, mode os.FileMode) (returnErr error) {
	var data []byte
	var err error
	if b, ok := value.([]byte); ok {
		data = b
	} else {
		data, err = json.Marshal(value)
	}
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".migration-tmp-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if removeErr := os.Remove(name); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && returnErr == nil {
			returnErr = fmt.Errorf("remove temporary migration state: %w", removeErr)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return closeMigrationTemp(tmp, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return closeMigrationTemp(tmp, err)
	}
	if err := tmp.Sync(); err != nil {
		return closeMigrationTemp(tmp, err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func closeMigrationTemp(tmp *os.File, operationErr error) error {
	if closeErr := tmp.Close(); closeErr != nil {
		return fmt.Errorf("%w; close temporary migration state: %w", operationErr, closeErr)
	}
	return operationErr
}
