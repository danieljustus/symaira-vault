package config

import (
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
	maxMigrationItems      = 100_000
	maxMigrationBytes      = 1 << 30
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
	totalBytes     int64
}

type migrationState struct {
	Version   int      `json:"version"`
	BackupDir string   `json:"backup_dir"`
	Published []string `json:"published"`
	Planned   []string `json:"planned"`
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
		{configSectionVault, filepath.Join(DefaultDataDir(), configSectionVault)},
		{configSectionAudit, filepath.Join(DefaultDataDir(), configSectionAudit)},
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
		if err := addMigrationItem(plan, MigrationItem{Source: src, Destination: dst, Kind: migrationKindDirectory}); err != nil {
			return err
		}
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
			if err := addMigrationItem(plan, MigrationItem{Source: path, Destination: target, Kind: kind, Bytes: size}); err != nil {
				return err
			}
			return nil
		})
	}
	return appendFileItem(plan, src, dst, info)
}

func appendFileItem(plan *MigrationPlan, src, dst string, info os.FileInfo) error {
	return addMigrationItem(plan, MigrationItem{Source: src, Destination: dst, Kind: "file", Bytes: info.Size()})
}

func addMigrationItem(plan *MigrationPlan, item MigrationItem) error {
	if len(plan.Items) >= maxMigrationItems {
		return fmt.Errorf("migration exceeds item limit (%d)", maxMigrationItems)
	}
	if item.Bytes < 0 || item.Bytes > maxMigrationBytes {
		return fmt.Errorf("migration file exceeds size limit: %s", item.Source)
	}
	if item.Bytes > maxMigrationBytes-plan.totalBytes {
		return fmt.Errorf("migration exceeds size limit (%d bytes)", maxMigrationBytes)
	}
	plan.Items = append(plan.Items, item)
	plan.totalBytes += item.Bytes
	return nil
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
	backupFD, mkdirErr := secureMkdirOpen(backup, 0o700)
	if mkdirErr != nil {
		return false, fmt.Errorf("create backup: %w", mkdirErr)
	}
	_ = closeMigrationFD(backupFD)
	for _, item := range plan.Items {
		if !isTopLevelMigrationItem(plan.Items, item) {
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
	for _, item := range plan.Items {
		if isTopLevelMigrationItem(plan.Items, item) {
			if err := validateMigrationDestination(item.Destination, plan); err != nil {
				return false, err
			}
			state.Planned = append(state.Planned, item.Destination)
		}
	}
	if err := writeJSONAtomic(statePath, state); err != nil {
		return false, err
	}
	if err := migrationPhase("state-published"); err != nil {
		return false, err
	}
	for _, item := range plan.Items {
		if !isTopLevelMigrationItem(plan.Items, item) {
			continue
		}
		if err := validateMigrationDestination(item.Destination, plan); err != nil {
			return false, err
		}
		if _, err := os.Lstat(item.Destination); err == nil {
			return false, fmt.Errorf("destination collision: %s", item.Destination)
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		parentFD, err := secureMkdirOpen(filepath.Dir(item.Destination), 0o700)
		if err != nil {
			return false, fmt.Errorf("create destination parent: %w", err)
		}
		_ = closeMigrationFD(parentFD)
		// Journal only after confirming the destination is absent. A recursive copy
		// can fail after creating a partial destination; recovery must then know it
		// owns that new destination, but never a pre-existing user destination.
		state.Published = append(state.Published, item.Destination)
		if err := writeJSONAtomic(statePath, state); err != nil {
			return false, err
		}
		if err := migrationPhase("published"); err != nil {
			return false, err
		}
		if err := copyEntry(item.Source, item.Destination); err != nil {
			return false, err
		}
	}
	if err := migrationPhase("verified"); err != nil {
		return false, err
	}
	if err := writeJSONAtomic(filepath.Join(plan.LegacyDir, migrationMarker), []byte("migration complete\n")); err != nil {
		return false, err
	}
	if err := secureRemovePath(statePath); err != nil {
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
	data, err := secureReadFile(statePath)
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
	plan, planErr := PreviewLegacyToXDG()
	if planErr != nil {
		return fmt.Errorf("inspect migration plan: %w", planErr)
	}
	if !plan.NeedsMigration || state.Version != 1 || filepath.Clean(state.BackupDir) != filepath.Join(plan.LegacyDir, migrationBackupDir) {
		return errors.New("refusing recovery for stale or invalid migration state")
	}
	expected := make(map[string]bool, len(plan.Items))
	for _, item := range plan.Items {
		if isTopLevelMigrationItem(plan.Items, item) {
			expected[item.Destination] = true
		}
	}
	for _, path := range state.Published {
		if !expected[path] {
			return fmt.Errorf("refusing recovery of unexpected destination: %s", path)
		}
		if err := validateMigrationDestination(path, plan); err != nil {
			return err
		}
	}
	for i := len(state.Published) - 1; i >= 0; i-- {
		if err := secureRemovePath(state.Published[i]); err != nil {
			return err
		}
	}
	if err := secureRemovePath(state.BackupDir); err != nil {
		return fmt.Errorf("remove migration backup: %w", err)
	}
	return secureRemovePath(statePath)
}

func validateMigrationDestination(path string, plan MigrationPlan) error {
	clean := filepath.Clean(path)
	allowed := false
	for _, item := range plan.Items {
		if isTopLevelMigrationItem(plan.Items, item) && filepath.Clean(item.Destination) == clean {
			allowed = true
			break
		}
	}
	if !allowed || !filepath.IsAbs(clean) {
		return fmt.Errorf("refusing unsafe migration destination: %s", path)
	}
	for _, root := range []string{DefaultConfigDir(), DefaultDataDir(), DefaultCacheDir()} {
		root = filepath.Clean(root)
		rel, err := filepath.Rel(root, clean)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if err := rejectSymlinkComponents(root, clean); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("refusing destination outside XDG roots: %s", path)
}

func rejectSymlinkComponents(root, path string) error {
	root = filepath.Clean(root)
	// Check the configured XDG home and the application directory below it;
	// system ancestors such as macOS's /var symlink are outside our root.
	if parent := filepath.Dir(root); filepath.Base(parent) != "." {
		if info, err := os.Lstat(parent); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink XDG root: %s", parent)
		}
	}
	if info, err := os.Lstat(root); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink XDG root: %s", root)
	}
	rel, _ := filepath.Rel(root, filepath.Clean(path))
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink destination component: %s", cur)
		}
	}
	return nil
}

func migrationPhase(phase string) error {
	if MigrationPhaseHook != nil {
		return MigrationPhaseHook(phase)
	}
	return nil
}

func copyEntry(src, dst string) error {
	return secureCopyEntry(src, dst)
}

func writeJSONAtomic(path string, value any) error {
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
	return secureWriteJSONAtomic(path, data)
}
