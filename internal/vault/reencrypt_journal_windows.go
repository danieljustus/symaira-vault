//go:build windows

package vault

import (
	"fmt"
	"os"
	"path/filepath"
)

// Windows has no directory fsync primitive. Every staged file is flushed with
// File.Sync before replacement, and the journal is atomically replaced. The
// journal remains the recovery authority if Windows loses power between those
// operations.
func syncReencryptDirectory(_ string) error { return nil }

func reencryptArtifactPaths(item *reencryptStaged) (string, string) {
	staged, ok := item.platform.(*windowsReencryptStaged)
	if !ok {
		return "", ""
	}
	return staged.tempPath, staged.backupPath
}

func recoverReencryptArtifacts(vaultDir string, journal *reencryptJournal) error {
	for _, entry := range journal.Entries {
		if entry.Digest == "" {
			continue
		}
		if err := validateReencryptJournalPath(vaultDir, entry.Path); err != nil {
			return err
		}
		if entry.Temp != "" {
			if err := validateReencryptJournalPath(vaultDir, entry.Temp); err != nil {
				return err
			}
		}
		if entry.Backup != "" {
			if err := validateReencryptJournalPath(vaultDir, entry.Backup); err != nil {
				return err
			}
		}
		targetMatches, err := verifyReencryptDigest(entry.Path, entry.Digest)
		if err != nil {
			return fmt.Errorf("verify target %q: %w", entry.Path, err)
		}
		backupExists, err := reencryptRegularExists(entry.Backup)
		if err != nil {
			return err
		}
		targetExists, err := reencryptRegularExists(entry.Path)
		if err != nil {
			return err
		}
		if !targetMatches && !backupExists && !targetExists {
			return fmt.Errorf("target and original backup are both missing for %q", entry.Path)
		}
		if targetMatches {
			if backupExists {
				if err := os.Remove(entry.Backup); err != nil {
					return fmt.Errorf("remove old ciphertext backup: %w", err)
				}
			}
		} else if backupExists {
			if _, err := os.Lstat(entry.Path); err == nil {
				return fmt.Errorf("refusing to replace changed target %q during recovery", entry.Path)
			} else if !os.IsNotExist(err) {
				return err
			}
			if err := os.Rename(entry.Backup, entry.Path); err != nil {
				return fmt.Errorf("restore original ciphertext: %w", err)
			}
		}
		if entry.Temp != "" {
			if err := removeReencryptArtifact(entry.Temp); err != nil {
				return err
			}
		}
	}
	return nil
}

func cleanupUnjournaledReencryptArtifacts(_ string, _ *reencryptJournal) error {
	// A filename is not authority to distinguish an abandoned transaction
	// artifact from a legitimate user entry. Journaled artifacts are removed
	// by recoverReencryptArtifacts; unknown files must be preserved.
	return nil
}

func validateReencryptJournalPath(vaultDir, path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("invalid recovery path %q", path)
	}
	rel, err := filepath.Rel(vaultDir, path)
	if err != nil || rel == ".." || (len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator)) {
		return fmt.Errorf("recovery path escapes vault: %q", path)
	}
	return nil
}

func reencryptRegularExists(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("re-encryption backup is not a regular file")
	}
	return true, nil
}

func removeReencryptArtifact(path string) error {
	if path == "" {
		return nil
	}
	if exists, err := reencryptRegularExists(path); err != nil {
		return err
	} else if !exists {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove re-encryption artifact: %w", err)
	}
	return nil
}
