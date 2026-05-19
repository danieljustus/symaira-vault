package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/git"
)

func MaybeAutoPull(vaultDir string, cfg *configpkg.Config) {
	if cfg == nil || cfg.Git == nil {
		return
	}

	if !cfg.Git.AutoPull {
		return
	}

	hasRemote, _ := git.HasRemote(vaultDir, "origin")
	if !hasRemote {
		return
	}

	interval := cfg.Git.AutoPullInterval
	if interval <= 0 {
		interval = configpkg.Default().Git.AutoPullInterval
	}

	if !git.ShouldAutoPull(vaultDir, interval) {
		return
	}

	result := git.PullWithResult(vaultDir)
	if result.Error != nil {
		if isOfflineErr(result.Error) {
			return
		}
		return
	}

	if result.Skipped && !result.HasRemote {
		return
	}

	if err := git.SetLastSyncTime(vaultDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not record sync time: %v\n", err)
	}

	hostname, _ := os.Hostname()
	if err := git.ResolveConflicts(vaultDir, hostname); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: conflict resolution failed: %v\n", err)
	}

	conflictFiles := findConflictFiles(vaultDir)
	if len(conflictFiles) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d conflict file(s) detected after auto-pull:\n", len(conflictFiles))
		for _, f := range conflictFiles {
			fmt.Fprintf(os.Stderr, "  %s\n", f)
		}
	}
}

func isOfflineErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection timed out") ||
		strings.Contains(msg, "i/o timeout")
}

func findConflictFiles(vaultDir string) []string {
	var conflicts []string
	_ = filepath.WalkDir(vaultDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if containsConflict(d.Name()) {
			rel, _ := filepath.Rel(vaultDir, path)
			conflicts = append(conflicts, rel)
		}
		return nil
	})
	return conflicts
}

func containsConflict(name string) bool {
	return len(name) > 11 && filepath.Base(name)[0:9] == ".conflict" ||
		(len(name) > 14 && name[0:14] == "config.conflict")
}
