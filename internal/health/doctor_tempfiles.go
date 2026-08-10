package health

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// staleTempFileAge is deliberately generous: an atomic write normally takes
// milliseconds, but a slow or paused process must not lose its in-flight temp
// file while it is still writing.
const staleTempFileAge = 24 * time.Hour

func checkVaultStaleTempFiles(vaultDir string, _ Options) Result {
	r := Result{
		ID:      "vault.stale_temp_files",
		Name:    "Stale atomic-write temp files",
		Fixable: true,
	}
	r.Fix = func() error {
		if FixDryRun {
			return nil
		}
		stale, err := findStaleTempFiles(vaultDir, time.Now())
		if err != nil {
			return err
		}
		for _, path := range stale {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove %s: %w", filepath.Base(path), err)
			}
		}
		return nil
	}

	stale, err := findStaleTempFiles(vaultDir, time.Now())
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot inspect atomic-write temp files: " + err.Error()
		return r
	}
	if len(stale) == 0 {
		r.Status = StatusOK
		r.Message = "no stale atomic-write temp files"
		return r
	}

	names := make([]string, 0, len(stale))
	for _, path := range stale {
		names = append(names, filepath.Base(path))
	}
	r.Status = StatusWarn
	r.Message = fmt.Sprintf("%d stale atomic-write temp file(s): %s", len(names), strings.Join(names, ", "))
	r.Hint = "run `symvault doctor --fix` to remove files older than 24h"
	return r
}

func findStaleTempFiles(vaultDir string, now time.Time) ([]string, error) {
	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		return nil, err
	}

	stale := make([]string, 0)
	for _, entry := range entries {
		// AtomicWriteFile creates names such as manifest.age.tmp-12345.
		// Restrict the sweep to direct children of vaultDir and this exact
		// marker; never recurse or inspect unrelated files elsewhere.
		if entry.IsDir() || !strings.Contains(entry.Name(), ".tmp-") {
			continue
		}
		path := filepath.Join(vaultDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if !info.Mode().IsRegular() || now.Sub(info.ModTime()) <= staleTempFileAge {
			continue
		}
		stale = append(stale, path)
	}
	sort.Strings(stale)
	return stale, nil
}
