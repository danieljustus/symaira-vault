// Package sync provides the iCloud Drive / filesystem sync substrate for the
// vault. It is CLI-agnostic, contains no Apple-specific imports, and reuses the
// vault's existing manifest guards rather than reimplementing them.
//
// The substrate covers three concerns:
//
//  1. Deterministic last-writer-wins conflict resolution by EntryMetadata.Version
//     (WinnerByVersion) with lossless conflict-copy preservation
//     (PreserveConflictCopy / ReconcileConflict).
//  2. Keeping the git repository outside the synced folder — handled by the git
//     package's EnsureGitOutside, which vault.Open invokes for filesystem-synced
//     vaults.
//  3. Manifest verification on load is performed by vault.Open itself (it cannot
//     live in this package without creating an import cycle), which surfaces
//     out-of-band entries via Vault.SyncReport instead of silently swallowing
//     them.
package sync

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/fsutil"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

// ReconcileConflict keeps the winner at its canonical path and preserves the
// loser as a conflict copy, returning the path of the created conflict copy.
// It is the lossless, deterministic resolution step for a two-device edit
// conflict on the same logical entry: callers decide the winner via
// WinnerByVersion and pass the loser's path here.

// WinnerByVersion implements a deterministic last-writer-wins conflict policy
// for two entries that share the same logical path but carry different
// metadata. The entry with the higher EntryMetadata.Version wins; the loser is
// returned so the caller can preserve it as a conflict copy. No data is ever
// discarded.
//
// The resolution is fully deterministic:
//   - highest Version wins,
//   - on equal Version, the most recently Updated entry wins,
//   - on equal Updated, the lexicographically smaller path wins (stable tiebreak
//     so the outcome never depends on map iteration order).
func WinnerByVersion(path string, a, b vault.EntryMetadata) (winner, loser vault.EntryMetadata) {
	if a.Version != b.Version {
		if a.Version > b.Version {
			return a, b
		}
		return b, a
	}
	if !a.Updated.Equal(b.Updated) {
		if a.Updated.After(b.Updated) {
			return a, b
		}
		return b, a
	}
	if path == "" || pathIsSmallerEqual(a, b) {
		return a, b
	}
	return b, a
}

// pathIsSmallerEqual is the final stable tiebreak used when both entries share
// the same Version and Updated timestamp. It compares the canonical JSON form of
// the two metadata values so the winner is determined by the metadata contents
// alone and never by argument order or map iteration.
func pathIsSmallerEqual(a, b vault.EntryMetadata) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return true
	}
	return string(ja) <= string(jb)
}

// conflictCopyName builds a deterministic, collision-resistant conflict copy
// filename for base (a .age file) using a UTC timestamp and an incrementing
// suffix when the candidate already exists.
func conflictCopyName(dir, base string, attempt int) string {
	name := strings.TrimSuffix(base, ".age")
	ts := time.Now().UTC().Format("20060102T150405")
	suffix := ""
	if attempt > 0 {
		suffix = fmt.Sprintf("-%d", attempt)
	}
	return filepath.Join(dir, fmt.Sprintf("%s.conflict-%s%s.age", name, ts, suffix))
}

// PreserveConflictCopy writes an immutable copy of srcPath to a sibling
// conflict file named "<name>.conflict-<timestamp>.age" and returns its path.
// It never deletes or mutates the source — lossless conflict preservation is a
// hard guarantee of the sync substrate. If a conflict copy with the generated
// name already exists, an incrementing suffix is appended until a free name is
// found.
func PreserveConflictCopy(srcPath string) (string, error) {
	info, err := os.Lstat(srcPath)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("cannot preserve conflict copy of a directory: %s", srcPath)
	}
	data, err := os.ReadFile(srcPath) // #nosec G304 -- srcPath is an explicit entry file supplied by the resolver
	if err != nil {
		return "", fmt.Errorf("read loser entry %s: %w", srcPath, err)
	}

	dir := filepath.Dir(srcPath)
	base := filepath.Base(srcPath)
	dst := conflictCopyName(dir, base, 0)
	for attempt := 1; ; attempt++ {
		if _, err := os.Lstat(dst); os.IsNotExist(err) {
			break
		}
		dst = conflictCopyName(dir, base, attempt)
	}

	if err := fsutil.AtomicWriteFile(dst, data, 0o600); err != nil {
		return "", fmt.Errorf("write conflict copy %s: %w", dst, err)
	}
	return dst, nil
}

// ReconcileConflict keeps the winner at its canonical path and preserves the
// loser as a conflict copy, returning the path of the created conflict copy.
// It is the lossless, deterministic resolution step for a two-device edit
// conflict on the same logical entry: callers decide the winner via
// WinnerByVersion and pass the loser's path here.
func ReconcileConflict(loserPath string) (string, error) {
	return PreserveConflictCopy(loserPath)
}
