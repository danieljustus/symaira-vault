package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/fsutil"
)

// entryFileStem strips the .age suffix and any sync-engine conflict suffix so
// two files that map to the same logical entry collapse to one key. Example:
// "login.example.age" and "login.example.conflict-20260826T101500.age" both
// reduce to "login.example".
func entryFileStem(name string) string {
	base := strings.TrimSuffix(name, ".age")
	if idx := strings.Index(base, ".conflict-"); idx >= 0 {
		base = base[:idx]
	}
	return base
}

// higherVersion returns the candidate with the higher EntryMetadata.Version,
// breaking ties deterministically by the most recent Updated timestamp and
// versionAfter reports whether a should win over b in the deterministic
// last-writer-wins policy: higher EntryMetadata.Version wins, then the more
// recently Updated timestamp, then the lexicographically larger path as a
// stable tiebreak so the outcome never depends on directory ordering. It
// mirrors sync.WinnerByVersion without importing the sync package (which would
// create an import cycle).
func versionAfter(a EntryMetadata, aPath string, b EntryMetadata, bPath string) bool {
	if a.Version != b.Version {
		return a.Version > b.Version
	}
	if !a.Updated.Equal(b.Updated) {
		return a.Updated.After(b.Updated)
	}
	// Equal version and timestamp: keep the larger logical path as winner so
	// the comparison is order-independent and never relies on map iteration.
	return aPath >= bPath
}

// reconcileEntryConflicts resolves concurrent edits to the same logical entry
// in a filesystem-synced vault. Two devices may each write a .age file for the
// same entry; the higher EntryMetadata.Version wins and every losing copy is
// preserved as a conflict copy (lossless). Files are grouped by stem; within a
// group the canonical file (matching the stem exactly) is preferred as the
// winner path. Unreadable files are kept untouched rather than dropped so no
// data is ever lost.
func reconcileEntryConflicts(vaultDir string, identity *age.X25519Identity) error {
	entriesDir := filepath.Join(vaultDir, entriesDirName)
	matches, err := filepath.Glob(filepath.Join(entriesDir, "*.age"))
	if err != nil {
		return err
	}
	groups := map[string][]string{}
	for _, path := range matches {
		groups[entryFileStem(filepath.Base(path))] = append(groups[entryFileStem(filepath.Base(path))], path)
	}

	for stem, files := range groups {
		if len(files) < 2 {
			continue
		}
		type cand struct {
			path string
			meta EntryMetadata
		}
		var cands []cand
		for _, f := range files {
			m, merr := GetEntryMetadata(vaultDir, stem, identity)
			if merr != nil {
				// Cannot read this candidate; leave it in place.
				continue
			}
			cands = append(cands, cand{path: f, meta: *m})
		}
		if len(cands) < 2 {
			continue
		}
		winner := cands[0]
		losers := []cand{cands[1]}
		for _, l := range cands[2:] {
			if versionAfter(l.meta, l.path, winner.meta, winner.path) {
				// l beats the current winner: demote the winner to a loser.
				losers = append(losers, winner)
				winner = l
			} else {
				losers = append(losers, l)
			}
		}
		for _, l := range losers {
			if l.path == winner.path {
				continue
			}
			if _, perr := preserveConflictCopy(l.path); perr != nil {
				if !os.IsNotExist(perr) {
					return perr
				}
			}
		}
	}
	return nil
}

// preserveConflictCopy writes an immutable copy of srcPath to a sibling
// "<name>.conflict-<utc-timestamp>.age" file (with an incrementing suffix on
// collision) and returns its path. It never deletes or mutates the source, so
// the losing side of a sync conflict is always retained losslessly.
func preserveConflictCopy(srcPath string) (string, error) {
	info, err := os.Lstat(srcPath)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("cannot preserve conflict copy of a directory: %s", srcPath)
	}
	data, err := os.ReadFile(srcPath) // #nosec G304 -- srcPath is an explicit entry file supplied by the reconciler
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(srcPath)
	base := filepath.Base(srcPath)
	name := strings.TrimSuffix(base, ".age")
	ts := time.Now().UTC().Format("20060102T150405")
	dst := filepath.Join(dir, fmt.Sprintf("%s.conflict-%s.age", name, ts))
	for attempt := 1; ; attempt++ {
		if _, err := os.Lstat(dst); os.IsNotExist(err) {
			break
		}
		dst = filepath.Join(dir, fmt.Sprintf("%s.conflict-%s-%d.age", name, ts, attempt))
	}
	if err := fsutil.AtomicWriteFile(dst, data, 0o600); err != nil {
		return "", err
	}
	return dst, nil
}
