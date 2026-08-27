package intake

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Watcher scans a user-selected folder for new credential material and
// stages it as quarantined review batches. It is deliberately conservative:
// files are only picked up after their size/mtime stabilized (debounce), it
// never deletes sources, never auto-promotes, and it keeps a per-file ledger
// so already-staged files are not re-intaked on the next poll.
type Watcher struct {
	dir      string
	interval time.Duration
	debounce time.Duration
	spool    *Spool
	opts     Options

	// ledger remembers the (size, mtime, sha) of staged files to dedupe
	// across polls without touching the vault.
	ledger map[string]string
}

// WatcherOptions configures the consume-folder watcher.
type WatcherOptions struct {
	Interval time.Duration
	Debounce time.Duration
	Options  Options
}

// DefaultWatcherOptions returns conservative defaults: poll every 10s, only
// pick up files stable for at least 5s.
func DefaultWatcherOptions() WatcherOptions {
	return WatcherOptions{
		Interval: 10 * time.Second,
		Debounce: 5 * time.Second,
		Options:  DefaultOptions(),
	}
}

// NewWatcher creates a watcher for dir.
func NewWatcher(dir string, opts WatcherOptions) (*Watcher, error) {
	if dir == "" {
		return nil, fmt.Errorf("watch directory is required")
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat watch directory: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("watch path is not a directory: %s", dir)
	}
	spool, err := NewSpool()
	if err != nil {
		return nil, err
	}
	if opts.Interval <= 0 {
		opts.Interval = 10 * time.Second
	}
	if opts.Debounce <= 0 {
		opts.Debounce = 5 * time.Second
	}
	return &Watcher{
		dir:      dir,
		interval: opts.Interval,
		debounce: opts.Debounce,
		spool:    spool,
		opts:     opts.Options,
		ledger:   map[string]string{},
	}, nil
}

// Close releases the watcher's spool.
func (w *Watcher) Close() {
	w.spool.Remove()
}

// ScanResult summarizes one poll.
type ScanResult struct {
	Scanned     int      `json:"scanned"`
	StagedPaths []string `json:"staged"`
	Skipped     []string `json:"skipped,omitempty"`
	Errors      []string `json:"errors,omitempty"`

	// internal: hydrated results for the batch writer; not serialized.
	StagedResults []FileResult `json:"-"`
}

// Scan performs one poll: list candidate files, pick up stable new ones,
// stage them via ProcessFiles (quarantine write is the caller's job via
// WriteBatch). It returns the staged spool paths so the caller can write the
// batch and clean up.
func (w *Watcher) Scan() (ScanResult, error) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return ScanResult{}, fmt.Errorf("read watch directory: %w", err)
	}

	now := time.Now()
	var candidates []string
	var res ScanResult
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Skip hidden files (dotfiles, .DS_Store, partial downloads).
		if len(e.Name()) > 0 && e.Name()[0] == '.' {
			continue
		}
		path := filepath.Join(w.dir, e.Name())
		info, err := e.Info()
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		// Debounce: the file must not have changed for w.debounce.
		if now.Sub(info.ModTime()) < w.debounce {
			continue
		}
		key := fmt.Sprintf("%s|%d|%d", path, info.Size(), info.ModTime().UnixNano())
		if _, seen := w.ledger[key]; seen {
			continue
		}
		candidates = append(candidates, path)
		res.Scanned++
	}
	sort.Strings(candidates)

	for _, path := range candidates {
		fr, err := ProcessFile(w.spool, path, w.opts)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			continue
		}
		if fr.Status != StatusOK {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %s", filepath.Base(path), fr.Reason))
			continue
		}
		// Remember the exact (size, mtime) so the next poll skips it; the
		// ledger is keyed by those, so a file that changes gets re-staged.
		if info, statErr := os.Stat(path); statErr == nil {
			w.ledger[fmt.Sprintf("%s|%d|%d", path, info.Size(), info.ModTime().UnixNano())] = fr.Provenance.SHA256
		}
		res.StagedPaths = append(res.StagedPaths, fr.spoolPath)
		res.StagedResults = append(res.StagedResults, fr)
	}
	return res, nil
}

// Run polls until stop is closed (or forever when stop is nil), calling
// onBatch for each non-empty scan. onBatch receives the staged results and
// must write the quarantine batch (WriteBatch) and clean the spool paths.
func (w *Watcher) Run(stop <-chan struct{}, onBatch func(results []FileResult) error) error {
	for {
		res, err := w.Scan()
		if err != nil {
			return err
		}
		if len(res.StagedResults) > 0 {
			if err := onBatch(res.StagedResults); err != nil {
				return err
			}
		}
		if stop != nil {
			select {
			case <-stop:
				return nil
			case <-time.After(w.interval):
			}
		} else {
			time.Sleep(w.interval)
		}
	}
}
