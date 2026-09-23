package intake

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcherPortPollingContract(t *testing.T) {
	tmp := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, tmp)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "sample.env")
	first, second := []byte("A=1\n"), []byte("A=2\n")
	if err := os.WriteFile(src, first, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	setMTime := func(path string, when time.Time) {
		t.Helper()
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	setMTime(src, now.Add(time.Hour))
	hidden := filepath.Join(dir, ".hidden.env")
	if err := os.WriteFile(hidden, first, 0o600); err != nil {
		t.Fatal(err)
	}
	setMTime(hidden, now.Add(-time.Hour))
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(src, filepath.Join(dir, "source-link.env")); err == nil {
		// Go's directory-entry metadata does not follow the symlink. With a
		// positive 1ns debounce it would be scanned if the type filter broke.
		linkOpts := DefaultWatcherOptions()
		linkOpts.Debounce = time.Nanosecond
		linkWatcher, newErr := NewWatcher(dir, linkOpts)
		if newErr != nil {
			t.Fatal(newErr)
		}
		defer linkWatcher.Close()
		linkResult, scanErr := linkWatcher.Scan()
		if scanErr != nil || linkResult.Scanned != 0 {
			t.Fatalf("symlink entered intake candidates: %v, %+v", scanErr, linkResult)
		}
	} else {
		t.Logf("symlink negative control unavailable on this host: %v", err)
	}

	opts := DefaultWatcherOptions()
	opts.Debounce = 0 // Go resets zero to the 5-second default.
	opts.Options.MaxFileSize = 8
	watcher, err := NewWatcher(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	if watcher.debounce != 5*time.Second {
		t.Fatalf("zero debounce normalized to %s, want 5s", watcher.debounce)
	}
	result, err := watcher.Scan()
	if err != nil || result.Scanned != 0 || len(result.StagedPaths) != 0 {
		t.Fatalf("fresh/hidden/subdir scan: %v, %+v", err, result)
	}

	setMTime(src, now.Add(-time.Hour))
	result, err = watcher.Scan()
	if err != nil || result.Scanned != 1 || len(result.StagedPaths) != 1 || len(result.StagedResults) != 1 || result.StagedResults[0].Status != StatusOK {
		t.Fatalf("first stable scan: %v, %+v", err, result)
	}
	staged := result.StagedPaths[0]
	if got, err := os.ReadFile(staged); err != nil || string(got) != string(first) {
		t.Fatalf("first staged bytes: %q, %v", got, err)
	}
	result, err = watcher.Scan()
	if err != nil || result.Scanned != 0 {
		t.Fatalf("unchanged file restaged: %v, %+v", err, result)
	}

	if err := os.WriteFile(src, second, 0o600); err != nil {
		t.Fatal(err)
	}
	setMTime(src, now.Add(-2*time.Hour))
	result, err = watcher.Scan()
	if err != nil || result.Scanned != 1 || len(result.StagedPaths) != 1 || result.StagedPaths[0] == staged {
		t.Fatalf("changed file not staged uniquely: %v, %+v", err, result)
	}
	if got, err := os.ReadFile(result.StagedPaths[0]); err != nil || string(got) != string(second) {
		t.Fatalf("second staged bytes: %q, %v", got, err)
	}
	if got, err := os.ReadFile(staged); err != nil || string(got) != string(first) {
		t.Fatalf("first staged bytes overwritten: %q, %v", got, err)
	}

	big := filepath.Join(dir, "oversize.env")
	if err := os.WriteFile(big, []byte("B=123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setMTime(big, now.Add(-time.Hour))
	for range 2 {
		result, err = watcher.Scan()
		if err != nil || result.Scanned != 1 || len(result.Skipped) != 1 || len(result.StagedPaths) != 0 {
			t.Fatalf("oversized source must be skipped but retried: %v, %+v", err, result)
		}
	}
	if got, err := os.ReadFile(src); err != nil || string(got) != string(second) {
		t.Fatalf("source changed by intake: %q, %v", got, err)
	}
}
