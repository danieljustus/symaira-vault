package intake

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcherPicksUpStableFile(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWatcherOptions()
	opts.Debounce = 100 * time.Millisecond
	w, err := NewWatcher(dir, opts)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer w.Close()

	// A file that is already stable gets picked up.
	src := filepath.Join(dir, "creds.env")
	if err := os.WriteFile(src, []byte("USERNAME=alice\nPASSWORD=hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	res, err := w.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Scanned != 1 || len(res.StagedPaths) != 1 {
		t.Fatalf("scan = %+v, want 1 staged", res)
	}
	if len(res.StagedResults) != 1 || res.StagedResults[0].Status != StatusOK {
		t.Fatalf("staged results = %+v", res.StagedResults)
	}

	// Second scan must not re-stage the same file.
	res2, err := w.Scan()
	if err != nil {
		t.Fatalf("Scan2: %v", err)
	}
	if len(res2.StagedPaths) != 0 {
		t.Fatalf("re-staged already seen file: %+v", res2)
	}
}

func TestWatcherSkipsFreshAndHiddenFiles(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWatcherOptions()
	opts.Debounce = 5 * time.Second
	w, err := NewWatcher(dir, opts)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer w.Close()

	// Fresh file (mtime within debounce) is skipped.
	fresh := filepath.Join(dir, "fresh.env")
	if err := os.WriteFile(fresh, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Hidden file is always skipped.
	if err := os.WriteFile(filepath.Join(dir, ".hidden.env"), []byte("B=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := w.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Scanned != 0 || len(res.StagedPaths) != 0 {
		t.Fatalf("scan = %+v, want nothing staged (fresh + hidden)", res)
	}
}

func TestWatcherRunStagesBatch(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWatcherOptions()
	opts.Debounce = 50 * time.Millisecond
	w, err := NewWatcher(dir, opts)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer w.Close()

	src := filepath.Join(dir, "login.txt")
	if err := os.WriteFile(src, []byte("username: alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	stop := make(chan struct{})
	got := make(chan []FileResult, 1)
	go func() {
		_ = w.Run(stop, func(results []FileResult) error {
			select {
			case got <- results:
			default:
			}
			return nil
		})
	}()

	select {
	case results := <-got:
		if len(results) != 1 || results[0].Status != StatusOK {
			t.Fatalf("batch results = %+v", results)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run never delivered a batch")
	}
	close(stop)
}

func TestWatcherLedgerTracksChangedFile(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultWatcherOptions()
	opts.Debounce = 50 * time.Millisecond
	w, err := NewWatcher(dir, opts)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer w.Close()

	src := filepath.Join(dir, "creds.env")
	if err := os.WriteFile(src, []byte("USERNAME=a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	res, err := w.Scan()
	if err != nil || len(res.StagedPaths) != 1 {
		t.Fatalf("first scan: %v %+v", err, res)
	}

	// Same size but changed content/mtime -> new ledger key -> re-staged.
	time.Sleep(150 * time.Millisecond)
	if err := os.WriteFile(src, []byte("USERNAME=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	res2, err := w.Scan()
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if len(res2.StagedPaths) != 1 {
		t.Fatalf("changed file not re-staged: %+v", res2)
	}
}

func TestWatcherRejectsNonDirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWatcher(f, DefaultWatcherOptions()); err == nil {
		t.Fatal("NewWatcher accepted a file path")
	}
}
