package intake

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcherPortRunImmediateBatchStopAndCleanup(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, root)
	}
	inbox := filepath.Join(root, "inbox")
	if err := os.Mkdir(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(inbox, "sample.env")
	if err := os.WriteFile(source, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(source, old, old); err != nil {
		t.Fatal(err)
	}
	opts := DefaultWatcherOptions()
	opts.Interval = 0 // Go restores the ten-second default.
	watcher, err := NewWatcher(inbox, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	if watcher.interval != 10*time.Second {
		t.Fatalf("zero interval became %s, want 10s", watcher.interval)
	}
	spool := watcher.spool.Dir()
	stop := make(chan struct{})
	close(stop)
	calls := 0
	err = watcher.Run(stop, func(results []FileResult) error {
		calls++
		if len(results) != 1 || results[0].Status != StatusOK {
			t.Fatalf("callback result = %+v", results)
		}
		if got, readErr := os.ReadFile(results[0].spoolPath); readErr != nil || string(got) != "A=1\n" {
			t.Fatalf("staged bytes = %q, %v", got, readErr)
		}
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("closed-stop run = %v, callback count = %d, want one immediate batch", err, calls)
	}
	if got, err := os.ReadFile(source); err != nil || string(got) != "A=1\n" {
		t.Fatalf("source changed: %q, %v", got, err)
	}
	watcher.Close()
	if _, err := os.Stat(spool); !os.IsNotExist(err) {
		t.Fatalf("private spool survives watcher close: %v", err)
	}
}

func TestWatcherPortRunLiveStopWakesWait(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, root)
	}
	inbox := filepath.Join(root, "inbox")
	if err := os.Mkdir(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(inbox, "sample.env")
	if err := os.WriteFile(source, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(source, old, old); err != nil {
		t.Fatal(err)
	}
	opts := DefaultWatcherOptions()
	opts.Interval = 30 * time.Second
	watcher, err := NewWatcher(inbox, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	stop := make(chan struct{})
	ready := make(chan int, 1)
	done := make(chan error, 1)
	calls := 0
	go func() {
		done <- watcher.Run(stop, func(results []FileResult) error {
			calls++
			select {
			case ready <- len(results):
			default:
			}
			return nil
		})
	}()
	select {
	case count := <-ready:
		if count != 1 {
			close(stop)
			t.Fatalf("callback got %d results, want one", count)
		}
	case <-time.After(10 * time.Second):
		close(stop)
		t.Fatal("watcher never delivered its immediate batch")
	}
	close(stop)
	select {
	case err := <-done:
		if err != nil || calls != 1 {
			t.Fatalf("stop result = %v, callback count = %d", err, calls)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("closed stop did not wake the waiting watcher")
	}
}

func TestWatcherPortRunPollsChangedFile(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, root)
	}
	inbox := filepath.Join(root, "inbox")
	if err := os.Mkdir(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(inbox, "sample.env")
	if err := os.WriteFile(source, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(source, old, old); err != nil {
		t.Fatal(err)
	}
	opts := DefaultWatcherOptions()
	opts.Interval = 10 * time.Millisecond
	opts.Debounce = time.Nanosecond
	watcher, err := NewWatcher(inbox, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	stop := make(chan struct{}, 1)
	done := make(chan error, 1)
	calls := 0
	var paths []string
	go func() {
		done <- watcher.Run(stop, func(results []FileResult) error {
			calls++
			if len(results) != 1 || results[0].Status != StatusOK {
				return fmt.Errorf("callback result = %+v", results)
			}
			paths = append(paths, results[0].spoolPath)
			if calls == 1 {
				if err := os.WriteFile(source, []byte("A=2\n"), 0o600); err != nil {
					return err
				}
				return os.Chtimes(source, old.Add(-time.Minute), old.Add(-time.Minute))
			}
			select {
			case stop <- struct{}{}:
			default:
			}
			return nil
		})
	}()
	select {
	case err := <-done:
		if err != nil || calls != 2 || len(paths) != 2 || paths[0] == paths[1] {
			t.Fatalf("polling result = %v, callbacks = %d, staged paths = %v", err, calls, paths)
		}
	case <-time.After(10 * time.Second):
		select {
		case stop <- struct{}{}:
		default:
		}
		t.Fatal("changed source was not delivered on a later poll")
	}
	if first, err := os.ReadFile(paths[0]); err != nil || string(first) != "A=1\n" {
		t.Fatalf("first staged bytes = %q, %v", first, err)
	}
	if second, err := os.ReadFile(paths[1]); err != nil || string(second) != "A=2\n" {
		t.Fatalf("second staged bytes = %q, %v", second, err)
	}
}

func TestWatcherPortRunEmptyPollCallbackAndScanErrors(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, root)
	}
	inbox := filepath.Join(root, "inbox")
	if err := os.Mkdir(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	oversize := filepath.Join(inbox, "oversize.env")
	if err := os.WriteFile(oversize, []byte("B=123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(oversize, old, old); err != nil {
		t.Fatal(err)
	}
	opts := DefaultWatcherOptions()
	opts.Options.MaxFileSize = 8
	watcher, err := NewWatcher(inbox, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	stop := make(chan struct{})
	close(stop)
	calls := 0
	if err := watcher.Run(stop, func([]FileResult) error { calls++; return nil }); err != nil || calls != 0 {
		t.Fatalf("skipped-only run = %v, callback count = %d, want zero", err, calls)
	}
	source := filepath.Join(inbox, "sample.env")
	if err := os.WriteFile(source, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(source, old, old); err != nil {
		t.Fatal(err)
	}
	unavailable := errors.New("synthetic batch failure")
	err = watcher.Run(nil, func(results []FileResult) error {
		calls++
		if len(results) != 1 || results[0].Status != StatusOK {
			t.Fatalf("callback result = %+v", results)
		}
		return unavailable
	})
	if !errors.Is(err, unavailable) || calls != 1 {
		t.Fatalf("batch error = %v, callback count = %d", err, calls)
	}
	if err := os.RemoveAll(inbox); err != nil {
		t.Fatal(err)
	}
	if err := watcher.Run(nil, func([]FileResult) error { calls++; return nil }); err == nil || calls != 1 {
		t.Fatalf("scan error = %v, callback count = %d", err, calls)
	}
}
