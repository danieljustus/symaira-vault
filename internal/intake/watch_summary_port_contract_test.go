package intake

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWatcherPortScanSummaryContract(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	inbox := filepath.Join(t.TempDir(), "inbox")
	if err := os.Mkdir(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(inbox, "good.env")
	big := filepath.Join(inbox, "oversize.env")
	hidden := filepath.Join(inbox, ".hidden.env")
	for path, data := range map[string]string{good: "A=1\n", big: "B=123456789\n", hidden: "C=2\n"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-time.Hour)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	opts := DefaultWatcherOptions()
	opts.Debounce = time.Nanosecond
	opts.Options.MaxFileSize = 8
	watcher, err := NewWatcher(inbox, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()

	first, err := watcher.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if first.Scanned != 2 || len(first.StagedPaths) != 1 || len(first.StagedResults) != 1 || len(first.Skipped) != 1 || len(first.Errors) != 0 {
		t.Fatalf("unexpected first scan summary: %+v", first)
	}
	if !strings.HasPrefix(first.Skipped[0], "oversize.env: ") {
		t.Fatalf("unexpected skip: %q", first.Skipped[0])
	}
	staged := first.StagedPaths[0]
	if data, err := os.ReadFile(staged); err != nil || string(data) != "A=1\n" {
		t.Fatalf("incorrect staged copy: %q, %v", data, err)
	}
	if data, err := os.ReadFile(good); err != nil || string(data) != "A=1\n" {
		t.Fatalf("source modified: %q, %v", data, err)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	var stagedPaths []string
	if err := json.Unmarshal(fields["staged"], &stagedPaths); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 || string(fields["scanned"]) != "2" || len(stagedPaths) != 1 || len(fields["skipped"]) == 0 {
		t.Fatalf("unexpected public scan JSON: %s", encoded)
	}
	if _, ok := fields["stagedResults"]; ok {
		t.Fatalf("private staged results leaked: %s", encoded)
	}

	second, err := watcher.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if second.Scanned != 1 || second.StagedPaths != nil || len(second.StagedResults) != 0 || len(second.Skipped) != 1 || len(second.Errors) != 0 {
		t.Fatalf("unexpected second scan summary: %+v", second)
	}
	encoded, err = json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	fields = nil
	if err := json.Unmarshal(encoded, &fields); err != nil || string(fields["staged"]) != "null" || len(fields) != 3 {
		t.Fatalf("no-stage JSON should have staged:null and omit errors: %s (%v)", encoded, err)
	}
	CleanupResultFiles(first.StagedResults)
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("staged copy not removed: %v", err)
	}
	if data, err := os.ReadFile(good); err != nil || string(data) != "A=1\n" {
		t.Fatalf("cleanup touched source: %q, %v", data, err)
	}
}

func TestWatcherPortScanStageErrorContract(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	inbox := t.TempDir()
	file := filepath.Join(inbox, "good.env")
	if err := os.WriteFile(file, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
	opts := DefaultWatcherOptions()
	watcher, err := NewWatcher(inbox, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	if err := os.RemoveAll(watcher.spool.Dir()); err != nil {
		t.Fatal(err)
	}
	result, err := watcher.Scan()
	if err != nil {
		t.Fatalf("per-file staging failure must be reported, not returned: %v", err)
	}
	if result.Scanned != 1 || result.StagedPaths != nil || len(result.StagedResults) != 0 || len(result.Skipped) != 0 || len(result.Errors) != 1 || !strings.HasPrefix(result.Errors[0], "good.env: stage ") {
		t.Fatalf("unexpected staging failure summary: %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil || len(fields) != 3 || string(fields["staged"]) != "null" || len(fields["errors"]) == 0 {
		t.Fatalf("staging error JSON must report errors and keep staged:null: %s (%v)", encoded, err)
	}
}

func TestWatcherPortScanMetadataErrorContract(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires Unix directory search permissions and an unprivileged user")
	}
	t.Setenv("TMPDIR", t.TempDir())
	inbox := filepath.Join(t.TempDir(), "inbox")
	if err := os.Mkdir(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(inbox, "good.env")
	if err := os.WriteFile(file, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
	watcher, err := NewWatcher(inbox, DefaultWatcherOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	if err := os.Chmod(inbox, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(inbox, 0o700) })
	result, err := watcher.Scan()
	if err != nil {
		t.Fatalf("per-entry metadata failure must be reported: %v", err)
	}
	if result.Scanned != 0 || len(result.Errors) != 1 || len(result.Skipped) != 0 || !strings.HasPrefix(result.Errors[0], "good.env: ") {
		t.Fatalf("unexpected metadata failure summary: %+v", result)
	}
}
