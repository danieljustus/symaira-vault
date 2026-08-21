package git

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// conflictRepo creates a vault repository with entries/a.age committed as
// "v1" and returns its directory together with the paths of the entry and of
// the conflict copy ResolveConflicts would produce for device "test-device".
func conflictRepo(t *testing.T) (dir, entryPath, conflictPath string) {
	t.Helper()
	dir = t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatalf("mkdir entries: %v", err)
	}
	writeFile(t, dir, "entries/a.age", []byte("v1"))
	if err := AutoCommit(dir, "initial"); err != nil {
		t.Fatalf("AutoCommit: %v", err)
	}
	return dir, filepath.Join(dir, "entries", "a.age"), filepath.Join(dir, "entries", "a.conflict-test-device.age")
}

// TestResolveConflictsSkipsWhenContentMatchesCommitted is the regression test
// for the conflict copy that reappeared on every CLI invocation: a file whose
// working-tree content equals the committed version has not diverged, so no
// conflict copy may be written even when git reports the file as modified.
func TestResolveConflictsSkipsWhenContentMatchesCommitted(t *testing.T) {
	dir, entryPath, conflictPath := conflictRepo(t)

	repo, err := openRepo(dir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	if err := writeConflictCopy(entryPath, conflictPath, headCommit(repo), "entries/a.age"); err != nil {
		t.Fatalf("writeConflictCopy: %v", err)
	}

	if _, err := os.Stat(conflictPath); !os.IsNotExist(err) {
		t.Errorf("conflict copy written although the content matches HEAD (stat error = %v)", err)
	}
}

// TestResolveConflictsSkipsRewriteOfIdenticalConflictCopy covers the second
// half of the same bug: once a conflict copy exists, a further sync attempt
// must not rewrite it with the identical bytes.
func TestResolveConflictsSkipsRewriteOfIdenticalConflictCopy(t *testing.T) {
	dir, _, conflictPath := conflictRepo(t)
	writeFile(t, dir, "entries/a.age", []byte("v2"))

	if err := ResolveConflicts(dir, "test-device"); err != nil {
		t.Fatalf("ResolveConflicts: %v", err)
	}
	info, err := os.Stat(conflictPath)
	if err != nil {
		t.Fatalf("expected conflict copy %s: %v", filepath.Base(conflictPath), err)
	}

	// Backdate the copy so a rewrite is visible regardless of filesystem
	// timestamp resolution.
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(conflictPath, past, past); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	if err := ResolveConflicts(dir, "test-device"); err != nil {
		t.Fatalf("ResolveConflicts (second run): %v", err)
	}
	after, err := os.Stat(conflictPath)
	if err != nil {
		t.Fatalf("stat after second run: %v", err)
	}
	if !after.ModTime().Equal(past) {
		t.Errorf("identical conflict copy rewritten: mtime %v, want %v", after.ModTime(), past)
	}
	if info.Size() != after.Size() {
		t.Errorf("conflict copy size changed from %d to %d", info.Size(), after.Size())
	}
}

// TestResolveConflictsWritesDivergingContent guards the fix from over-reach:
// content that really differs from the committed version is still preserved.
func TestResolveConflictsWritesDivergingContent(t *testing.T) {
	dir, _, conflictPath := conflictRepo(t)
	writeFile(t, dir, "entries/a.age", []byte("v2"))

	if err := ResolveConflicts(dir, "test-device"); err != nil {
		t.Fatalf("ResolveConflicts: %v", err)
	}
	data, err := os.ReadFile(conflictPath)
	if err != nil {
		t.Fatalf("expected conflict copy %s: %v", filepath.Base(conflictPath), err)
	}
	if string(data) != "v2" {
		t.Errorf("conflict copy content = %q, want %q", data, "v2")
	}
}

// TestResolveConflictsRefreshesOutdatedConflictCopy ensures an existing copy
// with different content is still replaced by the current local version.
func TestResolveConflictsRefreshesOutdatedConflictCopy(t *testing.T) {
	dir, _, conflictPath := conflictRepo(t)
	writeFile(t, dir, "entries/a.conflict-test-device.age", []byte("stale"))
	writeFile(t, dir, "entries/a.age", []byte("v2"))

	if err := ResolveConflicts(dir, "test-device"); err != nil {
		t.Fatalf("ResolveConflicts: %v", err)
	}
	data, err := os.ReadFile(conflictPath)
	if err != nil {
		t.Fatalf("read conflict copy: %v", err)
	}
	if string(data) != "v2" {
		t.Errorf("conflict copy content = %q, want %q", data, "v2")
	}
}

// TestWriteConflictCopySkipsMissingSource keeps a deleted file from aborting
// the sweep over the remaining files.
func TestWriteConflictCopySkipsMissingSource(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "gone.conflict-test-device.age")
	if err := writeConflictCopy(filepath.Join(dir, "gone.age"), dst, nil, "gone.age"); err != nil {
		t.Fatalf("writeConflictCopy: %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("conflict copy written for a missing source (stat error = %v)", err)
	}
}
