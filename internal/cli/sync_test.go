package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsOfflineErr_NoRouteToHost(t *testing.T) {
	err := &testError{msg: "dial tcp: no route to host"}
	if !isOfflineErr(err) {
		t.Error("isOfflineErr() = false for 'no route to host', want true")
	}
}

func TestIsOfflineErr_ConnectionRefused(t *testing.T) {
	err := &testError{msg: "dial tcp: connection refused"}
	if !isOfflineErr(err) {
		t.Error("isOfflineErr() = false for 'connection refused', want true")
	}
}

func TestIsOfflineErr_ConnectionTimedOut(t *testing.T) {
	err := &testError{msg: "dial tcp: connection timed out"}
	if !isOfflineErr(err) {
		t.Error("isOfflineErr() = false for 'connection timed out', want true")
	}
}

func TestIsOfflineErr_IOTimeout(t *testing.T) {
	err := &testError{msg: "i/o timeout"}
	if !isOfflineErr(err) {
		t.Error("isOfflineErr() = false for 'i/o timeout', want true")
	}
}

func TestIsOfflineErr_NonOfflineError(t *testing.T) {
	err := &testError{msg: "permission denied"}
	if isOfflineErr(err) {
		t.Error("isOfflineErr() = true for 'permission denied', want false")
	}
}

func TestIsOfflineErr_EmptyMessage(t *testing.T) {
	err := &testError{msg: ""}
	if isOfflineErr(err) {
		t.Error("isOfflineErr() = true for empty message, want false")
	}
}

func TestContainsConflict_ConflictPrefix(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{".conflict-something.txt", true},
		{"config.conflict-something.txt", false},
		{"normal-file.txt", false},
		{"config.yaml", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsConflict(tt.name)
			if got != tt.want {
				t.Errorf("containsConflict(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestFindConflictFiles_NoConflicts(t *testing.T) {
	dir := t.TempDir()
	entriesDir := filepath.Join(dir, "entries")
	createTestDir(t, entriesDir)
	createTestFiles(t, dir, "config.yaml", "identity.age")
	createTestFiles(t, entriesDir, "github.age")

	files := findConflictFiles(dir)
	if len(files) != 0 {
		t.Errorf("findConflictFiles() = %v, want empty", files)
	}
}

func TestFindConflictFiles_WithConflicts(t *testing.T) {
	dir := t.TempDir()
	createTestFiles(t, dir, ".conflict-abc123.txt", "normal.txt")

	files := findConflictFiles(dir)
	if len(files) != 1 {
		t.Fatalf("findConflictFiles() returned %d files, want 1", len(files))
	}

	if files[0] != ".conflict-abc123.txt" {
		t.Errorf("conflict file = %q, want .conflict-abc123.txt", files[0])
	}
}

func TestFindConflictFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	files := findConflictFiles(dir)
	if len(files) != 0 {
		t.Errorf("findConflictFiles() = %v, want empty", files)
	}
}

func TestFindConflictFiles_NestedConflicts(t *testing.T) {
	dir := t.TempDir()
	subdir := dir + "/subdir"
	createTestDir(t, subdir)
	createTestFiles(t, subdir, ".conflict-nested.txt")

	files := findConflictFiles(dir)
	if len(files) != 1 {
		t.Fatalf("findConflictFiles() returned %d files, want 1", len(files))
	}
	if files[0] != "subdir/.conflict-nested.txt" {
		t.Errorf("conflict file = %q, want subdir/.conflict-nested.txt", files[0])
	}
}

// testError is a simple error implementation for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func createTestFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("test content"), 0600); err != nil {
			t.Fatalf("createTestFiles: write %s: %v", name, err)
		}
	}
}

func createTestDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("createTestDir: %v", err)
	}
}