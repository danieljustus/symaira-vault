package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIsOfflineErr_Nil(t *testing.T) {
	if isOfflineErr(nil) {
		t.Error("expected false for nil error")
	}
}

func TestIsOfflineErr_NetworkError(t *testing.T) {
	err := errors.New("network error - please check your connection")
	if !isOfflineErr(err) {
		t.Error("expected true for network error")
	}
}

func TestIsOfflineErr_OtherError(t *testing.T) {
	err := errors.New("some other error")
	if isOfflineErr(err) {
		t.Error("expected false for non-network error")
	}
}

func TestContainsConflict(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{".conflict-abc123", true},
		{".conflictsomething12", true},
		{"normal-file.age", false},
		{"short", false},
		{"config.yaml", false},
	}
	for _, tc := range cases {
		got := containsConflict(tc.name)
		if got != tc.want {
			t.Errorf("containsConflict(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFindConflictFiles(t *testing.T) {
	tmp := t.TempDir()
	entriesDir := filepath.Join(tmp, "entries")
	if err := os.MkdirAll(entriesDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Create a conflict file in vault root.
	os.WriteFile(filepath.Join(tmp, ".conflict-rootfile"), []byte("x"), 0o600)
	// Create a conflict file in entries.
	os.WriteFile(filepath.Join(entriesDir, ".conflict-entry"), []byte("x"), 0o600)
	// Normal file.
	os.WriteFile(filepath.Join(tmp, "normal.age"), []byte("x"), 0o600)

	conflicts := findConflictFiles(tmp)
	if len(conflicts) < 2 {
		t.Errorf("expected at least 2 conflict files, got %d: %v", len(conflicts), conflicts)
	}
}

func TestFindConflictFiles_MissingDir(t *testing.T) {
	conflicts := findConflictFiles("/nonexistent-vault-dir-xyz")
	if conflicts != nil {
		t.Errorf("expected nil for missing directory, got %v", conflicts)
	}
}
