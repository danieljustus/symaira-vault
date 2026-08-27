package sync

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReconcileConflictPreservesLoser(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "login.example.age")
	want := []byte("encrypted loser")
	if err := os.WriteFile(source, want, 0o600); err != nil {
		t.Fatalf("seed loser: %v", err)
	}

	copyPath, err := ReconcileConflict(source)
	if err != nil {
		t.Fatalf("ReconcileConflict() error = %v", err)
	}
	if copyPath == source {
		t.Fatal("ReconcileConflict() must create a sibling copy")
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("source loser was not preserved: %v", err)
	}
	got, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatalf("read conflict copy: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("conflict copy = %q, want %q", got, want)
	}
}
