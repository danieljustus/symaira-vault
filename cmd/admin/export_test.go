package admin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateOutputFile_Mode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "export.txt")

	f, err := createOutputFile(path)
	if err != nil {
		t.Fatalf("createOutputFile: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 0o600", perm)
	}
}

func TestCreateOutputFile_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")

	if err := os.WriteFile(path, []byte("old content"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err := createOutputFile(path)
	if err != nil {
		t.Fatalf("createOutputFile: %v", err)
	}
	if _, err := f.WriteString("new"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "new" {
		t.Errorf("content = %q, want %q", string(data), "new")
	}
}
