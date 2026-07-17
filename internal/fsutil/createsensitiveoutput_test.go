package fsutil

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCreateSensitiveOutput_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not honored on Windows")
	}

	path := filepath.Join(t.TempDir(), "sensitive.txt")
	wc, err := CreateSensitiveOutput(path)
	if err != nil {
		t.Fatalf("CreateSensitiveOutput: %v", err)
	}
	if err := wc.Close(); err != nil {
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

func TestCreateSensitiveOutput_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")

	if err := os.WriteFile(path, []byte("old content"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	wc, err := CreateSensitiveOutput(path)
	if err != nil {
		t.Fatalf("CreateSensitiveOutput: %v", err)
	}
	if _, err := io.WriteString(wc, "new"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := wc.Close(); err != nil {
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

func TestCreateSensitiveOutput_StdoutPassthrough(t *testing.T) {
	wc, err := CreateSensitiveOutput("")
	if err != nil {
		t.Fatalf("CreateSensitiveOutput: %v", err)
	}
	// Close must be a no-op and never return an error.
	if err := wc.Close(); err != nil {
		t.Errorf("stdout Close should not return error, got: %v", err)
	}
}

func TestCreateSensitiveOutput_InvalidPath(t *testing.T) {
	_, err := CreateSensitiveOutput("/nonexistent/dir/file.txt")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}
