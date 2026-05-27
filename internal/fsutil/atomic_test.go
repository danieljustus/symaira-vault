package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAtomicWriteFile_BasicWrite(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.age")

	data := []byte("hello world")
	if err := AtomicWriteFile(filePath, data, 0o600); err != nil {
		t.Fatalf("AtomicWriteFile() error = %v", err)
	}

	got, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("file content = %q, want %q", string(got), string(data))
	}
}

func TestAtomicWriteFile_Overwrite(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.age")

	if err := os.WriteFile(filePath, []byte("original"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	newData := []byte("updated content")
	if err := AtomicWriteFile(filePath, newData, 0o600); err != nil {
		t.Fatalf("AtomicWriteFile() error = %v", err)
	}

	got, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(newData) {
		t.Errorf("file content = %q, want %q", string(got), string(newData))
	}
}

func TestAtomicWriteFile_NoTempFileLeftBehind(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.age")

	if err := AtomicWriteFile(filePath, []byte("data"), 0o600); err != nil {
		t.Fatalf("AtomicWriteFile() error = %v", err)
	}

	// Verify no .tmp-* files are left in the directory.
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Errorf("temp file %q left behind after atomic write", entry.Name())
		}
	}
}

func TestAtomicWriteFile_OldFileIntactOnFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; permissions test meaningless")
	}
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: chmod behavior differs")
	}

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.age")
	originalData := []byte("original content")

	if err := os.WriteFile(filePath, originalData, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := os.Chmod(tmpDir, 0o555); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer os.Chmod(tmpDir, 0o700)

	err := AtomicWriteFile(filePath, []byte("should fail"), 0o600)
	if err == nil {
		t.Fatal("expected AtomicWriteFile to fail on read-only directory")
	}

	got, readErr := os.ReadFile(filePath)
	if readErr != nil {
		t.Fatalf("ReadFile() error = %v", readErr)
	}
	if string(got) != string(originalData) {
		t.Errorf("old file content = %q, want %q", string(got), string(originalData))
	}
}
