//go:build windows

package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSafeWriteFileWindows_SymlinkAttack(t *testing.T) {
	tmpDir := t.TempDir()

	symlinkPath := filepath.Join(tmpDir, "attacked")
	targetPath := filepath.Join(t.TempDir(), "target")
	os.WriteFile(targetPath, []byte("sensitive"), 0o600)
	os.Symlink(targetPath, symlinkPath)

	err := SafeWriteFile(symlinkPath, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("SafeWriteFile should reject symlink attack")
	}
	pathErr, ok := err.(*os.PathError)
	if !ok {
		t.Fatalf("expected PathError, got %T", err)
	}
	if pathErr.Err != errUnsafePath {
		t.Errorf("expected errUnsafePath, got %v", pathErr.Err)
	}
}

func TestSafeWriteFileWindows_DirectoryTarget(t *testing.T) {
	tmpDir := t.TempDir()

	dirPath := filepath.Join(tmpDir, "mydir")
	os.MkdirAll(dirPath, 0o700)

	err := SafeWriteFile(dirPath, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("SafeWriteFile should reject directory target")
	}
}

func TestSafeWriteFileWindows_Success(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.age")

	data := []byte("hello world")
	err := SafeWriteFile(filePath, data, 0o600)
	if err != nil {
		t.Fatalf("SafeWriteFile() error = %v", err)
	}

	got, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("file content = %q, want %q", string(got), string(data))
	}
}

func TestSafeRemoveWindows_SymlinkAttack(t *testing.T) {
	tmpDir := t.TempDir()

	symlinkPath := filepath.Join(tmpDir, "link")
	targetPath := filepath.Join(t.TempDir(), "target")
	os.WriteFile(targetPath, []byte("sensitive"), 0o600)
	os.Symlink(targetPath, symlinkPath)

	err := SafeRemove(symlinkPath)
	if err == nil {
		t.Fatal("SafeRemove should reject symlink")
	}
}

func TestSafeRemoveWindows_DirectoryTarget(t *testing.T) {
	tmpDir := t.TempDir()

	dirPath := filepath.Join(tmpDir, "mydir")
	os.MkdirAll(dirPath, 0o700)

	err := SafeRemove(dirPath)
	if err == nil {
		t.Fatal("SafeRemove should reject directory")
	}
}

func TestSafeRemoveWindows_Success(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.age")

	os.WriteFile(filePath, []byte("hello"), 0o600)

	err := SafeRemove(filePath)
	if err != nil {
		t.Fatalf("SafeRemove() error = %v", err)
	}

	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("expected file to be removed")
	}
}

func TestSafeRemoveWindows_NotExist(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "nonexistent.age")

	err := SafeRemove(filePath)
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected ErrNotExist, got %v", err)
	}
}

func TestSafeMkdirAllWindows_Success(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "a", "b", "c")

	err := SafeMkdirAll(path, 0o700)
	if err != nil {
		t.Fatalf("SafeMkdirAll() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

func TestSafeMkdirAllWindows_Existing(t *testing.T) {
	tmpDir := t.TempDir()

	err := SafeMkdirAll(tmpDir, 0o700)
	if err != nil {
		t.Fatalf("SafeMkdirAll() error = %v", err)
	}
}

func TestRejectSymlink_Present(t *testing.T) {
	tmpDir := t.TempDir()

	symlinkPath := filepath.Join(tmpDir, "link")
	targetPath := filepath.Join(t.TempDir(), "target")
	os.WriteFile(targetPath, []byte("sensitive"), 0o600)
	os.Symlink(targetPath, symlinkPath)

	err := rejectSymlink(symlinkPath)
	if err == nil {
		t.Fatal("rejectSymlink should reject symlink")
	}
}

func TestRejectSymlink_NotExist(t *testing.T) {
	tmpDir := t.TempDir()
	nonexistent := filepath.Join(tmpDir, "nonexistent")

	err := rejectSymlink(nonexistent)
	if err != nil {
		t.Errorf("rejectSymlink should return nil for nonexistent path, got %v", err)
	}
}

func TestRejectSymlink_OtherError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: chmod behavior differs")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer os.Chmod(parent, 0o700)

	filePath := filepath.Join(parent, "test.age")
	err := rejectSymlink(filePath)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSafeWriteFileWindows_StatFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: chmod behavior differs")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer os.Chmod(parent, 0o700)

	filePath := filepath.Join(parent, "test.age")
	err := SafeWriteFile(filePath, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error")
	}
}
