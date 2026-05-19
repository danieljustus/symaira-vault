//go:build !windows

package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSafeWriteFile_SymlinkAttack(t *testing.T) {
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
	if pathErr.Err != syscall.ENOTDIR && pathErr.Err != syscall.ELOOP {
		t.Errorf("expected ENOTDIR or ELOOP, got %v", pathErr.Err)
	}
}

func TestSafeWriteFile_DirectoryTarget(t *testing.T) {
	tmpDir := t.TempDir()

	dirPath := filepath.Join(tmpDir, "mydir")
	os.MkdirAll(dirPath, 0o700)

	err := SafeWriteFile(dirPath, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("SafeWriteFile should reject directory target")
	}
}

func TestSafeWriteFile_Success(t *testing.T) {
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

func TestSafeWriteFile_ReadOnlyDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; permissions test meaningless")
	}
	parent := t.TempDir()
	os.Chmod(parent, 0o555)
	defer os.Chmod(parent, 0o700)

	filePath := filepath.Join(parent, "readonly.age")
	err := SafeWriteFile(filePath, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error writing to readonly directory")
	}
}

func TestSafeRemove_SymlinkAttack(t *testing.T) {
	tmpDir := t.TempDir()

	symlinkPath := filepath.Join(tmpDir, "link")
	targetPath := filepath.Join(t.TempDir(), "target")
	os.WriteFile(targetPath, []byte("sensitive"), 0o600)
	os.Symlink(targetPath, symlinkPath)

	err := SafeRemove(symlinkPath)
	if err == nil {
		t.Fatal("SafeRemove should reject symlink")
	}
	pathErr, ok := err.(*os.PathError)
	if !ok {
		t.Fatalf("expected PathError, got %T", err)
	}
	if pathErr.Err != syscall.ENOTDIR && pathErr.Err != syscall.ELOOP {
		t.Errorf("expected ENOTDIR or ELOOP, got %v", pathErr.Err)
	}
}

func TestSafeRemove_DirectoryTarget(t *testing.T) {
	tmpDir := t.TempDir()

	dirPath := filepath.Join(tmpDir, "mydir")
	os.MkdirAll(dirPath, 0o700)

	err := SafeRemove(dirPath)
	if err == nil {
		t.Fatal("SafeRemove should reject directory")
	}
}

func TestSafeRemove_Success(t *testing.T) {
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

func TestSafeRemove_NotExist(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "nonexistent.age")

	err := SafeRemove(filePath)
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
	pathErr, ok := err.(*os.PathError)
	if !ok {
		t.Fatalf("expected PathError, got %T", err)
	}
	if pathErr.Err != syscall.ENOENT {
		t.Errorf("expected ENOENT, got %v", pathErr.Err)
	}
}

func TestSafeMkdirAll_Success(t *testing.T) {
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

func TestSafeMkdirAll_Existing(t *testing.T) {
	tmpDir := t.TempDir()

	err := SafeMkdirAll(tmpDir, 0o700)
	if err != nil {
		t.Fatalf("SafeMkdirAll() error = %v", err)
	}
}

func TestSafeMkdirAll_SymlinkAttack_ExistingParent(t *testing.T) {
	tmpDir := t.TempDir()

	workDir := filepath.Join(tmpDir, "work")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}

	targetDir := filepath.Join(t.TempDir(), "sensitive")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(workDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDir, workDir); err != nil {
		t.Fatal(err)
	}

	err := SafeMkdirAll(filepath.Join(workDir, "sub"), 0o700)
	if err == nil {
		t.Fatal("SafeMkdirAll should reject symlink attack")
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("expected PathError, got %T", err)
	}
	if pathErr.Err != syscall.ELOOP {
		t.Errorf("expected ELOOP, got %v", pathErr.Err)
	}

	if _, err := os.Stat(filepath.Join(targetDir, "sub")); !os.IsNotExist(err) {
		t.Error("attacker target should not have been created")
	}
}

func TestSafeMkdirAll_SymlinkAttack_MidPath(t *testing.T) {
	tmpDir := t.TempDir()

	fake := filepath.Join(tmpDir, "a", "b")
	if err := os.MkdirAll(fake, 0o700); err != nil {
		t.Fatal(err)
	}

	targetDir := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(fake); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDir, fake); err != nil {
		t.Fatal(err)
	}

	err := SafeMkdirAll(filepath.Join(fake, "c", "d"), 0o700)
	if err == nil {
		t.Fatal("SafeMkdirAll should reject mid-path symlink")
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("expected PathError, got %T", err)
	}
	if pathErr.Err != syscall.ELOOP {
		t.Errorf("expected ELOOP, got %v", pathErr.Err)
	}

	if _, err := os.Stat(filepath.Join(targetDir, "c")); !os.IsNotExist(err) {
		t.Error("attacker target should not have been created")
	}
}

func TestSafeMkdirAll_DeepExistingPath(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "a", "b", "c")

	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}

	err := SafeMkdirAll(path, 0o700)
	if err != nil {
		t.Fatalf("SafeMkdirAll() on existing path error = %v", err)
	}
}

func TestSafeWriteFile_WriteFails(t *testing.T) {
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

func TestSafeRemove_FstatFails(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer os.Chmod(parent, 0o700)

	filePath := filepath.Join(parent, "test.age")
	err := SafeRemove(filePath)
	if err == nil {
		t.Fatal("expected error")
	}
}
