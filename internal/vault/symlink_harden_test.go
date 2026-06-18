//go:build !windows

package vault

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSafeWriteFile_SymlinkAttack(t *testing.T) {
	vaultDir := t.TempDir()

	symlinkPath := filepath.Join(vaultDir, "attacked")
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
	vaultDir := t.TempDir()

	dirPath := filepath.Join(vaultDir, "mydir")
	os.MkdirAll(dirPath, 0o700)

	err := SafeWriteFile(dirPath, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("SafeWriteFile should reject directory target")
	}
}

func TestSafeWriteFile_Success(t *testing.T) {
	vaultDir := t.TempDir()
	filePath := filepath.Join(vaultDir, "test.age")

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
	vaultDir := t.TempDir()

	symlinkPath := filepath.Join(vaultDir, "link")
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
	vaultDir := t.TempDir()

	dirPath := filepath.Join(vaultDir, "mydir")
	os.MkdirAll(dirPath, 0o700)

	err := SafeRemove(dirPath)
	if err == nil {
		t.Fatal("SafeRemove should reject directory")
	}
}

func TestSafeRemove_Success(t *testing.T) {
	vaultDir := t.TempDir()
	filePath := filepath.Join(vaultDir, "test.age")

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
	vaultDir := t.TempDir()
	filePath := filepath.Join(vaultDir, "nonexistent.age")

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
	vaultDir := t.TempDir()
	path := filepath.Join(vaultDir, "a", "b", "c")

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
	vaultDir := t.TempDir()

	err := SafeMkdirAll(vaultDir, 0o700)
	if err != nil {
		t.Fatalf("SafeMkdirAll() error = %v", err)
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

func TestSafeReadFile_SymlinkAttack(t *testing.T) {
	vaultDir := t.TempDir()

	targetPath := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(targetPath, []byte("sensitive"), 0o600)

	symlinkPath := filepath.Join(vaultDir, "tricked")
	os.Symlink(targetPath, symlinkPath)

	_, err := SafeReadFile(symlinkPath)
	if err == nil {
		t.Fatal("SafeReadFile should reject symlink")
	}
	pathErr, ok := err.(*os.PathError)
	if !ok {
		t.Fatalf("expected PathError, got %T", err)
	}
	if pathErr.Err != syscall.ELOOP && pathErr.Err != syscall.ENOTDIR {
		t.Errorf("expected ELOOP or ENOTDIR, got %v", pathErr.Err)
	}
}

func TestSafeReadFile_RegularFile(t *testing.T) {
	vaultDir := t.TempDir()
	filePath := filepath.Join(vaultDir, "test.age")

	data := []byte("hello world")
	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := SafeReadFile(filePath)
	if err != nil {
		t.Fatalf("SafeReadFile() error = %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content = %q, want %q", string(got), string(data))
	}
}

func TestSafeReadFile_NotExist(t *testing.T) {
	vaultDir := t.TempDir()
	_, err := SafeReadFile(filepath.Join(vaultDir, "nonexistent"))
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestSafeReadFile_DirectoryTarget(t *testing.T) {
	vaultDir := t.TempDir()
	dirPath := filepath.Join(vaultDir, "mydir")
	os.MkdirAll(dirPath, 0o700)

	_, err := SafeReadFile(dirPath)
	if err == nil {
		t.Fatal("SafeReadFile should reject directory target")
	}
}
