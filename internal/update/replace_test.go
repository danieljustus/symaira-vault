package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeScript creates an executable shell script at path that handles --version.
func writeScript(t *testing.T, path string) {
	t.Helper()
	content := "#!/bin/sh\necho symvault-test\n"
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func TestReplace_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping: shell script binaries not supported on windows")
	}

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "symvault")
	writeScript(t, binaryPath)

	content := "#!/bin/sh\necho symvault-test\n"
	if err := Replace(binaryPath, []byte(content)); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}

	backup := binaryPath + ".backup"
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("backup should exist after successful replace: %v", err)
	}

	cmd := exec.Command(binaryPath, "--version")
	if err := cmd.Run(); err != nil {
		t.Fatalf("replaced binary --version failed: %v", err)
	}
}

func TestReplace_BinaryNotFound(t *testing.T) {
	err := Replace("/nonexistent/binary/path", []byte("data"))
	if err == nil {
		t.Fatal("Replace() with non-existent path should error")
	}
	if !strings.Contains(err.Error(), "cannot stat") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReplace_NotRegularFile(t *testing.T) {
	tmpDir := t.TempDir()

	dirPath := filepath.Join(tmpDir, "mydir")
	if err := os.Mkdir(dirPath, 0o755); err != nil {
		t.Fatalf("Mkdir(%q) error = %v", dirPath, err)
	}

	err := Replace(dirPath, []byte("data"))
	if err == nil {
		t.Fatal("Replace() with a directory should error")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReplace_VerifyFailureRollsBack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping: execution verification not supported on windows")
	}

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "symvault")
	writeScript(t, binaryPath)

	cmd := exec.Command(binaryPath, "--version")
	if err := cmd.Run(); err != nil {
		t.Fatalf("original binary --version failed: %v", err)
	}

	garbageData := []byte("this is not a valid executable")
	err := Replace(binaryPath, garbageData)
	if err == nil {
		t.Fatal("Replace() with invalid binary data should error")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd = exec.Command(binaryPath, "--version")
	if err := cmd.Run(); err != nil {
		t.Fatalf("original binary should be restored but --version failed: %v", err)
	}
}

func TestReplace_PreservesPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping: unix permissions not applicable on windows")
	}

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "symvault")
	writeScript(t, binaryPath)

	if err := os.Chmod(binaryPath, 0o711); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	content := "#!/bin/sh\necho symvault-test\n"
	if err := Replace(binaryPath, []byte(content)); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}

	fi, err := os.Stat(binaryPath)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if fi.Mode().Perm() != 0o711 {
		t.Fatalf("permissions = %o, want 711", fi.Mode().Perm())
	}
}

func TestReplace_InvalidBinaryPathEmptyData(t *testing.T) {
	err := Replace("/nonexistent/binary", []byte{})
	if err == nil {
		t.Fatal("Replace() with non-existent path should error")
	}
}

func TestCreateBackup(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "test-binary")
	content := []byte("original-binary-content")
	if err := os.WriteFile(binaryPath, content, 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	backupPath, err := createBackup(binaryPath)
	if err != nil {
		t.Fatalf("createBackup() error = %v", err)
	}

	expected := binaryPath + ".backup"
	if runtime.GOOS == "windows" {
		expected = binaryPath + ".old"
	}
	if backupPath != expected {
		t.Fatalf("backup path = %q, want %q", backupPath, expected)
	}

	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("ReadFile(backup) error = %v", err)
	}
	if string(data) != string(content) {
		t.Fatalf("backup content = %q, want %q", string(data), string(content))
	}

	// Backup should be a different inode than original.
	sbOrig, _ := os.Stat(binaryPath)
	sbBackup, _ := os.Stat(backupPath)
	if os.SameFile(sbOrig, sbBackup) {
		t.Fatal("backup must be a separate file, not a hard link")
	}
}

func TestCreateBackup_SourceNotFound(t *testing.T) {
	_, err := createBackup("/nonexistent/path")
	if err == nil {
		t.Fatal("createBackup() with missing source should error")
	}
}

func TestRollback(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "test-binary")
	backupPath := filepath.Join(tmpDir, "test-binary.backup")

	originalContent := []byte("original-binary-data")
	corruptedContent := []byte("this is corrupted data that replaced the binary")

	if err := os.WriteFile(binaryPath, corruptedContent, 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(backupPath, originalContent, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := rollback(backupPath, binaryPath); err != nil {
		t.Fatalf("rollback() error = %v", err)
	}

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("ReadFile(binary) error = %v", err)
	}
	if string(data) != string(originalContent) {
		t.Fatalf("binary content = %q, want %q", string(data), string(originalContent))
	}

	// Backup must still exist after rollback.
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("backup should persist after rollback: %v", err)
	}
}

func TestRollback_BackupNotFound(t *testing.T) {
	err := rollback("/nonexistent/backup", "/tmp/dummy-binary")
	if err == nil {
		t.Fatal("rollback() with missing backup should error")
	}
}

func TestVerifyBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping: execution verification not supported on windows")
	}

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test-script")
	writeScript(t, scriptPath)

	if err := verifyBinary(scriptPath); err != nil {
		t.Fatalf("verifyBinary() on valid script error = %v", err)
	}
}

func TestVerifyBinary_NotFound(t *testing.T) {
	err := verifyBinary("/nonexistent/binary")
	if err == nil {
		t.Fatal("verifyBinary() with non-existent path should error")
	}
}

func TestVerifyBinary_NotExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping: execution verification not supported on windows")
	}

	tmpDir := t.TempDir()
	nonExecPath := filepath.Join(tmpDir, "noexec")
	if err := os.WriteFile(nonExecPath, []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := verifyBinary(nonExecPath); err == nil {
		t.Fatal("verifyBinary() on non-executable file should error")
	}
}

func TestBackupPath_Default(t *testing.T) {
	bp := backupPath("/usr/local/bin/symvault")
	expected := "/usr/local/bin/symvault.backup"
	if runtime.GOOS == "windows" {
		expected = "/usr/local/bin/symvault.old"
	}
	if bp != expected {
		t.Fatalf("backupPath() = %q, want %q", bp, expected)
	}
}

func TestBackupPath_WithSuffix(t *testing.T) {
	bp := backupPath("/home/user/bin/myapp")
	if !strings.HasSuffix(bp, ".backup") && !strings.HasSuffix(bp, ".old") {
		t.Fatalf("backupPath() = %q, expected .backup or .old suffix", bp)
	}
}

func TestWriteTempBinary(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "target-binary")

	data := []byte("new binary content")
	tmpPath, err := writeTempBinary(binaryPath, data)
	if err != nil {
		t.Fatalf("writeTempBinary() error = %v", err)
	}
	defer os.Remove(tmpPath) //nolint:errcheck

	// Temp file must be in the same directory as binaryPath.
	if filepath.Dir(tmpPath) != tmpDir {
		t.Fatalf("temp file dir = %q, want %q", filepath.Dir(tmpPath), tmpDir)
	}

	written, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("ReadFile(temp) error = %v", err)
	}
	if string(written) != string(data) {
		t.Fatalf("temp content = %q, want %q", string(written), string(data))
	}
}

func TestWriteTempBinary_EmptyData(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "target")

	tmpPath, err := writeTempBinary(binaryPath, []byte{})
	if err != nil {
		t.Fatalf("writeTempBinary() with empty data error = %v", err)
	}
	defer os.Remove(tmpPath) //nolint:errcheck

	fi, err := os.Stat(tmpPath)
	if err != nil {
		t.Fatalf("Stat(temp) error = %v", err)
	}
	if fi.Size() != 0 {
		t.Fatalf("temp file size = %d, want 0", fi.Size())
	}
}
