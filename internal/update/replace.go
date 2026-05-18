// Package update provides functionality for checking and managing OpenPass updates.
package update

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const (
	// backupSuffix is the suffix appended to the binary path for backup files.
	backupSuffix = ".backup"

	// windowsBackupSuffix is used on Windows to avoid confusion with .backup.
	windowsBackupSuffix = ".old"
)

// backupPath returns the backup file path for the given binary, using the
// platform-appropriate suffix.
func backupPath(binaryPath string) string {
	suffix := backupSuffix
	if runtime.GOOS == windowsOS {
		suffix = windowsBackupSuffix
	}
	return binaryPath + suffix
}

// createBackup copies the binary at binaryPath to a backup file in the same
// directory, using a platform-specific suffix (.backup on Unix, .old on
// Windows). Returns the path to the backup file.
func createBackup(binaryPath string) (string, error) {
	bp := backupPath(binaryPath)

	src, err := os.Open(filepath.Clean(binaryPath))
	if err != nil {
		return "", fmt.Errorf("open source for backup: %w", err)
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(filepath.Clean(bp), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("create backup file %q: %w", bp, err)
	}
	defer func() { _ = dst.Close() }()

	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("copy to backup: %w", err)
	}

	return bp, nil
}

// rollback restores the binary at binaryPath from the backup at backupPath.
// The backup file is preserved after the operation. If the binary file still
// exists at the time of rollback, its existing permissions are preserved.
func rollback(backupPath, binaryPath string) error {
	src, err := os.Open(filepath.Clean(backupPath))
	if err != nil {
		return fmt.Errorf("rollback: open backup %q: %w", backupPath, err)
	}
	defer func() { _ = src.Close() }()

	perm := os.FileMode(0o755)
	if fi, statErr := os.Stat(binaryPath); statErr == nil {
		perm = fi.Mode().Perm()
	}

	dst, err := os.OpenFile(filepath.Clean(binaryPath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("rollback: create %q: %w", binaryPath, err)
	}
	defer func() { _ = dst.Close() }()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("rollback: copy to %q: %w", binaryPath, err)
	}

	return nil
}

// verifyBinary runs the binary at binaryPath with --version and returns an
// error if the execution fails. This is used to validate a newly replaced
// binary before confirming the replacement.
func verifyBinary(binaryPath string) error {
	cmd := exec.Command(binaryPath, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("verify %q --version: %w (output: %s)",
			binaryPath, err, string(output))
	}
	return nil
}

// writeTempBinary creates a temporary file in the same directory as
// binaryPath, writes data to it, and returns the path to the temporary file.
// The file is created with os.CreateTemp so it gets a unique name. On any
// error during write or close, the partially written temp file is removed.
func writeTempBinary(binaryPath string, data []byte) (string, error) {
	dir := filepath.Dir(binaryPath)
	tmpFile, err := os.CreateTemp(dir, ".openpass-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp file in %q: %w", dir, err)
	}

	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("write data to temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close temp file: %w", err)
	}

	return tmpPath, nil
}

// Replace performs an atomic replacement of the binary at binaryPath with
// newBinaryData. The replacement sequence is:
//
//  1. Verify the binary file exists at binaryPath.
//  2. Create a backup of the current binary.
//  3. Write the new binary data to a temporary file in the same directory.
//  4. Preserve the original file permissions on the temporary file.
//  5. Atomically rename the temporary file to binaryPath.
//  6. Verify the new binary by executing it with --version.
//
// On any failure after step 2, the backup is restored (rollback). The backup
// is kept on disk after a successful replacement for safety.
//
// Windows: the destination file is removed before rename because os.Rename
// does not reliably overwrite existing files on Windows. The backup uses the
// .old suffix instead of .backup. MOVEFILE_DELAY_UNTIL_REBOOT is not
// implemented; the replacement is immediate.
func Replace(binaryPath string, newBinaryData []byte) (err error) {
	fi, err := os.Stat(binaryPath)
	if err != nil {
		return fmt.Errorf("replace: cannot stat %q: %w", binaryPath, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("replace: %q is not a regular file", binaryPath)
	}

	backupPath, err := createBackup(binaryPath)
	if err != nil {
		return fmt.Errorf("replace: create backup: %w", err)
	}

	tmpPath, err := writeTempBinary(binaryPath, newBinaryData)
	if err != nil {
		return fmt.Errorf("replace: write new binary: %w", err)
	}

	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
			if rbErr := rollback(backupPath, binaryPath); rbErr != nil {
				err = fmt.Errorf("%w; rollback failed: %w", err, rbErr)
			}
		}
	}()

	if chmodErr := os.Chmod(tmpPath, fi.Mode().Perm()); chmodErr != nil {
		err = fmt.Errorf("replace: preserve permissions: %w", chmodErr)
		return
	}

	if runtime.GOOS == windowsOS {
		if rmErr := os.Remove(binaryPath); rmErr != nil {
			err = fmt.Errorf("replace: remove original for rename on windows: %w", rmErr)
			return
		}
	}

	if renameErr := os.Rename(tmpPath, binaryPath); renameErr != nil {
		err = fmt.Errorf("replace: rename %q -> %q: %w", tmpPath, binaryPath, renameErr)
		return
	}

	if verifyErr := verifyBinary(binaryPath); verifyErr != nil {
		err = fmt.Errorf("replace: verification failed: %w", verifyErr)
		return
	}

	return nil
}
