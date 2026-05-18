//go:build !windows

package quotas

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// openQuotaFile opens (or creates) the quota file for read/write with
// permissions 0600. On Unix this uses the default OS open.
func openQuotaFile(path string) (*os.File, error) {
	return os.OpenFile(filepath.Clean(path), os.O_RDWR|os.O_CREATE, 0o600)
}

// lock acquires an exclusive file lock (flock LOCK_EX) on the quota file.
func (qc *QuotaCounter) lock() error {
	if err := syscall.Flock(int(qc.file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock: %w", err)
	}
	return nil
}

// unlock releases the file lock (flock LOCK_UN) on the quota file.
func (qc *QuotaCounter) unlock() error {
	if err := syscall.Flock(int(qc.file.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("funlock: %w", err)
	}
	return nil
}
