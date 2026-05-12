//go:build windows

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

const lockFileName = ".lock"

// DefaultLockTimeout is the default timeout for acquiring a write lock.
const DefaultLockTimeout = 30 * time.Second

// lockFileRetryInterval is the interval between retries when acquiring a lock.
const lockFileRetryInterval = 50 * time.Millisecond

// AcquireWriteLock opens (or creates) the vault lock file and acquires an
// exclusive LockFileEx on it. It retries with polling until the timeout
// expires and returns an error if the lock cannot be acquired in time.
func AcquireWriteLock(vaultDir string, timeout time.Duration) (*os.File, error) {
	if timeout <= 0 {
		timeout = DefaultLockTimeout
	}

	lockPath := filepath.Join(vaultDir, lockFileName)

	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		return nil, fmt.Errorf("create vault directory for lock: %w", err)
	}

	lockPathPtr, err := windows.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, fmt.Errorf("convert lock path: %w", err)
	}

	handle, err := windows.CreateFile(
		lockPathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}

	f := os.NewFile(uintptr(handle), lockPath)

	deadline := time.Now().Add(timeout)
	for {
		err := windows.LockFileEx(
			handle,
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			1, 0, // lock 1 byte (advisory lock, sufficient for .lock file)
			nil,
		)
		if err == nil {
			return f, nil
		}

		// ERROR_LOCK_VIOLATION (33) means the lock is held by another process — retry.
		// Any other error is unexpected — fail fast.
		errno, isErrno := err.(syscall.Errno)
		if !isErrno || errno != 33 {
			_ = f.Close()
			return nil, fmt.Errorf("lock error: %w", err)
		}

		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("vault is currently locked by another process, try again in a moment")
		}

		time.Sleep(lockFileRetryInterval)
	}
}

// ReleaseLock releases a LockFileEx lock and closes the lock file.
func ReleaseLock(lockFile *os.File) error {
	if lockFile == nil {
		return nil
	}

	if err := windows.UnlockFileEx(
		windows.Handle(lockFile.Fd()),
		0,
		1, 0, // must match the byte range used in LockFileEx
		nil,
	); err != nil {
		_ = lockFile.Close()
		return fmt.Errorf("unlock error: %w", err)
	}

	return lockFile.Close()
}
