//go:build !windows

package vault

import (
	"os"
	"syscall"

	"github.com/danieljustus/symaira-vault/internal/fsutil"
	"github.com/danieljustus/symaira-vault/internal/fsutil/safepath"
)

// SafeWriteFile atomically writes data to path, rejecting symlink and
// non-regular targets. The write is staged in a temporary file, fsynced,
// and renamed into place — so a crash mid-write cannot corrupt an existing
// entry.
func SafeWriteFile(path string, data []byte, perm os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return &os.PathError{Op: "open", Path: path, Err: syscall.ELOOP}
		}
		if !info.Mode().IsRegular() {
			return &os.PathError{Op: "open", Path: path, Err: syscall.ENOTDIR}
		}
	} else if !os.IsNotExist(err) {
		return &os.PathError{Op: "lstat", Path: path, Err: err}
	}

	return fsutil.AtomicWriteFile(path, data, perm)
}

// SafeRemove delegates to the safepath package's symlink-hardened remove.
func SafeRemove(path string) error {
	return safepath.DefaultManager.Remove(path)
}

// SafeMkdirAll delegates to the safepath package's component-walking
// mkdir that rejects non-root symlinks at each path component.
func SafeMkdirAll(path string, perm os.FileMode) error {
	return safepath.DefaultManager.MkdirAll(path, perm)
}
