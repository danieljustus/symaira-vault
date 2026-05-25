//go:build !windows

package vault

import (
	"os"
	"syscall"

	"github.com/danieljustus/symaira-vault/internal/fileutil"
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

	return fileutil.AtomicWriteFile(path, data, perm)
}

func SafeRemove(path string) error {
	flags := syscall.O_NOFOLLOW | syscall.O_RDONLY

	fd, err := syscall.Open(path, flags, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer func() { _ = syscall.Close(fd) }()

	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil {
		return &os.PathError{Op: "fstat", Path: path, Err: err}
	}

	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return &os.PathError{
			Op:   "open",
			Path: path,
			Err:  syscall.ENOTDIR,
		}
	}

	if err = syscall.Close(fd); err != nil {
		return &os.PathError{Op: "close", Path: path, Err: err}
	}

	return os.Remove(path)
}

func SafeMkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}
