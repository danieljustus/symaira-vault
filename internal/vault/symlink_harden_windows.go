//go:build windows

package vault

import (
	"errors"
	"io/fs"
	"os"

	"github.com/danieljustus/symaira-vault/internal/fsutil"
)

var errUnsafePath = errors.New("path is not a regular file")

// SafeWriteFile atomically writes data to path, rejecting symlink and
// non-regular targets. The write is staged in a temporary file and renamed
// into place — so a crash mid-write cannot corrupt an existing entry.
func SafeWriteFile(path string, data []byte, perm os.FileMode) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return &os.PathError{Op: "open", Path: path, Err: errUnsafePath}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return fsutil.AtomicWriteFile(path, data, perm)
}

func SafeRemove(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return &os.PathError{Op: "open", Path: path, Err: errUnsafePath}
	}
	return os.Remove(path)
}

func SafeMkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return &os.PathError{Op: "open", Path: path, Err: errUnsafePath}
		}
		return nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
