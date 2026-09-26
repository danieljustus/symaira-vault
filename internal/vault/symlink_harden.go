//go:build !windows

package vault

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

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
			return &os.PathError{Op: errOpOpen, Path: path, Err: syscall.ELOOP}
		}
		if !info.Mode().IsRegular() {
			return &os.PathError{Op: errOpOpen, Path: path, Err: syscall.ENOTDIR}
		}
	} else if !os.IsNotExist(err) {
		return &os.PathError{Op: "lstat", Path: path, Err: err}
	}

	return fsutil.AtomicWriteFile(path, data, perm)
}

// SafeReadFile reads the file at path after verifying it is not a symlink
// or other non-regular file. This prevents an attacker who controls a
// symlink at path from having the vault read an arbitrary file.
func SafeReadFile(path string) ([]byte, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, &os.PathError{Op: errOpOpen, Path: path, Err: syscall.ELOOP}
		}
		if !info.Mode().IsRegular() {
			return nil, &os.PathError{Op: errOpOpen, Path: path, Err: syscall.ENOTDIR}
		}
	} else if !os.IsNotExist(err) {
		return nil, &os.PathError{Op: "lstat", Path: path, Err: err}
	}

	return os.ReadFile(path) // #nosec G304 -- symlink check performed above
}

// readEntryFileBounded opens an entry without following a final symlink, rejects
// non-regular files before reading, and never allocates beyond the entry budget.
func readEntryFileBounded(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if !info.Mode().IsRegular() {
		return nil, &os.PathError{Op: "open", Path: path, Err: syscall.ENOTDIR}
	}
	return readEntryStreamBounded(file, path)
}

func readEntryRootedBounded(vaultDir, relative string) ([]byte, error) {
	root, err := os.OpenRoot(vaultDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := rejectEntryRootSymlinks(root, relative); err != nil {
		return nil, err
	}
	file, err := root.OpenFile(relative, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: filepath.Join(vaultDir, relative), Err: err}
	}
	defer file.Close()
	return readEntryStreamBounded(file, filepath.Join(vaultDir, relative))
}

func readEntryStreamBounded(file *os.File, path string) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if !info.Mode().IsRegular() {
		return nil, &os.PathError{Op: "open", Path: path, Err: syscall.ENOTDIR}
	}
	if info.Size() > maxEntryCiphertextBytesV1 {
		return nil, fmt.Errorf("%w: ciphertext", errEntryReadLimit)
	}
	bytes, err := io.ReadAll(io.LimitReader(file, maxEntryCiphertextBytesV1+1))
	if err != nil {
		return nil, err
	}
	if len(bytes) > maxEntryCiphertextBytesV1 {
		return nil, fmt.Errorf("%w: ciphertext", errEntryReadLimit)
	}
	return bytes, nil
}

func rejectEntryRootSymlinks(root *os.Root, relative string) error {
	if filepath.IsAbs(relative) {
		return fmt.Errorf("entry path escapes vault root: %q", relative)
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("entry path escapes vault root: %q", relative)
	}
	current := ""
	parts := strings.Split(filepath.ToSlash(clean), "/")
	for i, part := range parts {
		current = filepath.Join(current, filepath.FromSlash(part))
		info, err := root.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return &os.PathError{Op: "open", Path: relative, Err: syscall.ELOOP}
		}
		if i < len(parts)-1 && !info.IsDir() {
			return &os.PathError{Op: "open", Path: relative, Err: syscall.ENOTDIR}
		}
	}
	return nil
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
