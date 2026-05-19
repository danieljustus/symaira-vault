//go:build !windows

package fileutil

import (
	"os"
	"path/filepath"
	"syscall"
)

// AtomicWriteFile writes data to a unique temporary file in the same directory,
// fsyncs it, closes it, and then atomically renames it to path. This prevents
// partial writes or crashes from leaving the target file in an inconsistent
// state and avoids temp file name collisions under concurrency.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func SafeWriteFile(path string, data []byte, perm os.FileMode) error {
	flags := syscall.O_NOFOLLOW | os.O_CREATE | os.O_TRUNC | os.O_WRONLY

	fd, err := syscall.Open(path, flags, uint32(perm))
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

	n, err := syscall.Write(fd, data)
	if err != nil {
		return &os.PathError{Op: "write", Path: path, Err: err}
	}
	if n != len(data) {
		return &os.PathError{Op: "write", Path: path, Err: syscall.ENOSPC}
	}

	return nil
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

// SafeMkdirAll creates a directory at path and all necessary parent directories,
// hardening against symlink-traversal attacks. Each existing path component is
// checked with Lstat — symlinks owned by non-root are rejected (they are outside
// the system trust boundary, e.g. an attacker placing a symlink inside a
// user-writable vault directory). Root-owned symlinks (e.g. /var → /private/var
// on macOS) are trusted and resolved via EvalSymlinks so the remaining path is
// created at the real location.
func SafeMkdirAll(path string, perm os.FileMode) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	// Collect path components leaf-to-root so we can walk root-to-leaf.
	var components []string
	for p := filepath.Clean(abs); p != "/"; p = filepath.Dir(p) {
		components = append(components, filepath.Base(p))
	}

	// Walk root-to-leaf, verifying each existing component.
	cur := "/"
	for i := len(components) - 1; i >= 0; i-- {
		cur = filepath.Join(cur, components[i])

		fi, err := os.Lstat(cur)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			if err := os.Mkdir(cur, perm); err != nil {
				return err
			}
			continue
		}

		// Symlink check: allow root-owned symlinks (trusted system symlinks
		// like /var→/private/var on macOS), reject all others (attacker).
		if fi.Mode()&os.ModeSymlink != 0 {
			if stat, ok := fi.Sys().(*syscall.Stat_t); ok && stat.Uid == 0 {
				real, err := filepath.EvalSymlinks(cur)
				if err != nil {
					return err
				}
				cur = real
				continue
			}
			return &os.PathError{Op: "mkdir", Path: cur, Err: syscall.ELOOP}
		}

		if !fi.IsDir() {
			return &os.PathError{Op: "mkdir", Path: cur, Err: syscall.ENOTDIR}
		}
	}
	return nil
}
