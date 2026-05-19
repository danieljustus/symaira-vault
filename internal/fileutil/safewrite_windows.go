//go:build windows

package fileutil

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
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
		f.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// On Windows, renaming over an existing file can fail transiently if the
	// file is still held by the OS, antivirus, or search indexing. Retry with
	// a short backoff to absorb these races.
	var renameErr error
	for i := 0; i < 10; i++ {
		renameErr = os.Rename(tmp, path)
		if renameErr == nil {
			return nil
		}
		if i < 9 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	os.Remove(tmp)
	return renameErr
}

var errUnsafePath = errors.New("path is not a regular file")

func SafeWriteFile(path string, data []byte, perm os.FileMode) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if !info.Mode().IsRegular() {
		return &os.PathError{Op: "open", Path: path, Err: errUnsafePath}
	}

	n, err := file.Write(data)
	if err != nil {
		return &os.PathError{Op: "write", Path: path, Err: err}
	}
	if n != len(data) {
		return &os.PathError{Op: "write", Path: path, Err: io.ErrShortWrite}
	}
	return nil
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

// SafeMkdirAll creates a directory at path and all necessary parent directories.
// Unlike os.MkdirAll, it walks the path component-by-component so that a
// parent-directory symlink replacement is caught at the next component check.
func SafeMkdirAll(path string, perm os.FileMode) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	vol := filepath.VolumeName(abs)
	var parts []string
	for p := filepath.Clean(abs); len(p) > len(vol); {
		parts = append(parts, filepath.Base(p))
		next := filepath.Dir(p)
		if next == p {
			break
		}
		p = next
	}

	cur := vol + string(filepath.Separator)
	for i := len(parts) - 1; i >= 0; i-- {
		cur = filepath.Join(cur, parts[i])

		fi, err := os.Stat(cur)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			if err := os.Mkdir(cur, perm); err != nil {
				return err
			}
			continue
		}

		if !fi.IsDir() {
			return &os.PathError{Op: "mkdir", Path: cur, Err: errUnsafePath}
		}
	}
	return nil
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
