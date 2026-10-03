//go:build windows

package vault

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/fsutil"
	"github.com/danieljustus/symaira-vault/internal/fsutil/safepath"
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
			return &os.PathError{Op: errOpOpen, Path: path, Err: errUnsafePath}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return fsutil.AtomicWriteFile(path, data, perm)
}

func SafeRemove(path string) error {
	return safepath.DefaultManager.Remove(path)
}

func SafeMkdirAll(path string, perm os.FileMode) error {
	return safepath.DefaultManager.MkdirAll(path, perm)
}

// SafeReadFile reads the file at path after verifying it is not a symlink
// or other non-regular file. This prevents an attacker who controls a
// symlink at path from having the vault read an arbitrary file.
func SafeReadFile(path string) ([]byte, error) {
	if err := rejectSymlink(path); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, &os.PathError{Op: "open", Path: path, Err: errUnsafePath}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	return os.ReadFile(path) // #nosec G304 -- symlink check performed above
}

func readEntryFileBounded(path string) ([]byte, error) {
	if err := rejectSymlink(path); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readEntryStreamBounded(file, path)
}

func readRootedFileLimited(vaultDir, relative string, limit int64, budgets ...*vaultReadBatch) ([]byte, error) {
	var raw []byte
	err := withRootedFile(vaultDir, relative, func(file *os.File, path string) error {
		var err error
		raw, err = readEntryStreamLimited(file, path, limit, budgets...)
		return err
	})
	return raw, err
}

func withRootedFile(vaultDir, relative string, consume func(*os.File, string) error) error {
	root, err := os.OpenRoot(vaultDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := rejectEntryRootSymlinks(root, relative); err != nil {
		return err
	}
	file, err := root.Open(relative)
	if err != nil {
		return &os.PathError{Op: "open", Path: filepath.Join(vaultDir, relative), Err: err}
	}
	defer file.Close()
	return consume(file, filepath.Join(vaultDir, relative))
}

func readEntryStreamBounded(file *os.File, path string) ([]byte, error) {
	return readEntryStreamLimited(file, path, maxEntryCiphertextBytesV1)
}

func readEntryStreamLimited(file *os.File, path string, limit int64, budgets ...*vaultReadBatch) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, &os.PathError{Op: "open", Path: path, Err: errUnsafePath}
	}
	var batch *vaultReadBatch
	if len(budgets) != 0 {
		batch = budgets[0]
	}
	if budgetErr := batch.consume(0); budgetErr != nil {
		return nil, budgetErr
	}
	if info.Size() > limit {
		batch.fail()
		return nil, errEntryReadLimit
	}
	if budgetErr := batch.consume(int(info.Size())); budgetErr != nil {
		return nil, budgetErr
	}
	readLimit := limit
	if batch != nil {
		readLimit = info.Size()
	}
	bytes, err := io.ReadAll(io.LimitReader(file, readLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(bytes)) > readLimit {
		batch.fail()
		return nil, errEntryReadLimit
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
			return &os.PathError{Op: "open", Path: relative, Err: errUnsafePath}
		}
		if i < len(parts)-1 && !info.IsDir() {
			return &os.PathError{Op: "open", Path: relative, Err: errUnsafePath}
		}
	}
	return nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return &os.PathError{Op: errOpOpen, Path: path, Err: errUnsafePath}
		}
		return nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
