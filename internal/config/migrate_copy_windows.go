//go:build windows

package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Windows lacks the Unix *at APIs used by the hardened implementation. Keep
// the migration fail-closed for symlinks and exclusive destination creation.
func secureCopyEntry(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink: %s", src)
	}
	if info.IsDir() {
		if err := os.Mkdir(dst, 0o700); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := secureCopyEntry(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular source: %s", src)
	}
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxMigrationBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxMigrationBytes {
		return fmt.Errorf("source exceeds migration size limit: %s", src)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := out.Write(data)
	closeErr := out.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
