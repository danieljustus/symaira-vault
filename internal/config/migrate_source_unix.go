//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// opOpen is the os.PathError.Op reported for every failure below; each one
// originates from an open/openat call on the migration source path.
const opOpen = "open"

// openMigrationSource resolves every component from an opened directory. This
// deliberately rejects symlinked parents as well as a symlink leaf.
func openMigrationSource(path string) (*os.File, error) {
	clean, err := migrationAbsolutePath(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(string(filepathSeparator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepathSeparator)), string(filepathSeparator))
	if len(parts) == 0 || parts[len(parts)-1] == "" {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("invalid migration source: %s", path)
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, &os.PathError{Op: opOpen, Path: path, Err: openErr}
		}
		fd = next
	}
	leaf := parts[len(parts)-1]
	leafFD, err := unix.Openat(fd, leaf, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	_ = unix.Close(fd)
	if err != nil {
		return nil, &os.PathError{Op: opOpen, Path: path, Err: err}
	}
	file := os.NewFile(uintptr(leafFD), path)
	if file == nil {
		_ = syscall.Close(leafFD)
		return nil, &os.PathError{Op: opOpen, Path: path, Err: syscall.EINVAL}
	}
	return file, nil
}

const filepathSeparator = byte('/')

func migrationAbsolutePath(path string) (string, error) {
	clean, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	// /var is a system-owned macOS alias. Resolve only that known boundary;
	// user-controlled components remain no-followed below.
	if strings.HasPrefix(clean, "/var/") {
		if info, statErr := os.Lstat("/var"); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			if resolved, resolveErr := os.Readlink("/var"); resolveErr == nil && resolved == "private/var" {
				clean = "/private" + clean
			}
		}
	}
	return clean, nil
}
