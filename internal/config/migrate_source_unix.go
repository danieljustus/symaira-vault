//go:build !windows

package config

import (
	"os"
	"syscall"
)

func openMigrationSource(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, &os.PathError{Op: "open", Path: path, Err: syscall.EINVAL}
	}
	return file, nil
}
