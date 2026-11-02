//go:build windows

package safepath

import (
	"os"

	"github.com/danieljustus/symaira-vault/internal/fsutil"
)

type defaultManager struct{}

var DefaultManager Manager = &defaultManager{}

func (m *defaultManager) WriteFile(path string, data []byte, perm os.FileMode) error {
	return fsutil.SafeWriteFile(path, data, perm)
}

func (m *defaultManager) Remove(path string) error {
	return fsutil.SafeRemove(path)
}

func (m *defaultManager) MkdirAll(path string, perm os.FileMode) error {
	return fsutil.SafeMkdirAll(path, perm)
}
