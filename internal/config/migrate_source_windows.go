//go:build windows

package config

import "os"

func openMigrationSource(path string) (*os.File, error) {
	return os.Open(path)
}
