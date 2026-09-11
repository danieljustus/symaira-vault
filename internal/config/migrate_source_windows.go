//go:build windows

package config

import "os"

func openMigrationSource(string) (*os.File, error) {
	return nil, errMigrationUnsupported
}
