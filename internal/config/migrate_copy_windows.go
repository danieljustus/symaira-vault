//go:build windows

package config

import (
	"errors"
)

var errMigrationUnsupported = errors.New("legacy path migration is unavailable on Windows: secure descriptor-relative file operations are required")

func secureCopyEntry(_, _ string) error           { return errMigrationUnsupported }
func secureReadFile(string) ([]byte, error)       { return nil, errMigrationUnsupported }
func secureRemovePath(string) error               { return errMigrationUnsupported }
func secureWriteJSONAtomic(string, []byte) error  { return errMigrationUnsupported }
func secureMkdirOpen(string, uint32) (int, error) { return -1, errMigrationUnsupported }
func closeMigrationFD(int) error                  { return nil }
