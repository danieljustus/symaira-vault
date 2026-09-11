//go:build windows

package config

import "errors"

// Windows does not provide the descriptor-relative no-follow primitives used
// by the migration boundary. Refuse the operation rather than falling back to
// a path-based copy with a check/use race.
func secureCopyEntry(_, _ string) error {
	return errors.New("legacy path migration is unavailable on Windows: secure descriptor-relative file operations are required")
}
