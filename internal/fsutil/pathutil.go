// Package fsutil provides path validation, traversal detection, and safe file I/O.
package fsutil

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ErrInvalidPath is returned when a path contains invalid characters or patterns.
var ErrInvalidPath = errors.New("invalid path")

// ValidatePath validates a path for use in vault entry operations.
// It rejects paths containing:
//   - Parent directory traversal (..)
//   - Null bytes (\x00)
//   - Control characters (< 0x20)
//
// Returns nil if the path is valid, or an error describing the specific issue.
func ValidatePath(path string) error {
	if path == "" {
		return fmt.Errorf("%w: path is empty", ErrInvalidPath)
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("%w: path contains null byte", ErrInvalidPath)
	}

	// Check for control characters (anything below 0x20 except tab, newline which we allow)
	for _, r := range path {
		if r < 0x20 && r != '\t' && r != '\n' {
			return fmt.Errorf("%w: path contains control character 0x%02x", ErrInvalidPath, r)
		}
	}

	// Normalize path separators and check for traversal
	// First convert Windows backslashes to forward slashes for cross-platform consistency
	normalized := strings.ReplaceAll(path, "\\", "/")
	normalized = filepath.ToSlash(normalized)

	// Reject absolute paths
	if strings.HasPrefix(normalized, "/") {
		return fmt.Errorf("%w: path must be relative", ErrInvalidPath)
	}

	// Check for .. segments
	segments := strings.Split(normalized, "/")
	for _, segment := range segments {
		if segment == ".." {
			return fmt.Errorf("%w: path contains '..' segment", ErrInvalidPath)
		}
	}

	// Reject empty segments that result from double slashes or leading/trailing slashes
	// but allow them if the path is just "/" (checked above) or empty string (checked above)
	for _, segment := range segments {
		if segment == "" && len(segments) > 1 {
			return fmt.Errorf("%w: path contains empty segment (double slash)", ErrInvalidPath)
		}
	}

	return nil
}

// HasTraversal reports whether path contains an explicit parent-directory segment.
func HasTraversal(path string) bool {
	for _, segment := range strings.Split(filepath.ToSlash(path), "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}
