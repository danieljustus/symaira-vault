package fsutil

import (
	"os"

	corekitfsutil "github.com/danieljustus/symaira-corekit/fsutil"
)

// ErrInvalidPath is returned when a path contains invalid characters or patterns.
var ErrInvalidPath = corekitfsutil.ErrInvalidPath

// ValidatePath validates a path for use in vault entry operations.
// It rejects paths containing:
//   - Parent directory traversal (..)
//   - Null bytes (\x00)
//   - Control characters (< 0x20)
//
// Returns nil if the path is valid, or an error describing the specific issue.
func ValidatePath(path string) error {
	return corekitfsutil.ValidatePath(path)
}

// HasTraversal reports whether path contains an explicit parent-directory segment.
func HasTraversal(path string) bool {
	return corekitfsutil.HasTraversal(path)
}

// AtomicWriteFile writes data to a unique temporary file in the same directory,
// fsyncs it, closes it, and then atomically renames it to path. This prevents
// partial writes or crashes from leaving the target file in an inconsistent
// state and avoids temp file name collisions under concurrency.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	return corekitfsutil.AtomicWriteFile(path, data, perm)
}

// SafeWriteFile writes data to path while hardening against symlink-traversal
// attacks. It opens the file with O_NOFOLLOW and verifies the opened fd is a
// regular file before writing.
func SafeWriteFile(path string, data []byte, perm os.FileMode) error {
	return corekitfsutil.SafeWriteFile(path, data, perm)
}

// SafeRemove removes a regular file at path, hardening against symlink-traversal
// attacks. It opens the file with O_NOFOLLOW, verifies it is a regular file,
// closes it, then removes by path.
func SafeRemove(path string) error {
	return corekitfsutil.SafeRemove(path)
}

// SafeMkdirAll creates a directory at path and all necessary parent directories,
// hardening against symlink-traversal attacks. Each existing path component is
// checked with Lstat — symlinks owned by non-root are rejected (they are outside
// the system trust boundary, e.g. an attacker placing a symlink inside a
// user-writable vault directory). Root-owned symlinks (e.g. /var → /private/var
// on macOS) are trusted and resolved via EvalSymlinks so the remaining path is
// created at the real location.
func SafeMkdirAll(path string, perm os.FileMode) error {
	return corekitfsutil.SafeMkdirAll(path, perm)
}
