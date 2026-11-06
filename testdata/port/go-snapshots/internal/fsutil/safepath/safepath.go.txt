package safepath

import "os"

// SafeWriter writes data atomically and safely, rejecting symlink and non-regular
// file targets. Implementations must use O_NOFOLLOW or equivalent platform checks
// to prevent symlink traversal.
type SafeWriter interface {
	WriteFile(path string, data []byte, perm os.FileMode) error
}

// SafeRemover removes a regular file, rejecting symlinks and non-regular targets.
type SafeRemover interface {
	Remove(path string) error
}

// SafeMkdir creates directories with symlink-traversal protection. Each path
// component is verified to reject non-root symlinks.
type SafeMkdir interface {
	MkdirAll(path string, perm os.FileMode) error
}

// Manager combines SafeWriter, SafeRemover, and SafeMkdir into a single
// interface. Callers that need all three operations should depend on Manager
// to avoid multiple interface parameters.
type Manager interface {
	SafeWriter
	SafeRemover
	SafeMkdir
}
