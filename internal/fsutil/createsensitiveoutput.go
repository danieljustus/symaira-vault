package fsutil

import (
	"io"
	"os"
)

// noopWriteCloser wraps a Writer with a no-op Close so callers can defer
// Close without risking closing stdout or other shared file descriptors.
type noopWriteCloser struct {
	io.Writer
}

// Close is a no-op — it never returns an error.
func (noopWriteCloser) Close() error { return nil }

// CreateSensitiveOutput returns an io.WriteCloser for writing sensitive output.
// When path is empty it writes to os.Stdout with a no-op Close so that stdout
// is never closed. When path is non-empty it creates (or truncates) the file at
// path with mode 0600 so that only the file owner can read or write the
// contents.
func CreateSensitiveOutput(path string) (io.WriteCloser, error) {
	if path == "" {
		return noopWriteCloser{Writer: os.Stdout}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- output path is user-provided CLI argument
	if err != nil {
		return nil, err
	}
	return f, nil
}
