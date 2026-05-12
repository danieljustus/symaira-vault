//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package secureui

// newGUIBackend has no GUI support on this platform.
func newGUIBackend(_ runner) backend { return nil }
