//go:build !darwin

package session

// HasGUISession reports whether the process runs inside a GUI session.
// Only macOS supports biometric GUI prompts today; other platforms have
// no Aqua session to probe and always report false.
func HasGUISession() bool {
	return false
}
