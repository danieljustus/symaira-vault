//go:build !darwin && !linux

package secureui

// defaultCapsLockDetector has no implementation on this platform. Always
// returns false so the warning never fires; callers proceed normally.
func defaultCapsLockDetector() bool {
	return false
}
