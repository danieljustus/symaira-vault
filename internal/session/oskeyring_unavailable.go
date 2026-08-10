//go:build !(darwin || linux || windows || netbsd || openbsd || ((freebsd || dragonfly) && cgo))

package session

// VerifyOSKeyring is unavailable on platforms without the OS-keyring
// implementation. The doctor reports this as unavailable rather than
// attempting a platform-specific keychain operation.
func VerifyOSKeyring() error {
	return ErrKeyringUnavailable
}
