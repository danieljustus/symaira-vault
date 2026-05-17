package secureui

// capsLockDetector returns true when Caps Lock is currently engaged on this
// host. Implementations are best-effort: they return false when the platform
// has no usable API rather than blocking or panicking. Tests substitute this
// to drive both branches.
var capsLockDetector = defaultCapsLockDetector

// CapsLockWarning returns a short user-facing string when Caps Lock is on,
// or empty when it isn't or detection isn't available. Callers prepend it
// to their hidden-input prompt so users notice before they mistype a long
// passphrase.
func CapsLockWarning() string {
	if capsLockDetector() {
		return "⚠ Caps Lock is on — your passphrase may be miscased.\n"
	}
	return ""
}
