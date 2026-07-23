package redact

import (
	"crypto/rand"
	"encoding/hex"
	"os"
)

// EnvStrictMode is the opt-in environment variable that enables strict
// blocking mode (#696): when set to a truthy value, a ConfidenceHigh
// detection causes the Scanner to block delivery/persistence of the
// affected output instead of only redacting it in place. Disabled
// (redact-and-continue) by default — this is an explicit opt-in, matching
// this codebase's fail-safe-by-default / explicit-opt-in-for-stricter-
// behavior convention (see the environment-passphrase opt-in flag).
const EnvStrictMode = "SYMVAULT_REDACT_STRICT_MODE"

// StrictModeEnabled reports whether strict blocking mode is currently
// opted into via EnvStrictMode. Recognized truthy values are "1", "t",
// "true", "yes", "on" (case-insensitive); anything else, including unset,
// is treated as disabled.
func StrictModeEnabled() bool {
	return isTruthy(os.Getenv(EnvStrictMode))
}

func isTruthy(v string) bool {
	switch v {
	case "1", "t", "T", "true", "TRUE", "True", "yes", "YES", "Yes", "on", "ON", "On":
		return true
	default:
		return false
	}
}

// NewCorrelationID returns a random, unpredictable correlation ID suitable
// for tying a Scan call's audit event(s) back to the originating request.
// It carries no information about any scanned content.
func NewCorrelationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a fixed-but-unique-enough marker rather than
		// panicking: correlation IDs are an observability aid, not a
		// security boundary, so degrading gracefully is preferable to
		// failing the calling request over an audit nicety.
		return "corr-unavailable"
	}
	return hex.EncodeToString(b)
}
