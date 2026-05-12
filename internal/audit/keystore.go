// Package audit provides audit logging for MCP tool calls.
package audit

const (
	keyringService       = "openpass"
	keyringAccountPrefix = "audit-hmac-key"
)

// Keystore provides HMAC key persistence via OS keychain with file fallback.
type Keystore interface {
	// LoadOrCreateHMACKey returns the HMAC key, creating a new one if none exists.
	LoadOrCreateHMACKey() ([]byte, error)

	// LoadHMACKey returns the HMAC key if it exists, or an error if not found.
	LoadHMACKey() ([]byte, error)
}

func keyringAccount(auditDir string) string {
	return keyringAccountPrefix + ":" + auditDir
}
