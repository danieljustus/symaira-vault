// Package audit provides audit logging for MCP tool calls.
package audit

import (
	"path/filepath"
	"time"
)

const (
	keyringService       = "symaira"
	keyringAccountPrefix = "audit-hmac-key"
)

// Keystore provides HMAC key persistence via OS keychain with file fallback.
type Keystore interface {
	// LoadOrCreateHMACKey returns the HMAC key, creating a new one if none exists.
	LoadOrCreateHMACKey() ([]byte, error)

	// LoadHMACKey returns the HMAC key if it exists, or an error if not found.
	LoadHMACKey() ([]byte, error)

	// RotateKey generates a new HMAC key, archives the existing key, and
	// returns the new key bytes. The old key is archived to a timestamped
	// backup file (e.g. audit-hmac-key.YYYY-MM-DD) in the audit directory.
	RotateKey() ([]byte, error)
}

// RotateKeyArchivePath returns the archive path for an old HMAC key.
func RotateKeyArchivePath(auditDir string) string {
	return filepath.Join(auditDir, hmacKeyFileName+".rotated."+time.Now().UTC().Format("2006-01-02"))
}

func keyringAccount(auditDir string) string {
	return keyringAccountPrefix + ":" + auditDir
}
