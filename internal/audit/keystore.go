// Package audit provides audit logging for MCP tool calls.
package audit

import (
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	keyringService       = "symaira"
	keyringAccountPrefix = "audit-hmac-key"
)

// ArchivedKey is a previously-active HMAC key retired by RotateKey, paired
// with a stable, human-readable label identifying its generation (the
// rotation date encoded in its archive filename). Verification tries these
// as fallback candidates so a log written under an older key generation is
// reported as verified-under-an-older-generation rather than tampered
// (#685).
type ArchivedKey struct {
	Label string
	Key   []byte
}

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

	// LoadArchivedKeys returns every HMAC key generation retired by a prior
	// RotateKey call, most recently rotated first. A key that can't be
	// decoded or decrypted (e.g. a locally-encrypted archive with no
	// matching KEK) is silently skipped rather than returned as an error —
	// callers treat "no archived key verifies this log" as unverifiable,
	// not as a hard failure.
	LoadArchivedKeys() ([]ArchivedKey, error)
}

// RotateKeyArchivePath returns the archive path for an old HMAC key.
func RotateKeyArchivePath(auditDir string) string {
	return filepath.Join(auditDir, hmacKeyFileName+".rotated."+time.Now().UTC().Format("2006-01-02"))
}

// archivedKeyPaths returns every rotation-archive file in auditDir, most
// recently rotated first (lexicographic on the YYYY-MM-DD suffix, which
// sorts chronologically).
func archivedKeyPaths(auditDir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(auditDir, hmacKeyFileName+".rotated.*"))
	if err != nil {
		return nil, err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	return matches, nil
}

// archivedKeyLabel derives a stable generation label from an archive path's
// filename, e.g. "audit-hmac-key.rotated.2026-05-12" -> "2026-05-12".
func archivedKeyLabel(path string) string {
	return strings.TrimPrefix(filepath.Base(path), hmacKeyFileName+".rotated.")
}

func keyringAccount(auditDir string) string {
	return keyringAccountPrefix + ":" + auditDir
}
