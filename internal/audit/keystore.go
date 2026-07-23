// Package audit provides audit logging for MCP tool calls.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
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
	// returns the new key bytes together with the path the old key was
	// archived to.
	RotateKey() (newKey []byte, archivePath string, err error)

	// LoadArchivedKeys returns every archived (rotated-out) HMAC key found
	// in the audit directory, keyed by its fingerprint (see KeyFingerprint).
	// Used by the verifier to check log entries written under a key
	// generation that has since been rotated out.
	LoadArchivedKeys() (map[string][]byte, error)
}

// KeyFingerprint returns a stable 8-hex-char identifier for an HMAC key
// (the first 4 bytes of SHA-256(key), hex-encoded). It is recorded on audit
// log entries as the "kid" (key-generation ID) so a verifier can pick the
// matching key directly instead of trial-and-error, and is used as the
// archive filename suffix on rotation so distinct key generations never
// collide.
func KeyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:4])
}

// RotateKeyArchivePath returns the archive path for an old HMAC key being
// rotated out, keyed by the key's own fingerprint. Using the fingerprint
// (rather than the rotation date) keeps multiple rotations on the same day
// from overwriting each other's archived key.
func RotateKeyArchivePath(auditDir string, oldKey []byte) string {
	return filepath.Join(auditDir, hmacKeyFileName+".rotated."+KeyFingerprint(oldKey))
}

// LoadVerificationKeys returns the keystore's current HMAC key together
// with every archived key generation, keyed by fingerprint (kid), plus the
// fingerprint of the current key. The result is ready to pass to
// VerifyLogAgainstKeys.
func LoadVerificationKeys(ks Keystore) (keys map[string][]byte, currentKid string, err error) {
	current, err := ks.LoadHMACKey()
	if err != nil {
		return nil, "", fmt.Errorf("load current hmac key: %w", err)
	}
	currentKid = KeyFingerprint(current)
	keys = map[string][]byte{currentKid: current}

	archived, err := ks.LoadArchivedKeys()
	if err != nil {
		return keys, currentKid, fmt.Errorf("load archived hmac keys: %w", err)
	}
	for kid, key := range archived {
		if _, exists := keys[kid]; !exists {
			keys[kid] = key
		}
	}
	return keys, currentKid, nil
}

func keyringAccount(auditDir string) string {
	return keyringAccountPrefix + ":" + auditDir
}
