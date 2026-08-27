// Package mobilebind is the non-internal export of the Symaira Vault mobile
// bridge. gomobile bind cannot run against an internal/... path (gobind code is
// generated in a synthetic package outside the module root), so the bridge API
// is re-exported here from internal/mobilebind. See ADR 0006 D2 and the
// spike-gomobile-bind report (issue #862).
package mobilebind

import (
	"github.com/danieljustus/symaira-vault/internal/mobilebind"
)

// GenerateIdentity generates a new age X25519 identity and returns its secret key string.
func GenerateIdentity() (string, error) { return mobilebind.GenerateIdentity() }

// IdentityPublicKey derives the public recipient string (age1...) from a secret identity string.
func IdentityPublicKey(identityStr string) (string, error) {
	return mobilebind.IdentityPublicKey(identityStr)
}

// PublicKeyFingerprint computes a human-verifiable fingerprint for an age public key string.
func PublicKeyFingerprint(pubkey string) string { return mobilebind.PublicKeyFingerprint(pubkey) }

// EncryptWithPublicKey encrypts plaintext using an age recipient public key string.
func EncryptWithPublicKey(recipientStr string, plaintext []byte) ([]byte, error) {
	return mobilebind.EncryptWithPublicKey(recipientStr, plaintext)
}

// DecryptWithIdentity decrypts ciphertext using an age secret identity string.
func DecryptWithIdentity(identityStr string, ciphertext []byte) ([]byte, error) {
	return mobilebind.DecryptWithIdentity(identityStr, ciphertext)
}

// EncryptWithPassphrase encrypts plaintext using a passphrase (via age scrypt/argon2id).
func EncryptWithPassphrase(passphrase string, plaintext []byte) ([]byte, error) {
	return mobilebind.EncryptWithPassphrase(passphrase, plaintext)
}

// DecryptWithPassphrase decrypts ciphertext using a passphrase.
func DecryptWithPassphrase(passphrase string, ciphertext []byte) ([]byte, error) {
	return mobilebind.DecryptWithPassphrase(passphrase, ciphertext)
}

// InitVault initializes a new vault structure at vaultDir encrypted with passphrase.
func InitVault(vaultDir string, passphrase string) error {
	return mobilebind.InitVault(vaultDir, passphrase)
}

// OpenVaultWithPassphrase unlocks vaultDir and returns the decrypted master identity string.
func OpenVaultWithPassphrase(vaultDir string, passphrase string) (string, error) {
	return mobilebind.OpenVaultWithPassphrase(vaultDir, passphrase)
}

// EntryDataBridge is the JSON-serializable representation of a vault entry.
type EntryDataBridge = mobilebind.EntryDataBridge

// ReadEntryJSON reads and decrypts an entry from vaultDir, returning it as a JSON string.
func ReadEntryJSON(vaultDir string, entryPath string, identityStr string) (string, error) {
	return mobilebind.ReadEntryJSON(vaultDir, entryPath, identityStr)
}

// WriteEntryJSON parses entryJSON and writes it encrypted into vaultDir.
func WriteEntryJSON(vaultDir string, entryPath string, entryJSON string, identityStr string) error {
	return mobilebind.WriteEntryJSON(vaultDir, entryPath, entryJSON, identityStr)
}

// ListEntriesJSON lists all entry paths in vaultDir matching prefix, returned as a JSON array of strings.
func ListEntriesJSON(vaultDir string, prefix string, identityStr string) (string, error) {
	return mobilebind.ListEntriesJSON(vaultDir, prefix, identityStr)
}

// VerifyManifestIntegrity checks the integrity of manifest.age in vaultDir.
func VerifyManifestIntegrity(vaultDir string, identityStr string) (bool, error) {
	return mobilebind.VerifyManifestIntegrity(vaultDir, identityStr)
}
