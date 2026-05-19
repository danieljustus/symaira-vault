package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"filippo.io/age"
)

const ageEncryptionHeader = "age-encryption.org/"

// Sentinel errors for key file operations.
var (
	ErrKeyFileNotFound  = errors.New("key file not found")
	ErrIdentityRequired = errors.New("identity required to decrypt key")
)

// SaveEncryptedKey encrypts key material using the vault's age identity and
// writes it to the specified path with 0o600 permissions.  The identity's
// recipient is used as the encryption target so that the identity itself (or
// any identity derived from the same age key) can decrypt.
func SaveEncryptedKey(path string, key []byte, identity *age.X25519Identity) error {
	if identity == nil {
		return fmt.Errorf("save encrypted key: %w", ErrNilIdentity)
	}
	ciphertext, err := Encrypt(key, identity.Recipient())
	if err != nil {
		return fmt.Errorf("save encrypted key: %w", err)
	}
	return os.WriteFile(path, ciphertext, 0o600)
}

// LoadEncryptedKey reads an age-encrypted key file from path and decrypts it
// using the vault identity.
//
// If the file exists but is **not** age-encrypted (a legacy plaintext key
// written before this feature), the raw bytes are returned as-is so that
// callers can perform auto-migration.  Callers should use IsEncryptedKeyFile
// to distinguish between the two cases.
//
// Returns ErrKeyFileNotFound if the file does not exist.
func LoadEncryptedKey(path string, identity *age.X25519Identity) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("load encrypted key: %w", ErrKeyFileNotFound)
		}
		return nil, fmt.Errorf("load encrypted key: %w", err)
	}

	// Legacy plaintext — return as-is so the caller can auto-migrate.
	if !bytes.HasPrefix(data, []byte(ageEncryptionHeader)) {
		return data, nil
	}

	// Age-encrypted — decrypt with identity.
	if identity == nil {
		return nil, fmt.Errorf("load encrypted key: %w", ErrIdentityRequired)
	}
	plaintext, err := Decrypt(data, identity)
	if err != nil {
		return nil, fmt.Errorf("load encrypted key: %w", err)
	}
	return plaintext, nil
}

// IsEncryptedKeyFile returns true if the file at path starts with the
// age-encryption header, indicating it was written by SaveEncryptedKey.
// A non-existent file returns false, nil.
func IsEncryptedKeyFile(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return bytes.HasPrefix(data, []byte(ageEncryptionHeader)), nil
}
