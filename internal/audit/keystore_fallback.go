//go:build !(darwin || linux || windows)

package audit

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/logging"
)

const (
	// localEncryptionMarker prefixes locally-encrypted key files so they can
	// be distinguished from age-encrypted and legacy plaintext keys.
	localEncryptionMarker = "sv-local-v1:"
	// localKEKSize is the size of the local key-encryption-key in bytes.
	localKEKSize = 32
)

// fallbackKeystore implements Keystore using file-based HMAC key storage.
// It is used on platforms without OS keyring support.
//
// When an age identity is available, the HMAC key is encrypted with age
// (X25519 + ChaCha20-Poly1305).  When no identity is available, the key is
// encrypted with a locally-generated key-encryption-key (KEK) that is stored
// in a separate file.  This provides defense-in-depth: the HMAC key is never
// written to disk as plaintext, even without an age identity.
type fallbackKeystore struct {
	auditDir string
	identity *age.X25519Identity
}

// kekPath returns the path to the local key-encryption-key file.
func (k *fallbackKeystore) kekPath() string {
	return filepath.Join(k.auditDir, hmacKeyFileName+".kek")
}

// getOrCreateLocalKEK returns the local key-encryption-key, creating a new
// random 32-byte key if none exists.  The KEK is stored with 0o600 permissions.
func (k *fallbackKeystore) getOrCreateLocalKEK() ([]byte, error) {
	kekPath := k.kekPath()

	existing, err := os.ReadFile(filepath.Clean(kekPath))
	if err == nil && len(existing) == localKEKSize {
		return existing, nil
	}

	kek := make([]byte, localKEKSize)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		return nil, fmt.Errorf("generate local kek: %w", err)
	}
	if err := os.WriteFile(kekPath, kek, 0o600); err != nil {
		return nil, fmt.Errorf("write local kek: %w", err)
	}
	return kek, nil
}

// saveLocallyEncrypted encrypts key material with a locally-generated KEK and
// writes it to path with the local encryption marker prefix.
func (k *fallbackKeystore) saveLocallyEncrypted(path string, key []byte) error {
	kek, err := k.getOrCreateLocalKEK()
	if err != nil {
		return err
	}
	ciphertext, err := vaultcrypto.EncryptWithKey(key, kek)
	if err != nil {
		return fmt.Errorf("encrypt with local kek: %w", err)
	}
	marked := append([]byte(localEncryptionMarker), ciphertext...)
	return os.WriteFile(path, marked, 0o600)
}

// loadLocallyEncrypted reads a locally-encrypted key file and returns the
// decrypted key material.  Returns an error if the file does not have the
// local encryption marker or if decryption fails.
func (k *fallbackKeystore) loadLocallyEncrypted(path string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(data, []byte(localEncryptionMarker)) {
		return nil, fmt.Errorf("not a locally-encrypted key file")
	}
	ciphertext := data[len(localEncryptionMarker):]
	kek, err := k.getOrCreateLocalKEK()
	if err != nil {
		return nil, err
	}
	plaintext, err := vaultcrypto.DecryptWithKey(ciphertext, kek)
	if err != nil {
		return nil, fmt.Errorf("decrypt with local kek: %w", err)
	}
	return plaintext, nil
}

// LoadOrCreateHMACKey returns the HMAC key from the key file at
// filepath.Join(k.auditDir, "audit-hmac-key"), creating a new 32-byte key
// and saving it if none exists.
//
// When an age identity is available, the key is encrypted with age.  When no
// identity is available, the key is encrypted with a locally-generated KEK
// so that it is never written to disk as plaintext.
func (k *fallbackKeystore) LoadOrCreateHMACKey() ([]byte, error) {
	keyPath := filepath.Join(k.auditDir, hmacKeyFileName)

	// Try loading an existing key (age-encrypted, locally-encrypted, or legacy plaintext).
	existing, loadErr := k.loadHMACKey(keyPath)
	if loadErr == nil && len(existing) == hmacKeySize {
		return existing, nil
	}

	// If the key file exists but couldn't be loaded, surface the error.
	if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
		if !errors.Is(loadErr, vaultcrypto.ErrKeyFileNotFound) {
			return nil, fmt.Errorf("read existing hmac key: %w", loadErr)
		}
	}

	// Create a new key.
	key := make([]byte, hmacKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate hmac key: %w", err)
	}

	if k.identity != nil {
		if err := vaultcrypto.SaveEncryptedKey(keyPath, key, k.identity); err != nil {
			return nil, fmt.Errorf("write encrypted hmac key: %w", err)
		}
	} else {
		if err := k.saveLocallyEncrypted(keyPath, key); err != nil {
			return nil, fmt.Errorf("write locally-encrypted hmac key: %w", err)
		}
	}

	return key, nil
}

// loadHMACKey reads the HMAC key from path, handling age-encrypted,
// locally-encrypted, and legacy plaintext formats.  On success it returns
// the raw key bytes.  Auto-migration to encrypted storage is performed when
// a legacy plaintext key is found and an identity is available.
func (k *fallbackKeystore) loadHMACKey(path string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	// Locally-encrypted format (prefixed with marker).
	if bytes.HasPrefix(data, []byte(localEncryptionMarker)) {
		return k.loadLocallyEncrypted(path)
	}

	// Age-encrypted format.
	if bytes.HasPrefix(data, []byte("age-encryption.org/")) {
		if k.identity == nil {
			return nil, fmt.Errorf("load encrypted key: %w", vaultcrypto.ErrIdentityRequired)
		}
		plaintext, err := vaultcrypto.Decrypt(data, k.identity)
		if err != nil {
			return nil, fmt.Errorf("decrypt age-encrypted key: %w", err)
		}
		return plaintext, nil
	}

	// Legacy plaintext key.  Auto-migrate if identity is available.
	if k.identity != nil {
		_ = vaultcrypto.SaveEncryptedKey(path, data, k.identity)
	}
	return data, nil
}

// LoadHMACKey loads the HMAC key from the key file.  Returns an error if the
// file does not exist or the key is not exactly hmacKeySize bytes.
func (k *fallbackKeystore) LoadHMACKey() ([]byte, error) {
	keyPath := filepath.Join(k.auditDir, hmacKeyFileName)

	data, err := k.loadHMACKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read HMAC key: %w", err)
	}

	if len(data) != hmacKeySize {
		return nil, fmt.Errorf("invalid HMAC key size: got %d, want %d", len(data), hmacKeySize)
	}

	return data, nil
}

// RotateKey generates a new HMAC key, archives the existing key file to
// a timestamped backup, and writes the new key to the key file.
func (k *fallbackKeystore) RotateKey() ([]byte, error) {
	keyPath := filepath.Join(k.auditDir, hmacKeyFileName)

	_, err := k.LoadHMACKey()
	if err != nil {
		return nil, fmt.Errorf("load existing key for rotation: %w", err)
	}

	archivePath := RotateKeyArchivePath(k.auditDir)
	if err := os.Rename(keyPath, archivePath); err != nil {
		return nil, fmt.Errorf("archive old HMAC key: %w", err)
	}

	newKey := make([]byte, hmacKeySize)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, fmt.Errorf("generate new HMAC key: %w", err)
	}

	if k.identity != nil {
		if err := vaultcrypto.SaveEncryptedKey(keyPath, newKey, k.identity); err != nil {
			return nil, fmt.Errorf("write encrypted HMAC key: %w", err)
		}
	} else {
		if err := k.saveLocallyEncrypted(keyPath, newKey); err != nil {
			return nil, fmt.Errorf("write locally-encrypted HMAC key: %w", err)
		}
	}

	return newKey, nil
}

// LoadArchivedKeys reads every rotation-archive file RotateKey has written
// to the audit directory, reusing loadHMACKey to handle whichever format
// (age-encrypted, locally-encrypted, or legacy plaintext) the archive was
// saved in. A file that can't be decrypted (e.g. no matching identity or
// KEK) is skipped rather than returned as an error.
func (k *fallbackKeystore) LoadArchivedKeys() ([]ArchivedKey, error) {
	paths, err := archivedKeyPaths(k.auditDir)
	if err != nil {
		return nil, err
	}
	var keys []ArchivedKey
	for _, p := range paths {
		key, loadErr := k.loadHMACKey(p)
		if loadErr != nil || len(key) != hmacKeySize {
			continue
		}
		keys = append(keys, ArchivedKey{Label: archivedKeyLabel(p), Key: key})
	}
	return keys, nil
}

// NewKeystore creates a fallbackKeystore on platforms without OS keyring support.
func NewKeystore(auditDir string, identity *age.X25519Identity) Keystore {
	logging.Default().Warn("Using file-based HMAC key storage (unsupported platform).")
	return &fallbackKeystore{auditDir: auditDir, identity: identity}
}
