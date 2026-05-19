//go:build !(darwin || linux || windows)

package audit

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/logging"
)

// fallbackKeystore implements Keystore using file-based HMAC key storage.
// It is used on platforms without OS keyring support.  When identity is set
// the key is encrypted at rest using the vault's age identity.
type fallbackKeystore struct {
	auditDir string
	identity *age.X25519Identity
}

// LoadOrCreateHMACKey returns the HMAC key from the encrypted file at
// filepath.Join(k.auditDir, "audit-hmac-key"), creating a new 32-byte key
// and saving it encrypted using the vault identity if none exists.
func (k *fallbackKeystore) LoadOrCreateHMACKey() ([]byte, error) {
	keyPath := filepath.Join(k.auditDir, hmacKeyFileName)

	existing, err := vaultcrypto.LoadEncryptedKey(keyPath, k.identity)
	if err != nil {
		if !errors.Is(err, vaultcrypto.ErrKeyFileNotFound) {
			return nil, fmt.Errorf("read existing hmac key: %w", err)
		}
		// Key file does not exist — create a new one below.
	} else if len(existing) == hmacKeySize {
		// Auto-migrate legacy plaintext key if identity is available.
		encrypted, _ := vaultcrypto.IsEncryptedKeyFile(keyPath)
		if !encrypted && k.identity != nil {
			_ = vaultcrypto.SaveEncryptedKey(keyPath, existing, k.identity)
		}
		return existing, nil
	}

	key := make([]byte, hmacKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate hmac key: %w", err)
	}

	if k.identity != nil {
		if err := vaultcrypto.SaveEncryptedKey(keyPath, key, k.identity); err != nil {
			return nil, fmt.Errorf("write encrypted hmac key: %w", err)
		}
	} else {
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			return nil, fmt.Errorf("write hmac key: %w", err)
		}
	}

	return key, nil
}

// LoadHMACKey loads the HMAC key from the encrypted file at
// filepath.Join(k.auditDir, "audit-hmac-key"). Returns an error if the
// file does not exist or the key is not exactly hmacKeySize bytes.
func (k *fallbackKeystore) LoadHMACKey() ([]byte, error) {
	keyPath := filepath.Join(k.auditDir, hmacKeyFileName)

	data, err := vaultcrypto.LoadEncryptedKey(keyPath, k.identity)
	if err != nil {
		return nil, fmt.Errorf("read HMAC key: %w", err)
	}

	if len(data) != hmacKeySize {
		return nil, fmt.Errorf("invalid HMAC key size: got %d, want %d", len(data), hmacKeySize)
	}

	// Auto-migrate legacy plaintext key if identity is available.
	encrypted, _ := vaultcrypto.IsEncryptedKeyFile(keyPath)
	if !encrypted && k.identity != nil {
		_ = vaultcrypto.SaveEncryptedKey(keyPath, data, k.identity)
	}

	return data, nil
}

// NewKeystore is set by init() to create a fallbackKeystore on platforms
// without OS keyring support. The identity parameter is optional; when nil
// the key is stored as plaintext (backward-compatible mode).
var NewKeystore func(auditDir string, identity *age.X25519Identity) Keystore

func init() {
	NewKeystore = func(auditDir string, identity *age.X25519Identity) Keystore {
		logging.Default().Warn("Using file-based HMAC key storage (unsupported platform).")
		return &fallbackKeystore{auditDir: auditDir, identity: identity}
	}
}
