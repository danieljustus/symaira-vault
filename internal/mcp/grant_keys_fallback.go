//go:build !(darwin || linux || windows)

package mcp

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

const (
	grantKeyFileName = "grant-signing-key"
	grantKeySize     = 32
)

// LoadOrCreateGrantSigningKey loads the grant signing key from an encrypted
// file at vaultDir/grant-signing-key, creating a new 32-byte key if none
// exists. When identity is provided the key is encrypted at rest.
func LoadOrCreateGrantSigningKey(vaultDir string, identity *age.X25519Identity) ([]byte, error) {
	keyPath := filepath.Join(vaultDir, grantKeyFileName)

	existing, err := vaultcrypto.LoadEncryptedKey(keyPath, identity)
	if err != nil {
		if !errors.Is(err, vaultcrypto.ErrKeyFileNotFound) {
			return nil, fmt.Errorf("read existing grant signing key: %w", err)
		}
		// Key file does not exist — create a new one below.
	} else if len(existing) == grantKeySize {
		// Auto-migrate legacy plaintext key if identity is available.
		encrypted, _ := vaultcrypto.IsEncryptedKeyFile(keyPath)
		if !encrypted && identity != nil {
			_ = vaultcrypto.SaveEncryptedKey(keyPath, existing, identity)
		}
		return existing, nil
	}

	key := make([]byte, grantKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate grant signing key: %w", err)
	}

	if identity != nil {
		if err := vaultcrypto.SaveEncryptedKey(keyPath, key, identity); err != nil {
			return nil, fmt.Errorf("write encrypted grant signing key: %w", err)
		}
	} else {
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			return nil, fmt.Errorf("write grant signing key: %w", err)
		}
	}

	return key, nil
}

// LoadGrantSigningKey loads the grant signing key from the encrypted file at
// vaultDir/grant-signing-key. Returns an error if the file does not exist.
// When identity is provided, legacy plaintext keys are auto-migrated.
func LoadGrantSigningKey(vaultDir string, identity *age.X25519Identity) ([]byte, error) {
	keyPath := filepath.Join(vaultDir, grantKeyFileName)

	data, err := vaultcrypto.LoadEncryptedKey(keyPath, identity)
	if err != nil {
		return nil, fmt.Errorf("read grant signing key: %w", err)
	}

	if len(data) != grantKeySize {
		return nil, fmt.Errorf("invalid grant signing key size: got %d, want %d", len(data), grantKeySize)
	}

	// Auto-migrate legacy plaintext key if identity is available.
	encrypted, _ := vaultcrypto.IsEncryptedKeyFile(keyPath)
	if !encrypted && identity != nil {
		_ = vaultcrypto.SaveEncryptedKey(keyPath, data, identity)
	}

	return data, nil
}

func init() {
	logging.Default().Warn("Using file-based grant signing key storage (unsupported platform).")
}
