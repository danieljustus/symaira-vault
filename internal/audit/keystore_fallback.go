//go:build !(darwin || linux || windows)

package audit

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/danieljustus/OpenPass/internal/logging"
)

// fallbackKeystore implements Keystore using file-based HMAC key storage.
// It is used on platforms without OS keyring support.
type fallbackKeystore struct {
	auditDir string
}

// LoadOrCreateHMACKey returns the HMAC key from the file at
// filepath.Join(k.auditDir, "audit-hmac-key"), creating a new 32-byte key
// and writing it to the file if none exists.
func (k *fallbackKeystore) LoadOrCreateHMACKey() ([]byte, error) {
	keyPath := filepath.Join(k.auditDir, hmacKeyFileName)

	existing, err := os.ReadFile(keyPath) //#nosec G304 -- keyPath is constructed from auditDir
	if err == nil && len(existing) == hmacKeySize {
		return existing, nil
	}

	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read existing hmac key: %w", err)
	}

	key := make([]byte, hmacKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate hmac key: %w", err)
	}

	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return nil, fmt.Errorf("write hmac key: %w", err)
	}

	return key, nil
}

// LoadHMACKey loads the HMAC key from the file at
// filepath.Join(k.auditDir, "audit-hmac-key"). Returns an error if the
// file does not exist or the key is not exactly hmacKeySize bytes.
func (k *fallbackKeystore) LoadHMACKey() ([]byte, error) {
	keyPath := filepath.Join(k.auditDir, hmacKeyFileName)
	data, err := os.ReadFile(keyPath) //#nosec G304 -- keyPath is constructed from auditDir
	if err != nil {
		return nil, fmt.Errorf("read HMAC key: %w", err)
	}
	if len(data) != hmacKeySize {
		return nil, fmt.Errorf("invalid HMAC key size: got %d, want %d", len(data), hmacKeySize)
	}
	return data, nil
}

// NewKeystore is set by init() to create a fallbackKeystore on platforms
// without OS keyring support.
var NewKeystore func(auditDir string) Keystore

func init() {
	NewKeystore = func(auditDir string) Keystore {
		logging.Default().Warn("Using file-based HMAC key storage (unsupported platform).")
		return &fallbackKeystore{auditDir: auditDir}
	}
}
