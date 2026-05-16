//go:build !(darwin || linux || windows)

package mcp

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/danieljustus/OpenPass/internal/logging"
)

const (
	grantKeyFileName = "grant-signing-key"
	grantKeySize     = 32
)

// LoadOrCreateGrantSigningKey loads the grant signing key from a file at
// vaultDir/grant-signing-key, creating a new 32-byte key if none exists.
func LoadOrCreateGrantSigningKey(vaultDir string) ([]byte, error) {
	keyPath := filepath.Join(vaultDir, grantKeyFileName)

	existing, err := os.ReadFile(keyPath) //#nosec G304 -- keyPath is constructed from vaultDir
	if err == nil && len(existing) == grantKeySize {
		return existing, nil
	}

	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read existing grant signing key: %w", err)
	}

	key := make([]byte, grantKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate grant signing key: %w", err)
	}

	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return nil, fmt.Errorf("write grant signing key: %w", err)
	}

	return key, nil
}

// LoadGrantSigningKey loads the grant signing key from the file at
// vaultDir/grant-signing-key. Returns an error if the file does not exist.
func LoadGrantSigningKey(vaultDir string) ([]byte, error) {
	keyPath := filepath.Join(vaultDir, grantKeyFileName)
	data, err := os.ReadFile(keyPath) //#nosec G304 -- keyPath is constructed from vaultDir
	if err != nil {
		return nil, fmt.Errorf("read grant signing key: %w", err)
	}
	if len(data) != grantKeySize {
		return nil, fmt.Errorf("invalid grant signing key size: got %d, want %d", len(data), grantKeySize)
	}
	return data, nil
}

func init() {
	logging.Default().Warn("Using file-based grant signing key storage (unsupported platform).")
}
