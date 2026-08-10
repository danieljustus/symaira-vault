//go:build darwin || linux || windows

package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"

	"filippo.io/age"
	"github.com/zalando/go-keyring"

	"github.com/danieljustus/symaira-vault/internal/logging"
)

const (
	grantKeyringService       = "symaira"
	grantKeyringAccountPrefix = "grant-signing-key"
	grantKeySize              = 32
)

// memoryGrantKeyring is a simple in-memory string store used as fallback
// when the OS keyring is unavailable for grant signing keys.
type memoryGrantKeyring struct {
	mu    sync.RWMutex
	store map[string]string
}

func (m *memoryGrantKeyring) Get(service, account string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.store == nil {
		return "", fmt.Errorf("not found")
	}
	key := service + "|" + account
	val, ok := m.store[key]
	if !ok {
		return "", fmt.Errorf("not found")
	}
	return val, nil
}

func (m *memoryGrantKeyring) Set(service, account, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store == nil {
		m.store = make(map[string]string)
	}
	key := service + "|" + account
	m.store[key] = value
	return nil
}

var (
	grantFallbackActive bool
	grantFallbackMu     sync.RWMutex
	grantFallback       *memoryGrantKeyring
)

func getGrantFallback() *memoryGrantKeyring {
	grantFallbackMu.Lock()
	defer grantFallbackMu.Unlock()
	if grantFallback == nil {
		grantFallback = &memoryGrantKeyring{}
		logging.Default().Warn("OS keyring unavailable for grant signing key. Falling back to memory-only storage.")
	}
	grantFallbackActive = true
	return grantFallback
}

func isGrantFallbackActive() bool {
	grantFallbackMu.RLock()
	defer grantFallbackMu.RUnlock()
	return grantFallbackActive
}

func grantKeyringAccount(vaultDir string) string {
	return grantKeyringAccountPrefix + ":" + vaultDir
}

func grantSetWithFallback(service, account, value string) error {
	if isGrantFallbackActive() {
		return getGrantFallback().Set(service, account, value)
	}
	if err := keyring.Set(service, account, value); err != nil {
		return getGrantFallback().Set(service, account, value)
	}
	return nil
}

func grantGetWithFallback(service, account string) (string, error) {
	if isGrantFallbackActive() {
		return getGrantFallback().Get(service, account)
	}
	val, err := keyring.Get(service, account)
	if err != nil {
		return getGrantFallback().Get(service, account)
	}
	return val, nil
}

// LoadOrCreateGrantSigningKey loads the grant HMAC signing key from the OS
// keyring (with memory fallback), creating a new 32-byte key if none exists.
// The identity parameter is used by the fallback keystore for encrypting
// keys at rest and is ignored on OS keyring platforms.
func LoadOrCreateGrantSigningKey(vaultDir string, identity *age.X25519Identity) ([]byte, error) {
	key, err := LoadGrantSigningKey(vaultDir, identity)
	if err == nil {
		return key, nil
	}

	newKey := make([]byte, grantKeySize)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, fmt.Errorf("generate grant signing key: %w", err)
	}

	account := grantKeyringAccount(vaultDir)
	if storeErr := grantSetWithFallback(grantKeyringService, account, hex.EncodeToString(newKey)); storeErr != nil {
		return nil, fmt.Errorf("store grant signing key in keyring: %w", storeErr)
	}

	return newKey, nil
}

// LoadGrantSigningKey loads the grant HMAC signing key from the OS keyring
// (with memory fallback). Returns an error if no key exists.
// The identity parameter is used by the fallback keystore for encrypting
// keys at rest and is ignored on OS keyring platforms.
func LoadGrantSigningKey(vaultDir string, identity *age.X25519Identity) ([]byte, error) {
	account := grantKeyringAccount(vaultDir)
	hexKey, err := grantGetWithFallback(grantKeyringService, account)
	if err != nil {
		return nil, fmt.Errorf("grant signing key not found: %w", err)
	}
	return hex.DecodeString(hexKey)
}

// isTestOrCI reports whether the process is a `go test` binary or running
// under CI/headless automation. Mirrors internal/audit's isTestOrCI (kept
// separate per-package): test processes must never reach the real OS
// keychain, which is what produced the leftover keychain entries in #801.
func isTestOrCI() bool {
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" || os.Getenv("HEADLESS") != "" || os.Getenv("SYMVAULT_TEST_KEYRING") == "memory" {
		return true
	}
	for _, arg := range os.Args {
		if len(arg) >= 6 && arg[:6] == "-test." {
			return true
		}
	}
	if len(os.Args) > 0 {
		base := os.Args[0]
		for i := len(base) - 1; i >= 0; i-- {
			if base[i] == '/' || base[i] == '\\' {
				base = base[i+1:]
				break
			}
		}
		if (len(base) >= 5 && base[len(base)-5:] == ".test") ||
			(len(base) >= 9 && base[len(base)-9:] == ".test.exe") ||
			base == "test" { //nolint:goconst // test-binary sentinel, mirrors internal/audit's isTestOrCI
			return true
		}
	}
	return false
}

func init() {
	if isTestOrCI() {
		grantFallbackActive = true
		grantFallback = &memoryGrantKeyring{}
	}
}
