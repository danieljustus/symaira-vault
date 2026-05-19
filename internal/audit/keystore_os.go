//go:build darwin || linux || windows

package audit

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"filippo.io/age"
	"github.com/zalando/go-keyring"

	"github.com/danieljustus/OpenPass/internal/logging"
)

// osKeystore implements Keystore by storing HMAC keys in the OS keyring
// with automatic fallback to process memory when the keyring is unavailable.
type osKeystore struct {
	auditDir string
}

// memoryKeyring is a simple in-memory string store used as fallback when
// the OS keyring is unavailable.
type memoryKeyring struct {
	mu    sync.RWMutex
	store map[string]string
}

func (m *memoryKeyring) Get(service, account string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.store == nil {
		return "", errors.New("not found")
	}

	key := service + "|" + account
	val, ok := m.store[key]
	if !ok {
		return "", errors.New("not found")
	}
	return val, nil
}

func (m *memoryKeyring) Set(service, account, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.store == nil {
		m.store = make(map[string]string)
	}

	key := service + "|" + account
	m.store[key] = value
	return nil
}

func (m *memoryKeyring) Delete(service, account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.store == nil {
		return nil
	}

	key := service + "|" + account
	delete(m.store, key)
	return nil
}

var (
	fallbackActive bool
	fallbackMu     sync.RWMutex
	fallback       *memoryKeyring
)

func getFallback() *memoryKeyring {
	fallbackMu.Lock()
	defer fallbackMu.Unlock()

	if fallback == nil {
		fallback = &memoryKeyring{}
		logging.Default().Warn("OS keyring unavailable for audit HMAC key. Falling back to memory-only storage.")
	}
	fallbackActive = true
	return fallback
}

func isFallbackActive() bool {
	fallbackMu.RLock()
	defer fallbackMu.RUnlock()
	return fallbackActive
}

func (k *osKeystore) setWithFallback(service, account, value string) error {
	if isFallbackActive() {
		return getFallback().Set(service, account, value)
	}

	if err := keyring.Set(service, account, value); err != nil {
		return getFallback().Set(service, account, value)
	}
	return nil
}

func (k *osKeystore) getWithFallback(service, account string) (string, error) {
	if isFallbackActive() {
		return getFallback().Get(service, account)
	}

	val, err := keyring.Get(service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", err
		}
		return getFallback().Get(service, account)
	}
	return val, nil
}

// LoadOrCreateHMACKey returns the HMAC key, creating a new 32-byte key
// and storing it hex-encoded in the OS keyring if none exists.
func (k *osKeystore) LoadOrCreateHMACKey() ([]byte, error) {
	key, err := k.LoadHMACKey()
	if err == nil {
		return key, nil
	}

	hmacKey := make([]byte, hmacKeySize)
	if _, err := io.ReadFull(rand.Reader, hmacKey); err != nil {
		return nil, fmt.Errorf("generate HMAC key: %w", err)
	}

	account := keyringAccount(k.auditDir)
	hexKey := hex.EncodeToString(hmacKey)
	if err := k.setWithFallback(keyringService, account, hexKey); err != nil {
		return nil, fmt.Errorf("store HMAC key in keyring: %w", err)
	}

	return hmacKey, nil
}

// LoadHMACKey loads the HMAC key from the OS keyring (with memory fallback).
// If not found in the keyring, it checks for a file-based key at
// filepath.Join(k.auditDir, "audit-hmac-key") and migrates it into the
// keyring, deleting the file on success.
func (k *osKeystore) LoadHMACKey() ([]byte, error) {
	account := keyringAccount(k.auditDir)

	hexKey, err := k.getWithFallback(keyringService, account)
	if err == nil {
		return hex.DecodeString(hexKey)
	}

	keyPath := filepath.Join(k.auditDir, hmacKeyFileName)
	data, fileErr := os.ReadFile(keyPath) //#nosec G304 -- auditDir is controlled
	if fileErr != nil {
		if os.IsNotExist(fileErr) {
			return nil, err
		}
		return nil, fmt.Errorf("read HMAC key file: %w", fileErr)
	}

	hexKeyStr := hex.EncodeToString(data)
	if storeErr := k.setWithFallback(keyringService, account, hexKeyStr); storeErr == nil {
		_ = os.Remove(keyPath)
	}

	return data, nil
}

// NewKeystore is the package-level factory for creating a Keystore backed
// by the OS keyring. It is set by init() on platforms that support it.
// The identity parameter is used by the fallback keystore for encrypting
// keys at rest and is ignored on OS keyring platforms.
var NewKeystore func(auditDir string, identity *age.X25519Identity) Keystore

func init() {
	// In CI environments, keychain prompts can hang indefinitely.
	// Pre-activate memory fallback to avoid blocking.
	if os.Getenv("CI") != "" {
		fallbackActive = true
		fallback = &memoryKeyring{}
	}

	NewKeystore = func(auditDir string, identity *age.X25519Identity) Keystore {
		return &osKeystore{auditDir: auditDir}
	}
}
