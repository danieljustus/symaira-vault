//go:build darwin || linux || windows

package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/zalando/go-keyring"

	"github.com/danieljustus/symaira-vault/internal/logging"
)

// keyringTimeout is the maximum time to wait for an OS keyring operation.
// On macOS, the security command can hang indefinitely when the keychain
// is locked or when running in a headless environment.
const keyringTimeout = 5 * time.Second

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

// keyringSetWithTimeout attempts to store a value in the OS keyring with a
// timeout. If the operation does not complete within keyringTimeout, the
// fallback keyring is activated and the value is stored there instead.
func keyringSetWithTimeout(service, account, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), keyringTimeout)
	defer cancel()

	type result struct {
		err error
	}
	done := make(chan result, 1)

	go func() {
		done <- result{err: keyring.Set(service, account, value)}
	}()

	select {
	case <-ctx.Done():
		getFallback()
		return getFallback().Set(service, account, value)
	case r := <-done:
		return r.err
	}
}

// keyringGetWithTimeout attempts to retrieve a value from the OS keyring with
// a timeout. If the operation does not complete within keyringTimeout, the
// fallback keyring is activated and the lookup continues there.
func keyringGetWithTimeout(service, account string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), keyringTimeout)
	defer cancel()

	type result struct {
		val string
		err error
	}
	done := make(chan result, 1)

	go func() {
		val, err := keyring.Get(service, account)
		done <- result{val: val, err: err}
	}()

	select {
	case <-ctx.Done():
		getFallback()
		return getFallback().Get(service, account)
	case r := <-done:
		return r.val, r.err
	}
}

func (k *osKeystore) setWithFallback(service, account, value string) error {
	if isFallbackActive() {
		return getFallback().Set(service, account, value)
	}

	if err := keyringSetWithTimeout(service, account, value); err != nil {
		return getFallback().Set(service, account, value)
	}
	return nil
}

func (k *osKeystore) getWithFallback(service, account string) (string, error) {
	if isFallbackActive() {
		return getFallback().Get(service, account)
	}

	val, err := keyringGetWithTimeout(service, account)
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

// RotateKey generates a new HMAC key, archives the existing key as a
// hex-encoded file in the audit directory, and stores the new key in
// the OS keyring (with memory fallback).
func (k *osKeystore) RotateKey() ([]byte, error) {
	oldKey, err := k.LoadHMACKey()
	if err != nil {
		return nil, fmt.Errorf("load existing key for rotation: %w", err)
	}

	archivePath := RotateKeyArchivePath(k.auditDir)
	hexOld := hex.EncodeToString(oldKey)
	if err := os.WriteFile(archivePath, []byte(hexOld), 0o600); err != nil {
		return nil, fmt.Errorf("archive old HMAC key: %w", err)
	}

	newKey := make([]byte, hmacKeySize)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, fmt.Errorf("generate new HMAC key: %w", err)
	}

	account := keyringAccount(k.auditDir)
	hexNew := hex.EncodeToString(newKey)
	if err := k.setWithFallback(keyringService, account, hexNew); err != nil {
		return nil, fmt.Errorf("store new HMAC key in keyring: %w", err)
	}

	return newKey, nil
}

// NewKeystore is the package-level factory for creating a Keystore backed
// by the OS keyring. It is set by init() on platforms that support it.
// The identity parameter is used by the fallback keystore for encrypting
// keys at rest and is ignored on OS keyring platforms.
var NewKeystore func(auditDir string, identity *age.X25519Identity) Keystore

func init() {
	// In CI or headless environments, keychain prompts can hang indefinitely.
	// Pre-activate memory fallback to avoid blocking.
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" || os.Getenv("HEADLESS") != "" {
		fallbackActive = true
		fallback = &memoryKeyring{}
	}

	NewKeystore = func(auditDir string, identity *age.X25519Identity) Keystore {
		return &osKeystore{auditDir: auditDir}
	}
}
