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
	"strings"
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

// errMemoryKeyringNotFound is returned by the in-memory fallback store when
// no entry exists. It is a package sentinel so callers can distinguish "no
// key stored yet" from real keyring failures even when the fallback is
// active (test binaries, CI, or a tripped fallback) — IsHMACKeyNotFound
// treats it the same as the OS keyring's ErrNotFound.
var errMemoryKeyringNotFound = errors.New("audit: HMAC key not found in keyring")

func (m *memoryKeyring) Get(service, account string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.store == nil {
		return "", errMemoryKeyringNotFound
	}

	key := service + "|" + account
	val, ok := m.store[key]
	if !ok {
		return "", errMemoryKeyringNotFound
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

func (k *osKeystore) setWithFallback(account, value string) error {
	if isFallbackActive() {
		return getFallback().Set(keyringService, account, value)
	}

	if err := keyringSetWithTimeout(keyringService, account, value); err != nil {
		return getFallback().Set(keyringService, account, value)
	}
	return nil
}

func (k *osKeystore) getWithFallback(account string) (string, error) {
	if isFallbackActive() {
		return getFallback().Get(keyringService, account)
	}

	val, err := keyringGetWithTimeout(keyringService, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", err
		}
		return getFallback().Get(keyringService, account)
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
	if err := k.setWithFallback(account, hexKey); err != nil {
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

	hexKey, err := k.getWithFallback(account)
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
	if storeErr := k.setWithFallback(account, hexKeyStr); storeErr == nil {
		_ = os.Remove(keyPath)
	}

	return data, nil
}

// RotateKey generates a new HMAC key, archives the existing key as a
// hex-encoded file in the audit directory (named after the old key's
// fingerprint so repeated rotations never collide), and stores the new key
// in the OS keyring (with memory fallback).
//
// When no HMAC key exists yet, it bootstraps: a fresh key is generated and
// stored, no archive file is written (there is nothing to archive), and the
// returned archivePath is empty so callers can tell bootstrap from rotation.
// A key that exists but cannot be read (corrupt hex, permission problems)
// is NOT treated as "no key" — such errors still fail the rotation.
func (k *osKeystore) RotateKey() ([]byte, string, error) {
	oldKey, err := k.LoadHMACKey()
	if err != nil {
		if !IsHMACKeyNotFound(err) {
			return nil, "", fmt.Errorf("load existing key for rotation: %w", err)
		}

		// No key stored yet: bootstrap a fresh one instead of rotating.
		newKey := make([]byte, hmacKeySize)
		if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
			return nil, "", fmt.Errorf("generate new HMAC key: %w", err)
		}

		account := keyringAccount(k.auditDir)
		hexNew := hex.EncodeToString(newKey)
		if err := k.setWithFallback(account, hexNew); err != nil {
			return nil, "", fmt.Errorf("store new HMAC key in keyring: %w", err)
		}

		return newKey, "", nil
	}

	archivePath := RotateKeyArchivePath(k.auditDir, oldKey)
	hexOld := hex.EncodeToString(oldKey)
	if err := os.WriteFile(archivePath, []byte(hexOld), 0o600); err != nil {
		return nil, "", fmt.Errorf("archive old HMAC key: %w", err)
	}

	newKey := make([]byte, hmacKeySize)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, "", fmt.Errorf("generate new HMAC key: %w", err)
	}

	account := keyringAccount(k.auditDir)
	hexNew := hex.EncodeToString(newKey)
	if err := k.setWithFallback(account, hexNew); err != nil {
		return nil, "", fmt.Errorf("store new HMAC key in keyring: %w", err)
	}

	return newKey, archivePath, nil
}

// LoadArchivedKeys reads every rotated-out HMAC key file in the audit
// directory and returns them keyed by fingerprint. Archive files are
// hex-encoded, matching the format RotateKey writes.
func (k *osKeystore) LoadArchivedKeys() (map[string][]byte, error) {
	pattern := filepath.Join(k.auditDir, hmacKeyFileName+".rotated.*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("glob archived hmac keys: %w", err)
	}

	keys := make(map[string][]byte, len(matches))
	for _, path := range matches {
		data, readErr := os.ReadFile(path) //#nosec G304 -- path comes from Glob over k.auditDir
		if readErr != nil {
			continue
		}
		key, decodeErr := hex.DecodeString(strings.TrimSpace(string(data)))
		if decodeErr != nil || len(key) != hmacKeySize {
			continue
		}
		keys[KeyFingerprint(key)] = key
	}
	return keys, nil
}

// IsHMACKeyNotFound reports whether err means "no HMAC key is stored yet"
// (as opposed to a stored key that cannot be read). RotateKey uses it to
// bootstrap when no key exists while still failing on corrupt or unreadable
// keys. On OS keyring platforms not-found is the OS keyring's ErrNotFound or
// the in-memory fallback's sentinel.
func IsHMACKeyNotFound(err error) bool {
	return errors.Is(err, keyring.ErrNotFound) || errors.Is(err, errMemoryKeyringNotFound)
}

// NewKeystore creates a Keystore backed by the OS keyring.
// The identity parameter is used by the fallback keystore for encrypting
// keys at rest and is ignored on OS keyring platforms.
func NewKeystore(auditDir string, identity *age.X25519Identity) Keystore {
	return &osKeystore{auditDir: auditDir}
}

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
			base == "test" {
			return true
		}
	}
	return false
}

func init() {
	if isTestOrCI() {
		fallbackActive = true
		fallback = &memoryKeyring{}
	}
}
