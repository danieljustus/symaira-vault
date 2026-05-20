// Package session provides secure passphrase caching via OS keyring.
//
// Security Model:
//
// This package uses zalando/go-keyring to store vault passphrases in the
// OS keyring (macOS Keychain, Linux GNOME Keyring via D-Bus Secret Service,
// or Windows Credential Manager). The security properties are:
//
//  1. Encryption at Rest: All secrets are encrypted at rest by the OS keyring
//     using AES-256 (macOS Keychain) or equivalent mechanisms.
//
// 2. Transport Security:
//
//   - macOS: Secret passed via stdin to /usr/bin/security CLI (not visible in ps)
//
//   - Linux: D-Bus Secret Service API transmits secret as bytes. D-Bus is
//     local IPC; same-user processes can typically access session bus.
//
//   - Windows: Credential Manager API
//
//     3. Access Control: OS keyring requires user authentication to unlock.
//     The keyring typically prompts for password on first access per session.
//
// Threat Model Considerations:
//
//   - Local user access: OS keyring provides appropriate protection against
//     other local users (file permissions, user-specific keyring).
//   - Memory exposure: Passphrase exists in process memory during keyring
//     operations - unavoidable with any keyring integration.
//   - D-Bus interception (Linux): D-Bus is not encrypted by default for
//     local IPC. However, accessing D-Bus secrets requires the same user or
//     specific system configuration. If an attacker can sniff D-Bus messages,
//     they typically already have equivalent access to the user's session.
//
// Application-Level Encryption:
//
// In addition to OS keyring encryption, passphrases are encrypted with
// AES-256-GCM before keyring storage. The encryption key is a randomly
// generated 32-byte wrap key stored separately in the OS keyring.
// This provides defense-in-depth: even if the keyring blob is extracted,
// the passphrase remains encrypted without the wrap key.
//
// Backward Compatibility:
//
// Sessions stored in the legacy plaintext format (with a "passphrase" JSON
// field) are still readable. On load, old-format sessions are automatically
// re-encrypted and saved in the new format.
//
// See: https://github.com/zalando/go-keyring for library details.
package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
	"unsafe"

	"github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/metrics"
)

const (
	sessionAccount  = "session"
	identityAccount = "identity"
	wrapKeyAccount  = "wrap-key"
	wrapKeyLen      = 32
	aesGCMNonceLen  = 12
)

var (
	keyringSet    func(service, account, value string) error
	keyringGet    func(service, account string) (string, error)
	keyringDelete func(service, account string) error
)

const (
	CacheBackendOSKeyring = "os-keyring"
	CacheBackendMemory    = "memory"
	CacheBackendUnknown   = "unknown"
)

type CacheStatus struct {
	Backend    string `json:"backend"`
	Persistent bool   `json:"persistent"`
	Message    string `json:"message"`
}

var cacheStatusProvider = func() CacheStatus {
	return CacheStatus{
		Backend:    CacheBackendUnknown,
		Persistent: false,
		Message:    "Session cache backend has not been initialized.",
	}
}

func GetCacheStatus() CacheStatus {
	return cacheStatusProvider()
}

type storedSession struct {
	SavedAt             time.Time `json:"saved_at"`
	LastAccess          time.Time `json:"last_access"`
	Passphrase          string    `json:"passphrase,omitempty"`
	EncryptedPassphrase string    `json:"encrypted_passphrase,omitempty"`
	Nonce               string    `json:"nonce,omitempty"`
	TTL                 int64     `json:"ttl_ns"`
}

type storedIdentity struct {
	SavedAt           time.Time `json:"saved_at"`
	LastAccess        time.Time `json:"last_access"`
	EncryptedIdentity string    `json:"encrypted_identity"`
	Nonce             string    `json:"nonce"`
	TTL               int64     `json:"ttl_ns"`
}

func generateWrapKey() ([]byte, error) {
	key := make([]byte, wrapKeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate wrap key: %w", err)
	}
	return key, nil
}

func loadWrapKey(vaultDir string) ([]byte, error) {
	encWrapKey, err := keyringGet(serviceName(vaultDir), wrapKeyAccount)
	if err != nil {
		return nil, fmt.Errorf("load wrap key: %w", err)
	}
	if encWrapKey == "" {
		return nil, fmt.Errorf("wrap key not found")
	}
	wrapKey, err := base64.StdEncoding.DecodeString(encWrapKey)
	if err != nil {
		return nil, fmt.Errorf("decode wrap key: %w", err)
	}
	if len(wrapKey) != wrapKeyLen {
		return nil, fmt.Errorf("wrap key has invalid length: got %d, want %d", len(wrapKey), wrapKeyLen)
	}
	return wrapKey, nil
}

func getOrCreateWrapKey(vaultDir string) ([]byte, error) {
	wrapKey, err := loadWrapKey(vaultDir)
	if err == nil {
		return wrapKey, nil
	}

	wrapKey, err = generateWrapKey()
	if err != nil {
		return nil, err
	}

	encWrapKey := base64.StdEncoding.EncodeToString(wrapKey)
	if setErr := keyringSet(serviceName(vaultDir), wrapKeyAccount, encWrapKey); setErr != nil {
		return nil, fmt.Errorf("save wrap key: %w", setErr)
	}
	return wrapKey, nil
}

func deleteWrapKey(vaultDir string) error {
	if err := keyringDelete(serviceName(vaultDir), wrapKeyAccount); err != nil {
		return fmt.Errorf("delete wrap key: %w", err)
	}
	return nil
}

func encryptPassphrase(plaintext, key []byte) (string, string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, aesGCMNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil) // #nosec G407 // nonce randomly generated above
	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(nonce), nil
}

func decryptPassphrase(encB64, nonceB64 string, key []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

func serviceName(vaultDir string) string {
	return "openpass:" + vaultDir
}

func SavePassphrase(vaultDir string, passphrase []byte, ttl time.Duration) error {
	now := time.Now().UTC()
	wrapKey, err := getOrCreateWrapKey(vaultDir)
	if err != nil {
		return fmt.Errorf("wrap key: %w", err)
	}
	enc, nonce, encErr := encryptPassphrase(passphrase, wrapKey)
	if encErr != nil {
		return fmt.Errorf("encrypt passphrase: %w", encErr)
	}
	payload, err := json.Marshal(storedSession{
		EncryptedPassphrase: enc,
		Nonce:               nonce,
		SavedAt:             now,
		LastAccess:          now,
		TTL:                 int64(ttl),
	})
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	if err := keyringSet(serviceName(vaultDir), sessionAccount, string(payload)); err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

func LoadPassphrase(vaultDir string) ([]byte, error) {
	raw, err := keyringGet(serviceName(vaultDir), sessionAccount)
	if err != nil {
		metrics.RecordSessionCacheEvent("keyring_unavailable")
		return nil, fmt.Errorf("load session: %w", err)
	}

	var sess storedSession
	if unmarshalErr := json.Unmarshal([]byte(raw), &sess); unmarshalErr != nil {
		metrics.RecordSessionCacheEvent("miss")
		return nil, fmt.Errorf("decode session: %w", unmarshalErr)
	}

	if sess.TTL <= 0 {
		metrics.RecordSessionCacheEvent("miss")
		return nil, fmt.Errorf("session expired for vault %s: TTL is zero or negative", vaultDir)
	}

	lastActivity := sess.LastAccess
	if lastActivity.IsZero() {
		lastActivity = sess.SavedAt
	}
	if time.Since(lastActivity) > time.Duration(sess.TTL) {
		_ = ClearSession(vaultDir)
		metrics.RecordSessionCacheEvent("miss")
		return nil, fmt.Errorf("session expired for vault %s: last activity %v exceeded TTL %v", vaultDir, lastActivity.Format(time.RFC3339), time.Duration(sess.TTL))
	}

	passphrase, resolveErr := resolvePassphrase(&sess, vaultDir)
	if resolveErr != nil {
		metrics.RecordSessionCacheEvent("miss")
		return nil, resolveErr
	}

	// Migrate to wrap-key if still using PBKDF2-derived key
	_, wrapErr := loadWrapKey(vaultDir)
	if wrapErr != nil {
		_ = SavePassphrase(vaultDir, passphrase, time.Duration(sess.TTL))
	} else {
		sess.LastAccess = time.Now().UTC()
		payload, err := json.Marshal(sess)
		if err != nil {
			metrics.RecordSessionCacheEvent("hit")
			return passphrase, nil
		}
		if updateErr := keyringSet(serviceName(vaultDir), sessionAccount, string(payload)); updateErr != nil {
			metrics.RecordSessionCacheEvent("hit")
			return passphrase, nil
		}
		metrics.RecordSessionCacheEvent("refresh")
	}

	return passphrase, nil
}

func encryptionKey(vaultDir string) ([]byte, error) {
	wrapKey, err := loadWrapKey(vaultDir)
	if err != nil {
		return nil, fmt.Errorf("no wrap key available for vault %s: please run 'openpass unlock' to re-establish the session", vaultDir)
	}
	return wrapKey, nil
}

func resolvePassphrase(sess *storedSession, vaultDir string) ([]byte, error) {
	if sess.EncryptedPassphrase != "" && sess.Nonce != "" {
		key, err := encryptionKey(vaultDir)
		if err != nil {
			return nil, err
		}
		plain, err := decryptPassphrase(sess.EncryptedPassphrase, sess.Nonce, key)
		if err != nil {
			return nil, fmt.Errorf("decrypt session: %w", err)
		}
		return plain, nil
	}

	if sess.Passphrase != "" {
		plain := []byte(sess.Passphrase)
		key, err := encryptionKey(vaultDir)
		if err != nil {
			return nil, err
		}
		enc, nonce, encErr := encryptPassphrase(plain, key)
		if encErr == nil {
			sess.EncryptedPassphrase = enc
			sess.Nonce = nonce
			// Wipe the legacy plaintext from the struct string's backing memory
			// before clearing the field, so the passphrase does not remain on
			// the heap until the next GC cycle.
			// #nosec G103 — intentional: unsafe.StringData aliases the backing
			// array so Wipe can zero the only copy in memory.
			crypto.Wipe(unsafe.Slice(unsafe.StringData(sess.Passphrase), len(sess.Passphrase)))
			sess.Passphrase = ""
		}
		return plain, nil
	}

	return nil, fmt.Errorf("session expired for vault %s: no passphrase data available", vaultDir)
}

func ClearSession(vaultDir string) error {
	if err := keyringDelete(serviceName(vaultDir), sessionAccount); err != nil {
		return fmt.Errorf("clear session: %w", err)
	}
	_ = deleteWrapKey(vaultDir)
	_ = ClearIdentity(vaultDir)
	metrics.RecordSessionCacheEvent("evict")
	return nil
}

// SaveIdentity encrypts the X25519 identity string and stores it in the OS
// keyring with the same TTL semantics as the passphrase cache. On a cache
// hit, the scrypt KDF can be skipped entirely by using OpenWithCachedIdentity.
func SaveIdentity(vaultDir string, identity string, ttl time.Duration) error {
	now := time.Now().UTC()
	wrapKey, err := getOrCreateWrapKey(vaultDir)
	if err != nil {
		return fmt.Errorf("wrap key: %w", err)
	}
	enc, nonce, encErr := encryptPassphrase([]byte(identity), wrapKey)
	if encErr != nil {
		return fmt.Errorf("encrypt identity: %w", encErr)
	}
	payload, err := json.Marshal(storedIdentity{
		EncryptedIdentity: enc,
		Nonce:             nonce,
		SavedAt:           now,
		LastAccess:        now,
		TTL:               int64(ttl),
	})
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}
	if err := keyringSet(serviceName(vaultDir), identityAccount, string(payload)); err != nil {
		return fmt.Errorf("save identity: %w", err)
	}
	return nil
}

// LoadIdentity decrypts the cached X25519 identity from the OS keyring.
// Returns the identity string (AGE-SECRET-KEY-1... format) on success,
// or an error if the cache is missing, expired, or cannot be decrypted.
func LoadIdentity(vaultDir string) (string, error) {
	raw, err := keyringGet(serviceName(vaultDir), identityAccount)
	if err != nil {
		return "", fmt.Errorf("load identity: %w", err)
	}

	var ident storedIdentity
	if unmarshalErr := json.Unmarshal([]byte(raw), &ident); unmarshalErr != nil {
		return "", fmt.Errorf("decode identity: %w", unmarshalErr)
	}

	if ident.TTL <= 0 {
		return "", fmt.Errorf("identity cache expired for vault %s: TTL is zero or negative", vaultDir)
	}

	lastActivity := ident.LastAccess
	if lastActivity.IsZero() {
		lastActivity = ident.SavedAt
	}
	if time.Since(lastActivity) > time.Duration(ident.TTL) {
		_ = ClearIdentity(vaultDir)
		return "", fmt.Errorf("identity cache expired for vault %s: last activity %v exceeded TTL %v", vaultDir, lastActivity.Format(time.RFC3339), time.Duration(ident.TTL))
	}

	wrapKey, wrapErr := loadWrapKey(vaultDir)
	if wrapErr != nil {
		return "", fmt.Errorf("identity wrap key: %w", wrapErr)
	}
	identityBytes, err := decryptPassphrase(ident.EncryptedIdentity, ident.Nonce, wrapKey)
	if err != nil {
		return "", fmt.Errorf("decrypt identity: %w", err)
	}
	identityStr := string(identityBytes)
	crypto.Wipe(identityBytes)

	ident.LastAccess = time.Now().UTC()
	payload, marshalErr := json.Marshal(ident)
	if marshalErr != nil {
		return identityStr, nil
	}
	if updateErr := keyringSet(serviceName(vaultDir), identityAccount, string(payload)); updateErr != nil {
		return identityStr, nil
	}

	return identityStr, nil
}

// ClearIdentity removes the cached identity from the OS keyring.
func ClearIdentity(vaultDir string) error {
	if err := keyringDelete(serviceName(vaultDir), identityAccount); err != nil {
		return fmt.Errorf("clear identity: %w", err)
	}
	return nil
}

func IsSessionExpired(vaultDir string) bool {
	raw, err := keyringGet(serviceName(vaultDir), sessionAccount)
	if err != nil {
		return true
	}

	var sess storedSession
	if err := json.Unmarshal([]byte(raw), &sess); err != nil {
		return true
	}

	if sess.TTL <= 0 {
		return true
	}

	lastActivity := sess.LastAccess
	if lastActivity.IsZero() {
		lastActivity = sess.SavedAt
	}
	return time.Since(lastActivity) > time.Duration(sess.TTL)
}

func LoadPassphraseWithTouchID(ctx context.Context, vaultDir string) ([]byte, error) {
	return LoadBiometricPassphrase(ctx, vaultDir)
}
