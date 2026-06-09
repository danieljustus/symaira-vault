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
// field) are no longer auto-migrated on load. Run
// "symvault migrate session <vault-dir>" to upgrade an existing vault.
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
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/metrics"
)

const (
	sessionAccount  = "session"
	identityAccount = "identity"
	wrapKeyAccount  = "wrap-key"
	wrapKeyLen      = 32
	aesGCMNonceLen  = 12
)

const (
	CacheBackendOSKeyring = "os-keyring"
	CacheBackendMemory    = "memory"
	CacheBackendUnknown   = "unknown"
)

// ErrLegacyPlaintextSession is returned by LoadPassphrase when the cached
// session is in the legacy plaintext format. Run
// "symvault migrate session <vault-dir>" to upgrade.
var ErrLegacyPlaintextSession = errors.New("legacy plaintext session: run 'symvault migrate session' to upgrade")

// CacheStatus reports which storage backend the package is currently using
// and whether the cache survives process exit.
type CacheStatus struct {
	Backend    string `json:"backend"`
	Persistent bool   `json:"persistent"`
	Message    string `json:"message"`
}

// passphraseBytes is a byte slice that marshals to/from a plain JSON string
// (not base64). This preserves backward compatibility with sessions stored
// before the migration from string to []byte.
type passphraseBytes []byte

func (p passphraseBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(p))
}

func (p *passphraseBytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*p = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*p = []byte(s)
	return nil
}

type storedSession struct {
	SavedAt             time.Time       `json:"saved_at"`
	LastAccess          time.Time       `json:"last_access"`
	Passphrase          passphraseBytes `json:"passphrase,omitempty"`
	EncryptedPassphrase string          `json:"encrypted_passphrase,omitempty"`
	Nonce               string          `json:"nonce,omitempty"`
	TTL                 int64           `json:"ttl_ns"`
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

// serviceNameForVault returns the keyring service name used for a vault.
func serviceNameForVault(vaultDir string) string {
	return "symvault:" + vaultDir
}

// sanitizeVaultDir returns the last path component of vaultDir for use in
// user-visible error messages.
func sanitizeVaultDir(vaultDir string) string {
	return filepath.Base(vaultDir)
}

// Manager is the dependency-injected entry point for the session package.
// It holds a KeyringBackend and exposes the high-level Save/Load/Clear
// operations the rest of the codebase uses. The package also keeps a
// process-wide DefaultManager initialized from the platform's preferred
// backend (OS keyring with in-memory fallback on supported platforms, an
// in-memory store elsewhere) so existing call sites that use the free
// functions SavePassphrase / LoadPassphrase / etc. keep working.
type Manager struct {
	keyring KeyringBackend
	status  func() CacheStatus
}

// NewManager wires a KeyringBackend behind a Manager. The statusProvider
// is invoked by GetCacheStatus; pass nil to receive a default "unknown"
// status.
func NewManager(keyring KeyringBackend, statusProvider func() CacheStatus) *Manager {
	if statusProvider == nil {
		statusProvider = func() CacheStatus {
			return CacheStatus{
				Backend:    CacheBackendUnknown,
				Persistent: false,
				Message:    "Session cache backend has not been initialized.",
			}
		}
	}
	return &Manager{keyring: keyring, status: statusProvider}
}

// Keyring exposes the underlying backend for callers that need to
// migrate data or read raw entries (e.g. the migrate session subcommand).
func (m *Manager) Keyring() KeyringBackend {
	return m.keyring
}

// GetCacheStatus returns a description of the currently configured backend.
func (m *Manager) GetCacheStatus() CacheStatus {
	return m.status()
}

func (m *Manager) loadWrapKey(vaultDir string) ([]byte, error) {
	encWrapKey, err := m.keyring.Get(keyFor(serviceNameForVault(vaultDir), wrapKeyAccount))
	if err != nil {
		if errors.Is(err, ErrKeyringNotFound) {
			return nil, fmt.Errorf("wrap key not found")
		}
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

func (m *Manager) getOrCreateWrapKey(vaultDir string) ([]byte, error) {
	wrapKey, err := m.loadWrapKey(vaultDir)
	if err == nil {
		return wrapKey, nil
	}

	wrapKey, err = generateWrapKey()
	if err != nil {
		return nil, err
	}

	encWrapKey := base64.StdEncoding.EncodeToString(wrapKey)
	if setErr := m.keyring.Set(keyFor(serviceNameForVault(vaultDir), wrapKeyAccount), encWrapKey); setErr != nil {
		return nil, fmt.Errorf("save wrap key: %w", setErr)
	}
	return wrapKey, nil
}

func (m *Manager) deleteWrapKey(vaultDir string) error {
	if err := m.keyring.Delete(keyFor(serviceNameForVault(vaultDir), wrapKeyAccount)); err != nil {
		if errors.Is(err, ErrKeyringNotFound) {
			return nil
		}
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

// SavePassphrase encrypts passphrase with a freshly generated wrap key
// (creating the wrap key if it does not exist) and stores the encrypted
// payload in the configured KeyringBackend.
func (m *Manager) SavePassphrase(vaultDir string, passphrase []byte, ttl time.Duration) error {
	now := time.Now().UTC()
	wrapKey, err := m.getOrCreateWrapKey(vaultDir)
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
	if err := m.keyring.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), string(payload)); err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

// LoadPassphrase returns the cached passphrase. The hot path refuses to
// transparently upgrade a legacy plaintext session — the caller must run
// "symvault migrate session" first and receive ErrLegacyPlaintextSession.
func (m *Manager) LoadPassphrase(vaultDir string) ([]byte, error) {
	raw, err := m.keyring.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))
	if err != nil {
		metrics.RecordSessionCacheEvent("keyring_unavailable")
		if errors.Is(err, ErrKeyringNotFound) {
			return nil, fmt.Errorf("load session: %w", ErrKeyringNotFound)
		}
		return nil, fmt.Errorf("load session: %w", err)
	}

	var sess storedSession
	if unmarshalErr := json.Unmarshal([]byte(raw), &sess); unmarshalErr != nil {
		metrics.RecordSessionCacheEvent("miss")
		return nil, fmt.Errorf("decode session: %w", unmarshalErr)
	}

	if sess.TTL <= 0 {
		metrics.RecordSessionCacheEvent("miss")
		return nil, fmt.Errorf("session expired for vault %s: TTL is zero or negative", sanitizeVaultDir(vaultDir))
	}

	lastActivity := sess.LastAccess
	if lastActivity.IsZero() {
		lastActivity = sess.SavedAt
	}
	if time.Since(lastActivity) > time.Duration(sess.TTL) {
		_ = m.ClearSession(vaultDir)
		metrics.RecordSessionCacheEvent("miss")
		return nil, fmt.Errorf("session expired for vault %s: last activity %v exceeded TTL %v", sanitizeVaultDir(vaultDir), lastActivity.Format(time.RFC3339), time.Duration(sess.TTL))
	}

	if len(sess.Passphrase) > 0 {
		metrics.RecordSessionCacheEvent("miss")
		return nil, fmt.Errorf("%w: vault %s", ErrLegacyPlaintextSession, sanitizeVaultDir(vaultDir))
	}

	if sess.EncryptedPassphrase == "" || sess.Nonce == "" {
		metrics.RecordSessionCacheEvent("miss")
		return nil, fmt.Errorf("session expired for vault %s: no passphrase data available", sanitizeVaultDir(vaultDir))
	}

	wrapKey, err := m.loadWrapKey(vaultDir)
	if err != nil {
		metrics.RecordSessionCacheEvent("miss")
		return nil, fmt.Errorf("load wrap key: %w", err)
	}

	passphrase, err := decryptPassphrase(sess.EncryptedPassphrase, sess.Nonce, wrapKey)
	if err != nil {
		metrics.RecordSessionCacheEvent("miss")
		return nil, fmt.Errorf("decrypt session: %w", err)
	}

	sess.LastAccess = time.Now().UTC()
	payload, marshalErr := json.Marshal(sess)
	if marshalErr != nil {
		metrics.RecordSessionCacheEvent("hit")
		return passphrase, nil
	}
	if updateErr := m.keyring.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), string(payload)); updateErr != nil {
		metrics.RecordSessionCacheEvent("hit")
		return passphrase, nil
	}
	metrics.RecordSessionCacheEvent("refresh")

	return passphrase, nil
}

// MigrateSession reads the cached session in the legacy plaintext format
// and writes the encrypted form back to the backend. It is a no-op when
// the session is already in the new format. The returned boolean reports
// whether an upgrade was performed.
func (m *Manager) MigrateSession(vaultDir string) (bool, error) {
	raw, err := m.keyring.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))
	if err != nil {
		if errors.Is(err, ErrKeyringNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("load session: %w", err)
	}
	var sess storedSession
	if decodeErr := json.Unmarshal([]byte(raw), &sess); decodeErr != nil {
		return false, fmt.Errorf("decode session: %w", decodeErr)
	}
	if len(sess.Passphrase) == 0 {
		return false, nil
	}
	wrapKey, err := m.getOrCreateWrapKey(vaultDir)
	if err != nil {
		return false, fmt.Errorf("wrap key: %w", err)
	}
	enc, nonce, err := encryptPassphrase(sess.Passphrase, wrapKey)
	if err != nil {
		return false, fmt.Errorf("encrypt passphrase: %w", err)
	}
	sess.EncryptedPassphrase = enc
	sess.Nonce = nonce
	crypto.Wipe(sess.Passphrase)
	sess.Passphrase = nil
	payload, err := json.Marshal(sess)
	if err != nil {
		return false, fmt.Errorf("marshal session: %w", err)
	}
	if err := m.keyring.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), string(payload)); err != nil {
		return false, fmt.Errorf("save migrated session: %w", err)
	}
	return true, nil
}

// HasLegacyPlaintextSession reports whether the cached session is in the
// legacy plaintext format.
func (m *Manager) HasLegacyPlaintextSession(vaultDir string) (bool, error) {
	raw, err := m.keyring.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))
	if err != nil {
		if errors.Is(err, ErrKeyringNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("load session: %w", err)
	}
	var sess storedSession
	if err := json.Unmarshal([]byte(raw), &sess); err != nil {
		return false, fmt.Errorf("decode session: %w", err)
	}
	return len(sess.Passphrase) > 0, nil
}

func (m *Manager) encryptionKey(vaultDir string) ([]byte, error) {
	wrapKey, err := m.loadWrapKey(vaultDir)
	if err != nil {
		return nil, fmt.Errorf("no wrap key available for vault %s: please run 'symvault unlock' to re-establish the session", sanitizeVaultDir(vaultDir))
	}
	return wrapKey, nil
}

// ClearSession removes the cached passphrase, wrap key, and identity
// from the backend.
func (m *Manager) ClearSession(vaultDir string) error {
	if err := m.keyring.Delete(keyFor(serviceNameForVault(vaultDir), sessionAccount)); err != nil {
		if !errors.Is(err, ErrKeyringNotFound) {
			return fmt.Errorf("clear session: %w", err)
		}
	}
	_ = m.deleteWrapKey(vaultDir)
	_ = m.ClearIdentity(vaultDir)
	metrics.RecordSessionCacheEvent("evict")
	return nil
}

func (m *Manager) SaveIdentity(vaultDir string, identity string, ttl time.Duration) error {
	now := time.Now().UTC()
	wrapKey, err := m.getOrCreateWrapKey(vaultDir)
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
	if err := m.keyring.Set(keyFor(serviceNameForVault(vaultDir), identityAccount), string(payload)); err != nil {
		return fmt.Errorf("save identity: %w", err)
	}
	return nil
}

func (m *Manager) LoadIdentity(vaultDir string) (string, error) {
	raw, err := m.keyring.Get(keyFor(serviceNameForVault(vaultDir), identityAccount))
	if err != nil {
		return "", fmt.Errorf("load identity: %w", err)
	}

	var ident storedIdentity
	if unmarshalErr := json.Unmarshal([]byte(raw), &ident); unmarshalErr != nil {
		return "", fmt.Errorf("decode identity: %w", unmarshalErr)
	}

	if ident.TTL <= 0 {
		return "", fmt.Errorf("identity cache expired for vault %s: TTL is zero or negative", sanitizeVaultDir(vaultDir))
	}

	lastActivity := ident.LastAccess
	if lastActivity.IsZero() {
		lastActivity = ident.SavedAt
	}
	if time.Since(lastActivity) > time.Duration(ident.TTL) {
		_ = m.ClearIdentity(vaultDir)
		return "", fmt.Errorf("identity cache expired for vault %s: last activity %v exceeded TTL %v", sanitizeVaultDir(vaultDir), lastActivity.Format(time.RFC3339), time.Duration(ident.TTL))
	}

	wrapKey, wrapErr := m.loadWrapKey(vaultDir)
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
	if updateErr := m.keyring.Set(keyFor(serviceNameForVault(vaultDir), identityAccount), string(payload)); updateErr != nil {
		return identityStr, nil
	}

	return identityStr, nil
}

func (m *Manager) ClearIdentity(vaultDir string) error {
	if err := m.keyring.Delete(keyFor(serviceNameForVault(vaultDir), identityAccount)); err != nil {
		if errors.Is(err, ErrKeyringNotFound) {
			return nil
		}
		return fmt.Errorf("clear identity: %w", err)
	}
	return nil
}

func (m *Manager) IsSessionExpired(vaultDir string) bool {
	raw, err := m.keyring.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))
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

func (m *Manager) LoadPassphraseWithTouchID(ctx context.Context, vaultDir string) ([]byte, error) {
	return LoadBiometricPassphrase(ctx, vaultDir)
}

// defaultManager is the process-wide Manager used by the package-level
// Save/Load/Clear helpers. It is initialized once in init() from the
// platform-preferred backend.
var defaultManager *Manager

// SetDefaultManager replaces the process-wide Manager. Tests use this to
// inject a KeyringBackend without touching the global.
func SetDefaultManager(mgr *Manager) {
	defaultManager = mgr
}

// DefaultManager returns the process-wide Manager. It is initialized in
// init() so callers can rely on it being non-nil after package load.
func DefaultManager() *Manager {
	return defaultManager
}

// GetCacheStatus is the package-level entry point used by callers that
// have not been refactored to take a *Manager.
func GetCacheStatus() CacheStatus {
	return defaultManager.GetCacheStatus()
}

func SavePassphrase(vaultDir string, passphrase []byte, ttl time.Duration) error {
	return defaultManager.SavePassphrase(vaultDir, passphrase, ttl)
}

func LoadPassphrase(vaultDir string) ([]byte, error) {
	return defaultManager.LoadPassphrase(vaultDir)
}

func ClearSession(vaultDir string) error {
	return defaultManager.ClearSession(vaultDir)
}

func IsSessionExpired(vaultDir string) bool {
	return defaultManager.IsSessionExpired(vaultDir)
}

func SaveIdentity(vaultDir string, identity string, ttl time.Duration) error {
	return defaultManager.SaveIdentity(vaultDir, identity, ttl)
}

func LoadIdentity(vaultDir string) (string, error) {
	return defaultManager.LoadIdentity(vaultDir)
}

func ClearIdentity(vaultDir string) error {
	return defaultManager.ClearIdentity(vaultDir)
}

func LoadPassphraseWithTouchID(ctx context.Context, vaultDir string) ([]byte, error) {
	return defaultManager.LoadPassphraseWithTouchID(ctx, vaultDir)
}

func init() {
	defaultManager = NewManager(newPlatformKeyring(), platformCacheStatus)
}

// platformCacheStatus is set by the platform-specific init() that runs
// first (oskeyring.go on supported platforms, memory_init.go elsewhere).
var platformCacheStatus = func() CacheStatus {
	return CacheStatus{
		Backend:    CacheBackendUnknown,
		Persistent: false,
		Message:    "Session cache backend has not been initialized.",
	}
}
