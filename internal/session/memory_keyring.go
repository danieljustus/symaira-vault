package session

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// memoryKeyring stores session and identity entries in process memory only.
// All stored values are wrapped in SecureBytes for explicit memory zeroing
// on eviction, preventing sensitive data from lingering in process memory
// after lock/timeout.
type memoryKeyring struct {
	mu    sync.RWMutex
	store map[string]*SecureBytes
}

func vaultDirFromService(service string) string {
	return strings.TrimPrefix(service, "symvault:")
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (m *memoryKeyring) Set(service, account, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.store == nil {
		m.store = make(map[string]*SecureBytes)
	}

	if account == wrapKeyAccount || account == identityAccount || account == sessionAccount {
		key := service + "|" + account
		if old, ok := m.store[key]; ok {
			old.Destroy()
		}
		m.store[key] = NewSecureBytes([]byte(value))
		return nil
	}

	var sess storedSession
	if err := json.Unmarshal([]byte(value), &sess); err != nil {
		return fmt.Errorf("unmarshal session: %w", err)
	}

	if len(sess.Passphrase) > 0 {
		key, err := m.encryptionKeyForStore(service)
		if err != nil {
			return fmt.Errorf("encryption key: %w", err)
		}
		enc, nonce, err := encryptPassphrase(sess.Passphrase, key)
		if err != nil {
			return fmt.Errorf("encrypt passphrase: %w", err)
		}
		sess.EncryptedPassphrase = enc
		sess.Nonce = nonce
		sess.Passphrase = nil
	}

	payload, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	key := service + "|" + account
	if old, ok := m.store[key]; ok {
		old.Destroy()
	}
	m.store[key] = NewSecureBytes(append([]byte(nil), payload...))

	return nil
}

// encryptionKeyForStore looks up the wrap key for the given service
// directly in the store. Must be called while holding m.mu.
func (m *memoryKeyring) encryptionKeyForStore(service string) ([]byte, error) {
	wrapKeyKey := service + "|" + wrapKeyAccount
	if w, ok := m.store[wrapKeyKey]; ok {
		if k, err := base64.StdEncoding.DecodeString(string(w.Data())); err == nil && len(k) == wrapKeyLen {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no wrap key available")
}

func (m *memoryKeyring) Get(service, account string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.store == nil {
		return "", fmt.Errorf("not found")
	}

	key := service + "|" + account
	sb, ok := m.store[key]
	if !ok {
		return "", fmt.Errorf("not found")
	}

	payload := sb.Data()
	if account == wrapKeyAccount || account == identityAccount {
		return string(payload), nil
	}

	var sess storedSession
	if err := json.Unmarshal(payload, &sess); err != nil {
		sb.Destroy()
		delete(m.store, key)
		return "", fmt.Errorf("not found")
	}

	if sess.TTL <= 0 {
		sb.Destroy()
		delete(m.store, key)
		return "", fmt.Errorf("not found")
	}

	lastActivity := sess.LastAccess
	if lastActivity.IsZero() {
		lastActivity = sess.SavedAt
	}
	if time.Since(lastActivity) > time.Duration(sess.TTL) {
		sb.Destroy()
		delete(m.store, key)
		return "", fmt.Errorf("not found")
	}

	sess.LastAccess = time.Now().UTC()
	newPayload, err := json.Marshal(sess)
	if err != nil {
		return "", fmt.Errorf("not found")
	}

	sb.Destroy()
	m.store[key] = NewSecureBytes(append([]byte(nil), newPayload...))

	return string(newPayload), nil
}

func (m *memoryKeyring) Delete(service, account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.store == nil {
		return nil
	}

	key := service + "|" + account
	if sb, ok := m.store[key]; ok {
		sb.Destroy()
		delete(m.store, key)
	}

	return nil
}

// DestroyAll zeroes every entry in the keyring at once. This is used
// by ClearSession/Lock to ensure all sensitive data is wiped even if
// individual Delete calls are skipped.
func (m *memoryKeyring) DestroyAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, sb := range m.store {
		sb.Destroy()
		delete(m.store, key)
	}
}

// memoryKeyringBackend adapts memoryKeyring to the KeyringBackend
// interface by splitting the single composite key back into the
// service/account pair the underlying store uses.
type memoryKeyringBackend struct {
	inner *memoryKeyring
}

// NewMemoryKeyringBackend returns a standalone in-memory KeyringBackend.
//
// The in-memory store is the portable half of the keyring contract: it has no
// keychain, no platform and no timeouts, so it is the part the SESSION-002
// fixture can pin on every OS. Production selects a backend through
// newPlatformKeyring; this constructor exists so the contract generator and
// tests can address the memory store directly instead of depending on which
// platform the build targets.
func NewMemoryKeyringBackend() KeyringBackend {
	return &memoryKeyringBackend{inner: &memoryKeyring{}}
}

func (m *memoryKeyringBackend) Get(key string) (string, error) {
	service, account := splitKey(key)
	v, err := m.inner.Get(service, account)
	if err != nil {
		return "", ErrKeyringNotFound
	}
	return v, nil
}

func (m *memoryKeyringBackend) Set(key string, value string) error {
	service, account := splitKey(key)
	return m.inner.Set(service, account, value)
}

func (m *memoryKeyringBackend) Delete(key string) error {
	service, account := splitKey(key)
	return m.inner.Delete(service, account)
}

// SplitKeyringKey is the inverse of keyFor, and the pure seam the CFG-style
// contract pins: no filesystem, no keychain, no platform.
//
// addressable reports whether the key carries the "service|account" separator
// at all. A key without one cannot name a native keychain item -- it would be
// stored under an empty service, where every such key collides -- so the OS
// backend rejects it. The in-memory backend has no such hazard and keeps
// accepting it, which is why the decision is returned rather than enforced
// here.
//
// The split is taken at the LAST separator, so a service containing "|" (a
// vault directory may) still resolves to the intended account.
func SplitKeyringKey(key string) (service, account string, addressable bool) {
	idx := strings.LastIndex(key, "|")
	if idx < 0 {
		return "", key, false
	}
	return key[:idx], key[idx+1:], true
}

// splitKey is the inverse of keyFor.
func splitKey(key string) (service, account string) {
	service, account, _ = SplitKeyringKey(key)
	return service, account
}
