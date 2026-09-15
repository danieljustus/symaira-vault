package session

import (
	"fmt"
	"strings"
	"sync"
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

// Set stores value verbatim.
//
// It used to branch on the account: for an account that was not one of the
// three production ones it parsed the value as a session document and
// encrypted the passphrase with a wrap key it looked up in its own store. That
// branch was unreachable in production and implemented session encryption a
// second time, below an interface that is documented as opaque storage.
func (m *memoryKeyring) Set(service, account, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.store == nil {
		m.store = make(map[string]*SecureBytes)
	}

	key := service + "|" + account
	if old, ok := m.store[key]; ok {
		old.Destroy()
	}
	m.store[key] = NewSecureBytes([]byte(value))
	return nil
}

// Get returns the value previously stored under the key, which is what
// KeyringBackend documents and what the OS backend and the Rust side do.
//
// It used to parse a session-account value as a session document, enforce its
// own TTL, refresh LastAccess and rewrite the stored payload -- and DELETE the
// entry when the parse failed, destroying a value Set had just accepted and
// reporting it as never having existed. Manager.LoadPassphrase already
// performs every one of those steps above this interface, including the
// write-back, and it also enforces MaxLifetime, which this copy did not.
//
// The visible consequence of the removal: an idle-expired session on the
// in-memory fallback path now reports "expired" through the Manager instead of
// "not found" from here. That is the same error class the OS keyring path has
// always produced.
func (m *memoryKeyring) Get(service, account string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.store == nil {
		return "", fmt.Errorf("not found")
	}

	sb, ok := m.store[service+"|"+account]
	if !ok {
		return "", fmt.Errorf("not found")
	}
	return string(sb.Data()), nil
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
