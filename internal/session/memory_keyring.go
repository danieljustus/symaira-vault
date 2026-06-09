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
type memoryKeyring struct {
	mu    sync.RWMutex
	store map[string][]byte
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
		m.store = make(map[string][]byte)
	}

	if account == wrapKeyAccount || account == identityAccount || account == sessionAccount {
		key := service + "|" + account
		if old, ok := m.store[key]; ok {
			zeroBytes(old)
		}
		m.store[key] = []byte(value)
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
		zeroBytes(old)
	}
	m.store[key] = append([]byte(nil), payload...)

	return nil
}

// encryptionKeyForStore looks up the wrap key for the given service
// directly in the store. Must be called while holding m.mu.
func (m *memoryKeyring) encryptionKeyForStore(service string) ([]byte, error) {
	wrapKeyKey := service + "|" + wrapKeyAccount
	if w, ok := m.store[wrapKeyKey]; ok {
		if k, err := base64.StdEncoding.DecodeString(string(w)); err == nil && len(k) == wrapKeyLen {
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
	payload, ok := m.store[key]
	if !ok {
		return "", fmt.Errorf("not found")
	}

	if account == wrapKeyAccount || account == identityAccount {
		return string(payload), nil
	}

	var sess storedSession
	if err := json.Unmarshal(payload, &sess); err != nil {
		delete(m.store, key)
		return "", fmt.Errorf("not found")
	}

	if sess.TTL <= 0 {
		zeroBytes(payload)
		delete(m.store, key)
		return "", fmt.Errorf("not found")
	}

	lastActivity := sess.LastAccess
	if lastActivity.IsZero() {
		lastActivity = sess.SavedAt
	}
	if time.Since(lastActivity) > time.Duration(sess.TTL) {
		zeroBytes(payload)
		delete(m.store, key)
		return "", fmt.Errorf("not found")
	}

	sess.LastAccess = time.Now().UTC()
	newPayload, err := json.Marshal(sess)
	if err != nil {
		return "", fmt.Errorf("not found")
	}

	zeroBytes(payload)
	m.store[key] = append([]byte(nil), newPayload...)

	return string(newPayload), nil
}

func (m *memoryKeyring) Delete(service, account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.store == nil {
		return nil
	}

	key := service + "|" + account
	if payload, ok := m.store[key]; ok {
		zeroBytes(payload)
		delete(m.store, key)
	}

	return nil
}

// memoryKeyringBackend adapts memoryKeyring to the KeyringBackend
// interface by splitting the single composite key back into the
// service/account pair the underlying store uses.
type memoryKeyringBackend struct {
	inner *memoryKeyring
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

// splitKey is the inverse of keyFor.
func splitKey(key string) (service, account string) {
	idx := strings.LastIndex(key, "|")
	if idx < 0 {
		return "", key
	}
	return key[:idx], key[idx+1:]
}
