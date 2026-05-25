package session

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// memoryKeyring stores encrypted sessions in process memory only.
type memoryKeyring struct {
	mu    sync.RWMutex
	store map[string][]byte
}

func vaultDirFromService(service string) string {
	return strings.TrimPrefix(service, "symaira:")
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

	var sess storedSession
	if err := json.Unmarshal([]byte(value), &sess); err != nil {
		if account == wrapKeyAccount {
			// Wrap keys are stored as raw base64 (not session JSON)
			key := service + "|" + account
			if old, ok := m.store[key]; ok {
				zeroBytes(old)
			}
			m.store[key] = []byte(value)
			return nil
		}
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

// encryptionKeyForStore returns the encryption key for the given service,
// looking up the wrap key from the store directly (must be called while holding m.mu).
func (m *memoryKeyring) encryptionKeyForStore(service string) ([]byte, error) {
	// Try to find wrap key in our store
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

	var sess storedSession
	if err := json.Unmarshal(payload, &sess); err != nil {
		if account == wrapKeyAccount {
			// Wrap keys are stored as raw base64 (not session JSON)
			return string(payload), nil
		}
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

	if sess.EncryptedPassphrase != "" && sess.Nonce != "" {
		k, err := m.encryptionKeyForStore(service)
		if err != nil {
			zeroBytes(payload)
			delete(m.store, key)
			return "", fmt.Errorf("not found")
		}
		plain, err := decryptPassphrase(sess.EncryptedPassphrase, sess.Nonce, k)
		if err != nil {
			zeroBytes(payload)
			delete(m.store, key)
			return "", fmt.Errorf("not found")
		}
		zeroBytes(plain)
	} else if len(sess.Passphrase) == 0 {
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
