//go:build !cgo

package session

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMemoryKeyring_SetGetDelete(t *testing.T) {
	mk := &memoryKeyring{}

	service := "symvault:/tmp/vault"
	account := sessionAccount

	passphrase := "secret-passphrase"
	enc, nonce, err := encryptPassphrase([]byte(passphrase), testKey())
	if err != nil {
		t.Fatalf("encryptPassphrase() error = %v", err)
	}

	sess := storedSession{
		EncryptedPassphrase: enc,
		Nonce:               nonce,
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 int64(time.Hour),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if err := mk.Set(service, account, string(payload)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, err := mk.Get(service, account)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	var gotSess storedSession
	if err := json.Unmarshal([]byte(got), &gotSess); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if gotSess.EncryptedPassphrase == "" {
		t.Error("Get() returned session with empty EncryptedPassphrase")
	}

	if gotSess.LastAccess.Before(sess.LastAccess) || gotSess.LastAccess.Equal(sess.LastAccess) {
		t.Error("Get() should update LastAccess")
	}

	if err := mk.Delete(service, account); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if _, err := mk.Get(service, account); err == nil {
		t.Fatal("Get() after Delete() error = nil, want not found")
	}
}

func TestMemoryKeyring_EncryptsPlaintextPassphrase(t *testing.T) {
	mk := &memoryKeyring{}

	service := "symvault:/tmp/vault-plain"
	account := sessionAccount

	sess := storedSession{
		Passphrase: passphraseBytes([]byte("plaintext-secret")),
		SavedAt:    time.Now().UTC(),
		LastAccess: time.Now().UTC(),
		TTL:        int64(time.Hour),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if err := mk.Set(service, account, string(payload)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, err := mk.Get(service, account)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	var gotSess storedSession
	if err := json.Unmarshal([]byte(got), &gotSess); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if len(gotSess.Passphrase) > 0 {
		t.Error("Set() should encrypt plaintext passphrase")
	}
	if gotSess.EncryptedPassphrase == "" || gotSess.Nonce == "" {
		t.Error("Set() should set EncryptedPassphrase and Nonce")
	}
}

func TestMemoryKeyring_TTLExpiration(t *testing.T) {
	mk := &memoryKeyring{}

	service := "symvault:/tmp/vault-ttl"
	account := sessionAccount

	passphrase := "ttl-secret"
	enc, nonce, err := encryptPassphrase([]byte(passphrase), testKey())
	if err != nil {
		t.Fatalf("encryptPassphrase() error = %v", err)
	}

	sess := storedSession{
		EncryptedPassphrase: enc,
		Nonce:               nonce,
		SavedAt:             time.Now().UTC().Add(-2 * time.Second),
		LastAccess:          time.Now().UTC().Add(-2 * time.Second),
		TTL:                 int64(time.Second),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if err := mk.Set(service, account, string(payload)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if _, err := mk.Get(service, account); err == nil {
		t.Fatal("Get() error = nil, want expired")
	}
}

func TestMemoryKeyring_ZeroTTL(t *testing.T) {
	mk := &memoryKeyring{}

	service := "symvault:/tmp/vault-zerottl"
	account := sessionAccount

	passphrase := "zero-ttl-secret"
	enc, nonce, err := encryptPassphrase([]byte(passphrase), testKey())
	if err != nil {
		t.Fatalf("encryptPassphrase() error = %v", err)
	}

	sess := storedSession{
		EncryptedPassphrase: enc,
		Nonce:               nonce,
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 0,
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if err := mk.Set(service, account, string(payload)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if _, err := mk.Get(service, account); err == nil {
		t.Fatal("Get() error = nil, want expired for zero TTL")
	}
}

func TestMemoryKeyring_GetNotFound(t *testing.T) {
	mk := &memoryKeyring{}

	if _, err := mk.Get("symvault:/nonexistent", sessionAccount); err == nil {
		t.Fatal("Get() error = nil, want not found")
	}
}

func TestMemoryKeyring_MalformedJSON(t *testing.T) {
	mk := &memoryKeyring{}

	service := "symvault:/tmp/vault-badjson"
	account := sessionAccount

	if err := mk.Set(service, account, "not valid json"); err == nil {
		t.Fatal("Set() with malformed JSON error = nil, want error")
	}
}

func TestMemoryKeyring_DecryptIntegrityCheck(t *testing.T) {
	mk := &memoryKeyring{}

	service := "symvault:/tmp/vault-corrupt"
	account := sessionAccount

	sess := storedSession{
		EncryptedPassphrase: "dGVzdA==",
		Nonce:               "YWJjZGVmZ2hpamts",
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 int64(time.Hour),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if err := mk.Set(service, account, string(payload)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if _, err := mk.Get(service, account); err == nil {
		t.Fatal("Get() with corrupted ciphertext error = nil, want decrypt error")
	}
}

func TestMemoryKeyring_ThreadSafety(t *testing.T) {
	mk := &memoryKeyring{}

	service := "symvault:/tmp/vault-concurrent"
	account := sessionAccount

	passphrase := "concurrent-secret"
	enc, nonce, err := encryptPassphrase([]byte(passphrase), testKey())
	if err != nil {
		t.Fatalf("encryptPassphrase() error = %v", err)
	}

	sess := storedSession{
		EncryptedPassphrase: enc,
		Nonce:               nonce,
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 int64(time.Hour),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	done := make(chan struct{}, 3)

	go func() {
		for i := 0; i < 100; i++ {
			_ = mk.Set(service, account, string(payload))
		}
		done <- struct{}{}
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_, _ = mk.Get(service, account)
		}
		done <- struct{}{}
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_ = mk.Delete(service, account)
		}
		done <- struct{}{}
	}()

	for i := 0; i < 3; i++ {
		<-done
	}
}

func TestMemoryKeyring_DeleteZeroesData(t *testing.T) {
	mk := &memoryKeyring{}

	service := "symvault:/tmp/vault-zero"
	account := sessionAccount

	passphrase := "zero-secret"
	enc, nonce, err := encryptPassphrase([]byte(passphrase), testKey())
	if err != nil {
		t.Fatalf("encryptPassphrase() error = %v", err)
	}

	sess := storedSession{
		EncryptedPassphrase: enc,
		Nonce:               nonce,
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 int64(time.Hour),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if err := mk.Set(service, account, string(payload)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if err := mk.Delete(service, account); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if _, err := mk.Get(service, account); err == nil {
		t.Fatal("Get() after Delete() error = nil, want not found")
	}
}
