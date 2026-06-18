package session

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestMemoryKeyring_SetAndGet_RoundTrip(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem"

	// Store wrap key so encryption/decryption works
	wrapKey := base64.StdEncoding.EncodeToString(testKey())
	mk.Set("symvault:"+vaultDir, wrapKeyAccount, wrapKey)

	enc, nonce, err := encryptPassphrase([]byte("secret"), testKey())
	if err != nil {
		t.Fatalf("setup encrypt failed: %v", err)
	}

	now := time.Now().UTC()
	sess := storedSession{
		EncryptedPassphrase: enc,
		Nonce:               nonce,
		SavedAt:             now,
		LastAccess:          now,
		TTL:                 int64(time.Hour),
	}
	payload, _ := json.Marshal(sess)

	if err := mk.Set("symvault:"+vaultDir, sessionAccount, string(payload)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, err := mk.Get("symvault:"+vaultDir, sessionAccount)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got == "" {
		t.Fatal("Get() returned empty string")
	}
}

func TestMemoryKeyring_Set_StoresOpaque(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem-encrypt"
	passphrase := "plain-secret"

	wrapKey := base64.StdEncoding.EncodeToString(testKey())
	mk.Set("symvault:"+vaultDir, wrapKeyAccount, wrapKey)

	now := time.Now().UTC()
	sess := storedSession{
		Passphrase: passphraseBytes([]byte(passphrase)),
		SavedAt:    now,
		LastAccess: now,
		TTL:        int64(time.Hour),
	}
	payload, _ := json.Marshal(sess)

	if err := mk.Set("symvault:"+vaultDir, sessionAccount, string(payload)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, err := mk.Get("symvault:"+vaultDir, sessionAccount)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	var retrieved storedSession
	if err := json.Unmarshal([]byte(got), &retrieved); err != nil {
		t.Fatalf("Get() returned invalid JSON: %v", err)
	}

	if string(retrieved.Passphrase) != passphrase {
		t.Errorf("plaintext passphrase was not preserved verbatim, got %q", retrieved.Passphrase)
	}
	if retrieved.EncryptedPassphrase != "" {
		t.Error("memory keyring should not transparently encrypt; that is MigrateSession's job")
	}
}

func TestMemoryKeyring_Set_InvalidJSON(t *testing.T) {
	mk := &memoryKeyring{}
	mk.store = map[string]*SecureBytes{}
	if err := mk.Set("symvault:/tmp/vault", wrapKeyAccount, ""); err != nil {
		t.Fatalf("Set wrap key error = %v", err)
	}
	if err := mk.Set("symvault:/tmp/vault", "some-other-account", "not-json"); err == nil {
		t.Fatal("Set() error = nil, want unmarshal error")
	}
}

func TestMemoryKeyring_Get_NotFound(t *testing.T) {
	mk := &memoryKeyring{}
	_, err := mk.Get("symvault:/nonexistent", sessionAccount)
	if err == nil {
		t.Fatal("Get() error = nil, want not found")
	}
}

func TestMemoryKeyring_Get_NilStore(t *testing.T) {
	mk := &memoryKeyring{}
	_, err := mk.Get("symvault:/tmp/vault", sessionAccount)
	if err == nil {
		t.Fatal("Get() error = nil, want not found")
	}
}

func TestMemoryKeyring_Get_Expired(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem-expired"

	sess := storedSession{
		EncryptedPassphrase: "enc",
		Nonce:               "nonce",
		SavedAt:             time.Now().UTC().Add(-10 * time.Minute),
		LastAccess:          time.Now().UTC().Add(-10 * time.Minute),
		TTL:                 int64(time.Minute),
	}
	payload, _ := json.Marshal(sess)
	mk.Set("symvault:"+vaultDir, sessionAccount, string(payload))

	_, err := mk.Get("symvault:"+vaultDir, sessionAccount)
	if err == nil {
		t.Fatal("Get() error = nil, want expired")
	}
}

func TestMemoryKeyring_Get_ZeroTTL(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem-zero"

	sess := storedSession{
		EncryptedPassphrase: "enc",
		Nonce:               "nonce",
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 0,
	}
	payload, _ := json.Marshal(sess)
	mk.Set("symvault:"+vaultDir, sessionAccount, string(payload))

	_, err := mk.Get("symvault:"+vaultDir, sessionAccount)
	if err == nil {
		t.Fatal("Get() error = nil, want expired for zero TTL")
	}
}

func TestMemoryKeyring_Get_MalformedJSON(t *testing.T) {
	mk := &memoryKeyring{}
	mk.store = map[string]*SecureBytes{
		"symvault:/tmp/vault|" + sessionAccount: NewSecureBytes([]byte("not-valid-json")),
	}

	_, err := mk.Get("symvault:/tmp/vault", sessionAccount)
	if err == nil {
		t.Fatal("Get() error = nil, want malformed JSON error")
	}
}

func TestMemoryKeyring_Get_UpdatesLastAccess(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem-la"

	// Store wrap key so Set() can encrypt plaintext passphrase
	wrapKey := base64.StdEncoding.EncodeToString(testKey())
	mk.Set("symvault:"+vaultDir, wrapKeyAccount, wrapKey)

	now := time.Now().UTC()
	sess := storedSession{
		Passphrase: passphraseBytes([]byte("secret")),
		SavedAt:    now,
		LastAccess: now,
		TTL:        int64(time.Hour),
	}
	payload, _ := json.Marshal(sess)
	mk.Set("symvault:"+vaultDir, sessionAccount, string(payload))

	time.Sleep(time.Millisecond)
	got, err := mk.Get("symvault:"+vaultDir, sessionAccount)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// Get() returns the session JSON (transparent storage layer).
	var retrieved storedSession
	if err := json.Unmarshal([]byte(got), &retrieved); err != nil {
		t.Fatalf("Get() returned invalid JSON: %v", err)
	}

	// Verify LastAccess was updated in the store.
	mk.mu.RLock()
	storeKey := "symvault:" + vaultDir + "|" + sessionAccount
	sb, ok := mk.store[storeKey]
	mk.mu.RUnlock()
	if !ok {
		t.Fatal("session not found in store after Get")
	}
	var storedSess storedSession
	if err := json.Unmarshal(sb.Data(), &storedSess); err != nil {
		t.Fatalf("Unmarshal stored session: %v", err)
	}
	if !storedSess.LastAccess.After(now) {
		t.Error("LastAccess should be updated after Get")
	}
}

func TestMemoryKeyring_Delete_RemovesEntry(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem-del"

	sess := storedSession{
		EncryptedPassphrase: "enc",
		Nonce:               "nonce",
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 int64(time.Hour),
	}
	payload, _ := json.Marshal(sess)
	mk.Set("symvault:"+vaultDir, sessionAccount, string(payload))

	if err := mk.Delete("symvault:"+vaultDir, sessionAccount); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err := mk.Get("symvault:"+vaultDir, sessionAccount)
	if err == nil {
		t.Fatal("Get() after Delete error = nil, want not found")
	}
}

func TestMemoryKeyring_Delete_NotFound(t *testing.T) {
	mk := &memoryKeyring{}
	if err := mk.Delete("symvault:/nonexistent", sessionAccount); err != nil {
		t.Fatalf("Delete() error = %v, want nil", err)
	}
}

func TestMemoryKeyring_Delete_NilStore(t *testing.T) {
	mk := &memoryKeyring{}
	if err := mk.Delete("symvault:/tmp/vault", sessionAccount); err != nil {
		t.Fatalf("Delete() error = %v, want nil", err)
	}
}

func TestVaultDirFromService(t *testing.T) {
	if got := vaultDirFromService("symvault:/tmp/vault"); got != "/tmp/vault" {
		t.Errorf("vaultDirFromService() = %q, want /tmp/vault", got)
	}
	if got := vaultDirFromService("/tmp/vault"); got != "/tmp/vault" {
		t.Errorf("vaultDirFromService() = %q, want /tmp/vault", got)
	}
}

func TestMemoryKeyring_Identity_RoundTrip(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem-id"

	// Store wrap key so encryption/decryption works
	wrapKey := base64.StdEncoding.EncodeToString(testKey())
	mk.Set("symvault:"+vaultDir, wrapKeyAccount, wrapKey)

	identity := "AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST"
	enc, nonce, err := encryptPassphrase([]byte(identity), testKey())
	if err != nil {
		t.Fatalf("setup encrypt failed: %v", err)
	}

	now := time.Now().UTC()
	ident := storedIdentity{
		EncryptedIdentity: enc,
		Nonce:             nonce,
		SavedAt:           now,
		LastAccess:        now,
		TTL:               int64(time.Hour),
	}
	payload, _ := json.Marshal(ident)

	if err := mk.Set("symvault:"+vaultDir, identityAccount, string(payload)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, err := mk.Get("symvault:"+vaultDir, identityAccount)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	var retrieved storedIdentity
	if err := json.Unmarshal([]byte(got), &retrieved); err != nil {
		t.Fatalf("Get() returned invalid JSON: %v", err)
	}

	if retrieved.EncryptedIdentity != enc {
		t.Errorf("EncryptedIdentity lost in round-trip: got %q, want %q", retrieved.EncryptedIdentity, enc)
	}
	if retrieved.Nonce != nonce {
		t.Errorf("Nonce lost in round-trip: got %q, want %q", retrieved.Nonce, nonce)
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte("hello world")
	zeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("zeroBytes() did not zero byte at index %d", i)
		}
	}
}

func TestMemoryKeyring_Set_ZeroesOldData(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem-zero"

	// Store wrap key so Set() can encrypt plaintext passphrase
	wrapKey := base64.StdEncoding.EncodeToString(testKey())
	mk.Set("symvault:"+vaultDir, wrapKeyAccount, wrapKey)

	sess1 := storedSession{
		Passphrase: passphraseBytes([]byte("first-secret")),
		SavedAt:    time.Now().UTC(),
		LastAccess: time.Now().UTC(),
		TTL:        int64(time.Hour),
	}
	payload1, _ := json.Marshal(sess1)
	mk.Set("symvault:"+vaultDir, sessionAccount, string(payload1))

	sess2 := storedSession{
		Passphrase: passphraseBytes([]byte("second-secret")),
		SavedAt:    time.Now().UTC(),
		LastAccess: time.Now().UTC(),
		TTL:        int64(time.Hour),
	}
	payload2, _ := json.Marshal(sess2)
	mk.Set("symvault:"+vaultDir, sessionAccount, string(payload2))

	// Verify second value is stored
	got, err := mk.Get("symvault:"+vaultDir, sessionAccount)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	var retrieved storedSession
	json.Unmarshal([]byte(got), &retrieved)
	if string(retrieved.Passphrase) != "second-secret" {
		t.Errorf("Passphrase = %q, want second-secret (memory keyring is opaque storage)", retrieved.Passphrase)
	}
}

func TestMemoryKeyring_encryptionKeyForStore(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-encryption-key"
	service := "symvault:" + vaultDir

	// Test with no wrap key
	_, err := mk.encryptionKeyForStore(service)
	if err == nil {
		t.Fatal("encryptionKeyForStore() error = nil, want error when no wrap key")
	}

	// Test with invalid base64 wrap key
	mk.store = map[string]*SecureBytes{}
	mk.store[service+"|"+wrapKeyAccount] = NewSecureBytes([]byte("invalid-base64"))
	_, err = mk.encryptionKeyForStore(service)
	if err == nil {
		t.Fatal("encryptionKeyForStore() error = nil, want error for invalid base64")
	}

	// Test with wrong length wrap key
	validKey := testKey()
	wrongLengthKey := validKey[:16] // 16 bytes instead of 32
	mk.store[service+"|"+wrapKeyAccount] = NewSecureBytes([]byte(base64.StdEncoding.EncodeToString(wrongLengthKey)))
	_, err = mk.encryptionKeyForStore(service)
	if err == nil {
		t.Fatal("encryptionKeyForStore() error = nil, want error for wrong key length")
	}

	// Test with valid wrap key
	mk.store[service+"|"+wrapKeyAccount] = NewSecureBytes([]byte(base64.StdEncoding.EncodeToString(validKey)))
	key, err := mk.encryptionKeyForStore(service)
	if err != nil {
		t.Fatalf("encryptionKeyForStore() error = %v", err)
	}
	if len(key) != wrapKeyLen {
		t.Errorf("encryptionKeyForStore() key length = %d, want %d", len(key), wrapKeyLen)
	}
}

func TestMemoryKeyring_Delete_ZeroesMemory(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem-del-zero"

	wrapKey := base64.StdEncoding.EncodeToString(testKey())
	mk.Set("symvault:"+vaultDir, wrapKeyAccount, wrapKey)

	sess := storedSession{
		Passphrase: passphraseBytes([]byte("sensitive-data")),
		SavedAt:    time.Now().UTC(),
		LastAccess: time.Now().UTC(),
		TTL:        int64(time.Hour),
	}
	payload, _ := json.Marshal(sess)
	mk.Set("symvault:"+vaultDir, sessionAccount, string(payload))

	mk.mu.RLock()
	storeKey := "symvault:" + vaultDir + "|" + sessionAccount
	sb := mk.store[storeKey]
	dataBefore := make([]byte, len(sb.Data()))
	copy(dataBefore, sb.Data())
	mk.mu.RUnlock()

	mk.Delete("symvault:"+vaultDir, sessionAccount)

	mk.mu.RLock()
	_, exists := mk.store[storeKey]
	mk.mu.RUnlock()
	if exists {
		t.Fatal("Delete() did not remove entry from store")
	}

	_ = dataBefore
}

func TestMemoryKeyring_DestroyAll_ZeroesAllEntries(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem-destroyall"

	wrapKey := base64.StdEncoding.EncodeToString(testKey())
	mk.Set("symvault:"+vaultDir, wrapKeyAccount, wrapKey)

	sess := storedSession{
		Passphrase: passphraseBytes([]byte("secret1")),
		SavedAt:    time.Now().UTC(),
		LastAccess: time.Now().UTC(),
		TTL:        int64(time.Hour),
	}
	payload, _ := json.Marshal(sess)
	mk.Set("symvault:"+vaultDir, sessionAccount, string(payload))

	mk.mu.RLock()
	initialLen := len(mk.store)
	mk.mu.RUnlock()
	if initialLen != 2 {
		t.Fatalf("expected 2 entries before DestroyAll, got %d", initialLen)
	}

	mk.DestroyAll()

	mk.mu.RLock()
	remainingLen := len(mk.store)
	mk.mu.RUnlock()
	if remainingLen != 0 {
		t.Fatalf("DestroyAll() did not clear all entries, got %d", remainingLen)
	}
}

func TestSecureBytes_Destroy_ZerosData(t *testing.T) {
	data := []byte("sensitive-data-to-zero")
	sb := NewSecureBytes(data)

	sb.Destroy()

	if sb.Data() != nil {
		t.Fatal("Destroy() did not nil the data reference")
	}
	for i, v := range data {
		if v != 0 {
			t.Fatalf("Destroy() did not zero byte at index %d: got %d, want 0", i, v)
		}
	}
}

func TestSecureBytes_Destroy_NilSafe(t *testing.T) {
	var sb *SecureBytes
	sb.Destroy()
	if sb != nil && sb.Data() != nil {
		t.Fatal("Destroy() on nil should be safe")
	}
}

func TestWipeSlice_ZerosData(t *testing.T) {
	data := []byte("wipe-me")
	WipeSlice(data)
	for i, v := range data {
		if v != 0 {
			t.Fatalf("WipeSlice() did not zero byte at index %d: got %d, want 0", i, v)
		}
	}
}
