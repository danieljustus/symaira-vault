package session

import (
	"encoding/base64"
	"encoding/json"
	"strings"
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

// TestMemoryKeyring_Set_StoresAnyValueVerbatim replaces
// TestMemoryKeyring_Set_InvalidJSON.
//
// Set used to reject a value it could not parse as a session document, for
// accounts other than the three production ones. KeyringBackend documents
// opaque storage, the OS backend stores any string, and the Rust side is a
// byte map -- so rejecting here was the outlier. The property that matters,
// that only well-formed sessions are ever written, belongs to the Manager and
// is asserted there.
func TestMemoryKeyring_Set_StoresAnyValueVerbatim(t *testing.T) {
	mk := &memoryKeyring{}
	if err := mk.Set("symvault:/tmp/vault", "some-other-account", "not-json"); err != nil {
		t.Fatalf("Set() error = %v, want nil for opaque storage", err)
	}
	got, err := mk.Get("symvault:/tmp/vault", "some-other-account")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != "not-json" {
		t.Errorf("Get() = %q, want the value Set stored verbatim", got)
	}
}

// TestMemoryKeyring_RoundTripsAValueSetJustAccepted is the regression guard for
// the defect this change fixes: Get used to parse a session-account value and
// DELETE the entry when the parse failed, destroying a value Set had accepted
// and reporting it as never having existed.
func TestMemoryKeyring_RoundTripsAValueSetJustAccepted(t *testing.T) {
	backend := NewMemoryKeyringBackend()
	key := keyFor("symvault:/tmp/vault", sessionAccount)
	if err := backend.Set(key, "opaque-value"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, err := backend.Get(key)
	if err != nil {
		t.Fatalf("Get() after Set = %v, want the stored value", err)
	}
	if got != "opaque-value" {
		t.Errorf("Get() = %q, want %q", got, "opaque-value")
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

// The next three replace TestMemoryKeyring_Get_Expired,
// TestMemoryKeyring_Get_ZeroTTL and TestMemoryKeyring_Get_MalformedJSON.
//
// Those asserted that the in-memory backend enforced TTL and JSON validity.
// Manager.LoadPassphrase already enforces both -- and also MaxLifetime, which
// the backend copy did not -- so the property is verified at the layer that
// owns it. The error a caller sees changes from the backend's "not found" to
// the Manager's "expired", which is the class the OS keyring path has always
// produced.

func TestManagerOverMemory_RejectsAnIdleExpiredSession(t *testing.T) {
	backend := NewMemoryKeyringBackend()
	vaultDir := "/tmp/vault-mem-expired"
	payload, _ := json.Marshal(storedSession{
		EncryptedPassphrase: "enc",
		Nonce:               "nonce",
		SavedAt:             time.Now().UTC().Add(-10 * time.Minute),
		LastAccess:          time.Now().UTC().Add(-10 * time.Minute),
		TTL:                 int64(time.Minute),
	})
	if err := backend.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), string(payload)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	_, err := NewManager(backend, nil).LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() error = nil, want expired")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("LoadPassphrase() error = %v, want an expiry error", err)
	}
}

func TestManagerOverMemory_RejectsAZeroTTLSession(t *testing.T) {
	backend := NewMemoryKeyringBackend()
	vaultDir := "/tmp/vault-mem-zero-ttl"
	payload, _ := json.Marshal(storedSession{
		EncryptedPassphrase: "enc",
		Nonce:               "nonce",
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 0,
	})
	if err := backend.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), string(payload)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if _, err := NewManager(backend, nil).LoadPassphrase(vaultDir); err == nil {
		t.Fatal("LoadPassphrase() error = nil, want rejection for a zero TTL")
	}
}

func TestManagerOverMemory_RejectsAMalformedSession(t *testing.T) {
	backend := NewMemoryKeyringBackend()
	vaultDir := "/tmp/vault-mem-malformed"
	if err := backend.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), "not-valid-json"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if _, err := NewManager(backend, nil).LoadPassphrase(vaultDir); err == nil {
		t.Fatal("LoadPassphrase() error = nil, want a decode error")
	}
	// And the entry must still be there: a failed read is not a delete.
	if _, err := backend.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount)); err != nil {
		t.Errorf("the malformed entry was destroyed by reading it: %v", err)
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

// TestMemoryKeyring_encryptionKeyForStore used to exercise
// memoryKeyring.encryptionKeyForStore, which looked up a wrap key in the
// backend's own store so Set could encrypt a passphrase below the storage
// interface. That branch was unreachable for every account production uses and
// duplicated Manager-level encryption; it and this test were removed together.
// Passphrase encryption itself is unchanged and covered by the Manager tests.

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
