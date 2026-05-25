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

func TestMemoryKeyring_Set_EncryptsPlaintextPassphrase(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem-encrypt"
	passphrase := "plain-secret"

	// Store wrap key so Set() can encrypt plaintext passphrase
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
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if len(retrieved.Passphrase) > 0 {
		t.Error("plaintext passphrase should be encrypted after Set")
	}
	if retrieved.EncryptedPassphrase == "" {
		t.Error("EncryptedPassphrase should be set after Set")
	}
	if retrieved.Nonce == "" {
		t.Error("Nonce should be set after Set")
	}
}

func TestMemoryKeyring_Set_InvalidJSON(t *testing.T) {
	mk := &memoryKeyring{}
	if err := mk.Set("symvault:/tmp/vault", sessionAccount, "not-json"); err == nil {
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
	mk.store = map[string][]byte{
		"symvault:/tmp/vault|" + sessionAccount: []byte("not-valid-json"),
	}

	_, err := mk.Get("symvault:/tmp/vault", sessionAccount)
	if err == nil {
		t.Fatal("Get() error = nil, want malformed JSON error")
	}
}

func TestMemoryKeyring_Get_CorruptedCiphertext(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem-corrupt"

	sess := storedSession{
		EncryptedPassphrase: "dGVzdA==",
		Nonce:               "YWJjZGVmZ2hpamts",
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 int64(time.Hour),
	}
	payload, _ := json.Marshal(sess)
	mk.Set("symvault:"+vaultDir, sessionAccount, string(payload))

	_, err := mk.Get("symvault:"+vaultDir, sessionAccount)
	if err == nil {
		t.Fatal("Get() error = nil, want decrypt error")
	}
}

func TestMemoryKeyring_Get_NoPassphraseData(t *testing.T) {
	mk := &memoryKeyring{}
	vaultDir := "/tmp/vault-mem-nodata"

	sess := storedSession{
		SavedAt:    time.Now().UTC(),
		LastAccess: time.Now().UTC(),
		TTL:        int64(time.Hour),
	}
	payload, _ := json.Marshal(sess)
	mk.Set("symvault:"+vaultDir, sessionAccount, string(payload))

	_, err := mk.Get("symvault:"+vaultDir, sessionAccount)
	if err == nil {
		t.Fatal("Get() error = nil, want no data error")
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

	var retrieved storedSession
	json.Unmarshal([]byte(got), &retrieved)
	if !retrieved.LastAccess.After(now) {
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
	// After Set encrypts plaintext, the passphrase should be empty
	if len(retrieved.Passphrase) > 0 {
		t.Error("Passphrase should be encrypted/empty after Set")
	}
}
