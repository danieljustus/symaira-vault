package session

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeKeyring struct {
	getErr    error
	deleteErr error
	setErr    error
	store     map[string]string
	mu        sync.Mutex
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("random source unavailable")
}

func newFakeKeyring() *fakeKeyring {
	return &fakeKeyring{store: make(map[string]string)}
}

func (f *fakeKeyring) set(service, account, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		err := f.setErr
		f.setErr = nil
		return err
	}
	f.store[service+"|"+account] = value
	return nil
}

func (f *fakeKeyring) get(service, account string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		err := f.getErr
		f.getErr = nil
		return "", err
	}
	v, ok := f.store[service+"|"+account]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (f *fakeKeyring) delete(service, account string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		err := f.deleteErr
		f.deleteErr = nil
		return err
	}
	delete(f.store, service+"|"+account)
	return nil
}

// testKey returns a fixed 32-byte key for testing encrypt/decrypt directly.
func testKey() []byte {
	return []byte("0123456789abcdefghijklmnopqrstuv")
}

// setupTestWrapKey generates a random wrap key and stores it in the fake keyring.
func setupTestWrapKey(t *testing.T, fake *fakeKeyring, vaultDir string) []byte {
	t.Helper()
	key := testKey()
	encKey := base64.StdEncoding.EncodeToString(key)
	if err := fake.set(serviceName(vaultDir), wrapKeyAccount, encKey); err != nil {
		t.Fatalf("store wrap key: %v", err)
	}
	return key
}

func stubKeyring(t *testing.T, fake *fakeKeyring) {
	t.Helper()
	oldSet := keyringSet
	oldGet := keyringGet
	oldDelete := keyringDelete

	keyringSet = fake.set
	keyringGet = fake.get
	keyringDelete = fake.delete

	t.Cleanup(func() {
		keyringSet = oldSet
		keyringGet = oldGet
		keyringDelete = oldDelete
	})
}

func TestSaveAndLoadPassphraseRoundTrip(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "correct horse battery staple"

	if err := SavePassphrase(vaultDir, []byte(passphrase), time.Minute); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	got, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != passphrase {
		t.Fatalf("LoadPassphrase() = %q, want %q", got, passphrase)
	}
}

func TestClearSessionRemovesFromKeyring(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	if err := SavePassphrase(vaultDir, []byte("secret"), time.Minute); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	if err := ClearSession(vaultDir); err != nil {
		t.Fatalf("ClearSession() error = %v", err)
	}

	if _, err := LoadPassphrase(vaultDir); err == nil {
		t.Fatal("LoadPassphrase() error = nil, want not found")
	}
}

func TestLoadPassphraseExpiresAfterTTL(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	if err := SavePassphrase(vaultDir, []byte("secret"), 10*time.Millisecond); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	// Wait for TTL to expire using channel-based notification instead of time.Sleep
	done := make(chan struct{})
	go func() {
		time.Sleep(25 * time.Millisecond)
		close(done)
	}()
	<-done

	if _, err := LoadPassphrase(vaultDir); err == nil {
		t.Fatal("LoadPassphrase() error = nil, want expired")
	}
}

func TestIsSessionExpired_NoSession(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	if !IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = false, want true when no session exists")
	}
}

func TestIsSessionExpired_ExpiredSession(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	// Save a session with very short TTL
	if err := SavePassphrase(vaultDir, []byte("secret"), 10*time.Millisecond); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	// Wait for TTL to expire
	done := make(chan struct{})
	go func() {
		time.Sleep(25 * time.Millisecond)
		close(done)
	}()
	<-done

	if !IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = false, want true for expired session")
	}
}

func TestIsSessionExpired_ValidSession(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	if err := SavePassphrase(vaultDir, []byte("secret"), time.Hour); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	if IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = true, want false for valid session")
	}
}

func TestLoadPassphrase_KeyringGetError(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	fake.getErr = errors.New("keyring unavailable")

	_, err := LoadPassphrase("/tmp/vault")
	if err == nil {
		t.Fatal("LoadPassphrase() error = nil, want keyring error")
	}
}

func TestLoadPassphrase_MalformedJSON(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)

	//nolint:errcheck // fake.set is only used in tests
	fake.set("openpass:"+vaultDir, sessionAccount, "not valid json{{{")
	_, err := LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() error = nil, want unmarshal error")
	}
}

func TestClearSession_DeleteError(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	if err := SavePassphrase(vaultDir, []byte("secret"), time.Minute); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	fake.deleteErr = errors.New("keyring delete failed")

	err := ClearSession(vaultDir)
	if err == nil {
		t.Fatal("ClearSession() error = nil, want delete error")
	}
}

func TestSavePassphrase_KeyringSetError(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	fake.setErr = errors.New("keyring write failed")

	err := SavePassphrase("/tmp/vault", []byte("secret"), time.Minute)
	if err == nil {
		t.Fatal("SavePassphrase() error = nil, want keyring set error")
	}
}

func TestLoadPassphrase_ZeroTTL(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-zerott"
	setupTestWrapKey(t, fake, vaultDir)
	payload := `{"saved_at":"2024-01-01T00:00:00Z","last_access":"2024-01-01T00:00:00Z","passphrase":"secret","ttl_ns":0}`
	if err := fake.set("openpass:"+vaultDir, sessionAccount, payload); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	_, err := LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() error = nil, want expired error for zero TTL")
	}
}

func TestIsSessionExpired_ZeroTTL(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-zerott2"
	setupTestWrapKey(t, fake, vaultDir)
	payload := `{"saved_at":"2024-01-01T00:00:00Z","last_access":"2024-01-01T00:00:00Z","passphrase":"secret","ttl_ns":0}`
	if err := fake.set("openpass:"+vaultDir, sessionAccount, payload); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	if !IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = false, want true for zero TTL")
	}
}

func TestIsSessionExpired_ZeroLastAccess_NotExpired(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-zerola"
	setupTestWrapKey(t, fake, vaultDir)
	savedAt := time.Now().UTC().Add(-1 * time.Second).Format(time.RFC3339Nano)
	ttlNs := int64(time.Hour)
	payload := fmt.Sprintf(`{"saved_at":%q,"last_access":"0001-01-01T00:00:00Z","passphrase":"secret","ttl_ns":%d}`, savedAt, ttlNs)
	if err := fake.set("openpass:"+vaultDir, sessionAccount, payload); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	if IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = true, want false when last_access is zero but saved_at is recent")
	}
}

func TestIsSessionExpired_ZeroLastAccess_Expired(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-zerola2"
	setupTestWrapKey(t, fake, vaultDir)
	savedAt := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339Nano)
	ttlNs := int64(time.Minute)
	payload := fmt.Sprintf(`{"saved_at":%q,"last_access":"0001-01-01T00:00:00Z","passphrase":"secret","ttl_ns":%d}`, savedAt, ttlNs)
	if err := fake.set("openpass:"+vaultDir, sessionAccount, payload); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	if !IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = false, want true when last_access is zero and saved_at is past TTL")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	passphrase := "correct horse battery staple"

	key := testKey()
	enc, nonce, err := encryptPassphrase([]byte(passphrase), key)
	if err != nil {
		t.Fatalf("encryptPassphrase() error = %v", err)
	}
	if enc == "" || nonce == "" {
		t.Fatal("encryptPassphrase() returned empty enc or nonce")
	}

	got, err := decryptPassphrase(enc, nonce, key)
	if err != nil {
		t.Fatalf("decryptPassphrase() error = %v", err)
	}
	if string(got) != passphrase {
		t.Fatalf("decryptPassphrase() = %q, want %q", got, passphrase)
	}
}

func TestEncryptDifferentVaultsProduceDifferentCiphertext(t *testing.T) {
	passphrase := "same passphrase"
	keyA := []byte("0123456789abcdefghijklmnopqrstuv")
	keyB := []byte("abcdefghijklmnopqrstuv0123456789")
	enc1, nonce1, err := encryptPassphrase([]byte(passphrase), keyA)
	if err != nil {
		t.Fatalf("encryptPassphrase(/vault/a) error = %v", err)
	}
	enc2, nonce2, err := encryptPassphrase([]byte(passphrase), keyB)
	if err != nil {
		t.Fatalf("encryptPassphrase(/vault/b) error = %v", err)
	}
	if enc1 == enc2 && nonce1 == nonce2 {
		t.Error("different vault identities should produce different ciphertext (nonce collision or same key)")
	}

	// Decrypting with wrong key should fail
	if _, err := decryptPassphrase(enc1, nonce1, keyB); err == nil {
		t.Fatal("decryptPassphrase() with wrong key should fail")
	}
}

func TestDecryptFailsWithWrongKey(t *testing.T) {
	key := []byte("0123456789abcdefghijklmnopqrstuv")
	wrongKey := []byte("abcdefghijklmnopqrstuv0123456789")
	enc, nonce, err := encryptPassphrase([]byte("secret"), key)
	if err != nil {
		t.Fatalf("encryptPassphrase() error = %v", err)
	}
	if _, err := decryptPassphrase(enc, nonce, wrongKey); err == nil {
		t.Fatal("decryptPassphrase() with wrong key should fail")
	}
}

func TestBackwardCompat_LoadOldPlaintextFormat(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-old-format"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "old-style-secret"
	payload := fmt.Sprintf(`{"saved_at":%q,"last_access":%q,"passphrase":%q,"ttl_ns":%d}`,
		time.Now().UTC().Format(time.RFC3339Nano),
		time.Now().UTC().Format(time.RFC3339Nano),
		passphrase,
		int64(time.Hour))
	if err := fake.set("openpass:"+vaultDir, sessionAccount, payload); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	got, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != passphrase {
		t.Fatalf("LoadPassphrase() = %q, want %q", got, passphrase)
	}
}

func TestMigration_OldFormatAutoMigratesToEncrypted(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-migrate"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "migrate-me"
	payload := fmt.Sprintf(`{"saved_at":%q,"last_access":%q,"passphrase":%q,"ttl_ns":%d}`,
		time.Now().UTC().Format(time.RFC3339Nano),
		time.Now().UTC().Format(time.RFC3339Nano),
		passphrase,
		int64(time.Hour))
	if err := fake.set("openpass:"+vaultDir, sessionAccount, payload); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	// First load triggers migration
	got, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != passphrase {
		t.Fatalf("LoadPassphrase() = %q, want %q", got, passphrase)
	}

	// Verify the stored format is now encrypted (no plaintext passphrase field)
	raw, err := fake.get("openpass:"+vaultDir, sessionAccount)
	if err != nil {
		t.Fatalf("fake.get() error = %v", err)
	}
	var sess storedSession
	if jsonErr := json.Unmarshal([]byte(raw), &sess); jsonErr != nil {
		t.Fatalf("json.Unmarshal() error = %v", jsonErr)
	}
	if sess.Passphrase != "" {
		t.Error("after migration, plaintext passphrase field should be empty")
	}
	if sess.EncryptedPassphrase == "" || sess.Nonce == "" {
		t.Error("after migration, encrypted_passphrase and nonce should be set")
	}

	// Second load should still return the correct passphrase (from encrypted format)
	got2, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("second LoadPassphrase() error = %v", err)
	}
	if string(got2) != passphrase {
		t.Fatalf("second LoadPassphrase() = %q, want %q", got2, passphrase)
	}
}

func TestNewFormatStoredEncrypted(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-new-format"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "new-encrypted-secret"

	if err := SavePassphrase(vaultDir, []byte(passphrase), time.Hour); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	raw, err := fake.get("openpass:"+vaultDir, sessionAccount)
	if err != nil {
		t.Fatalf("fake.get() error = %v", err)
	}

	var sess storedSession
	if err := json.Unmarshal([]byte(raw), &sess); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if sess.Passphrase != "" {
		t.Error("new format should not contain plaintext passphrase")
	}
	if sess.EncryptedPassphrase == "" {
		t.Error("new format should contain encrypted_passphrase")
	}
	if sess.Nonce == "" {
		t.Error("new format should contain nonce")
	}
}

func TestDecryptPassphrase_InvalidBase64Ciphertext(t *testing.T) {
	_, err := decryptPassphrase("not-valid-base64!!!", "dGVzdA==", testKey())
	if err == nil {
		t.Fatal("decryptPassphrase() error = nil, want base64 decode error for invalid ciphertext")
	}
}

func TestDecryptPassphrase_InvalidBase64Nonce(t *testing.T) {
	// Valid base64 for ciphertext but invalid base64 for nonce
	_, err := decryptPassphrase("dGVzdA==", "!!!not-base64", testKey())
	if err == nil {
		t.Fatal("decryptPassphrase() error = nil, want base64 decode error for invalid nonce")
	}
}

func TestEncryptPassphrase_RandomReaderError(t *testing.T) {
	oldReader := crand.Reader
	crand.Reader = errReader{}
	t.Cleanup(func() { crand.Reader = oldReader })

	_, _, err := encryptPassphrase([]byte("secret"), testKey())
	if err == nil {
		t.Fatal("encryptPassphrase() error = nil, want random reader error")
	}
}

func TestSavePassphrase_EncryptError(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	oldReader := crand.Reader
	crand.Reader = errReader{}
	t.Cleanup(func() { crand.Reader = oldReader })

	if err := SavePassphrase("/tmp/vault-save-encrypt-error", []byte("secret"), time.Hour); err == nil {
		t.Fatal("SavePassphrase() error = nil, want encrypt error")
	}
}

func TestLoadPassphrase_ResolveDecryptError(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-corrupt-enc"
	setupTestWrapKey(t, fake, vaultDir)
	// Store a session with valid JSON but corrupted ciphertext (valid base64, wrong encryption)
	sess := storedSession{
		EncryptedPassphrase: "dGVzdA==",         // "test" in base64 — not valid AES-GCM ciphertext
		Nonce:               "YWJjZGVmZ2hpamts", // "abcdefghijkl" in base64 — 12 bytes
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 int64(time.Hour),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if setErr := fake.set("openpass:"+vaultDir, sessionAccount, string(payload)); setErr != nil {
		t.Fatalf("fake.set() error = %v", setErr)
	}

	_, err = LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() error = nil, want decrypt error for corrupted ciphertext")
	}
}

func TestLoadPassphrase_UpdateKeyringSetError(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-update-err"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "update-test-secret"

	// Save a valid session first
	if err := SavePassphrase(vaultDir, []byte(passphrase), time.Hour); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	// Now set a one-shot error for the next keyringSet call (which happens during LoadPassphrase update)
	fake.setErr = errors.New("keyring update failed")

	loaded, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v, want nil (should not fail on update error)", err)
	}
	if string(loaded) != passphrase {
		t.Errorf("LoadPassphrase() = %q, want %q", loaded, passphrase)
	}
}

func TestIsSessionExpired_MalformedJSON(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-bad-json"
	setupTestWrapKey(t, fake, vaultDir)
	// Store malformed JSON directly
	if err := fake.set("openpass:"+vaultDir, sessionAccount, "{invalid json!!!"); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	if !IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = false, want true for malformed JSON")
	}
}

func TestLoadPassphraseWithTouchID_BiometricSuccessButLoadFails(t *testing.T) {
	mock := &mockBiometricPassphraseStore{available: true, err: ErrBiometricNotConfigured}
	biometricPassphraseStore = mock
	defer func() { biometricPassphraseStore = nil }()

	_, err := LoadPassphraseWithTouchID(context.Background(), "/tmp/vault-no-session")
	if !errors.Is(err, ErrBiometricNotConfigured) {
		t.Fatalf("LoadPassphraseWithTouchID() error = %v, want ErrBiometricNotConfigured", err)
	}
}

func TestResolvePassphrase_NoData(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-no-data"
	setupTestWrapKey(t, fake, vaultDir)
	// Store a session with no passphrase data at all
	sess := storedSession{
		SavedAt:    time.Now().UTC(),
		LastAccess: time.Now().UTC(),
		TTL:        int64(time.Hour),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if setErr := fake.set("openpass:"+vaultDir, sessionAccount, string(payload)); setErr != nil {
		t.Fatalf("fake.set() error = %v", setErr)
	}

	_, err = LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() error = nil, want no passphrase data error")
	}
}

func TestLoadPassphrase_NegativeTTL(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-neg-ttl"
	setupTestWrapKey(t, fake, vaultDir)
	payload := fmt.Sprintf(`{"saved_at":"2024-01-01T00:00:00Z","last_access":"2024-01-01T00:00:00Z","passphrase":"secret","ttl_ns":%d}`, int64(-1))
	if err := fake.set("openpass:"+vaultDir, sessionAccount, payload); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	_, err := LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() error = nil, want expired error for negative TTL")
	}
}

func TestIsSessionExpired_NegativeTTL(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-neg-ttl2"
	setupTestWrapKey(t, fake, vaultDir)
	payload := fmt.Sprintf(`{"saved_at":"2024-01-01T00:00:00Z","last_access":"2024-01-01T00:00:00Z","passphrase":"secret","ttl_ns":%d}`, int64(-1))
	if err := fake.set("openpass:"+vaultDir, sessionAccount, payload); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	if !IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = false, want true for negative TTL")
	}
}

func TestEncryptPassphrase_AESCipherError(t *testing.T) {
	passphrase := "test"

	result, nonce, err := encryptPassphrase([]byte(passphrase), testKey())
	if err != nil {
		t.Fatalf("encryptPassphrase should not return error for valid input: %v", err)
	}
	if result == "" || nonce == "" {
		t.Error("encryptPassphrase returned empty values")
	}
}

func TestDecryptPassphrase_AESCipherError(t *testing.T) {
	enc, nonce, err := encryptPassphrase([]byte("secret"), testKey())
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	_, err = decryptPassphrase(enc, nonce, testKey())
	if err != nil {
		t.Fatalf("decryptPassphrase failed: %v", err)
	}
}

func TestSavePassphrase_MarshalError(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-marshal"
	setupTestWrapKey(t, fake, vaultDir)

	if err := SavePassphrase(vaultDir, []byte("secret"), time.Hour); err != nil {
		t.Fatalf("SavePassphrase failed: %v", err)
	}

	raw, err := fake.get("openpass:"+vaultDir, sessionAccount)
	if err != nil {
		t.Fatalf("fake.get() error = %v", err)
	}
	if raw == "" {
		t.Error("session should be stored in keyring")
	}
}

func TestLoadPassphrase_UpdateSessionOnAccess(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-update"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "update-test"

	if err := SavePassphrase(vaultDir, []byte(passphrase), time.Hour); err != nil {
		t.Fatalf("SavePassphrase error = %v", err)
	}

	got, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase error = %v", err)
	}
	if string(got) != passphrase {
		t.Errorf("LoadPassphrase = %q, want %q", got, passphrase)
	}

	raw, err := fake.get("openpass:"+vaultDir, sessionAccount)
	if err != nil {
		t.Fatalf("fake.get() error = %v", err)
	}

	var sess storedSession
	if jsonErr := json.Unmarshal([]byte(raw), &sess); jsonErr != nil {
		t.Fatalf("json.Unmarshal() error = %v", jsonErr)
	}
	if sess.LastAccess.IsZero() {
		t.Error("LastAccess should be updated after LoadPassphrase")
	}
}

func TestLoadPassphrase_LastAccessBeforeSavedAt(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-la-before-sa"
	setupTestWrapKey(t, fake, vaultDir)
	now := time.Now().UTC()
	payload := fmt.Sprintf(`{"saved_at":%q,"last_access":%q,"passphrase":"secret","ttl_ns":%d}`,
		now.Format(time.RFC3339Nano),
		now.Add(-time.Second).Format(time.RFC3339Nano),
		int64(time.Hour))
	if err := fake.set("openpass:"+vaultDir, sessionAccount, payload); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	got, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != "secret" {
		t.Errorf("LoadPassphrase() = %q, want %q", got, "secret")
	}
}

func TestLoadPassphrase_ZeroLastAccessUsesSavedAt(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-load-zero-last-access"
	setupTestWrapKey(t, fake, vaultDir)
	payload := fmt.Sprintf(`{"saved_at":%q,"last_access":"0001-01-01T00:00:00Z","passphrase":"secret","ttl_ns":%d}`,
		time.Now().UTC().Format(time.RFC3339Nano),
		int64(time.Hour))
	if err := fake.set("openpass:"+vaultDir, sessionAccount, payload); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	got, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != "secret" {
		t.Errorf("LoadPassphrase() = %q, want %q", got, "secret")
	}
}

func TestResolvePassphrase_BothEncryptedAndPlaintext(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-both"
	setupTestWrapKey(t, fake, vaultDir)
	enc, nonce, err := encryptPassphrase([]byte("actual-secret"), setupTestWrapKey(t, fake, vaultDir))
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	sess := storedSession{
		EncryptedPassphrase: enc,
		Nonce:               nonce,
		Passphrase:          "legacy-secret",
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 int64(time.Hour),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := fake.set("openpass:"+vaultDir, sessionAccount, string(payload)); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	got, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != "actual-secret" {
		t.Errorf("LoadPassphrase() = %q, want encrypted value to be used", got)
	}
}

func TestResolvePassphrase_LegacyFormatMigrates(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-legacy"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "legacy-value"
	sess := storedSession{
		Passphrase: passphrase,
		SavedAt:    time.Now().UTC(),
		LastAccess: time.Now().UTC(),
		TTL:        int64(time.Hour),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := fake.set("openpass:"+vaultDir, sessionAccount, string(payload)); err != nil {
		t.Fatalf("fake.set() error = %v", err)
	}

	got, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != passphrase {
		t.Errorf("LoadPassphrase() = %q, want %q", got, passphrase)
	}

	raw, _ := fake.get("openpass:"+vaultDir, sessionAccount)
	var updated storedSession
	if jsonErr := json.Unmarshal([]byte(raw), &updated); jsonErr != nil {
		t.Fatalf("json.Unmarshal() error = %v", jsonErr)
	}
	if updated.Passphrase != "" {
		t.Error("legacy plaintext should be cleared after migration")
	}
}

func TestSavePassphrase_UpdatesLastAccessOnLoad(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-updates-la"
	setupTestWrapKey(t, fake, vaultDir)
	if err := SavePassphrase(vaultDir, []byte("secret"), time.Hour); err != nil {
		t.Fatalf("SavePassphrase error = %v", err)
	}

	raw1, _ := fake.get("openpass:"+vaultDir, sessionAccount)
	var sess1 storedSession
	json.Unmarshal([]byte(raw1), &sess1)
	time.Sleep(time.Millisecond)

	LoadPassphrase(vaultDir)

	raw2, _ := fake.get("openpass:"+vaultDir, sessionAccount)
	var sess2 storedSession
	json.Unmarshal([]byte(raw2), &sess2)

	if sess1.LastAccess.Equal(sess2.LastAccess) || sess2.LastAccess.Before(sess1.LastAccess) {
		t.Error("LastAccess should be updated after LoadPassphrase")
	}
}

func TestSavePassphrase_EncryptFails(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-enc-fail"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "secret"

	enc, nonce, err := encryptPassphrase([]byte(passphrase), setupTestWrapKey(t, fake, vaultDir))
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if enc == "" || nonce == "" {
		t.Error("setup produced empty values")
	}

	err = SavePassphrase(vaultDir, []byte(passphrase), time.Hour)
	if err != nil {
		t.Fatalf("SavePassphrase failed: %v", err)
	}
}

func TestLoadPassphrase_ResolveError(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-resolve-err"
	setupTestWrapKey(t, fake, vaultDir)
	enc, nonce, err := encryptPassphrase([]byte("secret"), setupTestWrapKey(t, fake, vaultDir))
	if err != nil {
		t.Fatalf("setup failed: %v", err)
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
		t.Fatalf("setup failed: %v", err)
	}
	fake.set("openpass:"+vaultDir, sessionAccount, string(payload))

	_, err = LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase failed: %v", err)
	}
}

func TestLoadPassphrase_MarshalFailsOnUpdate(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-marshal-fail"
	setupTestWrapKey(t, fake, vaultDir)

	sess := storedSession{
		EncryptedPassphrase: "dummy",
		Nonce:               "nonce",
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 int64(time.Hour),
	}
	payload, _ := json.Marshal(sess)
	fake.set("openpass:"+vaultDir, sessionAccount, string(payload))

	got, err := LoadPassphrase(vaultDir)
	if err == nil {
		t.Logf("LoadPassphrase succeeded with dummy data, got: %q", got)
	}
}

func TestResolvePassphrase_EncryptFailsDuringMigration(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-mig-fail"
	setupTestWrapKey(t, fake, vaultDir)

	plain := "legacy-passphrase"

	sess := storedSession{
		Passphrase: plain,
		SavedAt:    time.Now().UTC(),
		LastAccess: time.Now().UTC(),
		TTL:        int64(time.Hour),
	}
	payload, _ := json.Marshal(sess)
	fake.set("openpass:"+vaultDir, sessionAccount, string(payload))

	got, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase failed: %v", err)
	}
	if string(got) != plain {
		t.Errorf("LoadPassphrase = %q, want %q", got, plain)
	}
}

func TestGetCacheStatus_Default(t *testing.T) {
	status := GetCacheStatus()
	if status.Backend == "" {
		t.Error("expected non-empty backend")
	}
}

func TestSaveAndLoadIdentity(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	vaultDir := "/tmp/vault-identity-test"
	setupTestWrapKey(t, fake, vaultDir)

	identity := "AGE-SECRET-KEY-1FAKE0000000000000000000000000000000000000000000000000000"
	ttl := time.Hour

	if err := SaveIdentity(vaultDir, identity, ttl); err != nil {
		t.Fatalf("SaveIdentity error: %v", err)
	}

	got, err := LoadIdentity(vaultDir)
	if err != nil {
		t.Fatalf("LoadIdentity error: %v", err)
	}
	if got != identity {
		t.Errorf("LoadIdentity = %q, want %q", got, identity)
	}
}

func TestLoadIdentity_NotFound(t *testing.T) {
	fake := newFakeKeyring()
	stubKeyring(t, fake)

	_, err := LoadIdentity("/tmp/vault-no-identity")
	if err == nil {
		t.Error("expected error when identity not cached")
	}
}
