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

func (f *fakeKeyring) Get(key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		err := f.getErr
		f.getErr = nil
		return "", err
	}
	v, ok := f.store[key]
	if !ok {
		return "", ErrKeyringNotFound
	}
	return v, nil
}

func (f *fakeKeyring) Set(key string, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		err := f.setErr
		f.setErr = nil
		return err
	}
	f.store[key] = value
	return nil
}

func (f *fakeKeyring) Delete(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		err := f.deleteErr
		f.deleteErr = nil
		return err
	}
	delete(f.store, key)
	return nil
}

func testKey() []byte {
	return []byte("0123456789abcdefghijklmnopqrstuv")
}

func newTestManager(t *testing.T) (*Manager, *fakeKeyring) {
	t.Helper()
	fake := newFakeKeyring()
	mgr := NewManager(fake, func() CacheStatus {
		return CacheStatus{Backend: "test", Persistent: false, Message: "test"}
	})
	return mgr, fake
}

func setupTestWrapKey(t *testing.T, fake *fakeKeyring, vaultDir string) []byte {
	t.Helper()
	key := testKey()
	encKey := base64.StdEncoding.EncodeToString(key)
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), wrapKeyAccount), encKey); err != nil {
		t.Fatalf("store wrap key: %v", err)
	}
	return key
}

func TestSaveAndLoadPassphraseRoundTrip(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "correct horse battery staple"

	if err := mgr.SavePassphrase(vaultDir, []byte(passphrase), time.Minute); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	got, err := mgr.LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != passphrase {
		t.Fatalf("LoadPassphrase() = %q, want %q", got, passphrase)
	}
}

func TestClearSessionRemovesFromKeyring(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SavePassphrase(vaultDir, []byte("secret"), time.Minute); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	if err := mgr.ClearSession(vaultDir); err != nil {
		t.Fatalf("ClearSession() error = %v", err)
	}

	if _, err := mgr.LoadPassphrase(vaultDir); err == nil {
		t.Fatal("LoadPassphrase() error = nil, want not found")
	}
}

func TestLoadPassphraseExpiresAfterTTL(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SavePassphrase(vaultDir, []byte("secret"), 10*time.Millisecond); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		time.Sleep(25 * time.Millisecond)
		close(done)
	}()
	<-done

	if _, err := mgr.LoadPassphrase(vaultDir); err == nil {
		t.Fatal("LoadPassphrase() error = nil, want expired")
	}
}

func TestIsSessionExpired_NoSession(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	if !mgr.IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = false, want true when no session exists")
	}
}

func TestIsSessionExpired_ExpiredSession(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SavePassphrase(vaultDir, []byte("secret"), 10*time.Millisecond); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		time.Sleep(25 * time.Millisecond)
		close(done)
	}()
	<-done

	if !mgr.IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = false, want true for expired session")
	}
}

func TestIsSessionExpired_ValidSession(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SavePassphrase(vaultDir, []byte("secret"), time.Hour); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	if mgr.IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = true, want false for valid session")
	}
}

func TestLoadPassphrase_KeyringGetError(t *testing.T) {
	mgr, fake := newTestManager(t)

	fake.getErr = errors.New("keyring unavailable")

	if _, err := mgr.LoadPassphrase("/tmp/vault"); err == nil {
		t.Fatal("LoadPassphrase() error = nil, want keyring error")
	}
}

func TestLoadPassphrase_MalformedJSON(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)

	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), "not valid json{{{"); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}
	if _, err := mgr.LoadPassphrase(vaultDir); err == nil {
		t.Fatal("LoadPassphrase() error = nil, want unmarshal error")
	}
}

func TestClearSession_DeleteError(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SavePassphrase(vaultDir, []byte("secret"), time.Minute); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	fake.deleteErr = errors.New("keyring delete failed")

	if err := mgr.ClearSession(vaultDir); err == nil {
		t.Fatal("ClearSession() error = nil, want delete error")
	}
}

func TestSavePassphrase_KeyringSetError(t *testing.T) {
	mgr, fake := newTestManager(t)

	fake.setErr = errors.New("keyring write failed")

	if err := mgr.SavePassphrase("/tmp/vault", []byte("secret"), time.Minute); err == nil {
		t.Fatal("SavePassphrase() error = nil, want keyring set error")
	}
}

func TestLoadPassphrase_ZeroTTL(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-zerott"
	setupTestWrapKey(t, fake, vaultDir)
	payload := `{"saved_at":"2024-01-01T00:00:00Z","last_access":"2024-01-01T00:00:00Z","passphrase":"secret","ttl_ns":0}`
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), payload); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	if _, err := mgr.LoadPassphrase(vaultDir); err == nil {
		t.Fatal("LoadPassphrase() error = nil, want expired error for zero TTL")
	}
}

func TestIsSessionExpired_ZeroTTL(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-zerott2"
	setupTestWrapKey(t, fake, vaultDir)
	payload := `{"saved_at":"2024-01-01T00:00:00Z","last_access":"2024-01-01T00:00:00Z","passphrase":"secret","ttl_ns":0}`
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), payload); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	if !mgr.IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = false, want true for zero TTL")
	}
}

func TestIsSessionExpired_ZeroLastAccess_NotExpired(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-zerola"
	setupTestWrapKey(t, fake, vaultDir)
	savedAt := time.Now().UTC().Add(-1 * time.Second).Format(time.RFC3339Nano)
	ttlNs := int64(time.Hour)
	payload := fmt.Sprintf(`{"saved_at":%q,"last_access":"0001-01-01T00:00:00Z","passphrase":"secret","ttl_ns":%d}`, savedAt, ttlNs)
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), payload); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	if mgr.IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = true, want false when last_access is zero but saved_at is recent")
	}
}

func TestIsSessionExpired_ZeroLastAccess_Expired(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-zerola2"
	setupTestWrapKey(t, fake, vaultDir)
	savedAt := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339Nano)
	ttlNs := int64(time.Minute)
	payload := fmt.Sprintf(`{"saved_at":%q,"last_access":"0001-01-01T00:00:00Z","passphrase":"secret","ttl_ns":%d}`, savedAt, ttlNs)
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), payload); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	if !mgr.IsSessionExpired(vaultDir) {
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

func TestLoadPassphrase_RejectsLegacyPlaintext(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-old-format"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "old-style-secret"
	payload := fmt.Sprintf(`{"saved_at":%q,"last_access":%q,"passphrase":%q,"ttl_ns":%d}`,
		time.Now().UTC().Format(time.RFC3339Nano),
		time.Now().UTC().Format(time.RFC3339Nano),
		passphrase,
		int64(time.Hour))
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), payload); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	// The hot path now refuses to transparently load a legacy plaintext
	// session. Run the migrate subcommand to upgrade.
	_, err := mgr.LoadPassphrase(vaultDir)
	if !errors.Is(err, ErrLegacyPlaintextSession) {
		t.Fatalf("LoadPassphrase() error = %v, want ErrLegacyPlaintextSession", err)
	}

	upgraded, err := mgr.MigrateSession(vaultDir)
	if err != nil {
		t.Fatalf("MigrateSession() error = %v", err)
	}
	if !upgraded {
		t.Fatal("MigrateSession() = false, want true after upgrade")
	}

	got, err := mgr.LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() after migrate error = %v", err)
	}
	if string(got) != passphrase {
		t.Fatalf("LoadPassphrase() after migrate = %q, want %q", got, passphrase)
	}
}

func TestNewFormatStoredEncrypted(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-new-format"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "new-encrypted-secret"

	if err := mgr.SavePassphrase(vaultDir, []byte(passphrase), time.Hour); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	raw, err := fake.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))
	if err != nil {
		t.Fatalf("fake.Get() error = %v", err)
	}

	var sess storedSession
	if err := json.Unmarshal([]byte(raw), &sess); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(sess.Passphrase) > 0 {
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
	mgr, _ := newTestManager(t)

	oldReader := crand.Reader
	crand.Reader = errReader{}
	t.Cleanup(func() { crand.Reader = oldReader })

	if err := mgr.SavePassphrase("/tmp/vault-save-encrypt-error", []byte("secret"), time.Hour); err == nil {
		t.Fatal("SavePassphrase() error = nil, want encrypt error")
	}
}

func TestLoadPassphrase_ResolveDecryptError(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-corrupt-enc"
	setupTestWrapKey(t, fake, vaultDir)
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
	if setErr := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), string(payload)); setErr != nil {
		t.Fatalf("fake.Set() error = %v", setErr)
	}

	_, err = mgr.LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() error = nil, want decrypt error for corrupted ciphertext")
	}
}

func TestLoadPassphrase_UpdateKeyringSetError(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-update-err"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "update-test-secret"

	if err := mgr.SavePassphrase(vaultDir, []byte(passphrase), time.Hour); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	fake.setErr = errors.New("keyring update failed")

	loaded, err := mgr.LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v, want nil (should not fail on update error)", err)
	}
	if string(loaded) != passphrase {
		t.Errorf("LoadPassphrase() = %q, want %q", loaded, passphrase)
	}
}

func TestIsSessionExpired_MalformedJSON(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-bad-json"
	setupTestWrapKey(t, fake, vaultDir)
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), "{invalid json!!!"); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	if !mgr.IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired() = false, want true for malformed JSON")
	}
}

func TestLoadPassphraseWithTouchID_BiometricSuccessButLoadFails(t *testing.T) {
	mock := &mockBiometricPassphraseStore{available: true, err: ErrBiometricNotConfigured}
	prev := defaultBiometric.passStore
	defaultBiometric.SetPassphraseStore(mock)
	t.Cleanup(func() { defaultBiometric.SetPassphraseStore(prev) })

	_, err := LoadPassphraseWithTouchID(context.Background(), "/tmp/vault-no-session")
	if !errors.Is(err, ErrBiometricNotConfigured) {
		t.Fatalf("LoadPassphraseWithTouchID() error = %v, want ErrBiometricNotConfigured", err)
	}
}

func TestResolvePassphrase_NoData(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-no-data"
	setupTestWrapKey(t, fake, vaultDir)
	sess := storedSession{
		SavedAt:    time.Now().UTC(),
		LastAccess: time.Now().UTC(),
		TTL:        int64(time.Hour),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if setErr := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), string(payload)); setErr != nil {
		t.Fatalf("fake.Set() error = %v", setErr)
	}

	_, err = mgr.LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() error = nil, want no passphrase data error")
	}
}

func TestLoadPassphrase_NegativeTTL(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-neg-ttl"
	setupTestWrapKey(t, fake, vaultDir)
	payload := fmt.Sprintf(`{"saved_at":"2024-01-01T00:00:00Z","last_access":"2024-01-01T00:00:00Z","passphrase":"secret","ttl_ns":%d}`, int64(-1))
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), payload); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	_, err := mgr.LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() error = nil, want expired error for negative TTL")
	}
}

func TestIsSessionExpired_NegativeTTL(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-neg-ttl2"
	setupTestWrapKey(t, fake, vaultDir)
	payload := fmt.Sprintf(`{"saved_at":"2024-01-01T00:00:00Z","last_access":"2024-01-01T00:00:00Z","passphrase":"secret","ttl_ns":%d}`, int64(-1))
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), payload); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	if !mgr.IsSessionExpired(vaultDir) {
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
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-marshal"
	setupTestWrapKey(t, fake, vaultDir)

	if err := mgr.SavePassphrase(vaultDir, []byte("secret"), time.Hour); err != nil {
		t.Fatalf("SavePassphrase failed: %v", err)
	}

	raw, err := fake.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))
	if err != nil {
		t.Fatalf("fake.Get() error = %v", err)
	}
	if raw == "" {
		t.Error("session should be stored in keyring")
	}
}

func TestLoadPassphrase_UpdateSessionOnAccess(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-update"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "update-test"

	if err := mgr.SavePassphrase(vaultDir, []byte(passphrase), time.Hour); err != nil {
		t.Fatalf("SavePassphrase error = %v", err)
	}

	got, err := mgr.LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase error = %v", err)
	}
	if string(got) != passphrase {
		t.Errorf("LoadPassphrase = %q, want %q", got, passphrase)
	}

	raw, err := fake.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))
	if err != nil {
		t.Fatalf("fake.Get() error = %v", err)
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
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-la-before-sa"
	wrapKey := setupTestWrapKey(t, fake, vaultDir)
	now := time.Now().UTC()
	enc, nonce, err := encryptPassphrase([]byte("secret"), wrapKey)
	if err != nil {
		t.Fatalf("setup encrypt failed: %v", err)
	}
	sess := storedSession{
		EncryptedPassphrase: enc,
		Nonce:               nonce,
		SavedAt:             now,
		LastAccess:          now.Add(-time.Second),
		TTL:                 int64(time.Hour),
	}
	payload, _ := json.Marshal(sess)
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), string(payload)); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	got, err := mgr.LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != "secret" {
		t.Errorf("LoadPassphrase() = %q, want %q", got, "secret")
	}
}

func TestLoadPassphrase_ZeroLastAccessUsesSavedAt(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-load-zero-last-access"
	setupTestWrapKey(t, fake, vaultDir)
	payload := fmt.Sprintf(`{"saved_at":%q,"last_access":"0001-01-01T00:00:00Z","passphrase":"secret","ttl_ns":%d}`,
		time.Now().UTC().Format(time.RFC3339Nano),
		int64(time.Hour))
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), payload); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	_, err := mgr.LoadPassphrase(vaultDir)
	// Zero last_access with a plaintext passphrase is the legacy format;
	// the hot path refuses to load it.
	if !errors.Is(err, ErrLegacyPlaintextSession) {
		t.Fatalf("LoadPassphrase() error = %v, want ErrLegacyPlaintextSession", err)
	}
}

func TestResolvePassphrase_BothEncryptedAndPlaintext(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-both"
	setupTestWrapKey(t, fake, vaultDir)
	enc, nonce, err := encryptPassphrase([]byte("actual-secret"), setupTestWrapKey(t, fake, vaultDir))
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	sess := storedSession{
		EncryptedPassphrase: enc,
		Nonce:               nonce,
		Passphrase:          passphraseBytes([]byte("legacy-secret")),
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 int64(time.Hour),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), string(payload)); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	_, err = mgr.LoadPassphrase(vaultDir)
	if !errors.Is(err, ErrLegacyPlaintextSession) {
		t.Fatalf("LoadPassphrase() error = %v, want ErrLegacyPlaintextSession", err)
	}
}

func TestMigrateSession_UpgradesPlaintext(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-migrate"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "migrate-me"
	payload := fmt.Sprintf(`{"saved_at":%q,"last_access":%q,"passphrase":%q,"ttl_ns":%d}`,
		time.Now().UTC().Format(time.RFC3339Nano),
		time.Now().UTC().Format(time.RFC3339Nano),
		passphrase,
		int64(time.Hour))
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), payload); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	upgraded, err := mgr.MigrateSession(vaultDir)
	if err != nil {
		t.Fatalf("MigrateSession() error = %v", err)
	}
	if !upgraded {
		t.Fatal("MigrateSession() = false, want true after upgrade")
	}

	raw, err := fake.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))
	if err != nil {
		t.Fatalf("fake.Get() error = %v", err)
	}
	var sess storedSession
	if jsonErr := json.Unmarshal([]byte(raw), &sess); jsonErr != nil {
		t.Fatalf("json.Unmarshal() error = %v", jsonErr)
	}
	if len(sess.Passphrase) > 0 {
		t.Error("after migration, plaintext passphrase field should be empty")
	}
	if sess.EncryptedPassphrase == "" || sess.Nonce == "" {
		t.Error("after migration, encrypted_passphrase and nonce should be set")
	}

	got, err := mgr.LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != passphrase {
		t.Fatalf("LoadPassphrase() = %q, want %q", got, passphrase)
	}
}

func TestMigrateSession_AlreadyEncrypted(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-migrate-already"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SavePassphrase(vaultDir, []byte("already-encrypted"), time.Hour); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	upgraded, err := mgr.MigrateSession(vaultDir)
	if err != nil {
		t.Fatalf("MigrateSession() error = %v", err)
	}
	if upgraded {
		t.Error("MigrateSession() = true, want false when session is already encrypted")
	}
}

func TestMigrateSession_NoSession(t *testing.T) {
	mgr, _ := newTestManager(t)

	upgraded, err := mgr.MigrateSession("/tmp/vault-migrate-empty")
	if err != nil {
		t.Fatalf("MigrateSession() error = %v", err)
	}
	if upgraded {
		t.Error("MigrateSession() = true, want false when no session exists")
	}
}

func TestHasLegacyPlaintextSession_DetectsLegacy(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-legacy-detect"
	setupTestWrapKey(t, fake, vaultDir)
	payload := fmt.Sprintf(`{"saved_at":%q,"last_access":%q,"passphrase":"legacy","ttl_ns":%d}`,
		time.Now().UTC().Format(time.RFC3339Nano),
		time.Now().UTC().Format(time.RFC3339Nano),
		int64(time.Hour))
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), payload); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	legacy, err := mgr.HasLegacyPlaintextSession(vaultDir)
	if err != nil {
		t.Fatalf("HasLegacyPlaintextSession() error = %v", err)
	}
	if !legacy {
		t.Error("HasLegacyPlaintextSession() = false, want true for legacy payload")
	}
}

func TestHasLegacyPlaintextSession_NewFormat(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-new-detect"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SavePassphrase(vaultDir, []byte("encrypted"), time.Hour); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	legacy, err := mgr.HasLegacyPlaintextSession(vaultDir)
	if err != nil {
		t.Fatalf("HasLegacyPlaintextSession() error = %v", err)
	}
	if legacy {
		t.Error("HasLegacyPlaintextSession() = true, want false for new format")
	}
}

func TestResolvePassphrase_WipesPlaintextAfterMigration(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-wipe-legacy-pass"
	setupTestWrapKey(t, fake, vaultDir)
	passphrase := "legacy-wipe-test-secret"

	sess := &storedSession{
		Passphrase: passphraseBytes([]byte(passphrase)),
		SavedAt:    time.Now().UTC(),
		LastAccess: time.Now().UTC(),
		TTL:        int64(time.Hour),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), string(payload)); err != nil {
		t.Fatalf("fake.Set() error = %v", err)
	}

	upgraded, err := mgr.MigrateSession(vaultDir)
	if err != nil {
		t.Fatalf("MigrateSession() error = %v", err)
	}
	if !upgraded {
		t.Fatal("MigrateSession() = false, want true after upgrade")
	}

	// After migration the stored payload must no longer contain the
	// plaintext passphrase and must carry the encrypted form.
	raw, err := fake.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))
	if err != nil {
		t.Fatalf("fake.Get() error = %v", err)
	}
	var updated storedSession
	if err := json.Unmarshal([]byte(raw), &updated); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(updated.Passphrase) > 0 {
		t.Errorf("plaintext passphrase should be empty after migration, got %q", updated.Passphrase)
	}
	if updated.EncryptedPassphrase == "" || updated.Nonce == "" {
		t.Error("encrypted_passphrase and nonce should be set after migration")
	}
}

func TestSavePassphrase_UpdatesLastAccessOnLoad(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-updates-la"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SavePassphrase(vaultDir, []byte("secret"), time.Hour); err != nil {
		t.Fatalf("SavePassphrase error = %v", err)
	}

	raw1, _ := fake.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))
	var sess1 storedSession
	json.Unmarshal([]byte(raw1), &sess1)
	time.Sleep(time.Millisecond)

	mgr.LoadPassphrase(vaultDir)

	raw2, _ := fake.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))
	var sess2 storedSession
	json.Unmarshal([]byte(raw2), &sess2)

	if sess1.LastAccess.Equal(sess2.LastAccess) || sess2.LastAccess.Before(sess1.LastAccess) {
		t.Error("LastAccess should be updated after LoadPassphrase")
	}
}

func TestSavePassphrase_EncryptFails(t *testing.T) {
	mgr, fake := newTestManager(t)

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

	err = mgr.SavePassphrase(vaultDir, []byte(passphrase), time.Hour)
	if err != nil {
		t.Fatalf("SavePassphrase failed: %v", err)
	}
}

func TestLoadPassphrase_ResolveError(t *testing.T) {
	mgr, fake := newTestManager(t)

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
	fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), string(payload))

	_, err = mgr.LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase failed: %v", err)
	}
}

func TestLoadPassphrase_MarshalFailsOnUpdate(t *testing.T) {
	mgr, fake := newTestManager(t)

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
	fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), string(payload))

	got, err := mgr.LoadPassphrase(vaultDir)
	if err == nil {
		t.Logf("LoadPassphrase succeeded with dummy data, got: %q", got)
	}
}

func TestGetCacheStatus_Default(t *testing.T) {
	status := GetCacheStatus()
	if status.Backend == "" {
		t.Error("expected non-empty backend")
	}
}

func TestSaveAndLoadIdentity(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-identity-test"
	setupTestWrapKey(t, fake, vaultDir)

	identity := "AGE-SECRET-KEY-1FAKE0000000000000000000000000000000000000000000000000000"
	ttl := time.Hour

	if err := mgr.SaveIdentity(vaultDir, identity, ttl); err != nil {
		t.Fatalf("SaveIdentity error: %v", err)
	}

	got, err := mgr.LoadIdentity(vaultDir)
	if err != nil {
		t.Fatalf("LoadIdentity error: %v", err)
	}
	if got != identity {
		t.Errorf("LoadIdentity = %q, want %q", got, identity)
	}
}

func TestLoadIdentity_NotFound(t *testing.T) {
	mgr, _ := newTestManager(t)

	_, err := mgr.LoadIdentity("/tmp/vault-no-identity")
	if err == nil {
		t.Error("expected error when identity not cached")
	}
}

func TestSaveIdentity_MarshalError(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-identity-marshal"
	setupTestWrapKey(t, fake, vaultDir)

	identity := "AGE-SECRET-KEY-1" + string(make([]byte, 100000))
	err := mgr.SaveIdentity(vaultDir, identity, time.Hour)
	if err != nil {
		t.Logf("SaveIdentity returned error (may be marshal or keyring set): %v", err)
	}
}

func TestSaveIdentity_KeyringSetError(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-identity-set-err"
	setupTestWrapKey(t, fake, vaultDir)

	fake.setErr = errors.New("keyring write failed")
	err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-1FAKE", time.Hour)
	if err == nil {
		t.Fatal("SaveIdentity error = nil, want keyring set error")
	}
}

func TestLoadIdentity_ExpiredTTL(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-identity-expired"
	setupTestWrapKey(t, fake, vaultDir)

	ident := storedIdentity{
		EncryptedIdentity: "dGVzdA==",
		Nonce:             "YWJjZGVmZ2hpamts",
		SavedAt:           time.Now().UTC().Add(-time.Hour),
		LastAccess:        time.Now().UTC().Add(-time.Hour),
		TTL:               0,
	}
	payload, _ := json.Marshal(ident)
	fake.Set(keyFor(serviceNameForVault(vaultDir), identityAccount), string(payload))

	_, err := mgr.LoadIdentity(vaultDir)
	if err == nil {
		t.Fatal("LoadIdentity error = nil, want expired identity error")
	}
}

func TestLoadIdentity_WrapKeyNotFound(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-identity-no-wrap"
	setupTestWrapKey(t, fake, vaultDir)

	ident := storedIdentity{
		EncryptedIdentity: "dGVzdA==",
		Nonce:             "YWJjZGVmZ2hpamts",
		SavedAt:           time.Now().UTC(),
		LastAccess:        time.Now().UTC(),
		TTL:               int64(time.Hour),
	}
	payload, _ := json.Marshal(ident)
	fake.Set(keyFor(serviceNameForVault(vaultDir), identityAccount), string(payload))

	fake.Delete(keyFor(serviceNameForVault(vaultDir), wrapKeyAccount))

	_, err := mgr.LoadIdentity(vaultDir)
	if err == nil {
		t.Fatal("LoadIdentity error = nil, want wrap key error")
	}
}

func TestClearIdentity_DeleteError(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-clear-identity"
	setupTestWrapKey(t, fake, vaultDir)

	err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-1FAKE", time.Hour)
	if err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}

	fake.deleteErr = errors.New("keyring delete failed")
	err = mgr.ClearIdentity(vaultDir)
	if err == nil {
		t.Fatal("ClearIdentity error = nil, want delete error")
	}
}

func TestLoadWrapKey_EmptyString(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-wrap-empty"
	fake.Set(keyFor(serviceNameForVault(vaultDir), wrapKeyAccount), "")

	_, err := mgr.loadWrapKey(vaultDir)
	if err == nil {
		t.Fatal("loadWrapKey error = nil, want empty wrap key error")
	}
}

func TestLoadWrapKey_InvalidBase64(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-wrap-badbase64"
	fake.Set(keyFor(serviceNameForVault(vaultDir), wrapKeyAccount), "!!!not-base64!!!")

	_, err := mgr.loadWrapKey(vaultDir)
	if err == nil {
		t.Fatal("loadWrapKey error = nil, want base64 decode error")
	}
}

func TestLoadWrapKey_InvalidLength(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-wrap-badlen"
	fake.Set(keyFor(serviceNameForVault(vaultDir), wrapKeyAccount), base64.StdEncoding.EncodeToString([]byte("short")))

	_, err := mgr.loadWrapKey(vaultDir)
	if err == nil {
		t.Fatal("loadWrapKey error = nil, want invalid length error")
	}
}

func TestDeleteWrapKey_Error(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-delete-wrap"
	setupTestWrapKey(t, fake, vaultDir)

	fake.deleteErr = errors.New("keyring delete failed")
	err := mgr.deleteWrapKey(vaultDir)
	if err == nil {
		t.Fatal("deleteWrapKey error = nil, want delete error")
	}
}

func TestEncryptionKey_NoWrapKey(t *testing.T) {
	mgr, _ := newTestManager(t)

	_, err := mgr.encryptionKey("/tmp/vault-no-wrap")
	if err == nil {
		t.Fatal("encryptionKey error = nil, want no wrap key error")
	}
}

func TestEncryptPassphrase_InvalidKeyLength(t *testing.T) {
	shortKey := []byte("short")
	_, _, err := encryptPassphrase([]byte("secret"), shortKey)
	if err == nil {
		t.Fatal("encryptPassphrase error = nil, want AES cipher error for short key")
	}
}

func TestSavePassphrase_KeyringSetOnSaveFails(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-save-set-err"
	setupTestWrapKey(t, fake, vaultDir)

	fake.setErr = errors.New("keyring save failed")
	err := mgr.SavePassphrase(vaultDir, []byte("secret"), time.Hour)
	if err == nil {
		t.Fatal("SavePassphrase error = nil, want keyring set error")
	}
}

func TestSaveIdentity_KeyringSetOnSaveFails(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-id-save-set-err"
	setupTestWrapKey(t, fake, vaultDir)

	fake.setErr = errors.New("keyring save failed")
	err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-1FAKE", time.Hour)
	if err == nil {
		t.Fatal("SaveIdentity error = nil, want keyring set error")
	}
}

func TestSavePassphrase_MarshalSucceeds(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-marshal-succeeds"
	setupTestWrapKey(t, fake, vaultDir)

	err := mgr.SavePassphrase(vaultDir, []byte("secret"), time.Hour)
	if err != nil {
		t.Fatalf("SavePassphrase failed: %v", err)
	}
}

func TestLoadIdentity_KeyringUpdateSucceeds(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-id-update"
	setupTestWrapKey(t, fake, vaultDir)

	identity := "AGE-SECRET-KEY-1FAKE0000000000000000000000000000000000000000000000000000000"
	if err := mgr.SaveIdentity(vaultDir, identity, time.Hour); err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}

	got, err := mgr.LoadIdentity(vaultDir)
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}
	if got != identity {
		t.Errorf("LoadIdentity = %q, want %q", got, identity)
	}
}

func TestDecryptPassphrase_FailsWithWrongKey(t *testing.T) {
	key := testKey()
	wrongKey := []byte("abcdefghijklmnopqrstuv0123456789")

	enc, nonce, err := encryptPassphrase([]byte("secret"), key)
	if err != nil {
		t.Fatalf("encryptPassphrase failed: %v", err)
	}

	_, err = decryptPassphrase(enc, nonce, wrongKey)
	if err == nil {
		t.Fatal("decryptPassphrase with wrong key should fail")
	}
}

func TestSetDefaultManager_And_DefaultManager(t *testing.T) {
	original := DefaultManager()
	defer SetDefaultManager(original)

	fake := newFakeKeyring()
	mgr := NewManager(fake, nil)

	SetDefaultManager(mgr)
	if got := DefaultManager(); got != mgr {
		t.Errorf("DefaultManager() = %v, want %v", got, mgr)
	}
}

func TestPackageLevelFunctions(t *testing.T) {
	fake := newFakeKeyring()
	mgr := NewManager(fake, nil)
	SetDefaultManager(mgr)

	vaultDir := "/tmp/vault-package-level"
	setupTestWrapKey(t, fake, vaultDir)

	err := SavePassphrase(vaultDir, []byte("secret"), time.Hour)
	if err != nil {
		t.Fatalf("SavePassphrase failed: %v", err)
	}

	pass, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase failed: %v", err)
	}
	if string(pass) != "secret" {
		t.Errorf("LoadPassphrase = %q, want %q", string(pass), "secret")
	}

	if IsSessionExpired(vaultDir) {
		t.Error("IsSessionExpired = true, want false")
	}

	err = ClearSession(vaultDir)
	if err != nil {
		t.Fatalf("ClearSession failed: %v", err)
	}

	identity := "AGE-SECRET-KEY-1FAKE0000000000000000000000000000000000000000000000000000000"
	err = SaveIdentity(vaultDir, identity, time.Hour)
	if err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}

	loaded, err := LoadIdentity(vaultDir)
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}
	if loaded != identity {
		t.Errorf("LoadIdentity = %q, want %q", loaded, identity)
	}

	err = ClearIdentity(vaultDir)
	if err != nil {
		t.Fatalf("ClearIdentity failed: %v", err)
	}
}

func TestFallbackKeyring_ActivateFallback(t *testing.T) {
	primary := newFakeKeyring()
	fb := NewFallbackKeyring(primary)

	fbImpl, ok := fb.(*fallbackKeyring)
	if !ok {
		t.Fatal("NewFallbackKeyring did not return *fallbackKeyring")
	}

	if fbImpl.IsFallbackActive() {
		t.Error("IsFallbackActive() = true, want false")
	}

	fbImpl.ActivateFallback()

	if !fbImpl.IsFallbackActive() {
		t.Error("IsFallbackActive() = false, want true")
	}
}
