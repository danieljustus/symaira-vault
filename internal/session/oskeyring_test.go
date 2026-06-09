//go:build darwin || linux || windows || netbsd || openbsd || ((freebsd || dragonfly) && cgo)

package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestFallback_KeyringOperations(t *testing.T) {
	primary := &flakyKeyring{fail: true}
	fb := NewFallbackKeyring(primary)
	if _, err := fb.Get("any"); err == nil {
		t.Fatal("expected primary failure to surface")
	}
	if !fb.(*fallbackKeyring).IsFallbackActive() {
		t.Error("expected fallback to be active after primary failure")
	}

	vaultDir := "symvault:/tmp/vault-fallback"
	passphrase := []byte("fallback-secret")

	if err := fb.Set(keyFor(vaultDir, sessionAccount), string(mustMarshalSession(t, passphrase, time.Hour))); err != nil {
		t.Fatalf("fallback Set() error = %v", err)
	}

	raw, err := fb.Get(keyFor(vaultDir, sessionAccount))
	if err != nil {
		t.Fatalf("fallback Get() error = %v", err)
	}
	if raw == "" {
		t.Fatal("fallback Get() returned empty")
	}

	if err := fb.Delete(keyFor(vaultDir, sessionAccount)); err != nil {
		t.Fatalf("fallback Delete() error = %v", err)
	}

	_, err = fb.Get(keyFor(vaultDir, sessionAccount))
	if !errors.Is(err, ErrKeyringNotFound) {
		t.Fatalf("fallback Get() after Delete error = %v, want ErrKeyringNotFound", err)
	}
}

func TestFallback_PrimaryThenFallback(t *testing.T) {
	primary := &flakyKeyring{failFirst: true}
	fb := NewFallbackKeyring(primary)

	_, _ = fb.Get(keyFor("svc", "acc"))
	if !fb.(*fallbackKeyring).IsFallbackActive() {
		t.Error("expected fallback to be active after first failure")
	}

	if err := fb.Set(keyFor("svc", wrapKeyAccount), base64.StdEncoding.EncodeToString(testKey())); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, err := fb.Get(keyFor("svc", wrapKeyAccount))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got == "" {
		t.Error("Get() returned empty after fallback Set")
	}
}

func TestFallback_Delete_NotFoundTreatsAsSuccess(t *testing.T) {
	primary := &flakyKeyring{}
	fb := NewFallbackKeyring(primary)

	if err := fb.Delete("missing"); err != nil {
		t.Fatalf("Delete() error = %v, want nil for missing key", err)
	}
}

func TestFallback_Get_NotFoundDistinct(t *testing.T) {
	primary := &flakyKeyring{notFound: true}
	fb := NewFallbackKeyring(primary)

	_, err := fb.Get("absent")
	if !errors.Is(err, ErrKeyringNotFound) {
		t.Fatalf("Get() error = %v, want ErrKeyringNotFound", err)
	}
	if fb.(*fallbackKeyring).IsFallbackActive() {
		t.Error("not-found should not activate the fallback")
	}
}

type flakyKeyring struct {
	fail      bool
	failFirst bool
	notFound  bool
	called    int
	inner     *memoryKeyring
}

func (f *flakyKeyring) Get(key string) (string, error) {
	f.called++
	if f.fail || (f.failFirst && f.called == 1) {
		return "", errors.New("keyring unavailable")
	}
	if f.notFound {
		return "", ErrKeyringNotFound
	}
	if f.inner == nil {
		f.inner = &memoryKeyring{}
	}
	service, account := splitKey(key)
	return f.inner.Get(service, account)
}

func (f *flakyKeyring) Set(key string, value string) error {
	f.called++
	if f.fail || (f.failFirst && f.called == 1) {
		return errors.New("keyring unavailable")
	}
	if f.inner == nil {
		f.inner = &memoryKeyring{}
	}
	service, account := splitKey(key)
	return f.inner.Set(service, account, value)
}

func (f *flakyKeyring) Delete(key string) error {
	f.called++
	if f.fail || (f.failFirst && f.called == 1) {
		return errors.New("keyring unavailable")
	}
	if f.inner == nil {
		f.inner = &memoryKeyring{}
	}
	service, account := splitKey(key)
	return f.inner.Delete(service, account)
}

func mustMarshalSession(t *testing.T, passphrase []byte, ttl time.Duration) []byte {
	t.Helper()
	enc, nonce, err := encryptPassphrase(passphrase, testKey())
	if err != nil {
		t.Fatalf("setup encrypt failed: %v", err)
	}
	sess := storedSession{
		EncryptedPassphrase: enc,
		Nonce:               nonce,
		SavedAt:             time.Now().UTC(),
		LastAccess:          time.Now().UTC(),
		TTL:                 int64(ttl),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("setup marshal failed: %v", err)
	}
	return payload
}
