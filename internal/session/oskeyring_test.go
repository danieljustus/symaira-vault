//go:build darwin || linux || windows || netbsd || openbsd || ((freebsd || dragonfly) && cgo)

package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
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

// TestNewPlatformKeyring_NeverTouchesRealKeyringUnderTest guards against the
// class of bug in #682: multiple test binaries / parallel agents hitting the
// real macOS Keychain and triggering a native "keychain not found for
// wrap-key" GUI dialog. Under `go test`, isTestOrCI() must be true and the
// platform keyring must start with its in-memory fallback already active, so
// no test ever reaches the real OS keychain.
func TestNewPlatformKeyring_NeverTouchesRealKeyringUnderTest(t *testing.T) {
	if !isTestOrCI() {
		t.Fatal("isTestOrCI() = false while running under go test")
	}

	kb := newPlatformKeyring()
	fb, ok := kb.(*fallbackKeyring)
	if !ok {
		t.Fatalf("newPlatformKeyring() returned %T, want *fallbackKeyring", kb)
	}
	if !fb.IsFallbackActive() {
		t.Fatal("expected in-memory fallback to be active under go test, so the real OS keychain is never touched")
	}

	for _, account := range []string{wrapKeyAccount, identityAccount} {
		key := keyFor("symvault:/tmp/vault-platform-test", account)
		want := "value-" + account
		if err := fb.Set(key, want); err != nil {
			t.Fatalf("Set(%s) error = %v", account, err)
		}
		got, err := fb.Get(key)
		if err != nil {
			t.Fatalf("Get(%s) error = %v", account, err)
		}
		if got != want {
			t.Fatalf("Get(%s) = %q, want %q", account, got, want)
		}
	}

	// sessionAccount stores a structured storedSession payload, not a plain
	// string — round-trip it through the same helper the rest of this file
	// uses for that account.
	sessionKey := keyFor("symvault:/tmp/vault-platform-test", sessionAccount)
	sessionPayload := string(mustMarshalSession(t, []byte("fallback-secret"), time.Hour))
	if err := fb.Set(sessionKey, sessionPayload); err != nil {
		t.Fatalf("Set(%s) error = %v", sessionAccount, err)
	}
	if _, err := fb.Get(sessionKey); err != nil {
		t.Fatalf("Get(%s) error = %v", sessionAccount, err)
	}
}

// TestOSKeyring_NotFound_WrapKeySessionIdentity is the regression test the
// #682 acceptance criteria asks for: errSecItemNotFound (translated by
// zalando/go-keyring as keyring.ErrNotFound) must surface as the stable
// ErrKeyringNotFound domain error for each of the three accounts symvault
// stores, never as a raw/opaque error and never by blocking.
func TestOSKeyring_NotFound_WrapKeySessionIdentity(t *testing.T) {
	origGet := rawKeyringGet
	defer func() { rawKeyringGet = origGet }()
	rawKeyringGet = func(service, account string) (string, error) {
		return "", keyring.ErrNotFound
	}

	o := &osKeyring{}
	for _, account := range []string{wrapKeyAccount, sessionAccount, identityAccount} {
		key := keyFor("symvault:/tmp/vault-notfound-test", account)
		if _, err := o.Get(key); !errors.Is(err, ErrKeyringNotFound) {
			t.Fatalf("Get(%s) error = %v, want ErrKeyringNotFound", account, err)
		}
	}
}

// TestOSKeyring_Set_TimesOutInsteadOfBlockingOnGUIDialog reproduces the
// blocking Set() call from #682: when the underlying OS keyring call hangs
// (e.g. waiting on a native "no keychain found" dialog with no TTY to
// dismiss it), osKeyring must return ErrKeyringUnavailable within
// keyringTimeout instead of hanging indefinitely.
func TestOSKeyring_Set_TimesOutInsteadOfBlockingOnGUIDialog(t *testing.T) {
	origSet := rawKeyringSet
	origTimeout := keyringTimeout
	keyringTimeout = 20 * time.Millisecond
	block := make(chan struct{})
	started := make(chan struct{})
	rawKeyringSet = func(service, account, value string) error {
		close(started) // signals the read of rawKeyringSet already happened
		<-block        // simulates a real keychain call blocked on a GUI prompt
		return nil
	}

	o := &osKeyring{}
	start := time.Now()
	err := o.Set(keyFor("symvault:/tmp/vault-timeout-test", wrapKeyAccount), "v")
	elapsed := time.Since(start)

	// setWithTimeout's goroutine outlives the timed-out call. Wait for it to
	// have actually started (and thus finished reading the package-level
	// rawKeyringSet var) before restoring it below — otherwise restoring
	// concurrently with that read is itself a data race.
	<-started
	close(block)
	rawKeyringSet = origSet
	keyringTimeout = origTimeout

	if !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("Set() error = %v, want ErrKeyringUnavailable", err)
	}
	if elapsed > time.Second {
		t.Fatalf("Set() took %v, want it to return promptly after keyringTimeout", elapsed)
	}
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
