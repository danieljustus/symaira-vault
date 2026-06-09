package session

import (
	"context"
	"errors"
	"testing"
)

type mockBiometricAuthenticator struct {
	authErr   error
	available bool
}

type mockBiometricPassphraseStore struct {
	available  bool
	passphrase []byte
	err        error
}

func (m *mockBiometricAuthenticator) Authenticate(ctx context.Context, reason string) error {
	return m.authErr
}

func (m *mockBiometricAuthenticator) IsAvailable() bool {
	return m.available
}

func (m *mockBiometricPassphraseStore) IsAvailable() bool {
	return m.available
}

func (m *mockBiometricPassphraseStore) Save(ctx context.Context, vaultDir string, passphrase []byte) error {
	_, _ = ctx, vaultDir
	if m.err != nil {
		return m.err
	}
	m.passphrase = passphrase
	return nil
}

func (m *mockBiometricPassphraseStore) Load(ctx context.Context, vaultDir string) ([]byte, error) {
	_, _ = ctx, vaultDir
	if m.err != nil {
		return nil, m.err
	}
	if !m.available {
		return nil, ErrBiometricNotAvailable
	}
	return m.passphrase, nil
}

func (m *mockBiometricPassphraseStore) Delete(vaultDir string) error {
	_ = vaultDir
	m.passphrase = nil
	return m.err
}

func TestDefaultBiometricAuthenticator_NoopOnNil(t *testing.T) {
	prev := defaultBiometric.authenticator
	defaultBiometric.SetAuthenticator(nil)
	t.Cleanup(func() { defaultBiometric.SetAuthenticator(prev) })

	auth := defaultBiometric.Authenticator()
	if auth.IsAvailable() {
		t.Error("expected noop authenticator to not be available")
	}
	err := auth.Authenticate(context.Background(), "test")
	if !errors.Is(err, ErrBiometricNotAvailable) {
		t.Errorf("expected ErrBiometricNotAvailable, got %v", err)
	}
}

func TestSetBiometricAuthenticator(t *testing.T) {
	mock := &mockBiometricAuthenticator{available: true, authErr: nil}
	prev := defaultBiometric.authenticator
	defaultBiometric.SetAuthenticator(mock)
	t.Cleanup(func() { defaultBiometric.SetAuthenticator(prev) })

	auth := defaultBiometric.Authenticator()
	if auth != mock {
		t.Error("expected SetAuthenticator to return the set authenticator")
	}
}

func TestLoadPassphraseWithTouchID_Available(t *testing.T) {
	mock := &mockBiometricPassphraseStore{available: true, passphrase: []byte("secret")}
	prev := defaultBiometric.passStore
	defaultBiometric.SetPassphraseStore(mock)
	t.Cleanup(func() { defaultBiometric.SetPassphraseStore(prev) })

	got, err := LoadPassphraseWithTouchID(context.Background(), "/nonexistent")
	if err != nil {
		t.Fatalf("LoadPassphraseWithTouchID() error = %v", err)
	}
	if string(got) != "secret" {
		t.Fatalf("LoadPassphraseWithTouchID() = %q, want secret", got)
	}
}

func TestLoadPassphraseWithTouchID_NotAvailable(t *testing.T) {
	mock := &mockBiometricPassphraseStore{available: false}
	prev := defaultBiometric.passStore
	defaultBiometric.SetPassphraseStore(mock)
	t.Cleanup(func() { defaultBiometric.SetPassphraseStore(prev) })

	_, err := LoadPassphraseWithTouchID(context.Background(), "/nonexistent")
	if !errors.Is(err, ErrBiometricNotAvailable) {
		t.Errorf("expected ErrBiometricNotAvailable when not available, got %v", err)
	}
}

func TestLoadPassphraseWithTouchID_AuthFails(t *testing.T) {
	mock := &mockBiometricPassphraseStore{available: true, err: ErrBiometricFailed}
	prev := defaultBiometric.passStore
	defaultBiometric.SetPassphraseStore(mock)
	t.Cleanup(func() { defaultBiometric.SetPassphraseStore(prev) })

	_, err := LoadPassphraseWithTouchID(context.Background(), "/nonexistent")
	if !errors.Is(err, ErrBiometricFailed) {
		t.Errorf("expected ErrBiometricFailed when auth fails, got %v", err)
	}
}

func TestNoopBiometricAuthenticator(t *testing.T) {
	noop := noopBiometricAuthenticator{}
	if noop.IsAvailable() {
		t.Error("noop should not be available")
	}
	err := noop.Authenticate(context.Background(), "test")
	if !errors.Is(err, ErrBiometricNotAvailable) {
		t.Errorf("expected ErrBiometricNotAvailable, got %v", err)
	}
}

func TestBiometricErrorTypes(t *testing.T) {
	if ErrBiometricNotAvailable == ErrBiometricFailed {
		t.Error("ErrBiometricNotAvailable and ErrBiometricFailed should be distinct")
	}
}

func TestSetBiometricAuthenticator_ReplacesPrevious(t *testing.T) {
	mock1 := &mockBiometricAuthenticator{available: true, authErr: nil}
	mock2 := &mockBiometricAuthenticator{available: false}
	prev := defaultBiometric.authenticator
	defaultBiometric.SetAuthenticator(mock1)
	defaultBiometric.SetAuthenticator(mock2)
	t.Cleanup(func() { defaultBiometric.SetAuthenticator(prev) })

	auth := defaultBiometric.Authenticator()
	if auth != mock2 {
		t.Error("SetAuthenticator should replace previous authenticator")
	}
}

func TestBiometricAvailable_DefaultFalse(t *testing.T) {
	prev := defaultBiometric.passStore
	defaultBiometric.SetPassphraseStore(nil)
	t.Cleanup(func() { defaultBiometric.SetPassphraseStore(prev) })

	if BiometricAvailable() {
		t.Error("BiometricAvailable should return false when no store is set")
	}
}

func TestSaveBiometricPassphrase(t *testing.T) {
	mock := &mockBiometricPassphraseStore{available: true}
	prev := defaultBiometric.passStore
	defaultBiometric.SetPassphraseStore(mock)
	t.Cleanup(func() { defaultBiometric.SetPassphraseStore(prev) })

	if err := SaveBiometricPassphrase(context.Background(), "/vault", []byte("pass")); err != nil {
		t.Errorf("SaveBiometricPassphrase error: %v", err)
	}
}

func TestClearBiometricPassphrase(t *testing.T) {
	mock := &mockBiometricPassphraseStore{available: true}
	prev := defaultBiometric.passStore
	defaultBiometric.SetPassphraseStore(mock)
	t.Cleanup(func() { defaultBiometric.SetPassphraseStore(prev) })

	if err := ClearBiometricPassphrase("/vault"); err != nil {
		t.Errorf("ClearBiometricPassphrase error: %v", err)
	}
}

func TestNoopBiometricPassphraseStore(t *testing.T) {
	noop := noopBiometricPassphraseStore{}

	if noop.IsAvailable() {
		t.Error("noop store should not be available")
	}
	if err := noop.Save(context.Background(), "/vault", []byte("x")); !errors.Is(err, ErrBiometricNotAvailable) {
		t.Errorf("noop Save expected ErrBiometricNotAvailable, got %v", err)
	}
	if _, err := noop.Load(context.Background(), "/vault"); !errors.Is(err, ErrBiometricNotAvailable) {
		t.Errorf("noop Load expected ErrBiometricNotAvailable, got %v", err)
	}
	if err := noop.Delete("/vault"); err != nil {
		t.Errorf("noop Delete expected nil, got %v", err)
	}
}
