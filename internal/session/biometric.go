package session

import (
	"context"
	"errors"
)

var ErrBiometricNotAvailable = errors.New("biometric authentication not available")
var ErrBiometricFailed = errors.New("biometric authentication failed")
var ErrBiometricNotConfigured = errors.New("biometric authentication is not configured")

// BiometricAuthenticator prompts the user for a biometric factor (Touch ID,
// Face ID, Windows Hello, ...). It is independent of passphrase storage so
// callers can authenticate before unlocking the keyring.
type BiometricAuthenticator interface {
	Authenticate(ctx context.Context, reason string) error
	IsAvailable() bool
}

// BiometricPassphraseStore persists a passphrase behind a biometric prompt.
// Unlike KeyringBackend it is biometric-gated: every read requires a
// successful user authentication.
type BiometricPassphraseStore interface {
	IsAvailable() bool
	Save(ctx context.Context, vaultDir string, passphrase []byte) error
	Load(ctx context.Context, vaultDir string) ([]byte, error)
	Delete(vaultDir string) error
}

// BiometricManager owns the configured authenticator and passphrase
// store. The default manager uses the no-op fallbacks until a platform
// implementation claims the slot via SetAuthenticator / SetPassphraseStore.
//
// Tests use SetAuthenticator / SetPassphraseStore to swap in a fake.
// Production code calls the convenience helpers below (BiometricAvailable,
// SaveBiometricPassphrase, LoadBiometricPassphrase, ClearBiometricPassphrase)
// which delegate to the default manager.
type BiometricManager struct {
	authenticator BiometricAuthenticator
	passStore     BiometricPassphraseStore
}

// NewBiometricManager returns a manager wired to the supplied
// authenticator and store. Either may be nil to use the no-op fallback.
func NewBiometricManager(authenticator BiometricAuthenticator, store BiometricPassphraseStore) *BiometricManager {
	return &BiometricManager{authenticator: authenticator, passStore: store}
}

// SetAuthenticator replaces the configured authenticator. Pass nil to
// restore the no-op fallback.
func (m *BiometricManager) SetAuthenticator(a BiometricAuthenticator) {
	m.authenticator = a
}

// SetPassphraseStore replaces the configured passphrase store. Pass nil
// to restore the no-op fallback.
func (m *BiometricManager) SetPassphraseStore(s BiometricPassphraseStore) {
	m.passStore = s
}

// Authenticator returns the currently configured authenticator, falling
// back to a no-op when none has been set.
func (m *BiometricManager) Authenticator() BiometricAuthenticator {
	if m.authenticator != nil {
		return m.authenticator
	}
	return noopBiometricAuthenticator{}
}

// PassphraseStore returns the currently configured passphrase store,
// falling back to a no-op when none has been set.
func (m *BiometricManager) PassphraseStore() BiometricPassphraseStore {
	if m.passStore != nil {
		return m.passStore
	}
	return noopBiometricPassphraseStore{}
}

var defaultBiometric = NewBiometricManager(nil, nil)

// SetBiometricAuthenticator configures the authenticator used by the
// package-level helpers. Pass nil to restore the no-op fallback.
func SetBiometricAuthenticator(a BiometricAuthenticator) {
	defaultBiometric.SetAuthenticator(a)
}

// SetBiometricPassphraseStore configures the passphrase store used by
// the package-level helpers. Pass nil to restore the no-op fallback.
func SetBiometricPassphraseStore(store BiometricPassphraseStore) {
	defaultBiometric.SetPassphraseStore(store)
}

// DefaultBiometricAuthenticator returns the manager's authenticator.
func DefaultBiometricAuthenticator() BiometricAuthenticator {
	return defaultBiometric.Authenticator()
}

// DefaultBiometricPassphraseStore returns the manager's passphrase store.
func DefaultBiometricPassphraseStore() BiometricPassphraseStore {
	return defaultBiometric.PassphraseStore()
}

// DefaultBiometricManager returns the process-wide BiometricManager.
func DefaultBiometricManager() *BiometricManager {
	return defaultBiometric
}

func BiometricAvailable() bool {
	return defaultBiometric.PassphraseStore().IsAvailable()
}

func SaveBiometricPassphrase(ctx context.Context, vaultDir string, passphrase []byte) error {
	return defaultBiometric.PassphraseStore().Save(ctx, vaultDir, passphrase)
}

func LoadBiometricPassphrase(ctx context.Context, vaultDir string) ([]byte, error) {
	return defaultBiometric.PassphraseStore().Load(ctx, vaultDir)
}

func ClearBiometricPassphrase(vaultDir string) error {
	return defaultBiometric.PassphraseStore().Delete(vaultDir)
}

type noopBiometricAuthenticator struct{}

func (noopBiometricAuthenticator) Authenticate(ctx context.Context, reason string) error {
	return ErrBiometricNotAvailable
}

func (noopBiometricAuthenticator) IsAvailable() bool {
	return false
}

type noopBiometricPassphraseStore struct{}

func (noopBiometricPassphraseStore) IsAvailable() bool {
	return false
}

func (noopBiometricPassphraseStore) Save(_ context.Context, _ string, _ []byte) error {
	return ErrBiometricNotAvailable
}

func (noopBiometricPassphraseStore) Load(ctx context.Context, vaultDir string) ([]byte, error) {
	_, _ = ctx, vaultDir
	return nil, ErrBiometricNotAvailable
}

func (noopBiometricPassphraseStore) Delete(vaultDir string) error {
	_ = vaultDir
	return nil
}
