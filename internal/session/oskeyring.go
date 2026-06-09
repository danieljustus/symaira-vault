//go:build darwin || linux || windows || netbsd || openbsd || ((freebsd || dragonfly) && cgo)

package session

import (
	"errors"
	"fmt"
	"os"

	"github.com/zalando/go-keyring"

	"github.com/danieljustus/symaira-vault/internal/logging"
)

// osKeyring wraps zalando/go-keyring to conform to the KeyringBackend
// interface. It owns no state and is safe for concurrent use; the OS
// keyring is itself the source of truth.
type osKeyring struct{}

// NewOSKeyring returns a KeyringBackend that stores entries in the
// operating system keyring (macOS Keychain, GNOME Keyring / D-Bus Secret
// Service on Linux, Windows Credential Manager).
func NewOSKeyring() KeyringBackend {
	return &osKeyring{}
}

func (o *osKeyring) Get(key string) (string, error) {
	service, account := splitKey(key)
	val, err := keyring.Get(service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrKeyringNotFound
		}
		return "", err
	}
	return val, nil
}

func (o *osKeyring) Set(key string, value string) error {
	service, account := splitKey(key)
	return keyring.Set(service, account, value)
}

func (o *osKeyring) Delete(key string) error {
	service, account := splitKey(key)
	if err := keyring.Delete(service, account); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return ErrKeyringNotFound
		}
		return err
	}
	return nil
}

// newPlatformKeyring returns the appropriate KeyringBackend for the
// current build. On supported platforms this wires the OS keyring
// behind an in-memory fallback. The cascading fallback behavior matches
// the previous setWithFallback / getWithFallback / deleteWithFallback
// helpers: a keyring failure on the primary backend flips the fallback
// on and re-routes subsequent calls to the in-memory store for the rest
// of the process lifetime.
func newPlatformKeyring() KeyringBackend {
	inner := &fallbackKeyring{primary: NewOSKeyring(), fallback: &memoryKeyring{}}
	platformCacheStatus = func() CacheStatus {
		if inner.IsFallbackActive() {
			return CacheStatus{
				Backend:    CacheBackendMemory,
				Persistent: false,
				Message:    "OS keyring unavailable. Sessions are stored in process memory only.",
			}
		}
		return CacheStatus{
			Backend:    CacheBackendOSKeyring,
			Persistent: true,
			Message:    "OS keyring session cache is available.",
		}
	}
	fmt.Fprintln(os.Stderr, "Note: session cache uses OS keyring with in-memory fallback. Run 'symvault doctor' for help if you see fallback warnings.")
	logging.Default().Info("Session cache configured with OS keyring primary and in-memory fallback.")
	return inner
}
