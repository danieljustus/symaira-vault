// Package session contains the keyring storage abstraction used by the
// vault session layer. The KeyringBackend interface replaces the legacy
// package-level function variables (keyringSet / keyringGet / keyringDelete)
// so production code and tests depend on an explicit value rather than
// shared global state. Concrete implementations live alongside this file
// (oskeyring.go, memory_keyring.go, touchid_*.go).
//
// The interface intentionally matches the surface the previous function
// variables exposed, with a single composite key (typically "service|account")
// so call sites and tests can construct keys without having to model the
// service/account split.
package session

import (
	"errors"
	"sync"

	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
)

// ErrKeyringNotFound is returned by Get when the backend has no value for the
// given key. Backends translate their platform-specific not-found sentinel
// (e.g. keyring.ErrNotFound, C errSecItemNotFound) to this so callers can
// match a single error type.
var ErrKeyringNotFound = errors.New("session: keyring entry not found")

// ErrKeyringUnavailable is returned when the OS keyring backend did not
// respond within its timeout — typically because the keychain is locked or
// unavailable and would otherwise block on an interactive OS prompt (the
// native "keychain not found" dialog reported in #682). Distinct from
// ErrKeyringNotFound: the entry may still exist, but the backend could not
// be reached non-interactively.
var ErrKeyringUnavailable = errors.New("session: OS keyring unavailable (locked or non-interactive)")

// KeyringBackend is the dependency-injected storage layer for session and
// identity entries. Implementations must be safe for concurrent use.
type KeyringBackend interface {
	// Get returns the value previously stored under key, or
	// ErrKeyringNotFound if no such entry exists.
	Get(key string) (string, error)
	// Set stores value under key, replacing any existing value.
	Set(key string, value string) error
	// Delete removes the entry under key. A missing entry must not be an
	// error: implementations should return nil when the key does not exist
	// to preserve the previous "delete is idempotent" semantics.
	Delete(key string) error
}

// keyFor combines a service name and account into the single composite key
// that KeyringBackend implementations receive. Keeping the composition here
// (rather than at every call site) preserves the historical storage layout
// for existing backends (memory, OS keyring) that already key entries by
// "service|account".
func keyFor(service, account string) string {
	return service + "|" + account
}

// fallbackKeyring wraps an inner primary KeyringBackend with an in-memory
// fallback. It mirrors the cascading behavior the previous setWithFallback /
// getWithFallback / deleteWithFallback helpers implemented via package-level
// function variables:
//
//   - When the fallback has been activated, all operations are served from
//     memory so the session survives even after the primary backend starts
//     failing mid-process.
//   - When the fallback is not yet active, the primary backend is consulted
//     first; a failure on Set, Get (other than NotFound) or Delete flips the
//     fallback on and re-routes the call to the in-memory store.
//
// This is the only place that knows about the fallback contract; every other
// component in the session package interacts with a plain KeyringBackend.
type fallbackKeyring struct {
	primary  KeyringBackend
	fallback *memoryKeyring

	mu     sync.Mutex
	active bool
	warned bool
}

// NewFallbackKeyring returns a KeyringBackend that prefers primary but falls
// back to an in-memory store when the primary backend fails. The fallback
// remains active for the rest of the process lifetime once tripped.
func NewFallbackKeyring(primary KeyringBackend) KeyringBackend {
	return &fallbackKeyring{primary: primary, fallback: &memoryKeyring{}}
}

// ActivateFallback forces the fallback to the in-memory store. Used by tests
// that want to assert the fallback code path without driving the primary
// backend into a real failure.
func (f *fallbackKeyring) ActivateFallback() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = true
}

// IsFallbackActive reports whether the fallback is currently being used.
func (f *fallbackKeyring) IsFallbackActive() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active
}

// Set implements KeyringBackend.
func (f *fallbackKeyring) Set(key string, value string) error {
	f.mu.Lock()
	active := f.active
	f.mu.Unlock()
	if active {
		return f.fallbackAdapter().Set(key, value)
	}
	if err := f.primary.Set(key, value); err != nil {
		f.activateLocked()
		return f.fallbackAdapter().Set(key, value)
	}
	return nil
}

// Get implements KeyringBackend.
func (f *fallbackKeyring) Get(key string) (string, error) {
	f.mu.Lock()
	active := f.active
	f.mu.Unlock()
	if active {
		return f.fallbackAdapter().Get(key)
	}
	val, err := f.primary.Get(key)
	if err != nil {
		if errors.Is(err, ErrKeyringNotFound) {
			return "", err
		}
		f.activateLocked()
		return f.fallbackAdapter().Get(key)
	}
	return val, nil
}

// Delete implements KeyringBackend.
func (f *fallbackKeyring) Delete(key string) error {
	f.mu.Lock()
	active := f.active
	f.mu.Unlock()
	if active {
		return f.fallbackAdapter().Delete(key)
	}
	if err := f.primary.Delete(key); err != nil {
		// Treat not-found as success to preserve the "idempotent delete"
		// behavior the original deleteWithFallback implemented.
		if errors.Is(err, ErrKeyringNotFound) {
			return nil
		}
		f.activateLocked()
		return f.fallbackAdapter().Delete(key)
	}
	return nil
}

// fallbackAdapter returns the KeyringBackend view of the in-memory
// fallback store. It is recreated once the fallback has been activated
// so subsequent calls go through the public Get/Set/Delete that
// translate not-found errors to ErrKeyringNotFound.
func (f *fallbackKeyring) fallbackAdapter() KeyringBackend {
	return &memoryKeyringBackend{inner: f.fallback}
}

func (f *fallbackKeyring) activateLocked() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.active {
		f.active = true
		if !f.warned {
			f.warned = true
			cliout.Warnf("OS keyring unavailable — session cache falling back to in-memory storage. Sessions will not persist across restarts. For headless or non-interactive agents, set SYMVAULT_ALLOW_ENV_PASSPHRASE=1 and SYMVAULT_PASSPHRASE to unlock without the OS keychain. Run 'symvault doctor' for help.")
		}
	}
}
