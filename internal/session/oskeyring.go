//go:build darwin || linux || windows || netbsd || openbsd || ((freebsd || dragonfly) && cgo)

package session

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/danieljustus/symaira-vault/internal/logging"
)

// keyringTimeout bounds how long osKeyring waits for the underlying OS
// keyring call. On macOS, the "security" CLI invoked by zalando/go-keyring
// can block indefinitely waiting for a native GUI dialog (e.g. "keychain
// not found for wrap-key") when no keychain is available or no user is
// present to dismiss it — exactly the hang reported in #682 for parallel
// agents and headless/stdio runs. A var (not const) so tests can shorten it.
var keyringTimeout = 5 * time.Second

// rawKeyringGet/Set/Delete are the underlying zalando/go-keyring calls,
// exposed as function variables so tests can simulate a hanging OS keyring
// without depending on real keychain behavior.
var (
	rawKeyringGet    = keyring.Get
	rawKeyringSet    = keyring.Set
	rawKeyringDelete = keyring.Delete
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
	val, err := getWithTimeout(service, account)
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
	return setWithTimeout(service, account, value)
}

func (o *osKeyring) Delete(key string) error {
	service, account := splitKey(key)
	if err := deleteWithTimeout(service, account); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return ErrKeyringNotFound
		}
		return err
	}
	return nil
}

// getWithTimeout, setWithTimeout and deleteWithTimeout run the raw keyring
// call on a goroutine and bound the wait with keyringTimeout. A timeout
// returns ErrKeyringUnavailable — distinct from ErrKeyringNotFound — so
// callers (fallbackKeyring) can tell "no entry" from "keychain locked or
// non-interactive" and fall back to in-memory storage instead of hanging.
func getWithTimeout(service, account string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), keyringTimeout)
	defer cancel()

	type result struct {
		val string
		err error
	}
	done := make(chan result, 1)
	go func() {
		val, err := rawKeyringGet(service, account)
		done <- result{val: val, err: err}
	}()

	select {
	case <-ctx.Done():
		return "", ErrKeyringUnavailable
	case r := <-done:
		return r.val, r.err
	}
}

func setWithTimeout(service, account, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), keyringTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- rawKeyringSet(service, account, value)
	}()

	select {
	case <-ctx.Done():
		return ErrKeyringUnavailable
	case err := <-done:
		return err
	}
}

func deleteWithTimeout(service, account string) error {
	ctx, cancel := context.WithTimeout(context.Background(), keyringTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- rawKeyringDelete(service, account)
	}()

	select {
	case <-ctx.Done():
		return ErrKeyringUnavailable
	case err := <-done:
		return err
	}
}

// isTestOrCI reports whether the process is a `go test` binary or running
// under CI/headless automation. Mirrors internal/audit's isTestOrCI (kept
// separate per-package to avoid a cross-package dependency for a handful of
// lines): both packages independently must never let a test process reach
// the real OS keychain, which is what produced the repeated "keychain not
// found for wrap-key" dialog in #682 when many test binaries/agents ran in
// parallel against the developer's real login keychain.
func isTestOrCI() bool {
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" || os.Getenv("HEADLESS") != "" {
		return true
	}
	for _, arg := range os.Args {
		if len(arg) >= 6 && arg[:6] == "-test." {
			return true
		}
	}
	if len(os.Args) > 0 {
		base := os.Args[0]
		for i := len(base) - 1; i >= 0; i-- {
			if base[i] == '/' || base[i] == '\\' {
				base = base[i+1:]
				break
			}
		}
		if (len(base) >= 5 && base[len(base)-5:] == ".test") ||
			(len(base) >= 9 && base[len(base)-9:] == ".test.exe") ||
			base == "test" { //nolint:goconst // test-binary sentinel, mirrors internal/audit's isTestOrCI
			return true
		}
	}
	return false
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
	if isTestOrCI() {
		// Never dial the real OS keychain from a test binary or CI run: the
		// fallback starts active so every call is served from memory. This
		// is the direct fix for #682 — parallel test binaries/agents no
		// longer contend for the developer's real login keychain.
		inner.active = true
	}
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
	logging.Default().Debug("Session cache configured with OS keyring primary and in-memory fallback.")
	return inner
}
