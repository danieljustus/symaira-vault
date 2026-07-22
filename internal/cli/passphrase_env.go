package cli

import (
	"sync"

	"github.com/danieljustus/symaira-vault/internal/envutil"
)

var (
	cachedEnvPassphrase     []byte
	cachedEnvPassphraseOnce sync.Once
)

// zeroizeBytes overwrites a byte slice with zeros.
func zeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SniffAndClearEnvPassphrase reads SYMVAULT_PASSPHRASE (and the legacy
// OPENPASS_PASSPHRASE) from the environment, stores the value in a process-
// local buffer, and immediately unsets both variables so child processes
// cannot inherit the raw passphrase.
//
// Must be called before any child process is spawned, ideally in main().
func SniffAndClearEnvPassphrase() {
	cachedEnvPassphraseOnce.Do(func() {
		p := envutil.Getenv("SYMVAULT_PASSPHRASE", "OPENPASS_PASSPHRASE")
		if p != "" {
			if cachedEnvPassphrase != nil {
				zeroizeBytes(cachedEnvPassphrase)
			}
			cachedEnvPassphrase = []byte(p)
		}
		envutil.Unsetenv("SYMVAULT_PASSPHRASE", "OPENPASS_PASSPHRASE")
	})
}

// ConsumeCachedEnvPassphrase returns the early-cached env passphrase
// and clears the process-local reference. Ownership is transferred to
// the caller, which must zeroize the returned slice after use.
func ConsumeCachedEnvPassphrase() []byte {
	p := cachedEnvPassphrase
	cachedEnvPassphrase = nil
	return p
}

// ClearCachedEnvPassphrase zeroizes and clears the cached environment passphrase.
func ClearCachedEnvPassphrase() {
	if cachedEnvPassphrase != nil {
		zeroizeBytes(cachedEnvPassphrase)
		cachedEnvPassphrase = nil
	}
}

// HasCachedEnvPassphrase reports whether an environment passphrase was
// cached by SniffAndClearEnvPassphrase. Does not consume the cache.
func HasCachedEnvPassphrase() bool {
	return len(cachedEnvPassphrase) > 0
}

// SetCachedEnvPassphrase sets the cached passphrase for testing purposes.
// It zeroizes any previously cached bytes before replacement.
func SetCachedEnvPassphrase(p []byte) {
	if cachedEnvPassphrase != nil {
		zeroizeBytes(cachedEnvPassphrase)
	}
	cachedEnvPassphrase = p
}
