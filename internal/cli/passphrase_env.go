package cli

import (
	"sync"

	"github.com/danieljustus/symaira-vault/internal/envutil"
)

var (
	cachedEnvPassphrase     []byte
	cachedEnvPassphraseOnce sync.Once
)

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
			cachedEnvPassphrase = []byte(p)
		}
		envutil.Unsetenv("SYMVAULT_PASSPHRASE", "OPENPASS_PASSPHRASE")
	})
}

// ConsumeCachedEnvPassphrase returns the early-cached env passphrase
// and clears the process-local cache so the bytes are not retained.
func ConsumeCachedEnvPassphrase() []byte {
	p := cachedEnvPassphrase
	cachedEnvPassphrase = nil
	return p
}

// HasCachedEnvPassphrase reports whether an environment passphrase was
// cached by SniffAndClearEnvPassphrase. Does not consume the cache.
func HasCachedEnvPassphrase() bool {
	return len(cachedEnvPassphrase) > 0
}

// SetCachedEnvPassphrase sets the cached passphrase for testing purposes.
// This is used by tests that need to simulate an environment passphrase
// without going through SniffAndClearEnvPassphrase.
func SetCachedEnvPassphrase(p []byte) {
	cachedEnvPassphrase = p
}
