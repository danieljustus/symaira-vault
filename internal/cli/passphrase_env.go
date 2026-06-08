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

// consumeCachedEnvPassphrase returns the early-cached env passphrase
// and clears the process-local cache so the bytes are not retained.
func consumeCachedEnvPassphrase() []byte {
	p := cachedEnvPassphrase
	cachedEnvPassphrase = nil
	return p
}
