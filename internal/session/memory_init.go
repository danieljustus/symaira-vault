//go:build !(darwin || linux || windows || netbsd || openbsd || ((freebsd || dragonfly) && cgo))

package session

import (
	"fmt"
	"os"

	"github.com/danieljustus/symaira-vault/internal/logging"
)

// newPlatformKeyring returns the appropriate KeyringBackend for the
// current build. On platforms without an OS keyring implementation this
// is a plain in-memory store. The warning the previous memory_init.go
// printed on first use is preserved.
func newPlatformKeyring() KeyringBackend {
	platformCacheStatus = func() CacheStatus {
		return CacheStatus{
			Backend:    CacheBackendMemory,
			Persistent: false,
			Message:    "This build uses a memory-only session cache.",
		}
	}
	fmt.Fprintln(os.Stderr, "Warning: OS keyring unavailable — session will clear when this process exits. Run 'symvault doctor' for help.")
	logging.Default().Warn("Using memory-only session cache (session will clear on process exit).")
	return &memoryKeyringBackend{inner: &memoryKeyring{}}
}
