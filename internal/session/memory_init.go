//go:build !(darwin || linux || windows || netbsd || openbsd || ((freebsd || dragonfly) && cgo))

package session

import (
	"fmt"
	"os"

	"github.com/danieljustus/symaira-vault/internal/logging"
)

var memoryFallbackActive bool

func init() {
	DefaultBackend = &memoryKeyring{}
	memoryFallbackActive = true
	fmt.Fprintln(os.Stderr, "Warning: OS keyring unavailable — session will clear when this process exits. Run 'symvault doctor' for help.")
	cacheStatusProvider = func() CacheStatus {
		return CacheStatus{
			Backend:    CacheBackendMemory,
			Persistent: false,
			Message:    "This build uses a memory-only session cache.",
		}
	}
	logging.Default().Warn("Using memory-only session cache (session will clear on process exit).")
}
