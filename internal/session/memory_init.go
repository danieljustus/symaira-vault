//go:build !(darwin || linux || windows || netbsd || openbsd || ((freebsd || dragonfly) && cgo))

package session

import (
	"github.com/danieljustus/symaira-vault/internal/logging"
)

var memoryFallbackActive bool

func init() {
	mk := &memoryKeyring{}
	keyringSet = mk.Set
	keyringGet = mk.Get
	keyringDelete = mk.Delete
	memoryFallbackActive = true
	cacheStatusProvider = func() CacheStatus {
		return CacheStatus{
			Backend:    CacheBackendMemory,
			Persistent: false,
			Message:    "This build uses a memory-only session cache.",
		}
	}
	logging.Default().Warn("Using memory-only session cache (session will clear on process exit).")
}
