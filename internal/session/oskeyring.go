//go:build darwin || linux || windows || netbsd || openbsd || ((freebsd || dragonfly) && cgo)

package session

import ()

func init() {
	primary := OSKeyringBackend{}
	fallback := &memoryKeyring{}
	DefaultBackend = NewFallbackBackend(primary, fallback)
	cacheStatusProvider = func() CacheStatus {
		if fb, ok := DefaultBackend.(*FallbackBackend); ok && fb.isFallbackActive() {
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
}
