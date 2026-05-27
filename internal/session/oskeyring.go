//go:build darwin || linux || windows || netbsd || openbsd || ((freebsd || dragonfly) && cgo)

package session

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/zalando/go-keyring"

	"github.com/danieljustus/symaira-vault/internal/logging"
)

var (
	fallbackActive bool
	fallbackMu     sync.RWMutex
	fallback       *memoryKeyring
)

func getFallback() *memoryKeyring {
	fallbackMu.Lock()
	defer fallbackMu.Unlock()

	if fallback == nil {
		fallback = &memoryKeyring{}
		fmt.Fprintln(os.Stderr, "Warning: OS keyring unavailable \u2014 session will clear when this process exits. Run 'symvault doctor' for help.")
		logging.Default().Warn("OS keyring unavailable. Using memory-only session cache (session will clear on process exit).")
	}
	fallbackActive = true
	return fallback
}

func isFallbackActive() bool {
	fallbackMu.RLock()
	defer fallbackMu.RUnlock()
	return fallbackActive
}

func setWithFallback(service, account, value string) error {
	if isFallbackActive() {
		return getFallback().Set(service, account, value)
	}

	if err := keyring.Set(service, account, value); err != nil {
		return getFallback().Set(service, account, value)
	}
	return nil
}

func getWithFallback(service, account string) (string, error) {
	if isFallbackActive() {
		return getFallback().Get(service, account)
	}

	val, err := keyring.Get(service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", err
		}
		return getFallback().Get(service, account)
	}
	return val, nil
}

func deleteWithFallback(service, account string) error {
	if isFallbackActive() {
		return getFallback().Delete(service, account)
	}

	if err := keyring.Delete(service, account); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil
		}
		return getFallback().Delete(service, account)
	}
	return nil
}

func init() {
	keyringSet = setWithFallback
	keyringGet = getWithFallback
	keyringDelete = deleteWithFallback
	cacheStatusProvider = func() CacheStatus {
		if isFallbackActive() {
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
