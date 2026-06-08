package session

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/zalando/go-keyring"
	"github.com/danieljustus/symaira-vault/internal/logging"
)

type KeyringBackend interface {
	Set(service, account, value string) error
	Get(service, account string) (string, error)
	Delete(service, account string) error
}

type OSKeyringBackend struct{}

func (OSKeyringBackend) Set(service, account, value string) error {
	return keyring.Set(service, account, value)
}

func (OSKeyringBackend) Get(service, account string) (string, error) {
	return keyring.Get(service, account)
}

func (OSKeyringBackend) Delete(service, account string) error {
	err := keyring.Delete(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

type FallbackBackend struct {
	mu             sync.RWMutex
	primary        KeyringBackend
	fallback       KeyringBackend
	fallbackActive bool
}

func NewFallbackBackend(primary, fallback KeyringBackend) *FallbackBackend {
	return &FallbackBackend{
		primary:  primary,
		fallback: fallback,
	}
}

func (f *FallbackBackend) isFallbackActive() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.fallbackActive
}

func (f *FallbackBackend) setFallbackActive() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fallbackActive = true
}

func (f *FallbackBackend) Set(service, account, value string) error {
	if f.isFallbackActive() {
		return f.fallback.Set(service, account, value)
	}
	if err := f.primary.Set(service, account, value); err != nil {
		fmt.Fprintln(os.Stderr, "Warning: OS keyring unavailable — session will clear when this process exits. Run 'symvault doctor' for help.")
		logging.Default().Warn("OS keyring unavailable. Using memory-only session cache (session will clear on process exit).")
		f.setFallbackActive()
		return f.fallback.Set(service, account, value)
	}
	return nil
}

func (f *FallbackBackend) Get(service, account string) (string, error) {
	if f.isFallbackActive() {
		return f.fallback.Get(service, account)
	}
	val, err := f.primary.Get(service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", err
		}
		fmt.Fprintln(os.Stderr, "Warning: OS keyring unavailable — session will clear when this process exits. Run 'symvault doctor' for help.")
		logging.Default().Warn("OS keyring unavailable. Using memory-only session cache (session will clear on process exit).")
		f.setFallbackActive()
		return f.fallback.Get(service, account)
	}
	return val, nil
}

func (f *FallbackBackend) Delete(service, account string) error {
	if f.isFallbackActive() {
		return f.fallback.Delete(service, account)
	}
	if err := f.primary.Delete(service, account); err != nil {
		fmt.Fprintln(os.Stderr, "Warning: OS keyring unavailable — session will clear when this process exits. Run 'symvault doctor' for help.")
		logging.Default().Warn("OS keyring unavailable. Using memory-only session cache (session will clear on process exit).")
		f.setFallbackActive()
		return f.fallback.Delete(service, account)
	}
	return nil
}
