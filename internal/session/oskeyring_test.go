//go:build darwin || linux || windows || netbsd || openbsd || ((freebsd || dragonfly) && cgo)

package session

import (
	"errors"
	"testing"
)

type mockKeyringBackend struct {
	getErr    error
	setErr    error
	deleteErr error
	store     map[string]string
}

func newMockKeyringBackend() *mockKeyringBackend {
	return &mockKeyringBackend{store: make(map[string]string)}
}

func (m *mockKeyringBackend) Set(service, account, value string) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.store[service+"|"+account] = value
	return nil
}

func (m *mockKeyringBackend) Get(service, account string) (string, error) {
	if m.getErr != nil {
		return "", m.getErr
	}
	val, ok := m.store[service+"|"+account]
	if !ok {
		return "", errors.New("not found")
	}
	return val, nil
}

func (m *mockKeyringBackend) Delete(service, account string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.store, service+"|"+account)
	return nil
}

func TestFallbackBackend_PrimaryWorks(t *testing.T) {
	primary := newMockKeyringBackend()
	fallback := newMockKeyringBackend()
	fb := NewFallbackBackend(primary, fallback)

	if err := fb.Set("serv", "acc", "val"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	if fb.isFallbackActive() {
		t.Error("expected fallback NOT to be active")
	}

	got, err := fb.Get("serv", "acc")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != "val" {
		t.Errorf("got %q, want %q", got, "val")
	}

	// Verify only primary was modified
	if primary.store["serv|acc"] != "val" {
		t.Error("expected value in primary store")
	}
	if len(fallback.store) != 0 {
		t.Error("expected fallback store to be empty")
	}

	if err := fb.Delete("serv", "acc"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, ok := primary.store["serv|acc"]; ok {
		t.Error("expected deleted key in primary")
	}
}

func TestFallbackBackend_FallbackTriggered(t *testing.T) {
	primary := newMockKeyringBackend()
	fallback := newMockKeyringBackend()
	fb := NewFallbackBackend(primary, fallback)

	// Make primary fail on set
	primary.setErr = errors.New("primary set failed")

	if err := fb.Set("serv", "acc", "val"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	if !fb.isFallbackActive() {
		t.Error("expected fallback to be active")
	}

	// Primary should not have the value, fallback should
	if len(primary.store) != 0 {
		t.Error("expected primary store to be empty")
	}
	if fallback.store["serv|acc"] != "val" {
		t.Error("expected value in fallback store")
	}

	// Subsequent Get/Delete should go straight to fallback
	got, err := fb.Get("serv", "acc")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != "val" {
		t.Errorf("got %q, want %q", got, "val")
	}

	if err := fb.Delete("serv", "acc"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, ok := fallback.store["serv|acc"]; ok {
		t.Error("expected deleted key in fallback")
	}
}

func TestFallbackBackend_GetTriggersFallback(t *testing.T) {
	primary := newMockKeyringBackend()
	fallback := newMockKeyringBackend()
	fb := NewFallbackBackend(primary, fallback)

	// Make primary fail on get
	primary.getErr = errors.New("primary get failed")
	fallback.store["serv|acc"] = "val"

	got, err := fb.Get("serv", "acc")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != "val" {
		t.Errorf("got %q, want %q", got, "val")
	}

	if !fb.isFallbackActive() {
		t.Error("expected fallback to be active")
	}
}

func TestFallbackBackend_DeleteTriggersFallback(t *testing.T) {
	primary := newMockKeyringBackend()
	fallback := newMockKeyringBackend()
	fb := NewFallbackBackend(primary, fallback)

	// Make primary fail on delete
	primary.deleteErr = errors.New("primary delete failed")
	fallback.store["serv|acc"] = "val"

	if err := fb.Delete("serv", "acc"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if !fb.isFallbackActive() {
		t.Error("expected fallback to be active")
	}
}
