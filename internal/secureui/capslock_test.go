package secureui

import (
	"strings"
	"testing"
)

func TestCapsLockWarning_On(t *testing.T) {
	old := capsLockDetector
	defer func() { capsLockDetector = old }()
	capsLockDetector = func() bool { return true }

	w := CapsLockWarning()
	if !strings.Contains(w, "Caps Lock") {
		t.Errorf("expected warning to mention 'Caps Lock', got %q", w)
	}
}

func TestCapsLockWarning_Off(t *testing.T) {
	old := capsLockDetector
	defer func() { capsLockDetector = old }()
	capsLockDetector = func() bool { return false }

	if w := CapsLockWarning(); w != "" {
		t.Errorf("expected empty warning when caps lock is off, got %q", w)
	}
}
