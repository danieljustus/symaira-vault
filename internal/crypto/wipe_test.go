package crypto

import (
	"testing"
	"unsafe"
)

func TestWipeZeroesBytes(t *testing.T) {
	buf := []byte("sensitive data")
	Wipe(buf)
	for i, b := range buf {
		if b != 0 {
			t.Errorf("byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestWipeDoesNotPanicOnEmptySlice(t *testing.T) {
	var empty []byte
	Wipe(empty) // should not panic
}

func TestWipeUsesUnsafePointer(t *testing.T) {
	// Verify that wipeSink is updated after Wipe() call.
	// This test ensures the compiler cannot optimize away the zeroing.
	buf := []byte("test data")
	before := wipeSink.Load()
	Wipe(buf)
	after := wipeSink.Load()
	if before == after {
		t.Error("wipeSink was not updated; compiler may have optimized away Wipe()")
	}
	// Verify the pointer points to the buffer's backing array.
	if uintptr(unsafe.Pointer(&buf[0])) != after {
		t.Error("wipeSink does not point to buffer backing array")
	}
}

// TestWipeSurvivesAliasing guards against a refactor that accidentally copies
// the buffer via string conversion before wiping. The caller must hand the
// SAME backing slice that's still referenced; if the surrounding code does
// `data["password"] = string(password)` before Wipe, the copy in `data`
// survives, but the original `password` slice must still be zeroed.
func TestWipeSurvivesAliasing(t *testing.T) {
	original := []byte("hunter2-very-long-secret-12345")
	originalBackup := append([]byte(nil), original...)

	// Simulate the cmd/input.go pattern: string copy made elsewhere, then Wipe.
	leaked := string(original)
	Wipe(original)

	for i, b := range original {
		if b != 0 {
			t.Errorf("byte %d not zeroed after Wipe: got %d", i, b)
		}
	}
	// The string copy intentionally retains the value; this is the
	// documented limitation and we record it here so future readers know
	// the trade-off: callers must avoid string() conversions when possible.
	if leaked != string(originalBackup) {
		t.Errorf("string copy diverged unexpectedly: %q vs %q", leaked, originalBackup)
	}
}

// TestWipeMultipleSecrets stress-tests the wipe path with many concurrent
// allocations to catch any compiler optimization that batches zeros away.
func TestWipeMultipleSecrets(t *testing.T) {
	secrets := make([][]byte, 100)
	for i := range secrets {
		s := append([]byte(nil), []byte("secret-passphrase-no-")...)
		s = append(s, byte(i))
		secrets[i] = s
	}
	for _, s := range secrets {
		Wipe(s)
	}
	for i, s := range secrets {
		for j, b := range s {
			if b != 0 {
				t.Errorf("secret %d byte %d not zeroed: got %d", i, j, b)
			}
		}
	}
}
