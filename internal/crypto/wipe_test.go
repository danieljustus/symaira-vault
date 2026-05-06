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
	before := wipeSink
	Wipe(buf)
	after := wipeSink
	if before == after {
		t.Error("wipeSink was not updated; compiler may have optimized away Wipe()")
	}
	// Verify the pointer points to the buffer's backing array.
	if uintptr(unsafe.Pointer(&buf[0])) != after {
		t.Error("wipeSink does not point to buffer backing array")
	}
}
