package diff

import "testing"

func TestLimitedBufferBoundsCapturedOutput(t *testing.T) {
	buffer := newLimitedBuffer()
	value := make([]byte, maxCapturedStreamBytes+1)
	written, err := buffer.Write(value)
	if err != nil {
		t.Fatal(err)
	}
	if written != len(value) {
		t.Fatalf("writer reported %d bytes, want %d", written, len(value))
	}
	if !buffer.Truncated() {
		t.Fatal("expected truncation marker")
	}
	if len(buffer.Bytes()) != maxCapturedStreamBytes {
		t.Fatalf("captured %d bytes, want %d", len(buffer.Bytes()), maxCapturedStreamBytes)
	}
}
