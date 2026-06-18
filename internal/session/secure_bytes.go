package session

import (
	"crypto/subtle"
	"runtime"
)

// SecureBytes wraps a byte slice to provide explicit memory zeroing.
// The Destroy method zeroes the backing array before allowing GC to
// reclaim it, preventing sensitive data from lingering in process memory.
//
// Usage:
//
//	sb := NewSecureBytes(data)
//	// ... use sb.Data() ...
//	sb.Destroy() // zeros the backing array
type SecureBytes struct {
	data []byte
}

// NewSecureBytes creates a SecureBytes wrapping the given slice.
// The caller must not modify data after passing it to NewSecureBytes.
func NewSecureBytes(data []byte) *SecureBytes {
	return &SecureBytes{data: data}
}

// Data returns the underlying byte slice.
// Callers must not retain or modify the returned slice after Destroy is called.
func (s *SecureBytes) Data() []byte {
	if s == nil {
		return nil
	}
	return s.data
}

// Destroy zeroes the backing array and releases the reference.
// After Destroy, Data() returns nil.
// Uses runtime.KeepAlive to prevent the compiler from optimizing away
// the zeroing before the reference goes out of scope.
func (s *SecureBytes) Destroy() {
	if s == nil || s.data == nil {
		return
	}
	zeroBytes(s.data)
	// Prevent the compiler from optimizing away the zeroing by keeping
	// the reference alive through the zeroing operation.
	runtime.KeepAlive(s.data)
	s.data = nil
}

// DestroyWith copies src into the destination and zeroes src, using
// constant-time comparison to avoid timing side-channels when the
// data contains authentication material.
func DestroyWith(dst, src *SecureBytes) {
	if src == nil || src.data == nil {
		return
	}
	if dst != nil && dst.data != nil && len(dst.data) == len(src.data) {
		// Constant-time copy to avoid timing side-channels.
		subtle.ConstantTimeCopy(1, dst.data, src.data)
	}
	src.Destroy()
}

// WipeSlice zeroes a byte slice in place. This is a standalone function
// for callers that don't need the SecureBytes wrapper.
func WipeSlice(b []byte) {
	zeroBytes(b)
	runtime.KeepAlive(b)
}
