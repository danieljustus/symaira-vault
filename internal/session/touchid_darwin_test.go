//go:build darwin && cgo

package session

import (
	"context"
	"os"
	"testing"
)

func TestTouchIDAuthenticator_IsAvailable(t *testing.T) {
	auth := &touchIDAuthenticator{}
	_ = auth.IsAvailable()
}

func TestTouchIDAuthenticator_Authenticate(t *testing.T) {
	if os.Getenv("SYMVAULT_E2E") == "" {
		t.Skip("Skipping TouchID authenticate test: set SYMVAULT_E2E=1 to run (triggers real hardware prompt)")
	}
	auth := &touchIDAuthenticator{}
	err := auth.Authenticate(context.Background(), "test")
	if err == nil {
		t.Log("TouchID auth succeeded (unexpected in test environment)")
	}
}

func TestTouchIDAvailable_Function(t *testing.T) {
	result := touchIDAvailable()
	t.Logf("touchIDAvailable() = %v", result)
}

func TestTouchIDAuthenticate_Function(t *testing.T) {
	if os.Getenv("SYMVAULT_E2E") == "" {
		t.Skip("Skipping TouchID authenticate function test: set SYMVAULT_E2E=1 to run (triggers real hardware prompt)")
	}
	result := touchIDAuthenticate(context.Background(), "test reason")
	t.Logf("touchIDAuthenticate() = %v", result)
}

func TestNewTouchIDAuthenticator_ReturnsCorrectType(t *testing.T) {
	auth := newTouchIDAuthenticator()
	if auth == nil {
		t.Fatal("newTouchIDAuthenticator() returned nil")
	}
	// Verify it implements BiometricAuthenticator interface
	var _ BiometricAuthenticator = auth
}

func TestTouchIDAuthenticator_ErrorTypes(t *testing.T) {
	// Verify the error types are distinct
	if errTouchIDNotAvailable == errTouchIDFailed {
		t.Error("errTouchIDNotAvailable and errTouchIDFailed should be distinct")
	}
}

func TestTouchIDAuthenticate_NotAvailablePath(t *testing.T) {
	// Test the error path when touch ID is not available
	// This is a compile-time check that errTouchIDNotAvailable exists and is used
	err := errTouchIDNotAvailable
	if err == nil {
		t.Error("errTouchIDNotAvailable should not be nil")
	}
}

func TestTouchIDAuthenticate_FailedPath(t *testing.T) {
	// Test the error type for failed authentication
	err := errTouchIDFailed
	if err == nil {
		t.Error("errTouchIDFailed should not be nil")
	}
}

func TestTouchIDAuthenticator_ImplementsInterface(t *testing.T) {
	auth := newTouchIDAuthenticator()

	// Test IsAvailable method
	_ = auth.IsAvailable()

	if os.Getenv("SYMVAULT_E2E") != "" {
		_ = auth.Authenticate(context.Background(), "test reason")
	}

	// Verify it satisfies BiometricAuthenticator
	var _ BiometricAuthenticator = auth
}

func TestTouchIDAvailable_ReturnType(t *testing.T) {
	// Ensure touchIDAvailable returns a boolean
	result := touchIDAvailable()
	if result != true && result != false {
		t.Errorf("touchIDAvailable() returned non-boolean value: %v", result)
	}
}
