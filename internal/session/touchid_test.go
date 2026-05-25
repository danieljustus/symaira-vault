//go:build darwin

package session

import (
	"context"
	"testing"
	"time"
)

func TestBiometricServiceName(t *testing.T) {
	vaultDir := "/home/user/.symvault"
	got := biometricServiceName(vaultDir)
	want := "symvault-biometric:/home/user/.symvault"
	if got != want {
		t.Errorf("biometricServiceName(%q) = %q, want %q", vaultDir, got, want)
	}
}

func TestTouchIDAuthenticate_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := touchIDAuthenticate(ctx, "test")
	if err == nil {
		t.Fatal("touchIDAuthenticate with canceled context should return error")
	}
}

func TestTouchIDAuthenticate_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	err := touchIDAuthenticate(ctx, "test")
	if err == nil {
		t.Fatal("touchIDAuthenticate with expired timeout should return error")
	}
}
