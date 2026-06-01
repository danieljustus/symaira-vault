//go:build darwin && cgo

package session

import (
	"context"
	"reflect"
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

func TestBiometricServiceNamesIncludeOpenPassFallbacks(t *testing.T) {
	vaultDir := "/Users/alice/.symvault"
	got := biometricServiceNames(vaultDir)
	want := []string{
		"symvault-biometric:/Users/alice/.symvault",
		"openpass-biometric:/Users/alice/.symvault",
		"symvault-biometric:/Users/alice/.openpass",
		"openpass-biometric:/Users/alice/.openpass",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("biometricServiceNames(%q) = %#v, want %#v", vaultDir, got, want)
	}
}

func TestBiometricServiceNamesKeepsCustomPathScoped(t *testing.T) {
	vaultDir := "/Volumes/Safe/vault"
	got := biometricServiceNames(vaultDir)
	want := []string{
		"symvault-biometric:/Volumes/Safe/vault",
		"openpass-biometric:/Volumes/Safe/vault",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("biometricServiceNames(%q) = %#v, want %#v", vaultDir, got, want)
	}
}

func TestBiometricDeleteServiceNamesDoNotCrossVaultPaths(t *testing.T) {
	vaultDir := "/Users/alice/.symvault"
	got := biometricDeleteServiceNames(vaultDir)
	want := []string{
		"symvault-biometric:/Users/alice/.symvault",
		"openpass-biometric:/Users/alice/.symvault",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("biometricDeleteServiceNames(%q) = %#v, want %#v", vaultDir, got, want)
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
