package authguard

import (
	"context"
	"errors"
	"testing"

	"github.com/danieljustus/OpenPass/internal/session"
)

type mockBioAuth struct {
	available bool
	authErr   error
}

func (m *mockBioAuth) Authenticate(_ context.Context, _ string) error {
	return m.authErr
}

func (m *mockBioAuth) IsAvailable() bool {
	return m.available
}

func TestChallenger_Available(t *testing.T) {
	tests := []struct {
		name      string
		available bool
		want      bool
	}{
		{"available", true, true},
		{"unavailable", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Challenger{
				Authenticator: func() session.BiometricAuthenticator {
					return &mockBioAuth{available: tt.available}
				},
			}
			if got := c.Available(); got != tt.want {
				t.Errorf("Available() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChallenger_Available_NilChallenger(t *testing.T) {
	var c *Challenger
	if c.Available() {
		t.Error("nil Challenger should not be available")
	}
}

func TestChallenger_Challenge_Success(t *testing.T) {
	c := &Challenger{
		Authenticator: func() session.BiometricAuthenticator {
			return &mockBioAuth{available: true}
		},
	}
	if err := c.Challenge(context.Background(), OpTierUpgrade, "test reason"); err != nil {
		t.Errorf("Challenge() unexpected error: %v", err)
	}
}

func TestChallenger_Challenge_NotAvailable(t *testing.T) {
	c := &Challenger{
		Authenticator: func() session.BiometricAuthenticator {
			return &mockBioAuth{available: false}
		},
	}
	err := c.Challenge(context.Background(), OpTierUpgrade, "test reason")
	if err == nil {
		t.Fatal("Challenge() expected error when biometric not available")
	}
	if !errors.Is(err, session.ErrBiometricNotAvailable) {
		t.Errorf("Challenge() error should wrap ErrBiometricNotAvailable, got: %v", err)
	}
}

func TestChallenger_Challenge_AuthFails(t *testing.T) {
	c := &Challenger{
		Authenticator: func() session.BiometricAuthenticator {
			return &mockBioAuth{available: true, authErr: errors.New("user canceled")}
		},
	}
	err := c.Challenge(context.Background(), OpAuthMethodSet, "change auth method")
	if err == nil {
		t.Fatal("Challenge() expected error when auth fails")
	}
}

func TestChallenger_Challenge_NilChallenger(t *testing.T) {
	var c *Challenger
	err := c.Challenge(context.Background(), OpTierUpgrade, "reason")
	if err == nil {
		t.Fatal("nil Challenger Challenge() should return error")
	}
}

func TestChallenger_Challenge_NilAuthenticator(t *testing.T) {
	c := &Challenger{Authenticator: nil}
	err := c.Challenge(context.Background(), OpTierUpgrade, "reason")
	if err == nil {
		t.Fatal("nil Authenticator Challenge() should return error")
	}
}

func TestIsCriticalMCPTool(t *testing.T) {
	tests := []struct {
		toolName string
		want     bool
	}{
		{"set_auth_method", true},
		{"list_entries", false},
		{"get_entry", false},
		{"get_entry_value", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			if got := IsCriticalMCPTool(tt.toolName); got != tt.want {
				t.Errorf("IsCriticalMCPTool(%q) = %v, want %v", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestVerifyIdentity_Available(t *testing.T) {
	session.SetBiometricAuthenticator(&mockBioAuth{available: true})
	defer session.SetBiometricAuthenticator(nil)

	err := VerifyIdentity(context.Background(), OpTierUpgrade, "test")
	if err != nil {
		t.Errorf("VerifyIdentity() unexpected error: %v", err)
	}
}

func TestVerifyIdentity_NotAvailable(t *testing.T) {
	session.SetBiometricAuthenticator(&mockBioAuth{available: false})
	defer session.SetBiometricAuthenticator(nil)

	err := VerifyIdentity(context.Background(), OpTierUpgrade, "test")
	if err == nil {
		t.Fatal("VerifyIdentity() expected error when not available")
	}
}

func TestOperationType_String(t *testing.T) {
	tests := []struct {
		op   OperationType
		want string
	}{
		{OpTierUpgrade, "agent tier upgrade"},
		{OpAuthMethodSet, "auth method change"},
		{OperationType("unknown"), "unknown"},
	}
	for _, tt := range tests {
		t.Run(string(tt.op), func(t *testing.T) {
			if got := tt.op.String(); got != tt.want {
				t.Errorf("OperationType.String() = %q, want %q", got, tt.want)
			}
		})
	}
}
