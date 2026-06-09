package server

import (
	"context"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/audit"
	"github.com/danieljustus/symaira-vault/internal/authguard"
	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/session"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

//nolint:unparam // transport always "stdio" in current test suite
func newTestServerWithVault(t *testing.T, profile config.AgentProfile, transport string, vaultDir string) *Server {
	t.Helper()

	auditLog, err := audit.New("test", "", nil)
	if err != nil {
		t.Fatalf("audit.New() error = %v", err)
	}

	var identity *age.X25519Identity
	if vaultDir != "" {
		identity, err = age.GenerateX25519Identity()
		if err != nil {
			t.Fatalf("generate identity: %v", err)
		}
	}

	v := &vault.Vault{
		Dir:      vaultDir,
		Identity: identity,
	}

	return &Server{
		vault:         v,
		vaultService:  vault.NewVaultService(v, nil),
		agent:         &profile,
		auditLog:      auditLog,
		transport:     transport,
		hookRegistry:  NewHookRegistry(),
		biometricChallenger: &authguard.Challenger{
			Authenticator: func() session.BiometricAuthenticator {
				return &noopTestBiometricAuth{}
			},
		},
	}
}

type noopTestBiometricAuth struct{}

func (n *noopTestBiometricAuth) Authenticate(_ context.Context, _ string) error { return nil }
func (n *noopTestBiometricAuth) IsAvailable() bool                              { return false }

// mockVault creates a temp vault directory with entries for testing
func mockVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()

	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	// Create an entry
	entry := &vault.Entry{
		Data: map[string]any{
			"password": "testpass123",
			"username": "testuser",
		},
	}
	if err := vault.WriteEntry(dir, "github", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	return dir, identity
}
