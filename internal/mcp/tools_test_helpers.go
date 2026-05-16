package mcp

import (
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/audit"
	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

//nolint:unparam // transport always "stdio" in current test suite
func newTestServerWithVault(t *testing.T, profile config.AgentProfile, transport string, vaultDir string) *Server {
	t.Helper()

	auditLog, err := audit.New("test", "")
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

	return &Server{
		vault: &vault.Vault{
			Dir:      vaultDir,
			Identity: identity,
		},
		agent:     &profile,
		auditLog:  auditLog,
		transport: transport,
	}
}

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
