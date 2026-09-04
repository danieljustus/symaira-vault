package mcp

import (
	"os"
	"path/filepath"
	"testing"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	auth "github.com/danieljustus/symaira-vault/internal/mcp/auth"
)

func TestAgentTokenNew(t *testing.T) {
	vaultDir := t.TempDir()

	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("save config error: %v", err)
	}

	tokenID, err := createAgentTokenInRegistry(vaultDir, "test-agent", false)
	if err != nil {
		t.Fatalf("createAgentTokenInRegistry error: %v", err)
	}

	if tokenID == "" {
		t.Error("token ID should not be empty")
	}
	if tokenID == "<not-generated-dry-run>" {
		t.Error("should not be dry-run token")
	}

	reg := auth.NewTokenRegistry(auth.TokenRegistryFilePath(vaultDir))
	if err := reg.Load(); err != nil {
		t.Fatalf("load registry error: %v", err)
	}

	found := false
	for _, tok := range reg.List() {
		if tok.ID == tokenID {
			found = true
			if tok.AgentName != "test-agent" {
				t.Errorf("token agent = %q, want %q", tok.AgentName, "test-agent")
			}
			break
		}
	}
	if !found {
		t.Error("token not found in registry")
	}
}

func TestAgentTokenNew_DryRun(t *testing.T) {
	vaultDir := t.TempDir()

	tokenID, err := createAgentTokenInRegistry(vaultDir, "test-agent", true)
	if err != nil {
		t.Fatalf("createAgentTokenInRegistry dry-run error: %v", err)
	}

	if tokenID != "<not-generated-dry-run>" {
		t.Errorf("token ID = %q, want %q", tokenID, "<not-generated-dry-run>")
	}
}

func TestAgentTokenNew_InvalidName(t *testing.T) {
	vaultDir := t.TempDir()

	_, err := createAgentTokenInRegistry(vaultDir, "../evil-agent", false)
	if err == nil {
		t.Error("expected error for invalid agent name")
	}
}

func TestResolveTokenTTL(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{input: "24h", wantErr: false},
		{input: "7d", wantErr: false},
		{input: "30m", wantErr: false},
		{input: "invalid", wantErr: true},
		{input: "", wantErr: false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			_, err := ResolveTokenTTL("", tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ResolveTokenTTL(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestResolveTokenTTL_SevenDays(t *testing.T) {
	d, err := ResolveTokenTTL("", "7d")
	if err != nil {
		t.Fatalf("ResolveTokenTTL(\"7d\") error = %v", err)
	}
	if d.Hours() != 168 {
		t.Errorf("duration = %v hours, want 168", d.Hours())
	}
}

func TestResolveTokenTTL_EmptyDefault(t *testing.T) {
	d, err := ResolveTokenTTL("", "")
	if err != nil {
		t.Fatalf("ResolveTokenTTL(\"\") error = %v", err)
	}
	if d.Hours() != 24 {
		t.Errorf("duration = %v hours, want 24", d.Hours())
	}
}

func TestAgentTokenCommandRoutesAgentName(t *testing.T) {
	vaultDir := t.TempDir()
	t.Setenv("SYMVAULT_VAULT", vaultDir)

	output, err := os.CreateTemp(t.TempDir(), "agent-token-output")
	if err != nil {
		t.Fatalf("create output file: %v", err)
	}
	originalStdout := os.Stdout
	os.Stdout = output
	t.Cleanup(func() {
		os.Stdout = originalStdout
		_ = output.Close()
	})

	cmd := newAgentCmd()
	cmd.SetArgs([]string{"token", "new", "hermes", "--tools", "list_entries", "--ttl", "1h"})
	if err := cmd.Execute(); err != nil {
		os.Stdout = originalStdout
		t.Fatalf("execute token command: %v", err)
	}
	os.Stdout = originalStdout
	if err := output.Close(); err != nil {
		t.Fatalf("close output file: %v", err)
	}

	reg := auth.NewTokenRegistry(auth.TokenRegistryFilePath(vaultDir))
	if err := reg.Load(); err != nil {
		t.Fatalf("load registry: %v", err)
	}
	for _, token := range reg.List() {
		if token.AgentName == "hermes" {
			return
		}
	}
	t.Fatalf("token command did not persist a token for agent %q", "hermes")
}

func TestAgentTokenSubcommandsUseActionFirstArguments(t *testing.T) {
	cmd := newAgentTokenCmd()
	tests := []struct {
		name string
		args []string
	}{
		{name: "new", args: []string{"new", "hermes"}},
		{name: "list", args: []string{"list", "hermes"}},
		{name: "revoke", args: []string{"revoke", "hermes", "token-id"}},
		{name: "rotate", args: []string{"rotate", "hermes"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, args, err := cmd.Find(tt.args)
			if err != nil {
				t.Fatalf("find %s: %v", tt.name, err)
			}
			if found.Name() != tt.name {
				t.Fatalf("found command = %q, want %q", found.Name(), tt.name)
			}
			if err := found.Args(found, args); err != nil {
				t.Fatalf("validate %s args %v: %v", tt.name, args, err)
			}
		})
	}

	found, args, err := cmd.Find([]string{"hermes", "new"})
	if err != nil {
		t.Fatalf("find legacy ordering: %v", err)
	}
	if found != cmd {
		t.Fatalf("legacy ordering unexpectedly selected %q", found.Name())
	}
	if err := found.Args(found, args); err == nil {
		t.Fatal("legacy name-first ordering should fail instead of silently using the wrong agent")
	}
}

func TestAgentTokenRevokeRequiresMatchingAgent(t *testing.T) {
	vaultDir := t.TempDir()
	t.Setenv("SYMVAULT_VAULT", vaultDir)
	reg := auth.NewTokenRegistry(auth.TokenRegistryFilePath(vaultDir))
	token, _, err := reg.Create("test", []string{"list_entries"}, "hermes", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("save token: %v", err)
	}

	cmd := newAgentTokenRevokeCmd()
	if err := cmd.RunE(cmd, []string{"other-agent", token.ID}); err == nil {
		t.Fatal("revoke accepted a token owned by another agent")
	}
	assertAgentTokenRevoked(t, vaultDir, token.ID, false)

	if err := cmd.RunE(cmd, []string{"hermes", token.ID}); err != nil {
		t.Fatalf("revoke matching token: %v", err)
	}
	assertAgentTokenRevoked(t, vaultDir, token.ID, true)
}

func assertAgentTokenRevoked(t *testing.T, vaultDir, tokenID string, want bool) {
	t.Helper()
	reg := auth.NewTokenRegistry(auth.TokenRegistryFilePath(vaultDir))
	if err := reg.Load(); err != nil {
		t.Fatalf("load token registry: %v", err)
	}
	for _, token := range reg.List() {
		if token.ID == tokenID {
			if token.Revoked != want {
				t.Fatalf("token revoked = %v, want %v", token.Revoked, want)
			}
			return
		}
	}
	t.Fatalf("token %q not found", tokenID)
}
