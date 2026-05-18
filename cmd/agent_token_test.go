package cmd

import (
	"path/filepath"
	"testing"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp"
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

	reg := mcp.NewTokenRegistry(mcp.TokenRegistryFilePath(vaultDir))
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
			_, err := resolveTokenTTL("", tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("resolveTokenTTL(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestResolveTokenTTL_SevenDays(t *testing.T) {
	d, err := resolveTokenTTL("", "7d")
	if err != nil {
		t.Fatalf("resolveTokenTTL(\"7d\") error = %v", err)
	}
	if d.Hours() != 168 {
		t.Errorf("duration = %v hours, want 168", d.Hours())
	}
}

func TestResolveTokenTTL_EmptyDefault(t *testing.T) {
	d, err := resolveTokenTTL("", "")
	if err != nil {
		t.Fatalf("resolveTokenTTL(\"\") error = %v", err)
	}
	if d.Hours() != 24 {
		t.Errorf("duration = %v hours, want 24", d.Hours())
	}
}
