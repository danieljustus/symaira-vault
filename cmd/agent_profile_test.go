package cmd

import (
	"bytes"
	"path/filepath"
	"testing"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
)

func TestLoadAgentProfile(t *testing.T) {
	vaultDir := t.TempDir()

	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	cfg.Agents["test-agent"] = configpkg.AgentProfile{
		Tier:         "standard",
		AllowedPaths: []string{"test/*"},
		CanWrite:     true,
	}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("save config error: %v", err)
	}

	t.Setenv("OPENPASS_VAULT", vaultDir)

	profile, err := loadAgentProfile("test-agent")
	if err != nil {
		t.Fatalf("loadAgentProfile() error: %v", err)
	}

	if profile.Name != "test-agent" {
		t.Errorf("Name = %q, want %q", profile.Name, "test-agent")
	}
	if profile.Tier != "standard" {
		t.Errorf("Tier = %q, want %q", profile.Tier, "standard")
	}
	if !profile.CanWrite {
		t.Error("CanWrite should be true")
	}
}

func TestLoadAgentProfile_NotFound(t *testing.T) {
	vaultDir := t.TempDir()

	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("save config error: %v", err)
	}

	t.Setenv("OPENPASS_VAULT", vaultDir)

	_, err := loadAgentProfile("nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
}

func TestLoadAgentProfile_MissingConfig(t *testing.T) {
	vaultDir := t.TempDir()

	t.Setenv("OPENPASS_VAULT", vaultDir)

	_, err := loadAgentProfile("test-agent")
	if err == nil {
		t.Fatal("expected error when config file missing")
	}
}

func TestExtractAgentSection(t *testing.T) {
	configData := []byte(`
vaultDir: /tmp/test
agents:
  agent-one:
    tier: safe
    allowedPaths: ["team/*"]
    canWrite: false
  agent-two:
    tier: standard
    allowedPaths: ["*"]
`)

	section, err := extractAgentSection(configData, "agent-one")
	if err != nil {
		t.Fatalf("extractAgentSection() error: %v", err)
	}

	if len(section) == 0 {
		t.Fatal("extracted section is empty")
	}

	if !bytes.Contains(section, []byte("safe")) {
		t.Errorf("extracted section = %q, should contain 'safe'", string(section))
	}
}

func TestExtractAgentSection_NotFound(t *testing.T) {
	configData := []byte(`
vaultDir: /tmp/test
agents:
  existing-agent:
    tier: safe
`)

	_, err := extractAgentSection(configData, "missing-agent")
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
}

func TestExtractAgentSection_NoAgents(t *testing.T) {
	configData := []byte(`
vaultDir: /tmp/test
`)

	_, err := extractAgentSection(configData, "agent")
	if err == nil {
		t.Fatal("expected error when no agents section")
	}
}
