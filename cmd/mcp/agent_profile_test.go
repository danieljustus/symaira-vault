package mcp

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
)

func TestLoadAgentProfile(t *testing.T) {
	vaultDir := t.TempDir()

	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	cfg.Agents["test-agent"] = configpkg.AgentProfile{
		Tier:         configpkg.StrPtr("standard"),
		AllowedPaths: []string{"test/*"},
		CanWrite:     configpkg.BoolPtr(true),
	}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("save config error: %v", err)
	}

	t.Setenv("SYMVAULT_VAULT", vaultDir)

	profile, err := loadAgentProfile("test-agent")
	if err != nil {
		t.Fatalf("loadAgentProfile() error: %v", err)
	}

	if profile.Name != "test-agent" {
		t.Errorf("Name = %q, want %q", profile.Name, "test-agent")
	}
	if *profile.Tier != "standard" {
		t.Errorf("Tier = %q, want %q", *profile.Tier, "standard")
	}
	if profile.CanWrite == nil || !*profile.CanWrite {
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

	t.Setenv("SYMVAULT_VAULT", vaultDir)

	_, err := loadAgentProfile("nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent agent")
	}
}

func TestLoadAgentProfile_MissingConfig(t *testing.T) {
	vaultDir := t.TempDir()

	t.Setenv("SYMVAULT_VAULT", vaultDir)

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

func TestAgentProfileShowRoutesAgentName(t *testing.T) {
	vaultDir := t.TempDir()
	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	cfg.Agents["test-agent"] = configpkg.AgentProfile{
		Tier:         configpkg.StrPtr("standard"),
		AllowedPaths: []string{"test/*"},
	}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("save config: %v", err)
	}
	t.Setenv("SYMVAULT_VAULT", vaultDir)

	var output bytes.Buffer
	cmd := newAgentCmd()
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"profile", "show", "test-agent", "--output", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute profile show: %v", err)
	}

	var profile configpkg.AgentProfile
	if err := json.Unmarshal(output.Bytes(), &profile); err != nil {
		t.Fatalf("decode profile output: %v\n%s", err, output.String())
	}
	if profile.Name != "test-agent" {
		t.Fatalf("profile name = %q, want %q", profile.Name, "test-agent")
	}
}

func TestAgentProfileSubcommandsUseActionFirstArguments(t *testing.T) {
	cmd := newAgentProfileCmd()
	for _, action := range []string{"show", "edit", "export"} {
		t.Run(action, func(t *testing.T) {
			found, args, err := cmd.Find([]string{action, "test-agent"})
			if err != nil {
				t.Fatalf("find %s: %v", action, err)
			}
			if found.Name() != action {
				t.Fatalf("found command = %q, want %q", found.Name(), action)
			}
			if err := found.Args(found, args); err != nil {
				t.Fatalf("validate %s args %v: %v", action, args, err)
			}
		})
	}

	found, args, err := cmd.Find([]string{"test-agent", "show"})
	if err != nil {
		t.Fatalf("find legacy ordering: %v", err)
	}
	if found != cmd {
		t.Fatalf("legacy ordering unexpectedly selected %q", found.Name())
	}
	if err := found.Args(found, args); err == nil {
		t.Fatal("legacy name-first ordering should fail instead of silently selecting an unknown profile")
	}
}
