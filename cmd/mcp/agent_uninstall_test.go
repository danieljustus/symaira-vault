package mcp

import (
	"path/filepath"
	"testing"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
)

func TestAgentUninstallRemovesProfile(t *testing.T) {
	vaultDir := t.TempDir()
	configPath := filepath.Join(vaultDir, "config.yaml")

	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	cfg.Agents["test-agent"] = configpkg.AgentProfile{
		Name: "test-agent",
		Tier: configpkg.StrPtr("safe"),
	}
	if err := cfg.SaveTo(configPath); err != nil {
		t.Fatalf("save config: %v", err)
	}

	cfg, err := configpkg.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if _, ok := cfg.Agents["test-agent"]; !ok {
		t.Fatal("test-agent should exist before uninstall")
	}

	delete(cfg.Agents, "test-agent")
	if err := cfg.SaveTo(configPath); err != nil {
		t.Fatalf("save config after removal: %v", err)
	}

	cfg, err = configpkg.Load(configPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}

	if _, ok := cfg.Agents["test-agent"]; ok {
		t.Error("test-agent should be removed from config after uninstall")
	}
}

func TestAgentUninstallNonExistent(t *testing.T) {
	vaultDir := t.TempDir()
	configPath := filepath.Join(vaultDir, "config.yaml")

	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	for k := range cfg.Agents {
		delete(cfg.Agents, k)
	}
	if err := cfg.SaveTo(configPath); err != nil {
		t.Fatalf("save config: %v", err)
	}

	loaded, err := configpkg.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if _, ok := loaded.Agents["nonexistent"]; ok {
		t.Fatal("nonexistent agent should not be found in config")
	}
}

func TestAgentUninstallKeepsOtherAgents(t *testing.T) {
	vaultDir := t.TempDir()
	configPath := filepath.Join(vaultDir, "config.yaml")

	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	cfg.Agents["agent-a"] = configpkg.AgentProfile{Name: "agent-a", Tier: configpkg.StrPtr("safe")}
	cfg.Agents["agent-b"] = configpkg.AgentProfile{Name: "agent-b", Tier: configpkg.StrPtr("standard")}
	if err := cfg.SaveTo(configPath); err != nil {
		t.Fatalf("save config: %v", err)
	}

	cfg, err := configpkg.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	delete(cfg.Agents, "agent-a")
	if err := cfg.SaveTo(configPath); err != nil {
		t.Fatalf("save config: %v", err)
	}

	cfg, err = configpkg.Load(configPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}

	if _, ok := cfg.Agents["agent-a"]; ok {
		t.Error("agent-a should be removed")
	}
	if _, ok := cfg.Agents["agent-b"]; !ok {
		t.Error("agent-b should still exist after removing agent-a")
	}
}

func TestConfirmUninstallReturnsFalseOnNonTTY(t *testing.T) {
	result := confirmUninstall("test-agent")
	if result {
		t.Error("confirmUninstall should return false in non-terminal (test) environment")
	}
}
