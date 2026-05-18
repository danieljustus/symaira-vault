package cmd

import (
	"os"
	"path/filepath"
	"testing"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
)

func TestBuildInstallProfile_SafeTier(t *testing.T) {
	profile := buildInstallProfile("test", "safe")
	if profile.Tier != "safe" {
		t.Errorf("Tier = %q, want safe", profile.Tier)
	}
	if profile.Name != "test" {
		t.Errorf("Name = %q, want test", profile.Name)
	}
	if profile.CanWrite {
		t.Error("safe tier should have CanWrite=false")
	}
	if profile.CanRunCommands {
		t.Error("safe tier should have CanRunCommands=false")
	}
	if profile.CanUseClipboard {
		t.Error("safe tier should have CanUseClipboard=false")
	}
}

func TestBuildInstallProfile_StandardTier(t *testing.T) {
	profile := buildInstallProfile("test", "standard")
	if profile.Tier != "standard" {
		t.Errorf("Tier = %q, want standard", profile.Tier)
	}
	if profile.Name != "test" {
		t.Errorf("Name = %q, want test", profile.Name)
	}
	if !profile.CanUseClipboard {
		t.Error("standard tier should have CanUseClipboard=true")
	}
	if !profile.CanReadValues {
		t.Error("standard tier should have CanReadValues=true")
	}
}

func TestBuildInstallProfile_AdminTier(t *testing.T) {
	profile := buildInstallProfile("test", "admin")
	if profile.Tier != "admin" {
		t.Errorf("Tier = %q, want admin", profile.Tier)
	}
	if !profile.CanWrite {
		t.Error("admin tier should have CanWrite=true")
	}
	if !profile.CanRunCommands {
		t.Error("admin tier should have CanRunCommands=true")
	}
	if !profile.CanManageConfig {
		t.Error("admin tier should have CanManageConfig=true")
	}
}

func TestCreateAgentProfileConfig(t *testing.T) {
	vaultDir := t.TempDir()
	configPath, err := createAgentProfileConfig(vaultDir, "custom-agent", "safe", false, false)
	if err != nil {
		t.Fatalf("createAgentProfileConfig error: %v", err)
	}

	cfg, err := configpkg.Load(configPath)
	if err != nil {
		t.Fatalf("Load config error: %v", err)
	}

	profile, ok := cfg.Agents["custom-agent"]
	if !ok {
		t.Fatal("custom-agent profile not found in config")
	}
	if profile.Tier != "safe" {
		t.Errorf("Tier = %q, want safe", profile.Tier)
	}
	if profile.CanWrite {
		t.Error("safe tier should have CanWrite=false")
	}
}

func TestCreateAgentProfileConfig_DryRun(t *testing.T) {
	vaultDir := t.TempDir()
	_, err := createAgentProfileConfig(vaultDir, "custom-agent", "safe", false, true)
	if err != nil {
		t.Fatalf("createAgentProfileConfig dry-run error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(vaultDir, "config.yaml")); !os.IsNotExist(err) {
		t.Error("config.yaml should not exist in dry-run mode")
	}
}

func TestCreateAgentProfileConfig_ExistsNoForce(t *testing.T) {
	vaultDir := t.TempDir()
	if _, err := createAgentProfileConfig(vaultDir, "custom-agent", "safe", false, false); err != nil {
		t.Fatalf("first create error: %v", err)
	}

	_, err := createAgentProfileConfig(vaultDir, "custom-agent", "safe", false, false)
	if err == nil {
		t.Fatal("expected error for duplicate agent without --force")
	}
}

func TestCreateAgentProfileConfig_ExistsWithForce(t *testing.T) {
	vaultDir := t.TempDir()
	if _, err := createAgentProfileConfig(vaultDir, "custom-agent", "safe", false, false); err != nil {
		t.Fatalf("first create error: %v", err)
	}

	_, err := createAgentProfileConfig(vaultDir, "custom-agent", "standard", true, false)
	if err != nil {
		t.Fatalf("expected success with --force, got: %v", err)
	}

	cfg, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("Load config error: %v", err)
	}
	profile, ok := cfg.Agents["custom-agent"]
	if !ok {
		t.Fatal("custom-agent profile not found after force")
	}
	if profile.Tier != "standard" {
		t.Errorf("after force Tier = %q, want standard", profile.Tier)
	}
}

func TestValidTiers(t *testing.T) {
	tests := []struct {
		tier   string
		wantOK bool
	}{
		{"safe", true},
		{"standard", true},
		{"admin", true},
		{"invalid", false},
		{"", false},
		{"read-only", false},
	}

	for _, tc := range tests {
		t.Run(tc.tier, func(t *testing.T) {
			_, ok := validTiers[tc.tier]
			if ok != tc.wantOK {
				t.Errorf("validTiers[%q] = %v, want %v", tc.tier, ok, tc.wantOK)
			}
		})
	}
}

func TestTierPresetMapping(t *testing.T) {
	tests := []struct {
		tier string
		want string
	}{
		{"safe", "read-only"},
		{"standard", "standard"},
		{"admin", "admin"},
	}

	for _, tc := range tests {
		t.Run(tc.tier, func(t *testing.T) {
			got, ok := tierPresetMapping[tc.tier]
			if !ok {
				t.Fatalf("tierPresetMapping[%q] not found", tc.tier)
			}
			if got != tc.want {
				t.Errorf("tierPresetMapping[%q] = %q, want %q", tc.tier, got, tc.want)
			}
		})
	}
}

func TestCreateAgentProfileConfig_PreservesSkillPath(t *testing.T) {
	vaultDir := t.TempDir()
	configPath := filepath.Join(vaultDir, "config.yaml")

	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	cfg.Agents["custom-agent"] = configpkg.AgentProfile{
		Name:      "custom-agent",
		Tier:      "safe",
		SkillPath: "/custom/path/custom-agent.skill.md",
	}
	if err := cfg.SaveTo(configPath); err != nil {
		t.Fatalf("save initial config: %v", err)
	}

	_, err := createAgentProfileConfig(vaultDir, "custom-agent", "standard", true, false)
	if err != nil {
		t.Fatalf("createAgentProfileConfig with force error: %v", err)
	}

	cfg, err = configpkg.Load(configPath)
	if err != nil {
		t.Fatalf("Load config error: %v", err)
	}

	if cfg.Agents["custom-agent"].SkillPath != "/custom/path/custom-agent.skill.md" {
		t.Errorf("SkillPath = %q, want /custom/path/custom-agent.skill.md", cfg.Agents["custom-agent"].SkillPath)
	}
}
