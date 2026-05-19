package mcp

import (
	"testing"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
)

func TestBuildWhoamiInfo(t *testing.T) {
	vaultDir := t.TempDir()
	profile := configpkg.AgentProfile{
		Name:         "test-agent",
		Tier:         configpkg.StrPtr("safe"),
		AllowedPaths: []string{"test/*"},
	}

	info := buildWhoamiInfo("test-agent", vaultDir, &profile)

	if info.Name != "test-agent" {
		t.Errorf("Name = %q, want %q", info.Name, "test-agent")
	}
	if info.Tier != "safe" {
		t.Errorf("Tier = %q, want %q", info.Tier, "safe")
	}
	if len(info.AllowedPaths) != 1 || info.AllowedPaths[0] != "test/*" {
		t.Errorf("AllowedPaths = %v, want [test/*]", info.AllowedPaths)
	}
	if info.CanWrite {
		t.Error("CanWrite should be false by default")
	}
	if info.RequireApproval {
		t.Error("RequireApproval should be false by default")
	}
	if info.TokenCount != 0 {
		t.Errorf("TokenCount = %d, want 0", info.TokenCount)
	}
	if info.TokenFile != "" {
		t.Errorf("TokenFile = %q, want empty", info.TokenFile)
	}
}

func TestBuildWhoamiInfo_FullProfile(t *testing.T) {
	vaultDir := t.TempDir()
	profile := configpkg.AgentProfile{
		Name:                "power-agent",
		Tier:                configpkg.StrPtr("standard"),
		AllowedPaths:        []string{"prod/*", "dev/*"},
		AllowedTools:        []string{"list_entries", "get_entry"},
		CanWrite:            configpkg.BoolPtr(true),
		CanReadValues:       configpkg.BoolPtr(true),
		CanUseClipboard:     configpkg.BoolPtr(true),
		CanUseAutotype:      configpkg.BoolPtr(false),
		CanRunCommands:      configpkg.BoolPtr(true),
		CanManageConfig:     configpkg.BoolPtr(false),
		ApprovalMode:        configpkg.StrPtr("prompt"),
		RequireApproval:     configpkg.BoolPtr(true),
		MaxReadsPerHour:     configpkg.IntPtr(100),
		MaxReadsPerDay:      configpkg.IntPtr(500),
		MaxSecretsInSession: configpkg.IntPtr(10),
		SkillPath:           configpkg.StrPtr("/path/to/skill"),
	}

	info := buildWhoamiInfo("power-agent", vaultDir, &profile)

	if info.Name != "power-agent" {
		t.Errorf("Name = %q, want %q", info.Name, "power-agent")
	}
	if info.Tier != "standard" {
		t.Errorf("Tier = %q, want %q", info.Tier, "standard")
	}
	if !info.CanWrite {
		t.Error("CanWrite should be true")
	}
	if !info.CanReadValues {
		t.Error("CanReadValues should be true")
	}
	if !info.CanUseClipboard {
		t.Error("CanUseClipboard should be true")
	}
	if info.CanUseAutotype {
		t.Error("CanUseAutotype should be false")
	}
	if !info.CanRunCommands {
		t.Error("CanRunCommands should be true")
	}
	if info.CanManageConfig {
		t.Error("CanManageConfig should be false")
	}
	if !info.RequireApproval {
		t.Error("RequireApproval should be true")
	}
	if info.ApprovalMode != "prompt" {
		t.Errorf("ApprovalMode = %q, want %q", info.ApprovalMode, "prompt")
	}
	if info.Quotas.MaxReadsPerHour != 100 {
		t.Errorf("MaxReadsPerHour = %d, want 100", info.Quotas.MaxReadsPerHour)
	}
	if info.Quotas.MaxReadsPerDay != 500 {
		t.Errorf("MaxReadsPerDay = %d, want 500", info.Quotas.MaxReadsPerDay)
	}
	if info.Quotas.MaxSecretsInSession != 10 {
		t.Errorf("MaxSecretsInSession = %d, want 10", info.Quotas.MaxSecretsInSession)
	}
	if info.SkillPath != "/path/to/skill" {
		t.Errorf("SkillPath = %q, want %q", info.SkillPath, "/path/to/skill")
	}
	if len(info.AllowedTools) != 2 || info.AllowedTools[0] != "list_entries" {
		t.Errorf("AllowedTools = %v, want [list_entries get_entry]", info.AllowedTools)
	}
	if info.TokenCount != 0 {
		t.Errorf("TokenCount = %d, want 0", info.TokenCount)
	}
}

func TestBuildWhoamiInfo_EmptyProfile(t *testing.T) {
	vaultDir := t.TempDir()
	profile := configpkg.AgentProfile{
		Name: "minimal",
	}

	info := buildWhoamiInfo("minimal", vaultDir, &profile)

	if info.Name != "minimal" {
		t.Errorf("Name = %q, want %q", info.Name, "minimal")
	}
	if info.Tier != "" {
		t.Errorf("Tier = %q, want empty", info.Tier)
	}
	if info.ApprovalMode != "" {
		t.Errorf("ApprovalMode = %q, want empty", info.ApprovalMode)
	}
	if info.TokenCount != 0 {
		t.Errorf("TokenCount = %d, want 0", info.TokenCount)
	}
}
