package mcp

import (
	"path/filepath"
	"strings"
	"testing"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
)

func TestSortStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{name: "unsorted", input: []string{"c", "a", "b"}, want: []string{"a", "b", "c"}},
		{name: "already sorted", input: []string{"a", "b", "c"}, want: []string{"a", "b", "c"}},
		{name: "reverse", input: []string{"z", "y", "x"}, want: []string{"x", "y", "z"}},
		{name: "empty", input: []string{}, want: []string{}},
		{name: "single", input: []string{"a"}, want: []string{"a"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sortStrings(tc.input)
			for i := range tc.input {
				if tc.input[i] != tc.want[i] {
					t.Errorf("sortStrings result[%d] = %q, want %q", i, tc.input[i], tc.want[i])
				}
			}
		})
	}
}

func TestAgentListResult_String_Empty(t *testing.T) {
	result := AgentListResult{
		Agents: []AgentListItem{},
		Count:  0,
	}
	output := result.String()
	if !strings.Contains(output, "No agents configured") {
		t.Errorf("empty result should say 'No agents configured', got: %q", output)
	}
}

func TestAgentListResult_String_WithAgents(t *testing.T) {
	result := AgentListResult{
		Agents: []AgentListItem{
			{Name: "hermes", Tier: "safe", TokenValid: true, SkillManaged: true, LastSeen: "2026-05-15 10:30"},
		},
		Count: 1,
	}
	output := result.String()
	if !strings.Contains(output, "hermes") {
		t.Error("String() should contain agent name 'hermes'")
	}
	if !strings.Contains(output, "safe") {
		t.Error("String() should contain tier 'safe'")
	}
	if !strings.Contains(output, "valid") {
		t.Error("String() should contain token status 'valid'")
	}
	if !strings.Contains(output, "managed") {
		t.Error("String() should contain skill status 'managed'")
	}
	if !strings.Contains(output, "2026-05-15") {
		t.Error("String() should contain last seen date")
	}
}

func TestAgentListResult_String_TokenInvalid(t *testing.T) {
	result := AgentListResult{
		Agents: []AgentListItem{
			{Name: "test-agent", Tier: "standard", TokenID: "tok_abc", TokenValid: false, SkillInstalled: true},
		},
		Count: 1,
	}
	output := result.String()
	if !strings.Contains(output, "invalid") {
		t.Error("String() should show 'invalid' for non-valid but present token")
	}
}

func TestAgentListResult_String_MultipleAgents(t *testing.T) {
	result := AgentListResult{
		Agents: []AgentListItem{
			{Name: "claude", Tier: "admin", TokenValid: true, SkillManaged: true},
			{Name: "hermes", Tier: "safe", TokenValid: false, SkillInstalled: true},
		},
		Count: 2,
	}
	output := result.String()
	if !strings.Contains(output, "claude") {
		t.Error("String() should contain 'claude'")
	}
	if !strings.Contains(output, "hermes") {
		t.Error("String() should contain 'hermes'")
	}
	if !strings.Contains(output, "AGENT") {
		t.Error("String() should have AGENT header")
	}
	if !strings.Contains(output, "TIER") {
		t.Error("String() should have TIER header")
	}
}

func TestAgentListFromConfig(t *testing.T) {
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

	loaded, err := configpkg.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	found := false
	for name := range loaded.Agents {
		if name == "test-agent" {
			found = true
			break
		}
	}
	if !found {
		t.Error("test-agent not found in loaded config agents")
	}

	profile, ok := loaded.Agents["test-agent"]
	if !ok {
		t.Fatal("test-agent missing from agents map")
	}
	if *profile.Tier != "safe" {
		t.Errorf("test-agent tier = %q, want safe", *profile.Tier)
	}
}
