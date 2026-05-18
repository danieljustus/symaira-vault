package config

import (
	"testing"
)

func TestTierPresets_ApplyPresetValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		tier                 string
		wantCanWrite         bool
		wantCanRunCommands   bool
		wantCanManageConfig  bool
		wantCanUseClipboard  bool
		wantCanUseAutotype   bool
		wantCanReadValues    bool
		wantExposeValueTools bool
		wantAutoUnseal       bool
		wantApprovalMode     string
		wantRequireApproval  bool
	}{
		{
			name:                 "read-only",
			tier:                 "read-only",
			wantCanWrite:         false,
			wantCanRunCommands:   false,
			wantCanManageConfig:  false,
			wantCanUseClipboard:  false,
			wantCanUseAutotype:   false,
			wantCanReadValues:    false,
			wantExposeValueTools: false,
			wantAutoUnseal:       false,
			wantApprovalMode:     "none",
			wantRequireApproval:  false,
		},
		{
			name:                 "standard",
			tier:                 "standard",
			wantCanWrite:         false,
			wantCanRunCommands:   false,
			wantCanManageConfig:  false,
			wantCanUseClipboard:  true,
			wantCanUseAutotype:   true,
			wantCanReadValues:    true,
			wantExposeValueTools: false,
			wantAutoUnseal:       false,
			wantApprovalMode:     "prompt",
			wantRequireApproval:  true,
		},
		{
			name:                 "admin",
			tier:                 "admin",
			wantCanWrite:         true,
			wantCanRunCommands:   true,
			wantCanManageConfig:  true,
			wantCanUseClipboard:  true,
			wantCanUseAutotype:   true,
			wantCanReadValues:    true,
			wantExposeValueTools: true,
			wantAutoUnseal:       true,
			wantApprovalMode:     "prompt",
			wantRequireApproval:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preset, ok := TierPresets[TierPreset(tt.tier)]
			if !ok {
				t.Fatalf("TierPresets[%q] not found", tt.tier)
			}

			if preset.CanWrite != tt.wantCanWrite {
				t.Errorf("CanWrite = %v, want %v", preset.CanWrite, tt.wantCanWrite)
			}
			if preset.CanRunCommands != tt.wantCanRunCommands {
				t.Errorf("CanRunCommands = %v, want %v", preset.CanRunCommands, tt.wantCanRunCommands)
			}
			if preset.CanManageConfig != tt.wantCanManageConfig {
				t.Errorf("CanManageConfig = %v, want %v", preset.CanManageConfig, tt.wantCanManageConfig)
			}
			if preset.CanUseClipboard != tt.wantCanUseClipboard {
				t.Errorf("CanUseClipboard = %v, want %v", preset.CanUseClipboard, tt.wantCanUseClipboard)
			}
			if preset.CanUseAutotype != tt.wantCanUseAutotype {
				t.Errorf("CanUseAutotype = %v, want %v", preset.CanUseAutotype, tt.wantCanUseAutotype)
			}
			if preset.CanReadValues != tt.wantCanReadValues {
				t.Errorf("CanReadValues = %v, want %v", preset.CanReadValues, tt.wantCanReadValues)
			}
			if preset.ExposeValueTools != tt.wantExposeValueTools {
				t.Errorf("ExposeValueTools = %v, want %v", preset.ExposeValueTools, tt.wantExposeValueTools)
			}
			if preset.AutoUnseal != tt.wantAutoUnseal {
				t.Errorf("AutoUnseal = %v, want %v", preset.AutoUnseal, tt.wantAutoUnseal)
			}
			if preset.ApprovalMode != tt.wantApprovalMode {
				t.Errorf("ApprovalMode = %q, want %q", preset.ApprovalMode, tt.wantApprovalMode)
			}
			if preset.RequireApproval != tt.wantRequireApproval {
				t.Errorf("RequireApproval = %v, want %v", preset.RequireApproval, tt.wantRequireApproval)
			}
		})
	}
}

func TestTierPresets_UnknownTierNotInMap(t *testing.T) {
	t.Parallel()

	if _, ok := TierPresets["nonexistent"]; ok {
		t.Error("TierPresets should not contain nonexistent tier")
	}
}

func TestGetPreset_ReturnsCopy(t *testing.T) {
	t.Parallel()

	p1 := GetPreset("admin")
	if p1 == nil {
		t.Fatal("GetPreset(admin) returned nil")
	}

	p1.CanWrite = false

	p2 := GetPreset("admin")
	if p2 == nil {
		t.Fatal("GetPreset(admin) returned nil on second call")
	}
	if !p2.CanWrite {
		t.Error("GetPreset should return a copy; original preset should retain CanWrite=true")
	}
}

func TestGetPreset_UnknownTierReturnsNil(t *testing.T) {
	t.Parallel()

	if p := GetPreset("unknown"); p != nil {
		t.Errorf("GetPreset(unknown) = %v, want nil", p)
	}
}

func TestApplyTierPreset_PreservesNameAndAllowedPaths(t *testing.T) {
	t.Parallel()

	target := &AgentProfile{
		Name:         "my-agent",
		AllowedPaths: []string{"personal/*", "work/*"},
	}

	ok := ApplyTierPreset(target, "standard")
	if !ok {
		t.Fatal("ApplyTierPreset returned false for known tier")
	}

	if target.Name != "my-agent" {
		t.Errorf("Name should be preserved, got %q", target.Name)
	}
	if len(target.AllowedPaths) != 2 || target.AllowedPaths[0] != "personal/*" {
		t.Errorf("AllowedPaths should be preserved, got %v", target.AllowedPaths)
	}
}

func TestApplyTierPreset_StandardSetsAllowedExecutables(t *testing.T) {
	t.Parallel()

	target := &AgentProfile{Name: "test"}
	ok := ApplyTierPreset(target, "standard")
	if !ok {
		t.Fatal("ApplyTierPreset returned false for standard")
	}

	expected := []string{"curl", "git", "terraform", "npm", "node", "python", "python3", "docker", "kubectl"}
	if len(target.AllowedExecutables) != len(expected) {
		t.Fatalf("AllowedExecutables len = %d, want %d; got %v", len(target.AllowedExecutables), len(expected), target.AllowedExecutables)
	}
	for i, exe := range expected {
		if target.AllowedExecutables[i] != exe {
			t.Errorf("AllowedExecutables[%d] = %q, want %q", i, target.AllowedExecutables[i], exe)
		}
	}
}

func TestApplyTierPreset_AdminHasNoAllowedExecutables(t *testing.T) {
	t.Parallel()

	target := &AgentProfile{Name: "test"}
	ok := ApplyTierPreset(target, "admin")
	if !ok {
		t.Fatal("ApplyTierPreset returned false for admin")
	}

	if target.AllowedExecutables != nil {
		t.Errorf("Admin should have nil AllowedExecutables, got %v", target.AllowedExecutables)
	}
}

func TestApplyTierPreset_ReadOnlyHasNoAllowedExecutables(t *testing.T) {
	t.Parallel()

	target := &AgentProfile{Name: "test"}
	ok := ApplyTierPreset(target, "read-only")
	if !ok {
		t.Fatal("ApplyTierPreset returned false for read-only")
	}

	if target.AllowedExecutables != nil {
		t.Errorf("Read-only should have nil AllowedExecutables, got %v", target.AllowedExecutables)
	}
}

func TestApplyTierPreset_UnknownTierReturnsFalse(t *testing.T) {
	t.Parallel()

	target := &AgentProfile{Name: "test", CanWrite: true}
	ok := ApplyTierPreset(target, "bogus")
	if ok {
		t.Fatal("ApplyTierPreset should return false for unknown tier")
	}
	if !target.CanWrite {
		t.Error("CanWrite should not be changed by unknown tier")
	}
}

func TestApplyTierPreset_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		tier              string
		wantOK            bool
		wantCanWrite      bool
		wantCanRunCmds    bool
		wantCanClip       bool
		wantCanAuto       bool
		wantCanReadValues bool
		wantApprovalMode  string
	}{
		{name: "read-only", tier: "read-only", wantOK: true, wantCanWrite: false, wantCanRunCmds: false, wantCanClip: false, wantCanAuto: false, wantCanReadValues: false, wantApprovalMode: "none"},
		{name: "standard", tier: "standard", wantOK: true, wantCanWrite: false, wantCanRunCmds: false, wantCanClip: true, wantCanAuto: true, wantCanReadValues: true, wantApprovalMode: "prompt"},
		{name: "admin", tier: "admin", wantOK: true, wantCanWrite: true, wantCanRunCmds: true, wantCanClip: true, wantCanAuto: true, wantCanReadValues: true, wantApprovalMode: "prompt"},
		{name: "unknown", tier: "bogus", wantOK: false, wantCanWrite: false, wantCanRunCmds: false, wantCanClip: false, wantCanAuto: false, wantCanReadValues: false, wantApprovalMode: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &AgentProfile{Name: "test"}
			gotOK := ApplyTierPreset(target, tt.tier)

			if gotOK != tt.wantOK {
				t.Fatalf("ApplyTierPreset() = %v, want %v", gotOK, tt.wantOK)
			}
			if !gotOK {
				return
			}

			if target.CanWrite != tt.wantCanWrite {
				t.Errorf("CanWrite = %v, want %v", target.CanWrite, tt.wantCanWrite)
			}
			if target.CanRunCommands != tt.wantCanRunCmds {
				t.Errorf("CanRunCommands = %v, want %v", target.CanRunCommands, tt.wantCanRunCmds)
			}
			if target.CanUseClipboard != tt.wantCanClip {
				t.Errorf("CanUseClipboard = %v, want %v", target.CanUseClipboard, tt.wantCanClip)
			}
			if target.CanUseAutotype != tt.wantCanAuto {
				t.Errorf("CanUseAutotype = %v, want %v", target.CanUseAutotype, tt.wantCanAuto)
			}
			if target.CanReadValues != tt.wantCanReadValues {
				t.Errorf("CanReadValues = %v, want %v", target.CanReadValues, tt.wantCanReadValues)
			}
			if target.ApprovalMode != tt.wantApprovalMode {
				t.Errorf("ApprovalMode = %q, want %q", target.ApprovalMode, tt.wantApprovalMode)
			}
		})
	}
}
