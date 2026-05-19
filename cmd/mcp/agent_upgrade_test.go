package mcp

import (
	"path/filepath"
	"testing"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
)

func TestComputeTierDiff_SafeToStandard(t *testing.T) {
	oldProfile := buildInstallProfile("test", "safe")
	newProfile := buildInstallProfile("test", "standard")

	diff := computeTierDiff(oldProfile, newProfile)

	foundCanUseAutotype := false
	for _, d := range diff {
		if d.Field == "canUseAutotype" {
			foundCanUseAutotype = true
			if d.OldValue != "false" || d.NewValue != "true" {
				t.Errorf("canUseAutotype diff: old=%s new=%s, want false→true", d.OldValue, d.NewValue)
			}
		}
	}
	if !foundCanUseAutotype {
		t.Error("expected canUseAutotype in diff")
	}
}

func TestComputeTierDiff_SafeToAdmin(t *testing.T) {
	oldProfile := buildInstallProfile("test", "safe")
	newProfile := buildInstallProfile("test", "admin")

	diff := computeTierDiff(oldProfile, newProfile)

	foundCanWrite := false
	for _, d := range diff {
		if d.Field == "canWrite" {
			foundCanWrite = true
			if d.OldValue != "false" || d.NewValue != "true" {
				t.Errorf("canWrite diff: old=%s new=%s, want false→true", d.OldValue, d.NewValue)
			}
		}
	}
	if !foundCanWrite {
		t.Error("expected canWrite in diff")
	}
}

func TestComputeTierDiff_SameTier(t *testing.T) {
	oldProfile := buildInstallProfile("test", "standard")
	newProfile := buildInstallProfile("test", "standard")

	diff := computeTierDiff(oldProfile, newProfile)

	for _, d := range diff {
		if d.Changed {
			t.Errorf("unexpected change for %s: %s→%s", d.Field, d.OldValue, d.NewValue)
		}
	}
}

func TestComputeTierDiff_ReadOnlyToStandard(t *testing.T) {
	oldProfile := buildInstallProfile("test", "read-only")
	newProfile := buildInstallProfile("test", "standard")

	diff := computeTierDiff(oldProfile, newProfile)

	foundCanReadValues := false
	for _, d := range diff {
		if d.Field == "canReadValues" {
			foundCanReadValues = true
			if !d.Changed || d.OldValue != "false" || d.NewValue != "true" {
				t.Errorf("canReadValues diff: old=%s new=%s changed=%v, want false→true changed=true",
					d.OldValue, d.NewValue, d.Changed)
			}
		}
	}
	if !foundCanReadValues {
		t.Error("expected canReadValues in diff")
	}
}

func TestApplyTierUpgrade(t *testing.T) {
	vaultDir := t.TempDir()

	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	cfg.Agents["test-agent"] = configpkg.AgentProfile{
		Name:         "test-agent",
		Tier:         configpkg.StrPtr("safe"),
		AllowedPaths: []string{"*"},
	}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("save config error: %v", err)
	}

	if err := applyTierUpgrade(vaultDir, "test-agent", false); err != nil {
		t.Fatalf("applyTierUpgrade error: %v", err)
	}

	cfg, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("load config error: %v", err)
	}

	profile := cfg.Agents["test-agent"]
	if *profile.Tier != "standard" {
		t.Errorf("tier = %q, want \"standard\"", *profile.Tier)
	}
	if profile.RequireApproval == nil || !*profile.RequireApproval {
		t.Error("standard tier should have RequireApproval=true")
	}
	if *profile.ApprovalMode != "prompt" {
		t.Errorf("approvalMode = %q, want \"prompt\"", *profile.ApprovalMode)
	}
}

func TestApplyTierUpgrade_DryRun(t *testing.T) {
	vaultDir := t.TempDir()

	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	cfg.Agents["test-agent"] = configpkg.AgentProfile{
		Name: "test-agent",
		Tier: configpkg.StrPtr("safe"),
	}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("save config error: %v", err)
	}

	if err := applyTierUpgrade(vaultDir, "test-agent", true); err != nil {
		t.Fatalf("applyTierUpgrade dry-run error: %v", err)
	}

	cfg, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("load config error: %v", err)
	}

	if *cfg.Agents["test-agent"].Tier != "safe" {
		t.Error("dry-run should not modify tier")
	}
}

func TestApplyTierUpgrade_MissingAgent(t *testing.T) {
	vaultDir := t.TempDir()

	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("save config error: %v", err)
	}

	err := applyTierUpgrade(vaultDir, "nonexistent-agent", false)
	if err == nil {
		t.Fatal("expected error for nonexistent agent")
	}
}

func TestApplyTierUpgrade_NoConfig(t *testing.T) {
	vaultDir := t.TempDir()

	err := applyTierUpgrade(vaultDir, "test-agent", false)
	if err == nil {
		t.Fatal("expected error when no config file exists")
	}
}
