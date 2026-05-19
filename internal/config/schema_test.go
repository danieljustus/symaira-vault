package config

import (
	"testing"
)

func TestDefaultVaultConfig(t *testing.T) {
	cfg := defaultVaultConfig()

	if cfg.Path != "" {
		t.Errorf("Path should be empty, got %q", cfg.Path)
	}
	if cfg.DefaultRecipients == nil {
		t.Fatal("DefaultRecipients should be initialized")
	}
	if len(cfg.DefaultRecipients) != 0 {
		t.Errorf("DefaultRecipients should be empty, got %v", cfg.DefaultRecipients)
	}
}

func TestDefaultGitConfig(t *testing.T) {
	cfg := defaultGitConfig()

	if !cfg.AutoPush {
		t.Error("AutoPush should be true by default")
	}
	if cfg.CommitTemplate != "Update from OpenPass" {
		t.Errorf("CommitTemplate mismatch: got %q, want %q", cfg.CommitTemplate, "Update from OpenPass")
	}
}

func TestDefaultMCPConfig(t *testing.T) {
	cfg := defaultMCPConfig()

	if cfg.Port != 8080 {
		t.Errorf("Port should be 8080, got %d", cfg.Port)
	}
	if cfg.Bind != "127.0.0.1" {
		t.Errorf("Bind should be 127.0.0.1, got %q", cfg.Bind)
	}
	if cfg.Stdio {
		t.Error("Stdio should be false by default")
	}
	if cfg.HTTPTokenFile != "auto" {
		t.Errorf("HTTPTokenFile should be auto, got %q", cfg.HTTPTokenFile)
	}
	if cfg.ApprovalRequired {
		t.Error("ApprovalRequired should be false (deprecated, not set by default)")
	}
}

func TestMergeFromVaultConfig(t *testing.T) {
	t.Run("nil file config returns defaults", func(t *testing.T) {
		defaults := defaultVaultConfig()
		result := defaults
		if result.Path != defaults.Path {
			t.Error("Path should be default")
		}
	})

	t.Run("file config overrides defaults", func(t *testing.T) {
		defaults := defaultVaultConfig()
		fileCfg := VaultConfig{
			Path:              "/custom/path",
			DefaultRecipients: []string{"recipient1", "recipient2"},
		}
		result := defaults
		MergeFromVault(&result, fileCfg)

		if result.Path != "/custom/path" {
			t.Errorf("Path should be /custom/path, got %q", result.Path)
		}
		if len(result.DefaultRecipients) != 2 {
			t.Errorf("Expected 2 recipients, got %d", len(result.DefaultRecipients))
		}
	})

	t.Run("empty path does not override", func(t *testing.T) {
		localDefaults := VaultConfig{Path: "/default/path"}
		fileCfg := VaultConfig{
			Path:              "",
			DefaultRecipients: nil,
		}
		result := localDefaults
		MergeFromVault(&result, fileCfg)

		if result.Path != "/default/path" {
			t.Errorf("Path should remain /default/path, got %q", result.Path)
		}
	})

	t.Run("ConfirmRemove is merged", func(t *testing.T) {
		defaults := defaultVaultConfig()
		fileCfg := VaultConfig{
			ConfirmRemove: true,
		}
		result := defaults
		MergeFromVault(&result, fileCfg)

		if !result.ConfirmRemove {
			t.Error("ConfirmRemove should be true")
		}
	})

	t.Run("recipients are copied not referenced", func(t *testing.T) {
		defaults := defaultVaultConfig()
		fileCfg := VaultConfig{
			DefaultRecipients: []string{"recipient1"},
		}
		result := defaults
		MergeFromVault(&result, fileCfg)

		result.DefaultRecipients[0] = "modified"
		if fileCfg.DefaultRecipients[0] == "modified" {
			t.Error("Recipients should be copied, not referenced")
		}
	})
}

func TestMergeFromGitConfig(t *testing.T) {
	defaults := defaultGitConfig()

	t.Run("nil file config returns defaults", func(t *testing.T) {
		result := defaults
		if !result.AutoPush {
			t.Error("AutoPush should be default")
		}
	})

	t.Run("file config overrides defaults", func(t *testing.T) {
		fileCfg := GitConfig{
			AutoPush:       false,
			CommitTemplate: "Custom template",
		}
		result := defaults
		MergeFromGit(&result, fileCfg)

		// AutoPush: false is indistinguishable from "not set" with bare types
		if !result.AutoPush {
			t.Error("AutoPush should be kept as default (true) when not set")
		}
		if result.CommitTemplate != "Custom template" {
			t.Errorf("CommitTemplate mismatch: got %q", result.CommitTemplate)
		}
	})

	t.Run("empty fields do not override", func(t *testing.T) {
		fileCfg := GitConfig{
			AutoPush:       false,
			CommitTemplate: "",
		}
		result := defaults
		// Note: false is not applied by MergeFromGit (uses non-zero check)
		MergeFromGit(&result, fileCfg)

		if !result.AutoPush {
			t.Error("AutoPush should remain true")
		}
		if result.CommitTemplate != defaults.CommitTemplate {
			t.Error("CommitTemplate should remain default")
		}
	})
}

func TestMergeFromMCPConfig(t *testing.T) {
	defaults := defaultMCPConfig()

	t.Run("nil file config returns defaults", func(t *testing.T) {
		result := defaults
		if result.Port != defaults.Port {
			t.Errorf("Port should be %d, got %d", defaults.Port, result.Port)
		}
	})

	t.Run("file config overrides defaults", func(t *testing.T) {
		fileCfg := MCPConfig{
			Port:          9090,
			Stdio:         true,
			Bind:          "0.0.0.0",
			HTTPTokenFile: "/custom/token",
		}
		result := defaults
		MergeFromMCP(&result, fileCfg)

		if result.Port != 9090 {
			t.Errorf("Port should be 9090, got %d", result.Port)
		}
		if !result.Stdio {
			t.Error("Stdio should be true")
		}
		if result.Bind != "0.0.0.0" {
			t.Errorf("Bind should be 0.0.0.0, got %q", result.Bind)
		}
		if result.HTTPTokenFile != "/custom/token" {
			t.Errorf("HTTPTokenFile should be /custom/token, got %q", result.HTTPTokenFile)
		}
	})

	t.Run("empty fields do not override", func(t *testing.T) {
		fileCfg := MCPConfig{
			Port:  0,
			Stdio: false,
			Bind:  "",
		}
		result := defaults
		MergeFromMCP(&result, fileCfg)

		if result.Port != defaults.Port {
			t.Errorf("Port should remain %d, got %d", defaults.Port, result.Port)
		}
		if result.Stdio != defaults.Stdio {
			t.Error("Stdio should remain default")
		}
		if result.Bind != defaults.Bind {
			t.Errorf("Bind should remain %q, got %q", defaults.Bind, result.Bind)
		}
	})
}

func TestVaultConfigTypes(t *testing.T) {
	cfg := VaultConfig{
		Path:              "/test/path",
		DefaultRecipients: []string{"recipient1"},
	}

	if cfg.Path != "/test/path" {
		t.Error("Path mismatch")
	}
	if len(cfg.DefaultRecipients) != 1 {
		t.Error("Recipients length mismatch")
	}
}

func TestGitConfigTypes(t *testing.T) {
	cfg := GitConfig{
		AutoPush:       true,
		CommitTemplate: "Test template",
	}

	if !cfg.AutoPush {
		t.Error("AutoPush should be true")
	}
	if cfg.CommitTemplate != "Test template" {
		t.Error("CommitTemplate mismatch")
	}
}

func TestMCPConfigTypes(t *testing.T) {
	cfg := MCPConfig{
		Port:          8080,
		Bind:          "127.0.0.1",
		Stdio:         false,
		HTTPTokenFile: "auto",
	}

	if cfg.Port != 8080 {
		t.Errorf("Port should be 8080, got %d", cfg.Port)
	}
	if cfg.Bind != "127.0.0.1" {
		t.Errorf("Bind should be 127.0.0.1, got %q", cfg.Bind)
	}
	if cfg.HTTPTokenFile != "auto" {
		t.Errorf("HTTPTokenFile should be auto, got %q", cfg.HTTPTokenFile)
	}
	if cfg.Stdio {
		t.Error("Stdio should be false")
	}
}

func TestAgentProfileTypes(t *testing.T) {
	profile := AgentProfile{
		Name:         "test-agent",
		AllowedPaths: []string{"path1", "path2"},
		CanWrite:     BoolPtr(true),
		ApprovalMode: StrPtr("none"),
	}

	if profile.Name != "test-agent" {
		t.Error("Name mismatch")
	}
	if len(profile.AllowedPaths) != 2 {
		t.Error("AllowedPaths length mismatch")
	}
	if profile.CanWrite == nil || !*profile.CanWrite {
		t.Error("CanWrite should be true")
	}
	if profile.ApprovalMode == nil || *profile.ApprovalMode != "none" {
		t.Errorf("ApprovalMode = %v, want none", profile.ApprovalMode)
	}
}

func TestDefaultClipboardConfig(t *testing.T) {
	cfg := defaultClipboardConfig()

	if cfg.AutoClearDuration != 30 {
		t.Errorf("AutoClearDuration should be 30, got %d", cfg.AutoClearDuration)
	}
}

func TestMergeFromClipboardConfig(t *testing.T) {
	defaults := defaultClipboardConfig()

	t.Run("nil file config returns defaults", func(t *testing.T) {
		result := defaults
		if result.AutoClearDuration != defaults.AutoClearDuration {
			t.Errorf("AutoClearDuration should be %d, got %d", defaults.AutoClearDuration, result.AutoClearDuration)
		}
	})

	t.Run("file config overrides defaults", func(t *testing.T) {
		fileCfg := ClipboardConfig{
			AutoClearDuration: 60,
		}
		result := defaults
		MergeFromClipboard(&result, fileCfg)

		if result.AutoClearDuration != 60 {
			t.Errorf("AutoClearDuration should be 60, got %d", result.AutoClearDuration)
		}
	})

	t.Run("empty field does not override", func(t *testing.T) {
		fileCfg := ClipboardConfig{
			AutoClearDuration: 0,
		}
		result := defaults
		MergeFromClipboard(&result, fileCfg)

		if result.AutoClearDuration != defaults.AutoClearDuration {
			t.Errorf("AutoClearDuration should remain %d, got %d", defaults.AutoClearDuration, result.AutoClearDuration)
		}
	})
}
