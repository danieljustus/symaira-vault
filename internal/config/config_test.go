package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDefaultReturnsSensibleConfig(t *testing.T) {
	t.Parallel()

	cfg := Default()
	if cfg == nil {
		t.Fatal("Default returned nil")
	}

	wantVaultDir := filepath.Join(mustHomeDir(t), ".openpass")
	if cfg.VaultDir != wantVaultDir {
		t.Fatalf("VaultDir = %q, want %q", cfg.VaultDir, wantVaultDir)
	}
	if cfg.DefaultAgent != "default" {
		t.Fatalf("DefaultAgent = %q, want %q", cfg.DefaultAgent, "default")
	}

	// Built-in profile assertions
	type wantProfile struct {
		approvalMode string
		canWrite     bool
	}
	wantProfiles := map[string]wantProfile{
		"default":     {canWrite: false, approvalMode: "none"},
		"claude-code": {canWrite: true, approvalMode: "none"},
		"codex":       {canWrite: false, approvalMode: "none"},
		"hermes":      {canWrite: true, approvalMode: "none"},
		"openclaw":    {canWrite: true, approvalMode: "none"},
		"opencode":    {canWrite: false, approvalMode: "none"},
	}
	for name, want := range wantProfiles {
		got, ok := cfg.Agents[name]
		if !ok {
			t.Fatalf("missing built-in profile: %s", name)
		}
		if got.CanWrite != want.canWrite {
			t.Fatalf("profile %q CanWrite = %v, want %v", name, got.CanWrite, want.canWrite)
		}
		if got.ApprovalMode != want.approvalMode {
			t.Fatalf("profile %q ApprovalMode = %q, want %q", name, got.ApprovalMode, want.approvalMode)
		}
	}
}

func TestLoadUsesDefaultsForMissingFields(t *testing.T) {
	t.Parallel()

	path := writeTempFile(t, []byte("vaultDir: /custom/vault\nagents:\n  claude:\n    allowedPaths:\n      - personal/\n    canWrite: false\n    approvalMode: prompt\n"))

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.VaultDir != "/custom/vault" {
		t.Fatalf("VaultDir = %q, want %q", cfg.VaultDir, "/custom/vault")
	}
	if _, ok := cfg.Agents["default"]; !ok {
		t.Fatal("default profile should be present when omitted from file")
	}

	want := AgentProfile{
		Name:         "claude",
		AllowedPaths: []string{"personal/"},
		CanWrite:     false,
		ApprovalMode: "prompt",
	}
	if got := cfg.Agents["claude"]; got.Name != want.Name || got.CanWrite != want.CanWrite || got.ApprovalMode != want.ApprovalMode {
		t.Fatalf("claude profile = %+v, want %+v", got, want)
	}
}

func TestLoadEmptyFileReturnsDefaults(t *testing.T) {
	t.Parallel()

	path := writeTempFile(t, nil)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.DefaultAgent != "default" {
		t.Fatalf("DefaultAgent = %q, want %q", cfg.DefaultAgent, "default")
	}
	if _, ok := cfg.Agents["default"]; !ok {
		t.Fatal("missing default agent profile")
	}
}

func TestLoadMissingFileReturnsError(t *testing.T) {
	t.Parallel()

	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsInvalidYAML(t *testing.T) {
	t.Parallel()

	path := writeTempFile(t, []byte("vaultDir: [unterminated\n"))
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestSaveWritesToDefaultConfigPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := &Config{
		VaultDir:       filepath.Join(home, ".openpass"),
		DefaultAgent:   "default",
		SessionTimeout: defaultSessionTimeout,
		Agents: map[string]AgentProfile{
			"default": {
				Name:         "default",
				AllowedPaths: []string{},
				CanWrite:     false,
				ApprovalMode: "none",
			},
		},
	}

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	wantPath := filepath.Join(home, ".openpass", "config.yaml")
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("config file missing at %q: %v", wantPath, err)
	}

	loaded, err := Load(wantPath)
	if err != nil {
		t.Fatalf("Load(saved) error = %v", err)
	}
	agent := loaded.Agents["default"]
	if agent.CanWrite != false || agent.ApprovalMode != "none" {
		t.Fatalf("saved agent = %+v, want CanWrite=false ApprovalMode=none", agent)
	}
}

func TestSaveCreatesConfigDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := Default()
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(home, ".openpass")); err != nil {
		t.Fatalf("config directory missing: %v", err)
	}
}

func TestLoadParsesApprovalMode(t *testing.T) {
	t.Parallel()

	yaml := "agents:\n  myagent:\n    allowedPaths: [\"*\"]\n    canWrite: true\n    approvalMode: deny\n"
	path := writeTempFile(t, []byte(yaml))

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	agent := cfg.Agents["myagent"]
	if agent.ApprovalMode != "deny" {
		t.Fatalf("ApprovalMode = %q, want %q", agent.ApprovalMode, "deny")
	}
}

func TestLoadMapsRequireApprovalToApprovalMode(t *testing.T) {
	t.Parallel()

	yaml := "agents:\n  old-agent:\n    allowedPaths: [\"*\"]\n    canWrite: true\n    requireApproval: true\n"
	path := writeTempFile(t, []byte(yaml))

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	agent := cfg.Agents["old-agent"]
	if agent.ApprovalMode != "prompt" {
		t.Fatalf("ApprovalMode = %q, want %q", agent.ApprovalMode, "prompt")
	}
}

func TestLoadApprovalModeTakesPrecedence(t *testing.T) {
	t.Parallel()

	yaml := "agents:\n  both:\n    allowedPaths: [\"*\"]\n    canWrite: true\n    requireApproval: true\n    approvalMode: none\n"
	path := writeTempFile(t, []byte(yaml))

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	agent := cfg.Agents["both"]
	if agent.ApprovalMode != "none" {
		t.Fatalf("ApprovalMode = %q, want %q", agent.ApprovalMode, "none")
	}
}

func TestLoadRejectsInvalidApprovalMode(t *testing.T) {
	t.Parallel()

	yaml := "agents:\n  bad:\n    approvalMode: invalid\n"
	path := writeTempFile(t, []byte(yaml))

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected error for invalid approvalMode, got nil")
	}
}

func TestLoadParsesRedactFields(t *testing.T) {
	t.Parallel()

	yaml := "agents:\n  restricted:\n    allowedPaths: [\"*\"]\n    canWrite: false\n    redactFields:\n      - totp.secret\n      - password\n      - api.*\n"
	path := writeTempFile(t, []byte(yaml))

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	agent := cfg.Agents["restricted"]
	if len(agent.RedactFields) != 3 {
		t.Fatalf("RedactFields length = %d, want 3", len(agent.RedactFields))
	}
	if agent.RedactFields[0] != "totp.secret" {
		t.Errorf("RedactFields[0] = %q, want %q", agent.RedactFields[0], "totp.secret")
	}
	if agent.RedactFields[1] != "password" {
		t.Errorf("RedactFields[1] = %q, want %q", agent.RedactFields[1], "password")
	}
	if agent.RedactFields[2] != "api.*" {
		t.Errorf("RedactFields[2] = %q, want %q", agent.RedactFields[2], "api.*")
	}
}

func TestSaveWritesRedactFields(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := &Config{
		VaultDir:       filepath.Join(home, ".openpass"),
		DefaultAgent:   "default",
		SessionTimeout: defaultSessionTimeout,
		Agents: map[string]AgentProfile{
			"restricted": {
				Name:         "restricted",
				AllowedPaths: []string{"*"},
				CanWrite:     false,
				ApprovalMode: "deny",
				RedactFields: []string{"totp.secret", "password"},
			},
		},
	}

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := Load(filepath.Join(home, ".openpass", "config.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	agent := loaded.Agents["restricted"]
	if len(agent.RedactFields) != 2 {
		t.Fatalf("RedactFields length = %d, want 2", len(agent.RedactFields))
	}
	if agent.RedactFields[0] != "totp.secret" || agent.RedactFields[1] != "password" {
		t.Errorf("RedactFields = %v, want [totp.secret password]", agent.RedactFields)
	}
}

func TestNewDefaultAgentProfile(t *testing.T) {
	t.Parallel()

	profile := newDefaultAgentProfile("test-agent")

	if profile.Name != "test-agent" {
		t.Errorf("Name = %q, want %q", profile.Name, "test-agent")
	}
	if profile.AllowedPaths == nil {
		t.Fatal("AllowedPaths should not be nil")
	}
	if len(profile.AllowedPaths) != 0 {
		t.Errorf("AllowedPaths length = %d, want 0", len(profile.AllowedPaths))
	}
	if profile.CanWrite {
		t.Error("CanWrite should be false")
	}
	if profile.ApprovalMode != "none" {
		t.Errorf("ApprovalMode = %q, want %q", profile.ApprovalMode, "none")
	}
}

func TestLoadWithVaultGitMCPSections(t *testing.T) {
	t.Parallel()

	yaml := `vault:
  path: /my/vault
  default_recipients:
    - age1abc
git:
  auto_push: false
  commit_template: "custom commit"
mcp:
  port: 9090
  bind: "0.0.0.0"
clipboard:
  auto_clear_duration: 60
`
	path := writeTempFile(t, []byte(yaml))

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Vault == nil {
		t.Fatal("Vault should not be nil")
	}
	if cfg.Vault.Path != "/my/vault" {
		t.Errorf("Vault.Path = %q, want %q", cfg.Vault.Path, "/my/vault")
	}
	if len(cfg.Vault.DefaultRecipients) != 1 || cfg.Vault.DefaultRecipients[0] != "age1abc" {
		t.Errorf("Vault.DefaultRecipients = %v, want [age1abc]", cfg.Vault.DefaultRecipients)
	}

	if cfg.Git == nil {
		t.Fatal("Git should not be nil")
	}
	if cfg.Git.AutoPush {
		t.Error("Git.AutoPush should be false")
	}
	if cfg.Git.CommitTemplate != "custom commit" {
		t.Errorf("Git.CommitTemplate = %q, want %q", cfg.Git.CommitTemplate, "custom commit")
	}

	if cfg.MCP == nil {
		t.Fatal("MCP should not be nil")
	}
	if cfg.MCP.Port != 9090 {
		t.Errorf("MCP.Port = %d, want %d", cfg.MCP.Port, 9090)
	}
	if cfg.MCP.Bind != "0.0.0.0" {
		t.Errorf("MCP.Bind = %q, want %q", cfg.MCP.Bind, "0.0.0.0")
	}

	if cfg.Clipboard == nil {
		t.Fatal("Clipboard should not be nil")
	}
	if cfg.Clipboard.AutoClearDuration != 60 {
		t.Errorf("Clipboard.AutoClearDuration = %d, want %d", cfg.Clipboard.AutoClearDuration, 60)
	}
}

func TestLoadWithOnlyVaultSection(t *testing.T) {
	t.Parallel()

	yaml := `vault:
  path: /only/vault
`
	path := writeTempFile(t, []byte(yaml))

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Vault == nil {
		t.Fatal("Vault should not be nil")
	}
	if cfg.Vault.Path != "/only/vault" {
		t.Errorf("Vault.Path = %q, want %q", cfg.Vault.Path, "/only/vault")
	}
}

func TestSaveWithAllConfigSections(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := &Config{
		VaultDir:       filepath.Join(home, ".openpass"),
		DefaultAgent:   "default",
		SessionTimeout: defaultSessionTimeout,
		Agents: map[string]AgentProfile{
			"default": {
				Name:         "default",
				AllowedPaths: []string{"*"},
				CanWrite:     false,
				ApprovalMode: "none",
			},
		},
		Vault: &VaultConfig{
			Path:              "/vault/path",
			DefaultRecipients: []string{"recipient1"},
			ConfirmRemove:     true,
		},
		Git: &GitConfig{
			AutoPush:       false,
			CommitTemplate: "custom",
		},
		MCP: &MCPConfig{
			Port:          9090,
			Bind:          "0.0.0.0",
			Stdio:         true,
			HTTPTokenFile: "/token/path",
		},
		Update: &UpdateConfig{
			CacheTTL: 24 * time.Hour,
		},
		Clipboard: &ClipboardConfig{
			AutoClearDuration: 60,
		},
	}

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	wantPath := filepath.Join(home, ".openpass", "config.yaml")
	loaded, err := Load(wantPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.Vault == nil {
		t.Fatal("Vault should be saved and loaded")
	}
	if loaded.Vault.Path != "/vault/path" {
		t.Errorf("Vault.Path = %q, want %q", loaded.Vault.Path, "/vault/path")
	}
	if loaded.Vault.DefaultRecipients[0] != "recipient1" {
		t.Errorf("Vault.DefaultRecipients = %v, want [recipient1]", loaded.Vault.DefaultRecipients)
	}

	if loaded.Git == nil {
		t.Fatal("Git should be saved and loaded")
	}
	if loaded.Git.AutoPush {
		t.Error("Git.AutoPush should be false")
	}

	if loaded.MCP == nil {
		t.Fatal("MCP should be saved and loaded")
	}
	if loaded.MCP.Port != 9090 {
		t.Errorf("MCP.Port = %d, want %d", loaded.MCP.Port, 9090)
	}

	if loaded.Clipboard == nil {
		t.Fatal("Clipboard should be saved and loaded")
	}
	if loaded.Clipboard.AutoClearDuration != 60 {
		t.Errorf("Clipboard.AutoClearDuration = %d, want %d", loaded.Clipboard.AutoClearDuration, 60)
	}
}

func TestSaveWithNilConfigReturnsError(t *testing.T) {
	var cfg *Config
	if err := cfg.Save(); err == nil {
		t.Fatal("Save() on nil Config should return error")
	}
}

func TestSaveLoadRoundTrip_PreservesAllFields(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := &Config{
		VaultDir:       filepath.Join(home, ".openpass"),
		DefaultAgent:   "test-agent",
		SessionTimeout: defaultSessionTimeout,
		Agents: map[string]AgentProfile{
			"test-agent": {
				Name:            "test-agent",
				AllowedPaths:    []string{"path1", "path2"},
				CanWrite:        true,
				ApprovalMode:    "prompt",
				ApprovalTimeout: 2 * time.Minute,
				RequireApproval: true,
				DynamicProviders: map[string][]string{
					"postgres": {"readonly", "admin"},
					"aws-sts":  {"*"},
				},
			},
		},
		Vault: &VaultConfig{
			Path:              "/vault/path",
			DefaultRecipients: []string{"recipient1", "recipient2"},
			ConfirmRemove:     true,
		},
		MCP: &MCPConfig{
			Port:              9090,
			Bind:              "0.0.0.0",
			Stdio:             true,
			HTTPTokenFile:     "/token/path",
			ReadHeaderTimeout: 7 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      20 * time.Second,
			ShutdownTimeout:   8 * time.Second,
			ApprovalTimeout:   45 * time.Second,
		},
		Clipboard: &ClipboardConfig{
			AutoClearDuration: 90,
		},
	}

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	wantPath := filepath.Join(home, ".openpass", "config.yaml")
	loaded, err := Load(wantPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify Vault
	if loaded.Vault == nil {
		t.Fatal("Vault should not be nil after round-trip")
	}
	if loaded.Vault.Path != cfg.Vault.Path {
		t.Errorf("Vault.Path = %q, want %q", loaded.Vault.Path, cfg.Vault.Path)
	}
	if len(loaded.Vault.DefaultRecipients) != len(cfg.Vault.DefaultRecipients) {
		t.Errorf("Vault.DefaultRecipients len = %d, want %d", len(loaded.Vault.DefaultRecipients), len(cfg.Vault.DefaultRecipients))
	}
	if loaded.Vault.ConfirmRemove != cfg.Vault.ConfirmRemove {
		t.Errorf("Vault.ConfirmRemove = %v, want %v", loaded.Vault.ConfirmRemove, cfg.Vault.ConfirmRemove)
	}

	// Verify MCP
	if loaded.MCP == nil {
		t.Fatal("MCP should not be nil after round-trip")
	}
	if loaded.MCP.Port != cfg.MCP.Port {
		t.Errorf("MCP.Port = %d, want %d", loaded.MCP.Port, cfg.MCP.Port)
	}
	if loaded.MCP.Bind != cfg.MCP.Bind {
		t.Errorf("MCP.Bind = %q, want %q", loaded.MCP.Bind, cfg.MCP.Bind)
	}
	if loaded.MCP.Stdio != cfg.MCP.Stdio {
		t.Errorf("MCP.Stdio = %v, want %v", loaded.MCP.Stdio, cfg.MCP.Stdio)
	}
	if loaded.MCP.HTTPTokenFile != cfg.MCP.HTTPTokenFile {
		t.Errorf("MCP.HTTPTokenFile = %q, want %q", loaded.MCP.HTTPTokenFile, cfg.MCP.HTTPTokenFile)
	}
	if loaded.MCP.ReadHeaderTimeout != cfg.MCP.ReadHeaderTimeout {
		t.Errorf("MCP.ReadHeaderTimeout = %v, want %v", loaded.MCP.ReadHeaderTimeout, cfg.MCP.ReadHeaderTimeout)
	}
	if loaded.MCP.ReadTimeout != cfg.MCP.ReadTimeout {
		t.Errorf("MCP.ReadTimeout = %v, want %v", loaded.MCP.ReadTimeout, cfg.MCP.ReadTimeout)
	}
	if loaded.MCP.WriteTimeout != cfg.MCP.WriteTimeout {
		t.Errorf("MCP.WriteTimeout = %v, want %v", loaded.MCP.WriteTimeout, cfg.MCP.WriteTimeout)
	}
	if loaded.MCP.ShutdownTimeout != cfg.MCP.ShutdownTimeout {
		t.Errorf("MCP.ShutdownTimeout = %v, want %v", loaded.MCP.ShutdownTimeout, cfg.MCP.ShutdownTimeout)
	}
	if loaded.MCP.ApprovalTimeout != cfg.MCP.ApprovalTimeout {
		t.Errorf("MCP.ApprovalTimeout = %v, want %v", loaded.MCP.ApprovalTimeout, cfg.MCP.ApprovalTimeout)
	}

	// Verify Clipboard
	if loaded.Clipboard == nil {
		t.Fatal("Clipboard should not be nil after round-trip")
	}
	if loaded.Clipboard.AutoClearDuration != cfg.Clipboard.AutoClearDuration {
		t.Errorf("Clipboard.AutoClearDuration = %d, want %d", loaded.Clipboard.AutoClearDuration, cfg.Clipboard.AutoClearDuration)
	}

	// Verify AgentProfile
	agent, ok := loaded.Agents["test-agent"]
	if !ok {
		t.Fatal("test-agent profile should exist after round-trip")
	}
	if agent.CanWrite != cfg.Agents["test-agent"].CanWrite {
		t.Errorf("agent.CanWrite = %v, want %v", agent.CanWrite, cfg.Agents["test-agent"].CanWrite)
	}
	if agent.RequireApproval != cfg.Agents["test-agent"].RequireApproval {
		t.Errorf("agent.RequireApproval = %v, want %v", agent.RequireApproval, cfg.Agents["test-agent"].RequireApproval)
	}
	if agent.ApprovalTimeout != cfg.Agents["test-agent"].ApprovalTimeout {
		t.Errorf("agent.ApprovalTimeout = %v, want %v", agent.ApprovalTimeout, cfg.Agents["test-agent"].ApprovalTimeout)
	}
	if agent.ApprovalMode != cfg.Agents["test-agent"].ApprovalMode {
		t.Errorf("agent.ApprovalMode = %q, want %q", agent.ApprovalMode, cfg.Agents["test-agent"].ApprovalMode)
	}
	if len(agent.AllowedPaths) != len(cfg.Agents["test-agent"].AllowedPaths) {
		t.Errorf("agent.AllowedPaths len = %d, want %d", len(agent.AllowedPaths), len(cfg.Agents["test-agent"].AllowedPaths))
	}
	if agent.ExposeValueTools != cfg.Agents["test-agent"].ExposeValueTools {
		t.Errorf("agent.ExposeValueTools = %v, want %v", agent.ExposeValueTools, cfg.Agents["test-agent"].ExposeValueTools)
	}
	if agent.DynamicProviders == nil {
		t.Fatal("agent.DynamicProviders should not be nil after round-trip")
	}
	if len(agent.DynamicProviders) != 2 {
		t.Errorf("agent.DynamicProviders len = %d, want 2", len(agent.DynamicProviders))
	}
	if roles, ok := agent.DynamicProviders["postgres"]; !ok {
		t.Error("agent.DynamicProviders missing postgres provider")
	} else if len(roles) != 2 || roles[0] != "readonly" || roles[1] != "admin" {
		t.Errorf("agent.DynamicProviders['postgres'] = %v, want [readonly admin]", roles)
	}
	if roles, ok := agent.DynamicProviders["aws-sts"]; !ok {
		t.Error("agent.DynamicProviders missing aws-sts provider")
	} else if len(roles) != 1 || roles[0] != "*" {
		t.Errorf("agent.DynamicProviders['aws-sts'] = %v, want [*]", roles)
	}
}

func mustHomeDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir() error = %v", err)
	}
	return home
}

func TestLoadParsesRateLimitAndUpdateCacheTTL(t *testing.T) {
	t.Parallel()

	content := []byte(`
mcp:
  rate_limit: 120
update:
  cache_ttl: 12h
`)
	path := writeTempFile(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.MCP == nil {
		t.Fatal("MCP config is nil")
	}
	if cfg.MCP.RateLimit != 120 {
		t.Errorf("MCP.RateLimit = %d, want 120", cfg.MCP.RateLimit)
	}
	if cfg.Update == nil {
		t.Fatal("Update config is nil")
	}
	if cfg.Update.CacheTTL != 12*time.Hour {
		t.Errorf("Update.CacheTTL = %v, want 12h", cfg.Update.CacheTTL)
	}
}

func TestLoadDefaultsForRateLimitAndUpdateCacheTTL(t *testing.T) {
	t.Parallel()

	path := writeTempFile(t, []byte("{}\n"))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// When no MCP section is present, cfg.MCP is nil and callers use defaults
	if cfg.MCP != nil {
		t.Errorf("MCP config should be nil when not specified, got %+v", cfg.MCP)
	}
	// When no Update section is present, cfg.Update is nil and callers use defaults
	if cfg.Update != nil {
		t.Errorf("Update config should be nil when not specified, got %+v", cfg.Update)
	}

	// Verify defaults are used when section is explicitly empty
	path2 := writeTempFile(t, []byte("mcp:\n  bind: 127.0.0.1\nupdate:\n  cache_ttl: 0s\n"))
	cfg2, err := Load(path2)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg2.MCP == nil {
		t.Fatal("MCP config is nil")
	}
	if cfg2.MCP.RateLimit != 60 {
		t.Errorf("MCP.RateLimit default = %d, want 60", cfg2.MCP.RateLimit)
	}
	if cfg2.Update == nil {
		t.Fatal("Update config is nil")
	}
	if cfg2.Update.CacheTTL != 0 {
		t.Errorf("Update.CacheTTL = %v, want 0", cfg2.Update.CacheTTL)
	}
}

func writeTempFile(t *testing.T, content []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

// --- Validation Edge-Case Tests ---

func TestValidateConfigPath_RejectsTraversal(t *testing.T) {
	t.Parallel()

	// These paths escape the expected directory via ..
	badPaths := []string{
		"../etc/passwd",
		"foo/../../etc/passwd",
		"foo/bar/../../../root/.ssh",
		"./../../../etc",
		"..",
	}
	for _, p := range badPaths {
		err := validateConfigPath(p)
		if err == nil {
			t.Errorf("validateConfigPath(%q) = nil, want error", p)
		}
	}
}

func TestValidateConfigPath_AcceptsValidPaths(t *testing.T) {
	t.Parallel()

	validPaths := []string{
		"config.yaml",
		"subdir/config.yaml",
		"./config.yaml",
		"foo/bar.yaml",
		"~/.openpass/config.yaml",
	}
	for _, p := range validPaths {
		err := validateConfigPath(p)
		if err != nil {
			t.Errorf("validateConfigPath(%q) = %v, want nil", p, err)
		}
	}
}

func TestLoad_RejectsEmptyMCPBind(t *testing.T) {
	t.Parallel()

	// MCP bind is explicitly set to empty string, which should fail
	yaml := `mcp:
  bind: ""
`
	path := writeTempFile(t, []byte(yaml))
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() with empty MCP bind should return error")
	}
}

func TestLoad_RejectsMissingMCPBind(t *testing.T) {
	t.Parallel()

	// MCP section present but bind explicitly empty string
	yaml := `mcp:
  bind: ""
`
	path := writeTempFile(t, []byte(yaml))
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() with empty MCP bind should return error")
	}
}

func TestLoad_AcceptsZeroMCPBindBecauseDefault(t *testing.T) {
	t.Parallel()

	// MCP section with port only, bind defaults to 127.0.0.1 which is non-empty
	yaml := `mcp:
  port: 8080
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.MCP == nil {
		t.Fatal("MCP should not be nil")
	}
	if cfg.MCP.Bind != "127.0.0.1" {
		t.Errorf("MCP.Bind = %q, want 127.0.0.1", cfg.MCP.Bind)
	}
}

func TestLoad_RejectsInvalidApprovalMode(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		yaml string
	}{
		{"invalid_mode", `agents:
  test:
    approvalMode: invalid_mode
`},
		{"random_string", `agents:
  test:
    approvalMode: something
`},
		{"numeric", `agents:
  test:
    approvalMode: 123
`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempFile(t, []byte(tc.yaml))
			_, err := Load(path)
			if err == nil {
				t.Errorf("Load() with approvalMode %q = nil, want error", tc.name)
			}
		})
	}
}

func TestLoad_AcceptsAllValidApprovalModes(t *testing.T) {
	t.Parallel()

	validModes := []string{"none", "deny", "prompt"}
	for _, mode := range validModes {
		yaml := "agents:\n  test:\n    approvalMode: " + mode + "\n"
		path := writeTempFile(t, []byte(yaml))
		cfg, err := Load(path)
		if err != nil {
			t.Errorf("Load() with approvalMode %q = error %v", mode, err)
		} else if cfg.Agents["test"].ApprovalMode != mode {
			t.Errorf("ApprovalMode = %q, want %q", cfg.Agents["test"].ApprovalMode, mode)
		}
	}
}

func TestLoad_RequireApprovalTrueMapsToPrompt(t *testing.T) {
	t.Parallel()

	yaml := `agents:
  test:
    requireApproval: true
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Agents["test"].ApprovalMode != "prompt" {
		t.Errorf("ApprovalMode = %q, want prompt", cfg.Agents["test"].ApprovalMode)
	}
}

func TestLoad_RequireApprovalFalseMapsToNone(t *testing.T) {
	t.Parallel()

	yaml := `agents:
  test:
    requireApproval: false
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Agents["test"].ApprovalMode != "none" {
		t.Errorf("ApprovalMode = %q, want none", cfg.Agents["test"].ApprovalMode)
	}
}

func TestLoad_ApprovalModePrecedenceOverRequireApproval(t *testing.T) {
	t.Parallel()

	yaml := `agents:
  test:
    requireApproval: true
    approvalMode: deny
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Agents["test"].ApprovalMode != "deny" {
		t.Errorf("ApprovalMode = %q, want deny (approvalMode should take precedence)", cfg.Agents["test"].ApprovalMode)
	}
}

// --- Default Value Tests ---

func TestDefault_ReturnsBuiltInAgentProfiles(t *testing.T) {
	t.Parallel()

	cfg := Default()

	wantProfiles := []string{"default", "claude-code", "codex", "hermes", "openclaw", "opencode"}
	for _, name := range wantProfiles {
		if _, ok := cfg.Agents[name]; !ok {
			t.Errorf("missing built-in profile: %s", name)
		}
	}
}

func TestDefault_SessionTimeoutHasDefault(t *testing.T) {
	t.Parallel()

	cfg := Default()
	if cfg.SessionTimeout != defaultSessionTimeout {
		t.Errorf("SessionTimeout = %v, want %v", cfg.SessionTimeout, defaultSessionTimeout)
	}
}

func TestDefault_VaultDirIncludesHome(t *testing.T) {
	t.Parallel()

	cfg := Default()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir")
	}
	expectedPrefix := home + string(filepath.Separator)
	if cfg.VaultDir[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("VaultDir = %q, want prefix %q", cfg.VaultDir, expectedPrefix)
	}
}

func TestLoad_MissingAgentProfileCreatesDefault(t *testing.T) {
	t.Parallel()

	// When a referenced defaultAgent doesn't exist in the file,
	// Load should create it
	yaml := `defaultAgent: nonexistent
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if _, ok := cfg.Agents["nonexistent"]; !ok {
		t.Error("nonexistent agent should be auto-created")
	}
	if cfg.DefaultAgent != "nonexistent" {
		t.Errorf("DefaultAgent = %q, want nonexistent", cfg.DefaultAgent)
	}
}

func TestLoad_AgentsMapNeverNil(t *testing.T) {
	t.Parallel()

	// Even with empty config, Agents map should be initialized
	path := writeTempFile(t, []byte("{}\n"))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Agents == nil {
		t.Fatal("Agents should not be nil")
	}
	if len(cfg.Agents) == 0 {
		t.Error("Agents should contain built-in profiles")
	}
}

// --- File Permission/Error Tests ---

func TestLoad_NonexistentDirectory(t *testing.T) {
	t.Parallel()

	// Path in a directory that doesn't exist
	nonExistentPath := filepath.Join(t.TempDir(), "does", "not", "exist", "config.yaml")
	_, err := Load(nonExistentPath)
	if err == nil {
		t.Fatal("Load() on nonexistent path should return error")
	}
}

func TestSave_PermissionDeniedOnReadOnlyDir(t *testing.T) {
	t.Skip("Skipping: root-owned temp dir not reliable on macOS")

	// Create a read-only directory
	home := t.TempDir()
	readonlyDir := filepath.Join(home, "readonly")
	if err := os.MkdirAll(readonlyDir, 0o444); err != nil {
		t.Skip("cannot create readonly dir")
	}
	t.Setenv("HOME", home)

	cfg := &Config{
		VaultDir:       filepath.Join(readonlyDir, ".openpass"),
		DefaultAgent:   "default",
		SessionTimeout: defaultSessionTimeout,
		Agents:         builtinAgentProfiles(),
	}

	err := cfg.Save()
	if err == nil {
		t.Fatal("Save() to read-only directory should fail")
	}
}

func TestSave_FilePermissionDenied(t *testing.T) {
	t.Skip("Skipping: root-owned temp dir not reliable on macOS")

	home := t.TempDir()
	readonlyDir := filepath.Join(home, ".openpass")
	if err := os.MkdirAll(readonlyDir, 0o500); err != nil {
		t.Skip("cannot create dir with restricted perms")
	}
	t.Setenv("HOME", home)

	// Create a file inside that's read-only
	configPath := filepath.Join(readonlyDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("test: true\n"), 0o400); err != nil {
		t.Skip("cannot create read-only file")
	}

	cfg := &Config{
		VaultDir:       readonlyDir,
		DefaultAgent:   "default",
		SessionTimeout: defaultSessionTimeout,
		Agents:         builtinAgentProfiles(),
	}

	err := cfg.Save()
	if err == nil {
		t.Fatal("Save() to read-only file should fail")
	}
}

// --- Nested Config Structure Tests ---

func TestLoad_MCPWithAllTimeoutFields(t *testing.T) {
	t.Parallel()

	yaml := `mcp:
  port: 9090
  bind: "0.0.0.0"
  read_header_timeout: 3s
  read_timeout: 15s
  write_timeout: 20s
  shutdown_timeout: 8s
  approval_timeout: 45s
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.MCP == nil {
		t.Fatal("MCP should not be nil")
	}
	if cfg.MCP.ReadHeaderTimeout != 3*time.Second {
		t.Errorf("MCP.ReadHeaderTimeout = %v, want 3s", cfg.MCP.ReadHeaderTimeout)
	}
	if cfg.MCP.ReadTimeout != 15*time.Second {
		t.Errorf("MCP.ReadTimeout = %v, want 15s", cfg.MCP.ReadTimeout)
	}
	if cfg.MCP.WriteTimeout != 20*time.Second {
		t.Errorf("MCP.WriteTimeout = %v, want 20s", cfg.MCP.WriteTimeout)
	}
	if cfg.MCP.ShutdownTimeout != 8*time.Second {
		t.Errorf("MCP.ShutdownTimeout = %v, want 8s", cfg.MCP.ShutdownTimeout)
	}
	if cfg.MCP.ApprovalTimeout != 45*time.Second {
		t.Errorf("MCP.ApprovalTimeout = %v, want 45s", cfg.MCP.ApprovalTimeout)
	}
}

func TestLoad_VaultWithAllFields(t *testing.T) {
	t.Parallel()

	yaml := `vault:
  path: /custom/vault
  default_recipients:
    - age1recipient1
    - age1recipient2
  confirm_remove: true
  useTouchID: true
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Vault == nil {
		t.Fatal("Vault should not be nil")
	}
	if cfg.Vault.Path != "/custom/vault" {
		t.Errorf("Vault.Path = %q, want /custom/vault", cfg.Vault.Path)
	}
	if len(cfg.Vault.DefaultRecipients) != 2 {
		t.Errorf("Vault.DefaultRecipients len = %d, want 2", len(cfg.Vault.DefaultRecipients))
	}
	if !cfg.Vault.ConfirmRemove {
		t.Error("Vault.ConfirmRemove should be true")
	}
	if !cfg.Vault.UseTouchID {
		t.Error("Vault.UseTouchID should be true")
	}
}

func TestLoad_GitWithAllFields(t *testing.T) {
	t.Parallel()

	yaml := `git:
  auto_push: false
  commit_template: "Custom: {{.Date}} {{.Message}}"
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Git == nil {
		t.Fatal("Git should not be nil")
	}
	if cfg.Git.AutoPush {
		t.Error("Git.AutoPush should be false")
	}
	if cfg.Git.CommitTemplate != "Custom: {{.Date}} {{.Message}}" {
		t.Errorf("Git.CommitTemplate = %q", cfg.Git.CommitTemplate)
	}
}

func TestLoad_UpdateWithCacheTTL(t *testing.T) {
	t.Parallel()

	yaml := `update:
  cache_ttl: 48h
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Update == nil {
		t.Fatal("Update should not be nil")
	}
	if cfg.Update.CacheTTL != 48*time.Hour {
		t.Errorf("Update.CacheTTL = %v, want 48h", cfg.Update.CacheTTL)
	}
}

func TestLoad_ClipboardWithAutoClearDuration(t *testing.T) {
	t.Parallel()

	yaml := `clipboard:
  auto_clear_duration: 0
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Clipboard == nil {
		t.Fatal("Clipboard should not be nil")
	}
	if cfg.Clipboard.AutoClearDuration != 0 {
		t.Errorf("Clipboard.AutoClearDuration = %d, want 0 (disabled)", cfg.Clipboard.AutoClearDuration)
	}
}

func TestLoad_AllSectionsTogether(t *testing.T) {
	t.Parallel()

	yaml := `vaultDir: /global/vault
defaultAgent: claude-code
sessionTimeout: 30m
useTouchID: true
agents:
  claude-code:
    allowedPaths:
      - "work/*"
      - "personal/*"
    canWrite: true
    approvalMode: none
vault:
  path: /global/vault
  default_recipients:
    - age1global
git:
  auto_push: true
mcp:
  port: 9090
  bind: "0.0.0.0"
update:
  cache_ttl: 12h
clipboard:
  auto_clear_duration: 60
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.VaultDir != "/global/vault" {
		t.Errorf("VaultDir = %q, want /global/vault", cfg.VaultDir)
	}
	if cfg.DefaultAgent != "claude-code" {
		t.Errorf("DefaultAgent = %q, want claude-code", cfg.DefaultAgent)
	}
	if cfg.SessionTimeout != 30*time.Minute {
		t.Errorf("SessionTimeout = %v, want 30m", cfg.SessionTimeout)
	}
	if !cfg.UseTouchID {
		t.Error("UseTouchID should be true")
	}

	agent := cfg.Agents["claude-code"]
	if len(agent.AllowedPaths) != 2 {
		t.Errorf("AllowedPaths len = %d, want 2", len(agent.AllowedPaths))
	}
	if !agent.CanWrite {
		t.Error("CanWrite should be true")
	}

	if cfg.Vault == nil || cfg.Vault.Path != "/global/vault" {
		t.Error("Vault not properly loaded")
	}
	if cfg.Git == nil || !cfg.Git.AutoPush {
		t.Error("Git not properly loaded")
	}
	if cfg.MCP == nil || cfg.MCP.Port != 9090 {
		t.Error("MCP not properly loaded")
	}
	if cfg.Update == nil || cfg.Update.CacheTTL != 12*time.Hour {
		t.Error("Update not properly loaded")
	}
	if cfg.Clipboard == nil || cfg.Clipboard.AutoClearDuration != 60 {
		t.Error("Clipboard not properly loaded")
	}
}

// --- MCP Deprecated Field Test ---

func TestMergeFileMCPConfig_DeprecatedApprovalRequired(t *testing.T) {
	t.Parallel()

	defaults := defaultMCPConfig()
	approvalRequired := true
	fileCfg := &fileMCPConfig{
		ApprovalRequired: &approvalRequired,
	}
	// Should not error, just print warning
	result := MergeFileMCPConfig(fileCfg, defaults)
	if result.ApprovalRequired {
		t.Error("ApprovalRequired should not be set in result (deprecated, ignored)")
	}
}

// --- Update Section Missing Field Test ---

func TestMergeFileUpdateConfig_NilCacheTTL(t *testing.T) {
	t.Parallel()

	defaults := defaultUpdateConfig()
	// File config with nil CacheTTL (section present but field omitted)
	fileCfg := &fileUpdateConfig{
		CacheTTL: nil,
	}
	result := MergeFileUpdateConfig(fileCfg, defaults)

	// Should keep the default value
	if result.CacheTTL != defaults.CacheTTL {
		t.Errorf("CacheTTL = %v, want default %v", result.CacheTTL, defaults.CacheTTL)
	}
}

// --- SessionTimeout Edge Cases ---

func TestLoad_NegativeSessionTimeout_Ignored(t *testing.T) {
	t.Parallel()

	// Zero or negative session timeout in file should be ignored (kept at default)
	yaml := `sessionTimeout: -5m
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// Should still be default since -5m < 0 is ignored
	if cfg.SessionTimeout != defaultSessionTimeout {
		t.Errorf("SessionTimeout = %v, want %v (negative should be ignored)", cfg.SessionTimeout, defaultSessionTimeout)
	}
}

func TestLoad_ZeroSessionTimeout_Ignored(t *testing.T) {
	t.Parallel()

	yaml := `sessionTimeout: 0s
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// Zero should also be ignored (line 115: raw.SessionTimeout > 0)
	if cfg.SessionTimeout != defaultSessionTimeout {
		t.Errorf("SessionTimeout = %v, want %v (zero should be ignored)", cfg.SessionTimeout, defaultSessionTimeout)
	}
}

// --- UseTouchID Tests ---

func TestLoad_UseTouchIDTrue(t *testing.T) {
	t.Parallel()

	yaml := `useTouchID: true
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.UseTouchID {
		t.Error("UseTouchID should be true")
	}
}

func TestLoad_UseTouchIDFalse(t *testing.T) {
	t.Parallel()

	yaml := `useTouchID: false
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.UseTouchID {
		t.Error("UseTouchID should be false")
	}
}

// --- Agent AllowedPaths Tests ---

func TestLoad_AgentAllowedPathsNil(t *testing.T) {
	t.Parallel()

	yaml := `agents:
  test:
    allowedPaths: ~
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// When allowedPaths is null in YAML, it should become empty slice
	agent := cfg.Agents["test"]
	if agent.AllowedPaths == nil {
		t.Error("AllowedPaths should not be nil (should be empty slice)")
	}
	if len(agent.AllowedPaths) != 0 {
		t.Errorf("AllowedPaths len = %d, want 0", len(agent.AllowedPaths))
	}
}

func TestLoad_AgentAllowedPathsMultiple(t *testing.T) {
	t.Parallel()

	yaml := `agents:
  test:
    allowedPaths:
      - "work/*"
      - "personal/*"
      - "shared/*"
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	agent := cfg.Agents["test"]
	if len(agent.AllowedPaths) != 3 {
		t.Errorf("AllowedPaths len = %d, want 3", len(agent.AllowedPaths))
	}
}

// --- DefaultConfigPath Tests ---

func TestDefaultConfigPath_ReturnsExpectedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	path, err := defaultConfigPath()
	if err != nil {
		t.Fatalf("defaultConfigPath() error = %v", err)
	}

	expected := filepath.Join(home, ".openpass", "config.yaml")
	if path != expected {
		t.Errorf("defaultConfigPath() = %q, want %q", path, expected)
	}
}

// --- Empty Config File Tests ---

func TestLoad_WhitespaceOnlyFile(t *testing.T) {
	t.Parallel()

	path := writeTempFile(t, []byte("   \n\t\n  \n"))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// Should return defaults for everything
	if cfg.VaultDir == "" {
		t.Error("VaultDir should not be empty")
	}
	if cfg.DefaultAgent != "default" {
		t.Errorf("DefaultAgent = %q, want default", cfg.DefaultAgent)
	}
}

// --- MergeFileMCPConfig full timeout coverage ---

func TestMergeFileMCPConfig_AllTimeouts(t *testing.T) {
	t.Parallel()

	defaults := defaultMCPConfig()
	readHeaderTimeout := 3 * time.Second
	readTimeout := 15 * time.Second
	writeTimeout := 20 * time.Second
	shutdownTimeout := 8 * time.Second
	approvalTimeout := 45 * time.Second

	fileCfg := &fileMCPConfig{
		ReadHeaderTimeout: &readHeaderTimeout,
		ReadTimeout:       &readTimeout,
		WriteTimeout:      &writeTimeout,
		ShutdownTimeout:   &shutdownTimeout,
		ApprovalTimeout:   &approvalTimeout,
	}
	result := MergeFileMCPConfig(fileCfg, defaults)

	if result.ReadHeaderTimeout != 3*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 3s", result.ReadHeaderTimeout)
	}
	if result.ReadTimeout != 15*time.Second {
		t.Errorf("ReadTimeout = %v, want 15s", result.ReadTimeout)
	}
	if result.WriteTimeout != 20*time.Second {
		t.Errorf("WriteTimeout = %v, want 20s", result.WriteTimeout)
	}
	if result.ShutdownTimeout != 8*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 8s", result.ShutdownTimeout)
	}
	if result.ApprovalTimeout != 45*time.Second {
		t.Errorf("ApprovalTimeout = %v, want 45s", result.ApprovalTimeout)
	}
}

// --- Validate() Tests ---

func TestValidate_ValidConfigPasses(t *testing.T) {
	t.Parallel()
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() on default config = %v, want nil", err)
	}
}

func TestValidate_EmptyVaultDirFails(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.VaultDir = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() with empty VaultDir = nil, want error")
	}
	if !strings.Contains(err.Error(), "vaultDir") {
		t.Errorf("error = %q, should mention vaultDir", err.Error())
	}
}

func TestValidate_ZeroSessionTimeoutFails(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.SessionTimeout = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() with zero SessionTimeout = nil, want error")
	}
	if !strings.Contains(err.Error(), "sessionTimeout") {
		t.Errorf("error = %q, should mention sessionTimeout", err.Error())
	}
}

func TestValidate_MissingDefaultAgentFails(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.DefaultAgent = "nonexistent"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() with missing defaultAgent = nil, want error")
	}
	if !strings.Contains(err.Error(), "defaultAgent") {
		t.Errorf("error = %q, should mention defaultAgent", err.Error())
	}
}

func TestValidate_InvalidApprovalModeFails(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Agents["test"] = AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		ApprovalMode: "invalid",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() with invalid approvalMode = nil, want error")
	}
	if !strings.Contains(err.Error(), "approvalMode") {
		t.Errorf("error = %q, should mention approvalMode", err.Error())
	}
}

func TestValidate_InvalidGlobPatternFails(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Agents["test"] = AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"["}, // invalid glob
		ApprovalMode: "none",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() with invalid glob = nil, want error")
	}
	if !strings.Contains(err.Error(), "allowedPaths") {
		t.Errorf("error = %q, should mention allowedPaths", err.Error())
	}
}

func TestValidate_MultipleErrorsAggregated(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.VaultDir = ""
	cfg.SessionTimeout = 0
	cfg.DefaultAgent = "missing"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() with multiple errors = nil, want error")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "vaultDir") {
		t.Error("missing vaultDir error")
	}
	if !strings.Contains(errStr, "sessionTimeout") {
		t.Error("missing sessionTimeout error")
	}
	if !strings.Contains(errStr, "defaultAgent") {
		t.Error("missing defaultAgent error")
	}
}

func TestValidate_AcceptsAllValidApprovalModes(t *testing.T) {
	t.Parallel()
	validModes := []string{"none", "deny", "prompt", "auto"}
	for _, mode := range validModes {
		cfg := Default()
		cfg.Agents["test"] = AgentProfile{
			Name:         "test",
			AllowedPaths: []string{"*"},
			ApprovalMode: mode,
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() with approvalMode %q = %v, want nil", mode, err)
		}
	}
}

func TestValidate_NegativeAuditMaxFileSizeFails(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Audit = &AuditConfig{MaxFileSize: -1}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() with negative MaxFileSize = nil, want error")
	}
	if !strings.Contains(err.Error(), "audit.maxFileSize") {
		t.Errorf("error = %q, should mention audit.maxFileSize", err.Error())
	}
}

func TestValidate_NegativeClipboardAutoClearFails(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Clipboard = &ClipboardConfig{AutoClearDuration: -1}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() with negative AutoClearDuration = nil, want error")
	}
	if !strings.Contains(err.Error(), "clipboard.autoClearDuration") {
		t.Errorf("error = %q, should mention clipboard.autoClearDuration", err.Error())
	}
}

func TestValidate_ZeroClipboardAutoClearPasses(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Clipboard = &ClipboardConfig{AutoClearDuration: 0}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with zero AutoClearDuration = %v, want nil", err)
	}
}

// --- Profile Tests ---

func TestLoad_Profiles(t *testing.T) {
	t.Parallel()
	yaml := `profiles:
  work:
    vault: ~/.openpass-work
  family:
    vault: ~/vaults/family
defaultProfile: work
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Profiles) != 2 {
		t.Fatalf("Profiles len = %d, want 2", len(cfg.Profiles))
	}
	if cfg.DefaultProfile != "work" {
		t.Errorf("DefaultProfile = %q, want work", cfg.DefaultProfile)
	}
	work := cfg.ProfileForName("work")
	if work == nil {
		t.Fatal("ProfileForName(work) = nil")
	}
	if work.VaultPath != "~/.openpass-work" {
		t.Errorf("work.VaultPath = %q, want ~/.openpass-work", work.VaultPath)
	}
}

func TestLoad_ProfileMissingVaultPath(t *testing.T) {
	t.Parallel()
	yaml := `profiles:
  empty:
    vault: ""
`
	path := writeTempFile(t, []byte(yaml))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	empty := cfg.ProfileForName("empty")
	if empty == nil {
		t.Fatal("ProfileForName(empty) = nil")
	}
	if empty.VaultPath != "" {
		t.Errorf("empty.VaultPath = %q, want empty", empty.VaultPath)
	}
}

func TestLoad_NoProfiles(t *testing.T) {
	t.Parallel()
	path := writeTempFile(t, []byte("{}\n"))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Profiles != nil && len(cfg.Profiles) != 0 {
		t.Errorf("Profiles = %v, want nil or empty", cfg.Profiles)
	}
}

func TestSave_Profiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := Default()
	cfg.Profiles = map[string]*Profile{
		"work": {VaultPath: "~/.openpass-work"},
	}
	cfg.DefaultProfile = "work"

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := Load(filepath.Join(home, ".openpass", "config.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(loaded.Profiles) != 1 {
		t.Fatalf("Profiles len = %d, want 1", len(loaded.Profiles))
	}
	if loaded.DefaultProfile != "work" {
		t.Errorf("DefaultProfile = %q, want work", loaded.DefaultProfile)
	}
	work := loaded.ProfileForName("work")
	if work == nil || work.VaultPath != "~/.openpass-work" {
		t.Errorf("work profile = %v, want VaultPath=~/.openpass-work", work)
	}
}

func TestVaultDirForProfile(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Profiles = map[string]*Profile{
		"work": {VaultPath: "~/.openpass-work"},
	}
	if got := cfg.VaultDirForProfile("work"); got != "~/.openpass-work" {
		t.Errorf("VaultDirForProfile(work) = %q, want ~/.openpass-work", got)
	}
	if got := cfg.VaultDirForProfile("missing"); got != "" {
		t.Errorf("VaultDirForProfile(missing) = %q, want empty", got)
	}
}

func TestProfileForName_NilProfiles(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Profiles = nil
	if got := cfg.ProfileForName("work"); got != nil {
		t.Errorf("ProfileForName with nil Profiles = %v, want nil", got)
	}
}

func TestSetAuthMethod_Passphrase(t *testing.T) {
	t.Parallel()
	cfg := Default()
	if err := cfg.SetAuthMethod("passphrase"); err != nil {
		t.Fatalf("SetAuthMethod(passphrase): %v", err)
	}
	if cfg.AuthMethod != AuthMethodPassphrase {
		t.Errorf("AuthMethod = %q, want %q", cfg.AuthMethod, AuthMethodPassphrase)
	}
	if cfg.UseTouchID {
		t.Error("expected UseTouchID=false for passphrase method")
	}
}

func TestSetAuthMethod_TouchID(t *testing.T) {
	t.Parallel()
	cfg := Default()
	if err := cfg.SetAuthMethod("touch-id"); err != nil {
		t.Fatalf("SetAuthMethod(touch-id): %v", err)
	}
	if cfg.AuthMethod != AuthMethodTouchID {
		t.Errorf("AuthMethod = %q, want %q", cfg.AuthMethod, AuthMethodTouchID)
	}
	if !cfg.UseTouchID {
		t.Error("expected UseTouchID=true for touch-id method")
	}
}

func TestSetAuthMethod_SetsVaultSection(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Vault = &VaultConfig{}
	if err := cfg.SetAuthMethod("passphrase"); err != nil {
		t.Fatalf("SetAuthMethod: %v", err)
	}
	if cfg.Vault.AuthMethod != AuthMethodPassphrase {
		t.Errorf("Vault.AuthMethod = %q, want %q", cfg.Vault.AuthMethod, AuthMethodPassphrase)
	}
}

func TestSetAuthMethod_InvalidMethod(t *testing.T) {
	t.Parallel()
	cfg := Default()
	if err := cfg.SetAuthMethod("invalid-method"); err == nil {
		t.Error("expected error for invalid auth method, got nil")
	}
}

func TestIsLegacyMode_NilConfig(t *testing.T) {
	t.Parallel()
	var cfg *Config
	if !cfg.IsLegacyMode() {
		t.Error("expected IsLegacyMode=true for nil config")
	}
}

func TestIsLegacyMode_NilVault(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Vault = nil
	if !cfg.IsLegacyMode() {
		t.Error("expected IsLegacyMode=true when vault config is nil")
	}
}

func TestIsLegacyMode_ExplicitTrue(t *testing.T) {
	t.Parallel()
	cfg := Default()
	legacy := true
	cfg.Vault = &VaultConfig{LegacyMode: &legacy}
	if !cfg.IsLegacyMode() {
		t.Error("expected IsLegacyMode=true when explicitly set")
	}
}

func TestIsLegacyMode_ExplicitFalse(t *testing.T) {
	t.Parallel()
	cfg := Default()
	legacy := false
	cfg.Vault = &VaultConfig{LegacyMode: &legacy}
	if cfg.IsLegacyMode() {
		t.Error("expected IsLegacyMode=false when explicitly disabled")
	}
}

func TestDefaultAuditConfig(t *testing.T) {
	t.Parallel()
	ac := defaultAuditConfig()
	if ac.MaxFileSize <= 0 {
		t.Error("expected positive MaxFileSize")
	}
	if ac.MaxBackups <= 0 {
		t.Error("expected positive MaxBackups")
	}
	if ac.MaxAgeDays <= 0 {
		t.Error("expected positive MaxAgeDays")
	}
}

func TestDefaultLoggingConfig(t *testing.T) {
	t.Parallel()
	lc := defaultLoggingConfig()
	if lc.Level == "" {
		t.Error("expected non-empty Level")
	}
	if lc.Format == "" {
		t.Error("expected non-empty Format")
	}
}

func TestMergeFileAuditConfig_Nil(t *testing.T) {
	t.Parallel()
	defaults := defaultAuditConfig()
	result := MergeFileAuditConfig(nil, defaults)
	if result.MaxFileSize != defaults.MaxFileSize {
		t.Errorf("expected defaults preserved, got %d", result.MaxFileSize)
	}
}

func TestMergeFileAuditConfig_Override(t *testing.T) {
	t.Parallel()
	maxSize := int64(50)
	maxBackups := 3
	maxAge := 7
	fileCfg := &fileAuditConfig{
		MaxFileSize: &maxSize,
		MaxBackups:  &maxBackups,
		MaxAgeDays:  &maxAge,
	}
	defaults := defaultAuditConfig()
	result := MergeFileAuditConfig(fileCfg, defaults)
	if result.MaxFileSize != 50*1024*1024 {
		t.Errorf("MaxFileSize = %d, want %d", result.MaxFileSize, 50*1024*1024)
	}
	if result.MaxBackups != 3 {
		t.Errorf("MaxBackups = %d, want 3", result.MaxBackups)
	}
	if result.MaxAgeDays != 7 {
		t.Errorf("MaxAgeDays = %d, want 7", result.MaxAgeDays)
	}
}

func TestMergeFileLoggingConfig_Nil(t *testing.T) {
	t.Parallel()
	defaults := defaultLoggingConfig()
	result := MergeFileLoggingConfig(nil, defaults)
	if result.Level != defaults.Level {
		t.Errorf("expected defaults preserved, got %q", result.Level)
	}
}

func TestMergeFileLoggingConfig_Override(t *testing.T) {
	t.Parallel()
	level := "debug"
	format := "json"
	fileCfg := &fileLoggingConfig{
		Level:  &level,
		Format: &format,
	}
	defaults := defaultLoggingConfig()
	result := MergeFileLoggingConfig(fileCfg, defaults)
	if result.Level != "debug" {
		t.Errorf("Level = %q, want debug", result.Level)
	}
	if result.Format != "json" {
		t.Errorf("Format = %q, want json", result.Format)
	}
}

func TestEffectiveAuthMethod_Nil(t *testing.T) {
	var c *Config
	if got := c.EffectiveAuthMethod(); got != AuthMethodPassphrase {
		t.Errorf("nil config EffectiveAuthMethod = %q, want %q", got, AuthMethodPassphrase)
	}
}

func TestEffectiveAuthMethod_AuthMethod(t *testing.T) {
	c := &Config{AuthMethod: "passphrase"}
	if got := c.EffectiveAuthMethod(); got != AuthMethodPassphrase {
		t.Errorf("EffectiveAuthMethod = %q, want %q", got, AuthMethodPassphrase)
	}
}

func TestEffectiveAuthMethod_VaultAuthMethod(t *testing.T) {
	c := &Config{Vault: &VaultConfig{AuthMethod: "passphrase"}}
	if got := c.EffectiveAuthMethod(); got != AuthMethodPassphrase {
		t.Errorf("EffectiveAuthMethod = %q, want %q", got, AuthMethodPassphrase)
	}
}

func TestEffectiveAuthMethod_VaultUseTouchID(t *testing.T) {
	c := &Config{Vault: &VaultConfig{UseTouchID: true}}
	if got := c.EffectiveAuthMethod(); got != AuthMethodTouchID {
		t.Errorf("EffectiveAuthMethod = %q, want %q", got, AuthMethodTouchID)
	}
}

func TestEffectiveAuthMethod_Default(t *testing.T) {
	c := &Config{}
	if got := c.EffectiveAuthMethod(); got != AuthMethodPassphrase {
		t.Errorf("EffectiveAuthMethod = %q, want %q", got, AuthMethodPassphrase)
	}
}

// --- Tier Preset Tests ---

func TestPresets_ApplyTierPreset_ReadOnly(t *testing.T) {
	t.Parallel()
	p := &AgentProfile{Name: "test", AllowedPaths: []string{"*"}}
	ok := ApplyTierPreset(p, "read-only")
	if !ok {
		t.Fatal("ApplyTierPreset returned false for known tier")
	}
	if p.CanWrite {
		t.Error("CanWrite should be false for read-only")
	}
	if p.CanReadValues {
		t.Error("CanReadValues should be false for read-only")
	}
	if p.ExposeValueTools {
		t.Error("ExposeValueTools should be false for read-only")
	}
	if p.ApprovalMode != "none" {
		t.Errorf("ApprovalMode = %q, want none", p.ApprovalMode)
	}
	// AllowedPaths should be preserved
	if len(p.AllowedPaths) != 1 || p.AllowedPaths[0] != "*" {
		t.Error("AllowedPaths should be preserved from original profile")
	}
}

func TestPresets_ApplyTierPreset_Standard(t *testing.T) {
	t.Parallel()
	p := &AgentProfile{Name: "test", AllowedPaths: []string{"*"}}
	ok := ApplyTierPreset(p, "standard")
	if !ok {
		t.Fatal("ApplyTierPreset returned false for known tier")
	}
	if p.CanWrite {
		t.Error("CanWrite should be false for standard")
	}
	if !p.CanReadValues {
		t.Error("CanReadValues should be true for standard")
	}
	if p.ExposeValueTools {
		t.Error("ExposeValueTools should be false for standard")
	}
	if p.ApprovalMode != "prompt" {
		t.Errorf("ApprovalMode = %q, want prompt", p.ApprovalMode)
	}
}

func TestPresets_ApplyTierPreset_Admin(t *testing.T) {
	t.Parallel()
	p := &AgentProfile{Name: "test", AllowedPaths: []string{"*"}}
	ok := ApplyTierPreset(p, "admin")
	if !ok {
		t.Fatal("ApplyTierPreset returned false for known tier")
	}
	if !p.CanWrite {
		t.Error("CanWrite should be true for admin")
	}
	if !p.CanReadValues {
		t.Error("CanReadValues should be true for admin")
	}
	if !p.ExposeValueTools {
		t.Error("ExposeValueTools should be true for admin")
	}
	if !p.CanRunCommands {
		t.Error("CanRunCommands should be true for admin")
	}
	if !p.CanManageConfig {
		t.Error("CanManageConfig should be true for admin")
	}
	if !p.CanUseClipboard {
		t.Error("CanUseClipboard should be true for admin")
	}
}

func TestPresets_UnknownTier_Ignored(t *testing.T) {
	t.Parallel()
	p := &AgentProfile{Name: "test", AllowedPaths: []string{"*"}}
	p.CanWrite = true
	ok := ApplyTierPreset(p, "nonexistent")
	if ok {
		t.Fatal("ApplyTierPreset should return false for unknown tier")
	}
	if !p.CanWrite {
		t.Error("CanWrite should not be changed by unknown tier")
	}
}

// --- Tier Preset Load Tests ---

func TestLoad_TierStandardPreset(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	yamlContent := `agents:
  my-agent:
    tier: standard
`
	path := writeTempFile(t, []byte(yamlContent))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	agent, ok := cfg.Agents["my-agent"]
	if !ok {
		t.Fatal("my-agent should exist")
	}
	// Verify preset was applied
	if agent.CanWrite {
		t.Error("CanWrite should be false (standard preset)")
	}
	if !agent.CanReadValues {
		t.Error("CanReadValues should be true (standard preset)")
	}
	if agent.ExposeValueTools {
		t.Error("ExposeValueTools should be false (standard preset)")
	}
	if agent.Tier != "standard" {
		t.Errorf("Tier = %q, want standard", agent.Tier)
	}
}

func TestLoad_TierStandardWithExplicitOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	yamlContent := `agents:
  my-agent:
    tier: standard
    canWrite: true
`
	path := writeTempFile(t, []byte(yamlContent))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	agent, ok := cfg.Agents["my-agent"]
	if !ok {
		t.Fatal("my-agent should exist")
	}
	// Preset sets CanWrite=false, but explicit YAML override should win
	if !agent.CanWrite {
		t.Error("CanWrite should be true (explicit YAML overrides preset)")
	}
	// Preset should still apply for non-overridden fields
	if agent.ExposeValueTools {
		t.Error("ExposeValueTools should be false (from preset, not overridden)")
	}
}

func TestLoad_TierReadOnlyPreset(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	yamlContent := `agents:
  my-agent:
    tier: read-only
`
	path := writeTempFile(t, []byte(yamlContent))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	agent, ok := cfg.Agents["my-agent"]
	if !ok {
		t.Fatal("my-agent should exist")
	}
	if agent.CanWrite {
		t.Error("CanWrite should be false (read-only preset)")
	}
	if agent.CanReadValues {
		t.Error("CanReadValues should be false (read-only preset)")
	}
	if agent.ExposeValueTools {
		t.Error("ExposeValueTools should be false (read-only preset)")
	}
}

func TestLoad_TierAdminPreset(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	yamlContent := `agents:
  my-agent:
    tier: admin
`
	path := writeTempFile(t, []byte(yamlContent))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	agent, ok := cfg.Agents["my-agent"]
	if !ok {
		t.Fatal("my-agent should exist")
	}
	if !agent.CanWrite {
		t.Error("CanWrite should be true (admin preset)")
	}
	if !agent.CanReadValues {
		t.Error("CanReadValues should be true (admin preset)")
	}
	if !agent.ExposeValueTools {
		t.Error("ExposeValueTools should be true (admin preset)")
	}
	if !agent.CanRunCommands {
		t.Error("CanRunCommands should be true (admin preset)")
	}
}

// --- ExposeValueTools Tests ---

func TestLoad_ExposeValueToolsExplicitTrue(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	yamlContent := `agents:
  my-agent:
    exposeValueTools: true
`
	path := writeTempFile(t, []byte(yamlContent))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	agent := cfg.Agents["my-agent"]
	if !agent.ExposeValueTools {
		t.Error("ExposeValueTools should be true (explicitly set)")
	}
}

func TestLoad_ExposeValueToolsExplicitFalse(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	yamlContent := `agents:
  my-agent:
    exposeValueTools: false
`
	path := writeTempFile(t, []byte(yamlContent))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	agent := cfg.Agents["my-agent"]
	if agent.ExposeValueTools {
		t.Error("ExposeValueTools should be false (explicitly set)")
	}
}

func TestLoad_ExposeValueToolsBackwardCompat(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Config without tier and without exposeValueTools should default to true
	yamlContent := `agents:
  my-agent:
    canWrite: true
`
	path := writeTempFile(t, []byte(yamlContent))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	agent := cfg.Agents["my-agent"]
	if !agent.ExposeValueTools {
		t.Error("ExposeValueTools should default to true for backward compat")
	}
}

func TestLoad_ExposeValueToolsTierOverridesDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Config with tier=standard but no exposeValueTools - should be false from preset
	yamlContent := `agents:
  my-agent:
    tier: standard
`
	path := writeTempFile(t, []byte(yamlContent))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	agent := cfg.Agents["my-agent"]
	if agent.ExposeValueTools {
		t.Error("ExposeValueTools should be false (from standard preset)")
	}
}

func TestLoad_ExposeValueToolsExplicitOverridesTier(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Config with tier=standard but explicit exposeValueTools: true - value should be true
	yamlContent := `agents:
  my-agent:
    tier: standard
    exposeValueTools: true
`
	path := writeTempFile(t, []byte(yamlContent))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	agent := cfg.Agents["my-agent"]
	if !agent.ExposeValueTools {
		t.Error("ExposeValueTools should be true (explicit override of standard preset)")
	}
}
