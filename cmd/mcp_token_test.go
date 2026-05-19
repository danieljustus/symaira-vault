package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	mcpcmd "github.com/danieljustus/OpenPass/cmd/mcp"
	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/testutil"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func TestMCPTokenCommandRegistration(t *testing.T) {
	commands := mcpcmd.McpTokenCmd.Commands()
	if len(commands) != 3 {
		t.Fatalf("expected 3 subcommands, got %d", len(commands))
	}

	names := make(map[string]bool)
	for _, c := range commands {
		names[c.Name()] = true
	}

	for _, want := range []string{"create", "list", "revoke"} {
		if !names[want] {
			t.Errorf("missing subcommand: %s", want)
		}
	}
}

func TestMCPTokenCreate_Defaults(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "create", "--label", "test-default"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

//nolint:dupl
func TestMCPTokenCreate_WithToolsAndAgent(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{
		"--vault", vaultDir,
		"mcp", "token", "create",
		"--tools", "list_entries,get_entry",
		"--agent", "claude-code",
		"--label", "scoped-test",
	})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

//nolint:dupl
func TestMCPTokenCreate_MultipleToolFlags(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{
		"--vault", vaultDir,
		"mcp", "token", "create",
		"--tools", "list_entries",
		"--tools", "get_entry",
		"--label", "multi-flag",
	})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

//nolint:dupl
func TestMCPTokenCreate_WithTTL(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{
		"--vault", vaultDir,
		"mcp", "token", "create",
		"--ttl", "7d",
		"--label", "ttl-test",
	})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestMCPTokenCreate_DefaultTTLFromConfig(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	cfg.MCP = &config.MCPConfig{
		Bind: "127.0.0.1",
		Port: 8080,
	}
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{
		"--vault", vaultDir,
		"mcp", "token", "create",
		"--label", "config-ttl",
	})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

//nolint:dupl
func TestMCPTokenCreate_InvalidTTL(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{
		"--vault", vaultDir,
		"mcp", "token", "create",
		"--ttl", "not-a-duration",
		"--label", "invalid",
	})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestMCPTokenCreate_VaultPathError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	origHome := os.Getenv("HOME")
	_ = os.Unsetenv("HOME")
	_ = os.Unsetenv("OPENPASS_VAULT")
	defer func() { _ = os.Setenv("HOME", origHome) }()

	origVault := vault
	vault = "~/.openpass"
	defer func() { vault = origVault }()

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"mcp", "token", "create", "--label", "fail"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	var execErr error
	captureStderr(func() {
		execErr = cli.RootCmd.Execute()
	})

	if execErr == nil {
		t.Fatal("expected error when vault path cannot be resolved")
	}
}

//nolint:dupl
func TestMCPTokenList_Empty(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "list"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestMCPTokenList_WithTokens(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	regPath := mcp.TokenRegistryFilePath(vaultDir)
	reg := mcp.NewTokenRegistry(regPath)
	if err := reg.Load(); err != nil {
		t.Fatalf("load registry: %v", err)
	}
	_, _, err := reg.Create("list-test", []string{"list_entries", "get_entry"}, "claude-code", 24*time.Hour)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("save registry: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "list"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err = cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestMCPTokenRevoke_Success(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	regPath := mcp.TokenRegistryFilePath(vaultDir)
	reg := mcp.NewTokenRegistry(regPath)
	if err := reg.Load(); err != nil {
		t.Fatalf("load registry: %v", err)
	}
	token, _, err := reg.Create("revoke-test", []string{"*"}, "", 24*time.Hour)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("save registry: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "revoke", token.ID})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err = cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestMCPTokenRevoke_NotFound(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "revoke", "nonexistent-id"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestMCPTokenRevoke_DoubleRevoke(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	regPath := mcp.TokenRegistryFilePath(vaultDir)
	reg := mcp.NewTokenRegistry(regPath)
	if err := reg.Load(); err != nil {
		t.Fatalf("load registry: %v", err)
	}
	token, _, err := reg.Create("double-revoke", []string{"*"}, "", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("save registry: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "revoke", token.ID})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })

	err = cli.RootCmd.Execute()
	if err == nil {
		t.Fatal("expected deprecation error on first revoke")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message on first revoke, got: %v", err)
	}

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "revoke", token.ID})
	err = cli.RootCmd.Execute()
	if err == nil {
		t.Fatal("expected deprecation error on second revoke")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message on second revoke, got: %v", err)
	}
}

func TestMCPTokenList_RevokedToken(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	regPath := mcp.TokenRegistryFilePath(vaultDir)
	reg := mcp.NewTokenRegistry(regPath)
	if err := reg.Load(); err != nil {
		t.Fatalf("load registry: %v", err)
	}
	token, _, err := reg.Create("revoked-list", []string{"*"}, "", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	reg.Revoke(token.ID)
	if err := reg.Save(); err != nil {
		t.Fatalf("save registry: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "list"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err = cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestParseHumanDuration(t *testing.T) {
	tests := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"24h", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"0h", 0, false},
		{"", 0, true},
		{"not-a-duration", 0, true},
		{"-1h", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := mcpcmd.ParseHumanDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("mcpcmd.ParseHumanDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("mcpcmd.ParseHumanDuration(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolveTokenTTL_FromFlag(t *testing.T) {
	vaultDir := t.TempDir()
	d, err := mcpcmd.ResolveTokenTTL(vaultDir, "12h")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 12*time.Hour {
		t.Errorf("ttl = %v, want 12h", d)
	}
}

func TestResolveTokenTTL_FromConfig(t *testing.T) {
	vaultDir := t.TempDir()
	d, err := mcpcmd.ResolveTokenTTL(vaultDir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 24*time.Hour {
		t.Errorf("ttl = %v, want 24h", d)
	}
}

func TestResolveTokenTTL_DefaultFallback(t *testing.T) {
	vaultDir := t.TempDir()
	d, err := mcpcmd.ResolveTokenTTL(vaultDir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 24*time.Hour {
		t.Errorf("ttl = %v, want 24h", d)
	}
}

//nolint:dupl
func TestMCPTokenCreate_ZeroTTL(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{
		"--vault", vaultDir,
		"mcp", "token", "create",
		"--ttl", "0h",
		"--label", "zero-ttl",
	})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestMCPTokenList_ExpiredTokenExcluded(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	regPath := mcp.TokenRegistryFilePath(vaultDir)
	reg := mcp.NewTokenRegistry(regPath)
	if err := reg.Load(); err != nil {
		t.Fatalf("load registry: %v", err)
	}
	_, _, err := reg.Create("expired", []string{"*"}, "", 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	_, _, err = reg.Create("valid", []string{"*"}, "", 1*time.Hour)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("save registry: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "list"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err = cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

//nolint:dupl
func TestMCPTokenCreate_PreservesInRegistry(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{
		"--vault", vaultDir,
		"mcp", "token", "create",
		"--tools", "list_entries",
		"--label", "persist-test",
	})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestMCPTokenRevoke_MissingArg(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "revoke"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	var execErr error
	captureStderr(func() {
		execErr = cli.RootCmd.Execute()
	})

	if execErr == nil {
		t.Fatal("expected error for missing arg")
	}
}

func TestMCPTokenCreate_ToolsLongOutput(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	manyTools := []string{
		"tool_a", "tool_b", "tool_c", "tool_d", "tool_e",
		"tool_f", "tool_g", "tool_h", "tool_i", "tool_j",
	}

	regPath := mcp.TokenRegistryFilePath(vaultDir)
	reg := mcp.NewTokenRegistry(regPath)
	if err := reg.Load(); err != nil {
		t.Fatalf("load registry: %v", err)
	}
	_, _, err := reg.Create("many-tools", manyTools, "", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("save registry: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "list"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err = cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

//nolint:dupl
func TestMCPTokenList_HeaderFormat(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	regPath := mcp.TokenRegistryFilePath(vaultDir)
	reg := mcp.NewTokenRegistry(regPath)
	if err := reg.Load(); err != nil {
		t.Fatalf("load registry: %v", err)
	}
	_, _, err := reg.Create("header-test", []string{"*"}, "agent-name", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("save registry: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "list"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err = cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestMCPCmdRegistration(t *testing.T) {
	found := false
	for _, c := range cli.RootCmd.Commands() {
		if c.Name() == "mcp" {
			found = true
			break
		}
	}
	if !found {
		t.Error("mcp command not registered under root")
	}
}

//nolint:dupl
//nolint:dupl
func TestMCPTokenCreate_NegativeDayTTL(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{
		"--vault", vaultDir,
		"mcp", "token", "create",
		"--ttl", "-1d",
		"--label", "negative",
	})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestMCPTokenCreate_RegistryFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: file permissions differ")
	}
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{
		"--vault", vaultDir,
		"mcp", "token", "create",
		"--label", "perms-test",
	})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

//nolint:dupl
func TestMCPTokenCreate_EmptyLabelOK(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{
		"--vault", vaultDir,
		"mcp", "token", "create",
	})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestMCPTokenRevoke_VaultPathError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	origHome := os.Getenv("HOME")
	_ = os.Unsetenv("HOME")
	_ = os.Unsetenv("OPENPASS_VAULT")
	defer func() { _ = os.Setenv("HOME", origHome) }()

	origVault := vault
	vault = "~/.openpass"
	defer func() { vault = origVault }()

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"mcp", "token", "revoke", "some-id"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	var execErr error
	captureStderr(func() {
		execErr = cli.RootCmd.Execute()
	})

	if execErr == nil {
		t.Fatal("expected error when vault path cannot be resolved")
	}
}

func TestMCPTokenList_VaultPathError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	origHome := os.Getenv("HOME")
	_ = os.Unsetenv("HOME")
	_ = os.Unsetenv("OPENPASS_VAULT")
	defer func() { _ = os.Setenv("HOME", origHome) }()

	origVault := vault
	vault = "~/.openpass"
	defer func() { vault = origVault }()

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"mcp", "token", "list"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	var execErr error
	captureStderr(func() {
		execErr = cli.RootCmd.Execute()
	})

	if execErr == nil {
		t.Fatal("expected error when vault path cannot be resolved")
	}
}

//nolint:dupl
func TestMCPTokenCreate_WithDaySuffixTTL(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{
		"--vault", vaultDir,
		"mcp", "token", "create",
		"--ttl", "7d",
		"--label", "week-token",
	})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err := cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

//nolint:dupl
func TestMCPTokenList_EmptyAgentAndLabel(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	regPath := mcp.TokenRegistryFilePath(vaultDir)
	reg := mcp.NewTokenRegistry(regPath)
	if err := reg.Load(); err != nil {
		t.Fatalf("load registry: %v", err)
	}
	_, _, err := reg.Create("", []string{"*"}, "", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("save registry: %v", err)
	}

	vaultFlagReset(t)
	t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "mcp", "token", "list"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
	t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

	err = cli.RootCmd.Execute()

	if err == nil {
		t.Fatal("expected deprecation error")
	}
	if !strings.Contains(err.Error(), "deprecated in v4.0") {
		t.Errorf("expected deprecation message, got: %v", err)
	}
}

func TestMCPTokenCreate_RawTokenUnique(t *testing.T) {
	vaultDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	for i := 0; i < 3; i++ {
		vaultFlagReset(t)
		t.Cleanup(func() { resetCobraCommand(cli.RootCmd) })

		cli.RootCmd.SetArgs([]string{
			"--vault", vaultDir,
			"mcp", "token", "create",
			"--label", fmt.Sprintf("token-%d", i),
		})
		t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })
		t.Cleanup(func() { _ = mcpcmd.TokenCreateCmd.Flags().Set("ttl", "") })

		err := cli.RootCmd.Execute()
		if err == nil {
			t.Fatal("expected deprecation error")
		}
		if !strings.Contains(err.Error(), "deprecated in v4.0") {
			t.Errorf("expected deprecation message, got: %v", err)
		}
	}
}
