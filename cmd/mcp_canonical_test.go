package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	mcpcmd "github.com/danieljustus/symaira-vault/cmd/mcp"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/config"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestMcpCanonicalRegistration(t *testing.T) {
	root := NewRootCmd()
	var mcpCmd *cobra.Command
	var serveCmd *cobra.Command

	for _, c := range root.Commands() {
		if c.Name() == "mcp" {
			mcpCmd = c
		}
		if c.Name() == "serve" {
			serveCmd = c
		}
	}

	if mcpCmd == nil {
		t.Fatal("mcp command not found on NewRootCmd()")
	}
	if mcpCmd.Hidden {
		t.Error("canonical mcp command must not be hidden")
	}
	if mcpCmd.GroupID != cli.GroupIDAgentsMCP {
		t.Errorf("mcp command group = %q, want %q", mcpCmd.GroupID, cli.GroupIDAgentsMCP)
	}

	// Verify required flags exist on mcp
	requiredFlags := []string{"agent", "port", "stdio", "bind", "tls-cert", "tls-key", "tls-ca", "allow-locked"}
	for _, flagName := range requiredFlags {
		if mcpCmd.Flags().Lookup(flagName) == nil {
			t.Errorf("mcp command missing flag %q", flagName)
		}
	}

	// Verify subcommands exist on mcp
	requiredSubcommands := []string{"install", "uninstall", "status"}
	for _, sub := range requiredSubcommands {
		found := false
		for _, c := range mcpCmd.Commands() {
			if c.Name() == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("mcp missing subcommand %q", sub)
		}
	}

	if serveCmd == nil {
		t.Fatal("serve command not found on NewRootCmd()")
	}
	if !serveCmd.Hidden {
		t.Error("deprecated serve command must be Hidden: true")
	}
}

func TestServeDeprecationWarningStderrOnly(t *testing.T) {
	resetVaultState(t)

	tmpDir := t.TempDir()
	cfg := config.Default()
	_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("testpass"), cfg)

	origRunStdio := mcpcmd.RunStdioServerFunc
	var stdioCalled bool
	mcpcmd.RunStdioServerFunc = func(_ context.Context, _ *vaultpkg.Vault, _ string) error {
		stdioCalled = true
		return nil
	}
	defer func() { mcpcmd.RunStdioServerFunc = origRunStdio }()

	origUnlock := mcpcmd.ServeUnlockVault
	mcpcmd.ServeUnlockVault = func(vaultDir string, _ bool) (*vaultpkg.Vault, error) {
		return vaultpkg.OpenWithPassphrase(vaultDir, []byte("testpass"))
	}
	defer func() { mcpcmd.ServeUnlockVault = origUnlock }()

	root := NewRootCmd()
	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)
	root.SetOut(stdoutBuf)
	root.SetErr(stderrBuf)

	root.SetArgs([]string{"--vault", tmpDir, "serve", "--stdio", "--agent", "default"})
	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error executing serve: %v", err)
	}

	if !stdioCalled {
		t.Error("expected stdio server to be called by serve command")
	}

	// Crucial rule: Zero Stdio Pollution. Stdout must not contain deprecation warning.
	if strings.Contains(stdoutBuf.String(), "deprecated") {
		t.Errorf("stdout polluted with deprecation warning: %q", stdoutBuf.String())
	}
	if !strings.Contains(stderrBuf.String(), "Warning: 'symvault serve' is deprecated, use 'symvault mcp' instead.") {
		t.Errorf("stderr missing deprecation warning, got: %q", stderrBuf.String())
	}
}

func TestMcpCommandExecutesWithoutDeprecationWarning(t *testing.T) {
	resetVaultState(t)

	tmpDir := t.TempDir()
	cfg := config.Default()
	_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("testpass"), cfg)

	origRunStdio := mcpcmd.RunStdioServerFunc
	var stdioCalled bool
	mcpcmd.RunStdioServerFunc = func(_ context.Context, _ *vaultpkg.Vault, _ string) error {
		stdioCalled = true
		return nil
	}
	defer func() { mcpcmd.RunStdioServerFunc = origRunStdio }()

	origUnlock := mcpcmd.ServeUnlockVault
	mcpcmd.ServeUnlockVault = func(vaultDir string, _ bool) (*vaultpkg.Vault, error) {
		return vaultpkg.OpenWithPassphrase(vaultDir, []byte("testpass"))
	}
	defer func() { mcpcmd.ServeUnlockVault = origUnlock }()

	root := NewRootCmd()
	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)
	root.SetOut(stdoutBuf)
	root.SetErr(stderrBuf)

	root.SetArgs([]string{"--vault", tmpDir, "mcp", "--stdio", "--agent", "default"})
	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error executing mcp: %v", err)
	}

	if !stdioCalled {
		t.Error("expected stdio server to be called by mcp command")
	}

	if strings.Contains(stderrBuf.String(), "deprecated") {
		t.Errorf("canonical mcp command emitted unexpected deprecation warning on stderr: %q", stderrBuf.String())
	}
}

func TestGlobalJSONFlag(t *testing.T) {
	t.Run("JSON flag sets OutputFormat to json", func(t *testing.T) {
		root := NewRootCmd()
		stdoutBuf := new(bytes.Buffer)
		root.SetOut(stdoutBuf)
		root.SetArgs([]string{"version", "--json"})

		err := root.Execute()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cli.OutputFormat != "json" {
			t.Errorf("cli.OutputFormat = %q, want %q", cli.OutputFormat, "json")
		}
		if !strings.Contains(stdoutBuf.String(), `"version":`) {
			t.Errorf("expected JSON output containing '\"version\":', got: %q", stdoutBuf.String())
		}
	})

	t.Run("JSON flag overrides --output text", func(t *testing.T) {
		root := NewRootCmd()
		stdoutBuf := new(bytes.Buffer)
		root.SetOut(stdoutBuf)
		root.SetArgs([]string{"version", "--output", "text", "--json"})

		err := root.Execute()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cli.OutputFormat != "json" {
			t.Errorf("cli.OutputFormat = %q, want %q", cli.OutputFormat, "json")
		}
		if !strings.Contains(stdoutBuf.String(), `"version":`) {
			t.Errorf("expected JSON output containing '\"version\":', got: %q", stdoutBuf.String())
		}
	})

	t.Run("JSON flag overrides --output yaml", func(t *testing.T) {
		root := NewRootCmd()
		stdoutBuf := new(bytes.Buffer)
		root.SetOut(stdoutBuf)
		root.SetArgs([]string{"version", "--output", "yaml", "--json"})

		err := root.Execute()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cli.OutputFormat != "json" {
			t.Errorf("cli.OutputFormat = %q, want %q", cli.OutputFormat, "json")
		}
		if !strings.Contains(stdoutBuf.String(), `"version":`) {
			t.Errorf("expected JSON output containing '\"version\":', got: %q", stdoutBuf.String())
		}
	})
}
