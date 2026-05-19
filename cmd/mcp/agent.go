// Package mcp provides MCP server and agent management commands.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
)

var agentWriteConfig bool

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage agent profiles",
	Long: `Configure AI agent profiles with scoped permissions, tokens, and MCP integration.

Use 'openpass agent setup <name>' to create a new agent with an interactive wizard
that guides you through security tier selection, vault path scoping, and approval mode.`,
	Example: `  # Interactive new-agent wizard
  openpass agent setup claude-code

  # List configured agents
  openpass agent list

  # Issue a token for an agent
  openpass agent token new claude-code`,
}

var agentSetupCmd = &cobra.Command{
	Use:   "setup <name>",
	Short: "Create an agent profile interactively",
	Long: `Run an interactive wizard to create a new agent profile with:
  • Security tier (read-only, standard, admin)
  • Vault path glob restriction
  • Approval mode (prompt or deny)

The wizard creates a profile in config.yaml, a scoped token in the registry,
a token file, and outputs a ready-to-paste stdio MCP client configuration snippet.`,
	Args: cobra.ExactArgs(1),
	Annotations: map[string]string{
		cli.RequiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: openpass agent install <name>", nil)
	},
}

func promptApprovalMode(reader *bufio.Reader) string {
	for {
		fmt.Fprint(os.Stderr, "\nApproval mode:\n")
		fmt.Fprint(os.Stderr, "1) prompt — ask for each sensitive operation\n")
		fmt.Fprint(os.Stderr, "2) deny — block all sensitive operations\n")
		fmt.Fprint(os.Stderr, "Choice [1-2] (default: 1): ")

		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			continue
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return "prompt"
		}

		switch input {
		case "1":
			return "prompt"
		case "2":
			return "deny"
		default:
			fmt.Fprint(os.Stderr, "Invalid choice. Please enter 1 or 2.\n")
		}
	}
}

func validateAgentName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("agent name must not be empty")
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") || name == "." || strings.Contains(name, "..") {
		return fmt.Errorf("invalid agent name")
	}
	return nil
}

func buildProfile(name, tier, glob, approvalMode string, requireApproval bool) configpkg.AgentProfile {
	profile := configpkg.AgentProfile{
		Name:         name,
		AllowedPaths: []string{glob},
	}

	configpkg.ApplyTierPreset(&profile, tier)

	profile.AllowedPaths = []string{glob}
	profile.ApprovalMode = configpkg.StrPtr(approvalMode)
	profile.RequireApproval = configpkg.BoolPtr(requireApproval)

	return profile
}

func saveAgentConfig(vaultDir, name string, profile configpkg.AgentProfile) error {
	if err := validateAgentName(name); err != nil {
		return err
	}
	configPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			cfg = &configpkg.Config{
				VaultDir: vaultDir,
				Agents:   make(map[string]configpkg.AgentProfile),
			}
		} else {
			return fmt.Errorf("load config: %w", err)
		}
	}

	if cfg.Agents == nil {
		cfg.Agents = make(map[string]configpkg.AgentProfile)
	}
	cfg.Agents[name] = profile
	return cfg.SaveTo(configPath)
}

func writeAgentTokenFile(vaultDir, name, rawToken string) (string, error) {
	if err := validateAgentName(name); err != nil {
		return "", err
	}
	tokenDir := filepath.Join(vaultDir, "mcp-tokens")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		return "", fmt.Errorf("create token directory: %w", err)
	}

	tokenPath := filepath.Join(tokenDir, name+".token")
	if err := os.WriteFile(tokenPath, []byte(rawToken+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write token file: %w", err)
	}

	return tokenPath, nil
}

func outputAgentMCPSnippet(name, rawToken string) {
	args := []string{"serve", "--stdio", "--agent", name}

	config := map[string]any{
		"mcpServers": map[string]any{
			"openpass": map[string]any{
				"command": "openpass",
				"args":    args,
				"env": map[string]string{
					"OPENPASS_MCP_TOKEN": rawToken,
				},
			},
		},
	}

	fmt.Fprint(os.Stderr, "MCP config (generic stdio):\n")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding config: %v\n", err)
	}
}

func init() {
	agentCmd.AddCommand(agentSetupCmd)
	agentSetupCmd.Flags().BoolVar(&agentWriteConfig, "write-config", false, "write agent profile to config.yaml (always true in interactive mode)")
	cli.RootCmd.AddCommand(agentCmd)
}
