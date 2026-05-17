package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp"
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
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("agent setup needs a TTY; use 'openpass mcp token create' for non-interactive token creation")
		}

		name := args[0]
		if err := validateAgentName(name); err != nil {
			return err
		}

		reader := bufio.NewReader(os.Stdin)

		tier := promptSecurityTier(reader)
		glob := promptVaultPathGlob(reader)
		approvalMode := promptApprovalMode(reader)

		profile := buildProfile(name, tier, glob, approvalMode, true)
		vaultDir := getVaultDir()

		if err := saveAgentConfig(vaultDir, name, profile); err != nil {
			return fmt.Errorf("save agent config: %w", err)
		}

		// Create token
		tokenID, rawToken, err := createAgentToken(vaultDir, name)
		if err != nil {
			return fmt.Errorf("create agent token: %w", err)
		}

		// Write token file
		tokenFilePath, err := writeAgentTokenFile(vaultDir, name, rawToken)
		if err != nil {
			return fmt.Errorf("write token file: %w", err)
		}

		configPath := filepath.Join(vaultDir, "config.yaml")

		fmt.Fprintf(os.Stderr, "\n✓ Agent %q created\n\n", name)
		fmt.Fprintf(os.Stderr, "Profile:  %s\n", configPath)
		fmt.Fprintf(os.Stderr, "Token:    %s\n", tokenFilePath)
		fmt.Fprintf(os.Stderr, "Token ID: %s\n\n", tokenID)

		outputAgentMCPSnippet(name, rawToken)

		return nil
	},
}

func promptSecurityTier(reader *bufio.Reader) string {
	for {
		fmt.Fprint(os.Stderr, "\nSelect security tier:\n")
		fmt.Fprint(os.Stderr, "1) read-only — can list entries and read metadata only\n")
		fmt.Fprint(os.Stderr, "2) standard — recommended, clipboard + autotype + approvals\n")
		fmt.Fprint(os.Stderr, "3) admin — full access including commands and config\n")
		fmt.Fprint(os.Stderr, "Choice [1-3] (default: 2): ")

		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			continue
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return "standard"
		}

		switch input {
		case "1":
			return "read-only"
		case "2":
			return "standard"
		case "3":
			return "admin"
		default:
			fmt.Fprint(os.Stderr, "Invalid choice. Please enter a number between 1 and 3.\n")
		}
	}
}

func promptVaultPathGlob(reader *bufio.Reader) string {
	fmt.Fprint(os.Stderr, "\nAllowed vault path glob [*]: ")
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		return "*"
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return "*"
	}
	return input
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
	profile.ApprovalMode = approvalMode
	profile.RequireApproval = requireApproval

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

func createAgentToken(vaultDir, name string) (string, string, error) {
	if err := validateAgentName(name); err != nil {
		return "", "", err
	}
	regPath := mcp.TokenRegistryFilePath(vaultDir)
	reg := mcp.NewTokenRegistry(regPath)
	if err := reg.Load(); err != nil {
		return "", "", fmt.Errorf("load token registry: %w", err)
	}

	token, rawToken, err := reg.Create(name, []string{"*"}, name, 0)
	if err != nil {
		return "", "", fmt.Errorf("create token: %w", err)
	}

	if err := reg.Save(); err != nil {
		return "", "", fmt.Errorf("save token registry: %w", err)
	}

	return token.ID, rawToken, nil
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
	rootCmd.AddCommand(agentCmd)
}
