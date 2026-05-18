package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/danieljustus/OpenPass/internal/agentskill"
	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp"
)

var (
	agentUninstallKeepSkill  bool
	agentUninstallKeepConfig bool
	agentUninstallYes        bool
)

func confirmUninstall(name string) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}
	fmt.Fprintf(os.Stderr, "Remove agent %q and all associated data? This cannot be undone. [y/N] ", name)
	reader := bufio.NewReader(os.Stdin)
	reply, _ := reader.ReadString('\n')
	reply = strings.TrimSpace(strings.ToLower(reply))
	return reply == "y" || reply == "yes"
}

var agentUninstallCmd = &cobra.Command{
	Use:   "uninstall <name>",
	Short: "Remove an agent integration",
	Long: `Remove an agent profile, revoke all tokens, uninstall the skill file,
and clean up associated data.

This command:
  • Removes the agent profile from config.yaml
  • Revokes all MCP tokens associated with the agent
  • Removes the token file from the vault
  • Removes the skill file if it is managed by OpenPass

Use --keep-skill to preserve the skill file and --keep-config to keep the
agent's profile in config.yaml. Use --yes to skip the confirmation prompt.`,
	Args: cobra.ExactArgs(1),
	Example: `  # Interactive uninstall with confirmation
  openpass agent uninstall hermes

  # Non-interactive uninstall keeping the skill file
  openpass agent uninstall claude-code --yes --keep-skill`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := args[0]

		vaultDir := getVaultDir()
		configPath := filepath.Join(vaultDir, "config.yaml")
		cfg, err := configpkg.Load(configPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		profile, hasProfile := cfg.Agents[agentName]
		if !hasProfile {
			return fmt.Errorf("agent %q not found in config", agentName)
		}

		if !agentUninstallYes && !confirmUninstall(agentName) {
			fmt.Fprintln(os.Stderr, "Uninstall canceled.")
			return nil
		}

		if !agentUninstallKeepConfig {
			delete(cfg.Agents, agentName)
			if err := cfg.SaveTo(configPath); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			fmt.Fprintf(os.Stderr, "\u2713 Profile for %q removed from config\n", agentName)
		} else {
			fmt.Fprintf(os.Stderr, "\u26a0 Keeping profile for %q in config (--keep-config)\n", agentName)
		}

		regPath := mcp.TokenRegistryFilePath(vaultDir)
		reg := mcp.NewTokenRegistry(regPath)
		revokedCount := 0
		if loadErr := reg.Load(); loadErr == nil {
			for _, tok := range reg.List() {
				if tok.AgentName == agentName && !tok.Revoked {
					reg.Revoke(tok.ID)
					revokedCount++
				}
			}
			if revokedCount > 0 {
				if saveErr := reg.Save(); saveErr != nil {
					fmt.Fprintf(os.Stderr, "\u26a0 Failed to save token registry: %v\n", saveErr)
				}
			}
		}
		if revokedCount > 0 {
			fmt.Fprintf(os.Stderr, "\u2713 Revoked %d token(s) for %q\n", revokedCount, agentName)
		}

		tokenFilePath := filepath.Join(vaultDir, "mcp-tokens", agentName+".token")
		if _, statErr := os.Stat(tokenFilePath); statErr == nil {
			if rmErr := os.Remove(tokenFilePath); rmErr != nil {
				fmt.Fprintf(os.Stderr, "\u26a0 Failed to remove token file %s: %v\n", tokenFilePath, rmErr)
			} else {
				fmt.Fprintf(os.Stderr, "\u2713 Removed token file %s\n", tokenFilePath)
			}
		}

		if !agentUninstallKeepSkill {
			skillPath := profile.SkillPath
			if skillPath != "" {
				expanded := expandTilde(skillPath)
				if data, readErr := os.ReadFile(expanded); readErr == nil { //nolint:gosec G304 — skillPath is user-configured, validated by expandTilde
					manifest, parseErr := agentskill.ParseManifest(data)
					if parseErr == nil && manifest.ManagedBy == agentskill.SentinelValue {
						if rmErr := os.Remove(expanded); rmErr != nil {
							fmt.Fprintf(os.Stderr, "\u26a0 Failed to remove skill file %s: %v\n", expanded, rmErr)
						} else {
							fmt.Fprintf(os.Stderr, "\u2713 Removed skill file %s\n", expanded)
						}
					}
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "\u26a0 Keeping skill file (--keep-skill)\n")
		}

		fmt.Fprintf(os.Stderr, "\nAgent %q has been uninstalled.\n", agentName)
		fmt.Fprintf(os.Stderr, "Note: MCP server entries in the agent's config file (e.g. mcp.json) must be removed manually.\n")
		return nil
	},
}

func init() {
	agentUninstallCmd.Flags().BoolVar(&agentUninstallKeepSkill, "keep-skill", false, "Don't remove the skill file")
	agentUninstallCmd.Flags().BoolVar(&agentUninstallKeepConfig, "keep-config", false, "Don't modify the agent config file")
	agentUninstallCmd.Flags().BoolVar(&agentUninstallYes, "yes", false, "Skip confirmation prompt")

	agentCmd.AddCommand(agentUninstallCmd)
}
