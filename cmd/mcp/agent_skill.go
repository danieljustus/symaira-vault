package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/agentskill"
	configpkg "github.com/danieljustus/OpenPass/internal/config"
)

var agentSkillCmd = &cobra.Command{
	Use:   "skill",
	Short: "Manage agent skill packages",
	Long:  `Export or refresh embedded skill packages for AI agents.`,
}

var agentSkillExportCmd = &cobra.Command{
	Use:   "export <agent>",
	Short: "Export a rendered skill package for an agent",
	Long: `Pack the rendered skill file as a tar.gz archive for drop-in distribution.
The archive contains the rendered skill file (SKILL.md or AGENTS.md) and an
INSTALL.md with manual install instructions.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := args[0]
		outputPath, _ := cmd.Flags().GetString("output")
		if outputPath == "" {
			outputPath = fmt.Sprintf("openpass-%s-skill.tar.gz", agentName)
		}
		outputPath = filepath.Clean(outputPath)

		vars := buildTemplateVars(agentName)

		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()

		if err := agentskill.Export(agentName, vars, f); err != nil {
			_ = f.Close()
			_ = os.Remove(outputPath)
			return fmt.Errorf("export skill: %w", err)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Exported skill for %s to %s\n", agentName, outputPath)
		return nil
	},
}

var agentSkillRefreshCmd = &cobra.Command{
	Use:   "refresh <agent>",
	Short: "Refresh an installed skill file in place",
	Long: `Re-render the skill template for an agent and overwrite the installed
skill file if the hash has changed. Creates a backup before overwriting.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := args[0]

		vars := buildTemplateVars(agentName)

		targetPath := getSkillTargetPath(agentName)
		if targetPath == "" {
			return fmt.Errorf("no skill path configured for agent %q", agentName)
		}

		targetPath = expandTilde(targetPath)

		if err := agentskill.Refresh(agentName, targetPath, vars); err != nil {
			return fmt.Errorf("refresh skill: %w", err)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Refreshed skill for %s at %s\n", agentName, targetPath)
		return nil
	},
}

func buildTemplateVars(agentName string) agentskill.TemplateVars {
	vaultDir := cli.GetVaultDir()

	prefixConfig := agentskill.PrefixConfig(agentName)

	return agentskill.TemplateVars{
		AgentName:          agentName,
		ToolPrefix:         prefixConfig.ToolPrefix,
		SlashPrefix:        prefixConfig.SlashPrefix,
		OpenPassVersion:    cli.AppVersionStr(),
		ProfileTier:        "safe",
		VaultPath:          vaultDir,
		InstalledAt:        time.Now().UTC().Format(time.RFC3339),
		SkillSchemaVersion: agentskill.DefaultSkillSchemaVersion,
	}
}

func getSkillTargetPath(agentName string) string {
	configPath := filepath.Join(cli.GetVaultDir(), "config.yaml")
	cfg, err := configpkg.Load(configPath)
	if err != nil {
		return ""
	}

	if profile, ok := cfg.Agents[agentName]; ok && profile.SkillPath != nil {
		return *profile.SkillPath
	}
	return ""
}

func expandTilde(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}

func init() {
	agentSkillExportCmd.Flags().StringP("output", "o", "", "Output file path (default: openpass-<agent>-skill.tar.gz)")

	agentSkillCmd.AddCommand(agentSkillExportCmd)
	agentSkillCmd.AddCommand(agentSkillRefreshCmd)
	agentCmd.AddCommand(agentSkillCmd)
}
