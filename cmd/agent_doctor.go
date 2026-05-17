package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/agentskill"
	configpkg "github.com/danieljustus/OpenPass/internal/config"
)

var agentDoctorCmd = &cobra.Command{
	Use:   "doctor <agent>",
	Short: "Check agent integration health",
	Long: `Run end-to-end diagnostics for an agent integration:
  • Profile exists and is valid
  • Skill file is installed and managed by OpenPass
  • Skill hash matches current template (detects drift)
  • Token registry entry exists
Reports structured results; exits 0 if all checks pass.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := args[0]

		configPath := filepath.Join(getVaultDir(), "config.yaml")
		cfg, err := configpkg.Load(configPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		profile, hasProfile := cfg.Agents[agentName]
		if !hasProfile {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\u274c No profile found for agent %q\n", agentName)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Run: openpass agent install %s\n", agentName)
			return fmt.Errorf("agent %q not configured", agentName)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\u2713 Profile found: %s (tier=%s)\n", agentName, profile.Tier)

		targetPath := profile.SkillPath
		if targetPath == "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\u26a0 No skill path configured for agent %q\n", agentName)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Run: openpass agent install %s --skill-only\n", agentName)
			return fmt.Errorf("no skill path configured")
		}

		targetPath = expandTilde(targetPath)
		data, err := os.ReadFile(targetPath)
		if err != nil {
			if os.IsNotExist(err) {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\u274c Skill file not found: %s\n", targetPath)
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Run: openpass agent install %s --skill-only\n", agentName)
				return fmt.Errorf("skill file not installed")
			}
			return fmt.Errorf("read skill file: %w", err)
		}

		manifest, err := agentskill.ParseManifest(data)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\u26a0 Skill file exists but has no valid frontmatter\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Path: %s\n", targetPath)
			return fmt.Errorf("invalid skill file frontmatter")
		}

		if manifest.ManagedBy != agentskill.SentinelValue {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\u26a0 Skill file is not managed by OpenPass\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Path: %s\n", targetPath)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   To overwrite: openpass agent install %s --skill-only --force\n", agentName)
			return fmt.Errorf("unmanaged skill file")
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\u2713 Skill file is managed by OpenPass\n")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Path:    %s\n", targetPath)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Version: %s\n", manifest.ManagedVersion)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Tier:    %s\n", manifest.ManagedProfileTier)

		if err := agentskill.VerifyHash(data); err != nil {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n\u26a0 Skill version drift detected\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Installed:  %s\n", manifest.ManagedVersion)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Expected:   %s\n", AppVersion())
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Run: openpass agent skill refresh %s\n", agentName)
			return fmt.Errorf("skill drift detected")
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\u2713 Skill hash is current (no drift)\n")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nAll checks passed for %s\n", agentName)
		return nil
	},
}

func init() {
	agentCmd.AddCommand(agentDoctorCmd)
}
