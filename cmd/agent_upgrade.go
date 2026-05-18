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
	agentUpgradeTier   string
	agentUpgradeDryRun bool
	agentUpgradeYes    bool
	agentUpgradeReason string
	agentUpgradeRotate bool
)

type tierDiff struct {
	Field    string
	OldValue string
	NewValue string
	Changed  bool
}

func computeTierDiff(old, new configpkg.AgentProfile) []tierDiff {
	diffs := []tierDiff{
		{Field: "canWrite", OldValue: fmt.Sprintf("%t", old.CanWrite), NewValue: fmt.Sprintf("%t", new.CanWrite), Changed: old.CanWrite != new.CanWrite},
		{Field: "canRunCommands", OldValue: fmt.Sprintf("%t", old.CanRunCommands), NewValue: fmt.Sprintf("%t", new.CanRunCommands), Changed: old.CanRunCommands != new.CanRunCommands},
		{Field: "canManageConfig", OldValue: fmt.Sprintf("%t", old.CanManageConfig), NewValue: fmt.Sprintf("%t", new.CanManageConfig), Changed: old.CanManageConfig != new.CanManageConfig},
		{Field: "canUseClipboard", OldValue: fmt.Sprintf("%t", old.CanUseClipboard), NewValue: fmt.Sprintf("%t", new.CanUseClipboard), Changed: old.CanUseClipboard != new.CanUseClipboard},
		{Field: "canUseAutotype", OldValue: fmt.Sprintf("%t", old.CanUseAutotype), NewValue: fmt.Sprintf("%t", new.CanUseAutotype), Changed: old.CanUseAutotype != new.CanUseAutotype},
		{Field: "canReadValues", OldValue: fmt.Sprintf("%t", old.CanReadValues), NewValue: fmt.Sprintf("%t", new.CanReadValues), Changed: old.CanReadValues != new.CanReadValues},
		{Field: "exposeValueTools", OldValue: fmt.Sprintf("%t", old.ExposeValueTools), NewValue: fmt.Sprintf("%t", new.ExposeValueTools), Changed: old.ExposeValueTools != new.ExposeValueTools},
		{Field: "autoUnseal", OldValue: fmt.Sprintf("%t", old.AutoUnseal), NewValue: fmt.Sprintf("%t", new.AutoUnseal), Changed: old.AutoUnseal != new.AutoUnseal},
		{Field: "requireApproval", OldValue: fmt.Sprintf("%t", old.RequireApproval), NewValue: fmt.Sprintf("%t", new.RequireApproval), Changed: old.RequireApproval != new.RequireApproval},
		{Field: "approvalMode", OldValue: old.ApprovalMode, NewValue: new.ApprovalMode, Changed: old.ApprovalMode != new.ApprovalMode},
	}

	oldExec := strings.Join(old.AllowedExecutables, ", ")
	newExec := strings.Join(new.AllowedExecutables, ", ")
	if oldExec == "" {
		oldExec = "(none)"
	}
	if newExec == "" {
		newExec = "(none)"
	}
	diffs = append(diffs, tierDiff{Field: "allowedExecutables", OldValue: oldExec, NewValue: newExec, Changed: oldExec != newExec})

	oldTools := strings.Join(old.AllowedTools, ", ")
	newTools := strings.Join(new.AllowedTools, ", ")
	if oldTools == "" {
		oldTools = "(all)"
	}
	if newTools == "" {
		newTools = "(all)"
	}
	diffs = append(diffs, tierDiff{Field: "allowedTools", OldValue: oldTools, NewValue: newTools, Changed: oldTools != newTools})

	if old.MaxReadsPerHour != new.MaxReadsPerHour {
		diffs = append(diffs, tierDiff{Field: "maxReadsPerHour", OldValue: fmt.Sprintf("%d", old.MaxReadsPerHour), NewValue: fmt.Sprintf("%d", new.MaxReadsPerHour), Changed: true})
	}
	if old.MaxReadsPerDay != new.MaxReadsPerDay {
		diffs = append(diffs, tierDiff{Field: "maxReadsPerDay", OldValue: fmt.Sprintf("%d", old.MaxReadsPerDay), NewValue: fmt.Sprintf("%d", new.MaxReadsPerDay), Changed: true})
	}
	if old.MaxSecretsInSession != new.MaxSecretsInSession {
		diffs = append(diffs, tierDiff{Field: "maxSecretsInSession", OldValue: fmt.Sprintf("%d", old.MaxSecretsInSession), NewValue: fmt.Sprintf("%d", new.MaxSecretsInSession), Changed: true})
	}

	return diffs
}

func applyTierUpgrade(vaultDir, agentName, targetTier string, dryRun bool) error {
	configPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	profile, hasProfile := cfg.Agents[agentName]
	if !hasProfile {
		return fmt.Errorf("agent %q not found in config", agentName)
	}

	configpkg.ApplyTierPreset(&profile, targetTier)
	profile.Tier = targetTier

	if dryRun {
		return nil
	}

	cfg.Agents[agentName] = profile
	return cfg.SaveTo(configPath)
}

func printTierDiff(diffs []tierDiff) {
	fmt.Fprintf(os.Stderr, "  %-24s %-24s %s\n", "FIELD", "CURRENT", "NEW")
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", 72))
	for _, d := range diffs {
		if d.Changed {
			fmt.Fprintf(os.Stderr, "  \u2713 %-22s %-24s %s\n", d.Field, d.OldValue, d.NewValue)
		} else {
			fmt.Fprintf(os.Stderr, "  %-23s %-24s %s (unchanged)\n", d.Field, d.OldValue, d.NewValue)
		}
	}
}

func confirmUpgrade(agentName, targetTier string) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}
	fmt.Fprintf(os.Stderr, "Upgrade agent %q from current tier to %q? [y/N] ", agentName, targetTier)
	reader := bufio.NewReader(os.Stdin)
	reply, _ := reader.ReadString('\n')
	reply = strings.TrimSpace(strings.ToLower(reply))
	return reply == "y" || reply == "yes"
}

var agentUpgradeCmd = &cobra.Command{
	Use:   "upgrade <name>",
	Short: "Upgrade an agent's security tier",
	Long: `Show tier diff and upgrade an agent's security tier with interactive confirmation.

The upgrade applies the named tier preset (read-only, standard, or admin) to the
agent profile, updating all capability fields. Use --dry-run to preview changes
without writing. Use --rotate-token to also rotate the agent's MCP token.

The --reason flag is required when using --yes for non-interactive mode to ensure
an audit trail.`,
	Args: cobra.ExactArgs(1),
	Example: `  # Interactive upgrade to admin tier with token rotation
  openpass agent upgrade hermes --tier admin --rotate-token

  # Dry-run: preview changes without writing
  openpass agent upgrade claude-code --tier admin --dry-run

  # Non-interactive upgrade with audit reason
  openpass agent upgrade opencode --tier standard --yes --reason "CI pipeline automation upgrade"`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := args[0]

		if agentUpgradeTier == "" {
			return fmt.Errorf("--tier is required (valid: read-only, standard, admin)")
		}
		if agentUpgradeYes && agentUpgradeReason == "" {
			return fmt.Errorf("--reason is required when using --yes")
		}

		validTiers := map[string]bool{"read-only": true, "standard": true, "admin": true}
		if !validTiers[agentUpgradeTier] {
			return fmt.Errorf("invalid tier %q: valid values are read-only, standard, admin", agentUpgradeTier)
		}

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

		currentTier := profile.Tier
		if currentTier == "" {
			currentTier = "custom"
		}
		if currentTier == agentUpgradeTier {
			return fmt.Errorf("agent %q is already at tier %q", agentName, agentUpgradeTier)
		}

		oldProfile := profile
		configpkg.ApplyTierPreset(&profile, agentUpgradeTier)
		profile.Tier = agentUpgradeTier
		diffs := computeTierDiff(oldProfile, profile)

		fmt.Fprintf(os.Stderr, "Agent:   %s\n", agentName)
		fmt.Fprintf(os.Stderr, "Current: %s\n", currentTier)
		fmt.Fprintf(os.Stderr, "Target:  %s\n", agentUpgradeTier)
		if agentUpgradeReason != "" {
			fmt.Fprintf(os.Stderr, "Reason:  %s\n", agentUpgradeReason)
		}
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Tier changes:")
		printTierDiff(diffs)
		fmt.Fprintln(os.Stderr)

		if agentUpgradeDryRun {
			fmt.Fprintln(os.Stderr, "[DRY-RUN] No changes written.")
			return nil
		}

		if !agentUpgradeYes && !confirmUpgrade(agentName, agentUpgradeTier) {
			fmt.Fprintln(os.Stderr, "Upgrade cancelled.")
			return nil
		}

		cfg.Agents[agentName] = profile
		if err := cfg.SaveTo(configPath); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
		fmt.Fprintf(os.Stderr, "\u2713 Profile for %q upgraded to %q\n", agentName, agentUpgradeTier)

		if agentUpgradeRotate {
			regPath := mcp.TokenRegistryFilePath(vaultDir)
			reg := mcp.NewTokenRegistry(regPath)
			if loadErr := reg.Load(); loadErr != nil {
				return fmt.Errorf("load token registry: %w", loadErr)
			}

			for _, tok := range reg.List() {
				if tok.AgentName == agentName && !tok.Revoked {
					reg.Revoke(tok.ID)
				}
			}

			newTok, rawToken, createErr := reg.Create(
				fmt.Sprintf("upgrade-%s-%s", agentName, agentUpgradeTier),
				[]string{"*"},
				agentName,
				0,
			)
			if createErr != nil {
				return fmt.Errorf("create token for %q: %w", agentName, createErr)
			}
			if err := reg.Save(); err != nil {
				return fmt.Errorf("save token registry: %w", err)
			}

			tokenPath, writeErr := writeAgentTokenFile(vaultDir, agentName, rawToken)
			if writeErr != nil {
				return fmt.Errorf("write token file: %w", writeErr)
			}
			fmt.Fprintf(os.Stderr, "\u2713 Token rotated: %s (id=%s)\n", tokenPath, newTok.ID)
		}

		targetPath := profile.SkillPath
		if targetPath != "" {
			expanded := expandTilde(targetPath)
			vars := buildTemplateVars(agentName)
			vars.ProfileTier = agentUpgradeTier
			if err := agentskill.Refresh(agentName, expanded, vars); err != nil {
				fmt.Fprintf(os.Stderr, "\u26a0 Skill refresh: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "\u2713 Skill refreshed at %s\n", expanded)
			}
		}

		return nil
	},
}

func init() {
	agentUpgradeCmd.Flags().StringVar(&agentUpgradeTier, "tier", "", "Target security tier (read-only, standard, admin)")
	agentUpgradeCmd.Flags().BoolVar(&agentUpgradeDryRun, "dry-run", false, "Show diff without applying changes")
	agentUpgradeCmd.Flags().BoolVar(&agentUpgradeYes, "yes", false, "Non-interactive mode (requires --reason)")
	agentUpgradeCmd.Flags().StringVar(&agentUpgradeReason, "reason", "", "Audit reason for the upgrade (required with --yes)")
	agentUpgradeCmd.Flags().BoolVar(&agentUpgradeRotate, "rotate-token", false, "Rotate the agent's MCP token on upgrade")

	agentCmd.AddCommand(agentUpgradeCmd)
}
