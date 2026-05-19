package mcp

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/danieljustus/OpenPass/internal/agentskill"
	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp"
)

var (
	agentUpgradeTier       string
	agentUpgradeDryRun     bool
	agentUpgradeYes        bool
	agentUpgradeReason     string
	agentUpgradeRotate     bool
	agentUpgradeValidTiers = map[string]bool{"read-only": true, "standard": true, "admin": true}
)

type tierDiff struct {
	Field    string
	OldValue string
	NewValue string
	Changed  bool
}

func computeTierDiff(old, new configpkg.AgentProfile) []tierDiff {
	boolVal := func(p *bool) bool { return p != nil && *p }
	boolStr := func(p *bool) string { return fmt.Sprintf("%t", boolVal(p)) }
	intStr := func(p *int) string {
		if p != nil {
			return fmt.Sprintf("%d", *p)
		}
		return "0"
	}
	strVal := func(p *string) string {
		if p != nil {
			return *p
		}
		return ""
	}

	diffs := []tierDiff{
		{Field: "canWrite", OldValue: boolStr(old.CanWrite), NewValue: boolStr(new.CanWrite), Changed: boolVal(old.CanWrite) != boolVal(new.CanWrite)},
		{Field: "canRunCommands", OldValue: boolStr(old.CanRunCommands), NewValue: boolStr(new.CanRunCommands), Changed: boolVal(old.CanRunCommands) != boolVal(new.CanRunCommands)},
		{Field: "canManageConfig", OldValue: boolStr(old.CanManageConfig), NewValue: boolStr(new.CanManageConfig), Changed: boolVal(old.CanManageConfig) != boolVal(new.CanManageConfig)},
		{Field: "canUseClipboard", OldValue: boolStr(old.CanUseClipboard), NewValue: boolStr(new.CanUseClipboard), Changed: boolVal(old.CanUseClipboard) != boolVal(new.CanUseClipboard)},
		{Field: "canUseAutotype", OldValue: boolStr(old.CanUseAutotype), NewValue: boolStr(new.CanUseAutotype), Changed: boolVal(old.CanUseAutotype) != boolVal(new.CanUseAutotype)},
		{Field: "canReadValues", OldValue: boolStr(old.CanReadValues), NewValue: boolStr(new.CanReadValues), Changed: boolVal(old.CanReadValues) != boolVal(new.CanReadValues)},
		{Field: "exposeValueTools", OldValue: boolStr(old.ExposeValueTools), NewValue: boolStr(new.ExposeValueTools), Changed: boolVal(old.ExposeValueTools) != boolVal(new.ExposeValueTools)},
		{Field: "autoUnseal", OldValue: boolStr(old.AutoUnseal), NewValue: boolStr(new.AutoUnseal), Changed: boolVal(old.AutoUnseal) != boolVal(new.AutoUnseal)},
		{Field: "requireApproval", OldValue: boolStr(old.RequireApproval), NewValue: boolStr(new.RequireApproval), Changed: boolVal(old.RequireApproval) != boolVal(new.RequireApproval)},
		{Field: "approvalMode", OldValue: strVal(old.ApprovalMode), NewValue: strVal(new.ApprovalMode), Changed: strVal(old.ApprovalMode) != strVal(new.ApprovalMode)},
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

	oldMRPH := 0
	if old.MaxReadsPerHour != nil {
		oldMRPH = *old.MaxReadsPerHour
	}
	newMRPH := 0
	if new.MaxReadsPerHour != nil {
		newMRPH = *new.MaxReadsPerHour
	}
	if oldMRPH != newMRPH {
		diffs = append(diffs, tierDiff{Field: "maxReadsPerHour", OldValue: intStr(old.MaxReadsPerHour), NewValue: intStr(new.MaxReadsPerHour), Changed: true})
	}
	oldMRPD := 0
	if old.MaxReadsPerDay != nil {
		oldMRPD = *old.MaxReadsPerDay
	}
	newMRPD := 0
	if new.MaxReadsPerDay != nil {
		newMRPD = *new.MaxReadsPerDay
	}
	if oldMRPD != newMRPD {
		diffs = append(diffs, tierDiff{Field: "maxReadsPerDay", OldValue: intStr(old.MaxReadsPerDay), NewValue: intStr(new.MaxReadsPerDay), Changed: true})
	}
	oldMSIS := 0
	if old.MaxSecretsInSession != nil {
		oldMSIS = *old.MaxSecretsInSession
	}
	newMSIS := 0
	if new.MaxSecretsInSession != nil {
		newMSIS = *new.MaxSecretsInSession
	}
	if oldMSIS != newMSIS {
		diffs = append(diffs, tierDiff{Field: "maxSecretsInSession", OldValue: intStr(old.MaxSecretsInSession), NewValue: intStr(new.MaxSecretsInSession), Changed: true})
	}

	return diffs
}

func applyTierUpgrade(vaultDir, agentName string, dryRun bool) error {
	configPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	profile, hasProfile := cfg.Agents[agentName]
	if !hasProfile {
		return fmt.Errorf("agent %q not found in config", agentName)
	}

	configpkg.ApplyTierPreset(&profile, "standard")
	profile.Tier = configpkg.StrPtr("standard")

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
		cli.RequiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := args[0]

		if agentUpgradeTier == "" {
			return fmt.Errorf("--tier is required (valid: read-only, standard, admin)")
		}
		if agentUpgradeYes && agentUpgradeReason == "" {
			return fmt.Errorf("--reason is required when using --yes")
		}

		if !agentUpgradeValidTiers[agentUpgradeTier] {
			return fmt.Errorf("invalid tier %q: valid values are read-only, standard, admin", agentUpgradeTier)
		}

		vaultDir := cli.GetVaultDir()
		configPath := filepath.Join(vaultDir, "config.yaml")
		cfg, err := configpkg.Load(configPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		profile, hasProfile := cfg.Agents[agentName]
		if !hasProfile {
			return fmt.Errorf("agent %q not found in config", agentName)
		}

		currentTier := ""
		if profile.Tier != nil {
			currentTier = *profile.Tier
		}
		if currentTier == "" {
			currentTier = "custom"
		}
		if currentTier == agentUpgradeTier {
			return fmt.Errorf("agent %q is already at tier %q", agentName, agentUpgradeTier)
		}

		oldProfile := profile
		configpkg.ApplyTierPreset(&profile, agentUpgradeTier)
		profile.Tier = configpkg.StrPtr(agentUpgradeTier)
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
			fmt.Fprintln(os.Stderr, "Upgrade canceled.")
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

		targetPath := ""
		if profile.SkillPath != nil {
			targetPath = *profile.SkillPath
		}
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
