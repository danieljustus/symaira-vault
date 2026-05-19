package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp"
)

var agentWhoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current agent context",
	Long: `Display information about the current agent profile.

When the OPENPASS_AGENT environment variable is set, loads that agent's profile
and shows name, tier, allowed paths, tools, quotas, and vault status.

The --output json flag returns structured data matching the MCP openpass_whoami
response format.`,
	Example: `  # Show agent context
  OPENPASS_AGENT=my-agent openpass agent whoami

  # Show as JSON
  OPENPASS_AGENT=my-agent openpass agent whoami --output json`,
	Annotations: map[string]string{
		cli.RequiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := os.Getenv("OPENPASS_AGENT")
		if agentName == "" {
			return fmt.Errorf("OPENPASS_AGENT not set. Run without agent context or set OPENPASS_AGENT=<name>")
		}

		vaultDir := cli.GetVaultDir()
		configPath := filepath.Join(vaultDir, "config.yaml")
		cfg, err := configpkg.Load(configPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		profile, ok := cfg.Agents[agentName]
		if !ok {
			return fmt.Errorf("agent %q not found in config", agentName)
		}

		info := buildWhoamiInfo(agentName, vaultDir, &profile)

		output, _ := cmd.Flags().GetString("output")
		switch output {
		case "json":
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(info)
		default:
			printWhoamiTable(cmd, info)
			return nil
		}
	},
}

type whoamiInfo struct {
	Name            string   `json:"name"`
	Tier            string   `json:"tier"`
	AllowedPaths    []string `json:"allowed_paths"`
	AllowedTools    []string `json:"allowed_tools,omitempty"`
	CanWrite        bool     `json:"can_write"`
	CanReadValues   bool     `json:"can_read_values"`
	CanUseClipboard bool     `json:"can_use_clipboard"`
	CanUseAutotype  bool     `json:"can_use_autotype"`
	CanRunCommands  bool     `json:"can_run_commands"`
	CanManageConfig bool     `json:"can_manage_config"`
	ApprovalMode    string   `json:"approval_mode"`
	RequireApproval bool     `json:"require_approval"`
	TokenCount      int      `json:"token_count"`
	TokenFile       string   `json:"token_file,omitempty"`
	Quotas          struct {
		MaxReadsPerHour     int `json:"max_reads_per_hour,omitempty"`
		MaxReadsPerDay      int `json:"max_reads_per_day,omitempty"`
		MaxSecretsInSession int `json:"max_secrets_in_session,omitempty"`
	} `json:"quotas,omitempty"`
	SkillPath string `json:"skill_path,omitempty"`
}

func buildWhoamiInfo(agentName, vaultDir string, profile *configpkg.AgentProfile) whoamiInfo {
	bv := func(p *bool) bool { return p != nil && *p }
	sv := func(p *string) string {
		if p != nil {
			return *p
		}
		return ""
	}
	iv := func(p *int) int {
		if p != nil {
			return *p
		}
		return 0
	}

	info := whoamiInfo{
		Name:            agentName,
		Tier:            sv(profile.Tier),
		AllowedPaths:    profile.AllowedPaths,
		AllowedTools:    profile.AllowedTools,
		CanWrite:        bv(profile.CanWrite),
		CanReadValues:   bv(profile.CanReadValues),
		CanUseClipboard: bv(profile.CanUseClipboard),
		CanUseAutotype:  bv(profile.CanUseAutotype),
		CanRunCommands:  bv(profile.CanRunCommands),
		CanManageConfig: bv(profile.CanManageConfig),
		ApprovalMode:    sv(profile.ApprovalMode),
		RequireApproval: bv(profile.RequireApproval),
		SkillPath:       sv(profile.SkillPath),
	}
	info.Quotas.MaxReadsPerHour = iv(profile.MaxReadsPerHour)
	info.Quotas.MaxReadsPerDay = iv(profile.MaxReadsPerDay)
	info.Quotas.MaxSecretsInSession = iv(profile.MaxSecretsInSession)

	info.TokenCount = countAgentTokens(vaultDir, agentName)

	tokenFilePath := filepath.Join(vaultDir, "mcp-tokens", agentName+".token")
	if _, err := os.Stat(tokenFilePath); err == nil {
		info.TokenFile = tokenFilePath
	}

	return info
}

func countAgentTokens(vaultDir, agentName string) int {
	regPath := mcp.TokenRegistryFilePath(vaultDir)
	reg := mcp.NewTokenRegistry(regPath)
	if err := reg.Load(); err != nil {
		return 0
	}

	count := 0
	for _, t := range reg.List() {
		if t.AgentName == agentName && !t.Revoked && !t.IsExpired() {
			count++
		}
	}
	return count
}

func printWhoamiTable(cmd *cobra.Command, info whoamiInfo) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Agent:      %s\n", info.Name)
	if info.Tier != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Tier:       %s\n", info.Tier)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Paths:      %s\n", strings.Join(info.AllowedPaths, ", "))
	if len(info.AllowedTools) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Tools:      %s\n", strings.Join(info.AllowedTools, ", "))
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Write:      %t\n", info.CanWrite)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Read Vals:  %t\n", info.CanReadValues)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Clipboard:  %t\n", info.CanUseClipboard)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Autotype:   %t\n", info.CanUseAutotype)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Commands:   %t\n", info.CanRunCommands)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Config:     %t\n", info.CanManageConfig)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Approval:   %s\n", info.ApprovalMode)
	if info.Quotas.MaxReadsPerHour > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Quota/hr:   %d\n", info.Quotas.MaxReadsPerHour)
	}
	if info.Quotas.MaxReadsPerDay > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Quota/day:  %d\n", info.Quotas.MaxReadsPerDay)
	}
	if info.Quotas.MaxSecretsInSession > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Quota/sess: %d\n", info.Quotas.MaxSecretsInSession)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Tokens:     %d active\n", info.TokenCount)
	if info.TokenFile != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Token File: %s\n", info.TokenFile)
	}
	if info.SkillPath != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Skill:      %s\n", info.SkillPath)
	}
}

func init() {
	agentWhoamiCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")
	agentCmd.AddCommand(agentWhoamiCmd)
}
