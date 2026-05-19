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
	"github.com/danieljustus/OpenPass/internal/mcp"
)

// AgentListItem holds the display data for a single agent in the list output.
type AgentListItem struct {
	Name           string `json:"name"`
	Tier           string `json:"tier"`
	TokenID        string `json:"token_id,omitempty"`
	TokenValid     bool   `json:"token_valid"`
	SkillInstalled bool   `json:"skill_installed"`
	SkillManaged   bool   `json:"skill_managed"`
	LastSeen       string `json:"last_seen,omitempty"`
}

// AgentListResult is the structured output for `openpass agent list --output json`.
type AgentListResult struct {
	Agents []AgentListItem `json:"agents"`
	Count  int             `json:"count"`
}

// String returns the human-readable table representation.
func (r AgentListResult) String() string {
	if len(r.Agents) == 0 {
		return "No agents configured."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-14s %-10s %-10s %-12s %s\n", "AGENT", "TIER", "TOKEN", "SKILL", "LAST SEEN")
	b.WriteString(strings.Repeat("-", 70) + "\n")
	for _, a := range r.Agents {
		tokenStatus := "none"
		if a.TokenValid {
			tokenStatus = "valid"
		} else if a.TokenID != "" {
			tokenStatus = "invalid"
		}

		skillStatus := "missing"
		if a.SkillManaged {
			skillStatus = "managed"
		} else if a.SkillInstalled {
			skillStatus = "installed"
		}

		lastSeen := a.LastSeen
		if lastSeen == "" {
			lastSeen = "-"
		}

		fmt.Fprintf(&b, "%-14s %-10s %-10s %-12s %s\n",
			a.Name, a.Tier, tokenStatus, skillStatus, lastSeen)
	}
	return b.String()
}

var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configured agents",
	Long: `Show all installed agents with their tier, token status, and skill installation status.

Output columns:
  AGENT      Agent profile name
  TIER       Security tier (read-only, standard, admin, or custom)
  TOKEN      Token status from the registry (none, valid, invalid)
  SKILL      Skill file status (missing, installed, managed)
  LAST SEEN  Most recent token use timestamp`,
	Example: `  # List all agents in a table
  openpass agent list

  # JSON output for programmatic use
  openpass agent list --output json`,
	Annotations: map[string]string{
		cli.RequiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir := cli.GetVaultDir()

		configPath := filepath.Join(vaultDir, "config.yaml")
		cfg, err := configpkg.Load(configPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		regPath := mcp.TokenRegistryFilePath(vaultDir)
		reg := mcp.NewTokenRegistry(regPath)
		if loadErr := reg.Load(); loadErr != nil {
			return fmt.Errorf("load token registry: %w", loadErr)
		}
		allTokens := reg.List()

		result := AgentListResult{
			Agents: make([]AgentListItem, 0, len(cfg.Agents)),
		}

		names := make([]string, 0, len(cfg.Agents))
		for name := range cfg.Agents {
			names = append(names, name)
		}
		sortStrings(names)

		for _, name := range names {
			profile := cfg.Agents[name]

			tier := ""
			if profile.Tier != nil {
				tier = *profile.Tier
			}
			item := AgentListItem{
				Name: name,
				Tier: tier,
			}

			var lastSeen time.Time
			for _, tok := range allTokens {
				if tok.AgentName == name && !tok.Revoked && !tok.IsExpired() {
					item.TokenID = tok.ID
					item.TokenValid = true
					if tok.LastUsedAt != nil && tok.LastUsedAt.After(lastSeen) {
						lastSeen = *tok.LastUsedAt
					}
				}
			}
			if !lastSeen.IsZero() {
				item.LastSeen = lastSeen.Format("2006-01-02 15:04")
			}

			var skillPath string
			if profile.SkillPath != nil {
				skillPath = *profile.SkillPath
			}
			if skillPath != "" {
				expanded := expandTilde(skillPath)
				expanded = filepath.Clean(expanded)
				data, readErr := os.ReadFile(expanded)
				if readErr == nil {
					item.SkillInstalled = true
					if manifest, parseErr := agentskill.ParseManifest(data); parseErr == nil && manifest.ManagedBy == agentskill.SentinelValue {
						item.SkillManaged = true
					}
				}
			}

			result.Agents = append(result.Agents, item)
		}
		result.Count = len(result.Agents)

		switch cli.OutputFormat {
		case "json", "yaml":
			return cli.PrintResult(result)
		default:
			cmd.Print(result.String())
			return nil
		}
	},
}

func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

func init() {
	agentCmd.AddCommand(agentListCmd)
}
