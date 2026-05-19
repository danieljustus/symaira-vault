package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/mcp/install"

	"github.com/danieljustus/OpenPass/internal/agentskill"
)

var validTiers = map[string]bool{
	"safe":     true,
	"standard": true,
	"admin":    true,
}

var tierPresetMapping = map[string]string{
	"safe":     "read-only",
	"standard": "standard",
	"admin":    "admin",
}

type InstallResult struct {
	AgentName     string `json:"agent_name" yaml:"agent_name"`
	Tier          string `json:"tier" yaml:"tier"`
	Method        string `json:"method" yaml:"method"`
	ProfilePath   string `json:"profile_path" yaml:"profile_path"`
	TokenID       string `json:"token_id" yaml:"token_id"`
	MCPConfigPath string `json:"mcp_config_path" yaml:"mcp_config_path"`
	SkillPath     string `json:"skill_path" yaml:"skill_path"`
	SmokeTest     string `json:"smoke_test" yaml:"smoke_test"`
	BackupPath    string `json:"backup_path,omitempty" yaml:"backup_path,omitempty"`
}

var agentInstallCmd = &cobra.Command{
	Use:   "install [name]",
	Short: "Install and configure an AI agent for OpenPass",
	Long: `Unified install command that detects an AI agent, creates a security
profile in config.yaml, generates a scoped access token, injects the
MCP server configuration into the agent's config file, and installs the
embedded skill package — all in one step.

This replaces the older mcp install, mcp-config, and agent setup commands.

The default security tier is "safe" (read-only capabilities). For "standard"
or "admin" tiers, an interactive terminal is required to confirm the
security implications.

Supported agents: openclaw, claude-code, hermes, codex, opencode`,
	Example: `  # Install and configure Claude Code (auto-detect)
  openpass agent install claude-code

  # Detect all installed agents and configure each
  openpass agent install --auto-detect

  # HTTP transport with auto-generated bearer token
  openpass agent install hermes --http

  # Standard tier with explicit confirmation
  openpass agent install codex --tier standard

  # Preview what would happen without writing anything
  openpass agent install openclaw --dry-run

  # Only install the skill package, skip MCP config
  openpass agent install opencode --skill-only

  # Only inject MCP config, skip the skill
  openpass agent install claude-code --config-only

  # Force overwrite existing profile and MCP config entries
  openpass agent install hermes --force

  # Structured JSON output for scripting
  openpass agent install opencode --output json`,
	Args: func(cmd *cobra.Command, args []string) error {
		autoDetect, _ := cmd.Flags().GetBool("auto-detect")
		if autoDetect {
			if len(args) > 0 {
				return fmt.Errorf("cannot specify an agent name with --auto-detect")
			}
			return nil
		}
		if len(args) != 1 {
			return fmt.Errorf("requires exactly 1 argument (agent name), or use --auto-detect")
		}
		return nil
	},
	Annotations: map[string]string{
		cli.RequiresVaultAnnotation: "false",
	},
	RunE: agentInstallRunE,
}

func agentInstallRunE(cmd *cobra.Command, args []string) error {
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	autoDetect, _ := cmd.Flags().GetBool("auto-detect")
	httpMode, _ := cmd.Flags().GetBool("http")
	tier, _ := cmd.Flags().GetString("tier")
	skillOnly, _ := cmd.Flags().GetBool("skill-only")
	configOnly, _ := cmd.Flags().GetBool("config-only")
	force, _ := cmd.Flags().GetBool("force")

	if skillOnly && configOnly {
		return fmt.Errorf("--skill-only and --config-only cannot be used together")
	}

	if !validTiers[tier] {
		return fmt.Errorf("invalid tier %q: must be one of: safe, standard, admin", tier)
	}

	if tier != "safe" && !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf(
			"--tier %q requires an interactive terminal to confirm the security implications; "+
				"use --tier safe (default) for non-interactive installs", tier,
		)
	}

	vDir, err := cli.VaultPath()
	if err != nil {
		return err
	}

	var results []InstallResult

	if autoDetect {
		results, err = agentInstallAutoDetect(vDir, tier, httpMode, skillOnly, configOnly, force, dryRun)
	} else {
		var result InstallResult
		result, err = agentInstallSingle(vDir, args[0], tier, httpMode, skillOnly, configOnly, force, dryRun)
		if err != nil {
			return err
		}
		results = []InstallResult{result}
	}

	if err != nil {
		return err
	}

	if len(results) == 0 {
		return nil
	}

	return writeInstallOutput(results)
}

func agentInstallSingle(vDir, agentName, tier string, httpMode, skillOnly, configOnly, force, dryRun bool) (InstallResult, error) {
	result := InstallResult{
		AgentName: agentName,
		Tier:      tier,
		SmokeTest: "skipped",
	}

	agentType, err := install.ParseAgentType(agentName)
	if err != nil {
		return result, fmt.Errorf("unsupported agent %q", agentName)
	}

	def, err := install.GetAgentDefinition(agentType)
	if err != nil {
		return result, err
	}

	detectResult, err := install.DetectAgent(agentType)
	if err != nil {
		return result, fmt.Errorf("detect agent: %w", err)
	}

	if !detectResult.Detected {
		return result, fmt.Errorf("agent %q not detected (checked binary in PATH and config files)", def.DisplayName)
	}

	method := "stdio"
	if httpMode {
		method = "http"
	}
	result.Method = method

	profilePath, err := createAgentProfileConfig(vDir, agentName, tier, force, dryRun)
	if err != nil {
		return result, fmt.Errorf("create agent profile: %w", err)
	}
	result.ProfilePath = profilePath

	if !skillOnly {
		tokenID, err := createAgentTokenInRegistry(vDir, agentName, dryRun)
		if err != nil {
			return result, fmt.Errorf("create agent token: %w", err)
		}
		result.TokenID = tokenID
	}

	if !skillOnly {
		mcpConfigPath, backupPath, err := installMCPConfig(vDir, agentType, agentName, httpMode, dryRun)
		if err != nil {
			return result, fmt.Errorf("install MCP config: %w", err)
		}
		result.MCPConfigPath = mcpConfigPath
		result.BackupPath = backupPath
	}

	if !configOnly {
		skillPath, err := installSkillPackage(agentName, tier, dryRun)
		if err != nil {
			return result, fmt.Errorf("install skill package: %w", err)
		}
		result.SkillPath = skillPath
	}

	return result, nil
}

func agentInstallAutoDetect(vDir, tier string, httpMode, skillOnly, configOnly, force, dryRun bool) ([]InstallResult, error) {
	detected := install.DetectAllAgents()
	if len(detected) == 0 {
		cli.PrintlnQuietAware("No supported agents detected.")
		return nil, nil
	}

	var results []InstallResult
	var errs []string

	for agentType, detectResult := range detected {
		if !detectResult.Detected {
			continue
		}
		def, _ := install.GetAgentDefinition(agentType)
		cli.PrintQuietAware("Detected %s\n", def.DisplayName)

		result, err := agentInstallSingle(vDir, string(agentType), tier, httpMode, skillOnly, configOnly, force, dryRun)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", def.DisplayName, err))
			if result.AgentName != "" {
				results = append(results, result)
			}
			continue
		}
		results = append(results, result)
	}

	if len(errs) > 0 {
		return results, fmt.Errorf("errors during auto-detect install:\n  %s", strings.Join(errs, "\n  "))
	}
	return results, nil
}

func createAgentProfileConfig(vDir, name, tier string, force, dryRun bool) (string, error) {
	if err := validateAgentName(name); err != nil {
		return "", err
	}

	configPath := filepath.Join(vDir, "config.yaml")
	cfg, err := configpkg.Load(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			cfg = configpkg.Default()
			cfg.VaultDir = vDir
		} else {
			return "", fmt.Errorf("load config: %w", err)
		}
	}

	if cfg.Agents == nil {
		cfg.Agents = make(map[string]configpkg.AgentProfile)
	}

	existingProfile, hasExisting := cfg.Agents[name]
	if hasExisting && !force && !dryRun {
		return "", fmt.Errorf("agent %q already exists in config (use --force to overwrite)", name)
	}

	newProfile := buildInstallProfile(name, tier)

	if hasExisting {
		newProfile.SkillPath = existingProfile.SkillPath
		newProfile.SkillVersion = existingProfile.SkillVersion
	}

	cfg.Agents[name] = newProfile

	if dryRun {
		return configPath, nil
	}

	if err := cfg.SaveTo(configPath); err != nil {
		return "", fmt.Errorf("save config: %w", err)
	}

	return configPath, nil
}

func buildInstallProfile(name, tier string) configpkg.AgentProfile {
	profile := configpkg.AgentProfile{
		Name:         name,
		AllowedPaths: []string{},
		Tier:         configpkg.StrPtr(tier),
	}

	presetName := tier
	if mapped, ok := tierPresetMapping[tier]; ok {
		presetName = mapped
	}
	configpkg.ApplyTierPreset(&profile, presetName)

	return profile
}

func createAgentTokenInRegistry(vDir, name string, dryRun bool) (string, error) {
	if dryRun {
		return "<not-generated-dry-run>", nil
	}

	if err := validateAgentName(name); err != nil {
		return "", err
	}

	regPath := mcp.TokenRegistryFilePath(vDir)
	reg := mcp.NewTokenRegistry(regPath)
	if err := reg.Load(); err != nil {
		return "", fmt.Errorf("load token registry: %w", err)
	}

	token, rawToken, err := reg.Create(
		fmt.Sprintf("agent-install-%s", name),
		[]string{"*"},
		name,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("create token: %w", err)
	}

	if err := reg.Save(); err != nil {
		return "", fmt.Errorf("save token registry: %w", err)
	}

	if _, err := writeAgentTokenFile(vDir, name, rawToken); err != nil {
		return "", fmt.Errorf("write token file: %w", err)
	}

	return token.ID, nil
}

func installMCPConfig(vDir string, agentType install.AgentType, _ string, httpMode, dryRun bool) (string, string, error) {
	def, err := install.GetAgentDefinition(agentType)
	if err != nil {
		return "", "", err
	}

	serverConfig, tokenID, err := buildServerConfig(vDir, string(agentType), httpMode, dryRun)
	if err != nil {
		return "", "", fmt.Errorf("build server config: %w", err)
	}

	detectResult, err := install.DetectAgent(agentType)
	if err != nil {
		return "", "", err
	}

	configPath := detectResult.ConfigPath
	if configPath == "" {
		configPath, err = install.ResolveConfigPath(agentType)
		if err != nil {
			return "", "", err
		}
	}

	var backupPath string
	if !dryRun {
		backupPath, _ = install.BackupConfig(configPath)
	}

	_, err = install.Install(install.InstallOptions{
		AgentType:    agentType,
		ServerConfig: serverConfig,
		Format:       def.Format,
		ConfigPath:   configPath,
		DryRun:       dryRun,
	})
	if err != nil {
		return "", "", fmt.Errorf("install MCP config for %s: %w", def.DisplayName, err)
	}

	_ = tokenID
	return configPath, backupPath, nil
}

func installSkillPackage(agentName, tier string, dryRun bool) (string, error) {
	vars := buildTemplateVars(agentName)
	vars.ProfileTier = tier

	targetPath := resolveSkillPath(agentName)
	if targetPath == "" {
		return "", fmt.Errorf("cannot determine skill path for agent %q", agentName)
	}

	targetPath = expandTilde(targetPath)

	if dryRun {
		return targetPath, nil
	}

	if err := agentskill.Install(agentName, targetPath, vars, true); err != nil {
		return "", fmt.Errorf("install skill: %w", err)
	}

	return targetPath, nil
}

func resolveSkillPath(agentName string) string {
	if path := getSkillTargetPath(agentName); path != "" {
		return path
	}

	if profile, ok := configpkg.Default().Agents[agentName]; ok && profile.SkillPath != nil && *profile.SkillPath != "" {
		return *profile.SkillPath
	}

	return ""
}

func writeInstallOutput(results []InstallResult) error {
	switch cli.OutputFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if len(results) == 1 {
			return enc.Encode(results[0])
		}
		return enc.Encode(results)

	case "yaml":
		enc := yaml.NewEncoder(os.Stdout)
		defer func() { _ = enc.Close() }()
		if len(results) == 1 {
			return enc.Encode(results[0])
		}
		return enc.Encode(results)

	default:
		for _, r := range results {
			if r.ProfilePath == "" && r.MCPConfigPath == "" && r.SkillPath == "" {
				continue
			}
			cli.PrintQuietAware("✓ Agent %q configured\n", r.AgentName)
			cli.PrintQuietAware("  Tier:         %s\n", r.Tier)
			cli.PrintQuietAware("  Transport:    %s\n", r.Method)
			if r.ProfilePath != "" {
				cli.PrintQuietAware("  Profile:      %s\n", r.ProfilePath)
			}
			if r.TokenID != "" {
				if r.TokenID == "<not-generated-dry-run>" {
					cli.PrintQuietAware("  Token ID:     <not generated (dry-run)>\n")
				} else {
					cli.PrintQuietAware("  Token ID:     %s\n", r.TokenID)
				}
			}
			if r.MCPConfigPath != "" {
				cli.PrintQuietAware("  MCP config:   %s\n", r.MCPConfigPath)
			}
			if r.BackupPath != "" {
				cli.PrintQuietAware("  Backup:       %s\n", r.BackupPath)
			}
			if r.SkillPath != "" {
				cli.PrintQuietAware("  Skill:        %s\n", r.SkillPath)
			}
			cli.PrintQuietAware("  Smoke test:   %s\n", r.SmokeTest)
		}
		return nil
	}
}

func init() {
	agentCmd.AddCommand(agentInstallCmd)
	agentInstallCmd.Flags().Bool("auto-detect", false, "Detect all installed agents and configure each")
	agentInstallCmd.Flags().String("tier", "safe", "Security tier: safe (default), standard, or admin")
	agentInstallCmd.Flags().Bool("http", false, "Use HTTP transport with auto-generated bearer token")
	agentInstallCmd.Flags().Bool("dry-run", false, "Preview changes without applying them")
	agentInstallCmd.Flags().Bool("skill-only", false, "Only install the skill package, skip MCP config")
	agentInstallCmd.Flags().Bool("config-only", false, "Only inject MCP config, skip the skill")
	agentInstallCmd.Flags().Bool("force", false, "Overwrite existing agent profile and MCP config entries")
}
