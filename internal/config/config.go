// Package config provides configuration loading, validation, and defaults for OpenPass.
package config

import "time"

const (
	defaultConfigDir      = ".openpass"
	defaultConfigFile     = "config.yaml"
	defaultAgentName      = "default"
	defaultSessionTimeout = 15 * time.Minute
	AuthMethodPassphrase  = "passphrase"
	AuthMethodTouchID     = "touchid"
)

type CustomPattern struct {
	Name        string `yaml:"name"`
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
}

type Config struct {
	Agents         map[string]AgentProfile `yaml:"agents,omitempty"`
	Vault          *VaultConfig            `yaml:"vault,omitempty"`
	Git            *GitConfig              `yaml:"git,omitempty"`
	MCP            *MCPConfig              `yaml:"mcp,omitempty"`
	Update         *UpdateConfig           `yaml:"update,omitempty"`
	Clipboard      *ClipboardConfig        `yaml:"clipboard,omitempty"`
	Audit          *AuditConfig            `yaml:"audit,omitempty"`
	Logging        *LoggingConfig          `yaml:"logging,omitempty"`
	VaultDir       string                  `yaml:"vaultDir,omitempty"`
	DefaultAgent   string                  `yaml:"defaultAgent,omitempty"`
	SessionTimeout time.Duration           `yaml:"sessionTimeout,omitempty"`
	AuthMethod     string                  `yaml:"authMethod,omitempty"`
	UseTouchID     *bool                   `yaml:"useTouchID,omitempty"`
	Profiles       map[string]*Profile     `yaml:"profiles,omitempty"`
	DefaultProfile string                  `yaml:"defaultProfile,omitempty"`
	EnvWhitelist   []string                `yaml:"envWhitelist,omitempty"`
	ScanPatterns   []CustomPattern         `yaml:"scan_patterns,omitempty"`
}

type AgentProfile struct {
	Name                string              `yaml:"-"`
	Tier                *string             `yaml:"tier,omitempty"`
	ApprovalMode        *string             `yaml:"approvalMode,omitempty"`
	AllowedPaths        []string            `yaml:"allowedPaths,omitempty"`
	RedactFields        []string            `yaml:"redactFields,omitempty"`
	PerToolRedactFields map[string][]string `yaml:"perToolRedactFields,omitempty"`
	CanWrite            *bool               `yaml:"canWrite,omitempty"`
	CanRunCommands      *bool               `yaml:"canRunCommands,omitempty"`
	CanManageConfig     *bool               `yaml:"canManageConfig,omitempty"`
	CanUseClipboard     *bool               `yaml:"canUseClipboard,omitempty"`
	CanUseAutotype      *bool               `yaml:"canUseAutotype,omitempty"`
	CanReadValues       *bool               `yaml:"canReadValues,omitempty"`
	ExposeValueTools    *bool               `yaml:"exposeValueTools,omitempty"`
	AutoUnseal          *bool               `yaml:"autoUnseal,omitempty"`
	RequireApproval     *bool               `yaml:"requireApproval,omitempty"`
	ApprovalTimeout     *time.Duration      `yaml:"approvalTimeout,omitempty"`
	AllowedTools        []string            `yaml:"allowed_tools,omitempty"`
	MaxReadsPerHour     *int                `yaml:"max_reads_per_hour,omitempty"`
	MaxReadsPerDay      *int                `yaml:"max_reads_per_day,omitempty"`
	MaxSecretsInSession *int                `yaml:"max_secrets_in_session,omitempty"`
	DynamicProviders    map[string][]string `yaml:"dynamicProviders,omitempty"`
	AllowedEnvVars      []string            `yaml:"allowedEnvVars,omitempty"`
	AllowedExecutables  []string            `yaml:"allowedExecutables,omitempty"`
	PromptInjectionMode *string             `yaml:"promptInjectionMode,omitempty"`
	PreCallHooks        []string            `yaml:"pre_call_hooks,omitempty"`
	PostCallHooks       []string            `yaml:"post_call_hooks,omitempty"`
	SkillPath           *string             `yaml:"skillPath,omitempty"`
	SkillVersion        *string             `yaml:"skillVersion,omitempty"`
}

func (p *AgentProfile) EffectiveRedactFields(toolName string) []string {
	if p == nil {
		return nil
	}
	if len(p.RedactFields) == 0 && len(p.PerToolRedactFields[toolName]) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(p.RedactFields)+len(p.PerToolRedactFields[toolName]))
	result := make([]string, 0, len(p.RedactFields)+len(p.PerToolRedactFields[toolName]))
	for _, f := range p.RedactFields {
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			result = append(result, f)
		}
	}
	for _, f := range p.PerToolRedactFields[toolName] {
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			result = append(result, f)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
