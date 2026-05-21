// Package config provides configuration loading, validation, and defaults for OpenPass.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/danieljustus/OpenPass/internal/fileutil"
	"github.com/danieljustus/OpenPass/internal/pathutil"
)

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

func Default() *Config {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "~"
	}

	return &Config{
		VaultDir:       filepath.Join(home, defaultConfigDir),
		DefaultAgent:   defaultAgentName,
		SessionTimeout: defaultSessionTimeout,
		AuthMethod:     AuthMethodPassphrase,
		Agents:         builtinAgentProfiles(),
	}
}

func validateConfigPath(path string) error {
	if pathutil.HasTraversal(path) {
		return errors.New("config file path escapes expected directory")
	}
	return nil
}

func mergeStringPtr(dst, src *string) *string {
	if src != nil {
		return src
	}
	return dst
}

func mergeBoolPtr(dst, src *bool) *bool {
	if src != nil {
		return src
	}
	return dst
}

func mergeIntPtr(dst, src *int) *int {
	if src != nil {
		return src
	}
	return dst
}

func mergeDurationPtr(dst, src *time.Duration) *time.Duration {
	if src != nil {
		return src
	}
	return dst
}

func mergeStringSlice(dst, src []string) []string {
	if src != nil {
		return append([]string(nil), src...)
	}
	return dst
}

func mergeStringSliceMap(dst, src map[string][]string) map[string][]string {
	if src == nil {
		return dst
	}
	result := make(map[string][]string, len(src))
	for k, v := range src {
		result[k] = append([]string(nil), v...)
	}
	return result
}

func Load(path string) (*Config, error) {
	if err := validateConfigPath(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	cfg := Default()
	if len(bytes.TrimSpace(data)) == 0 {
		return cfg, nil
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	agentFields := loadAgentFields(&doc)
	sectionFields := loadSectionFields(&doc)

	var raw Config
	if err := doc.Decode(&raw); err != nil {
		return nil, err
	}

	mergeTopLevel(cfg, raw)
	mergeAgentProfiles(cfg, raw, agentFields)
	if err := validateAgents(cfg.Agents); err != nil {
		return nil, err
	}
	mergeSections(cfg, raw, sectionFields)

	if cfg.MCP != nil && cfg.MCP.Bind == "" {
		return nil, fmt.Errorf("mcp.bind must not be empty")
	}

	useTouchID := cfg.EffectiveAuthMethod() == AuthMethodTouchID
	cfg.UseTouchID = &useTouchID

	return cfg, nil
}

func mergeTopLevel(cfg *Config, raw Config) {
	if raw.VaultDir != "" {
		cfg.VaultDir = raw.VaultDir
	}
	if raw.DefaultAgent != "" {
		cfg.DefaultAgent = raw.DefaultAgent
	}
	if raw.SessionTimeout > 0 {
		cfg.SessionTimeout = raw.SessionTimeout
	}
	if raw.AuthMethod != "" {
		authMethod, err := NormalizeAuthMethod(raw.AuthMethod)
		if err == nil {
			cfg.AuthMethod = authMethod
		}
	}
	if raw.UseTouchID != nil && *raw.UseTouchID {
		cfg.UseTouchID = raw.UseTouchID
		if raw.AuthMethod == "" {
			cfg.AuthMethod = AuthMethodTouchID
		}
	}
	if raw.DefaultProfile != "" {
		cfg.DefaultProfile = raw.DefaultProfile
	}
	if raw.EnvWhitelist != nil {
		cfg.EnvWhitelist = append([]string(nil), raw.EnvWhitelist...)
	}
	if raw.ScanPatterns != nil {
		cfg.ScanPatterns = append([]CustomPattern(nil), raw.ScanPatterns...)
	}
	if raw.Profiles != nil {
		cfg.Profiles = make(map[string]*Profile, len(raw.Profiles))
		for name, fp := range raw.Profiles {
			cfg.Profiles[name] = &Profile{VaultPath: fp.VaultPath}
		}
	}
}

func mergeAgentProfiles(cfg *Config, raw Config, agentFields map[string]map[string]bool) {
	if raw.Agents != nil {
		for name, yamlProfile := range raw.Agents {
			cfg.Agents[name] = mergeAgentProfile(cfg.Agents[name], name, yamlProfile, agentFields[name])
		}
	}
	cfg.Agents = ensureAgentDefaults(cfg.Agents, cfg.DefaultAgent)
}

func mergeSections(cfg *Config, raw Config, sectionFields map[string]map[string]bool) {
	if raw.Vault != nil {
		cfg.Vault = mergeVaultConfig(raw.Vault, sectionFields["vault"], raw.AuthMethod, &cfg.AuthMethod)
	}
	if raw.Git != nil {
		cfg.Git = mergeGitConfig(raw.Git, sectionFields["git"])
	}
	if raw.MCP != nil {
		cfg.MCP = mergeMCPConfig(raw.MCP, sectionFields["mcp"], sectionFields["mcp_oauth"])
	}
	if raw.Update != nil {
		cfg.Update = mergeUpdateConfig(raw.Update, sectionFields["update"])
	}
	if raw.Clipboard != nil {
		cfg.Clipboard = mergeClipboardConfig(raw.Clipboard, sectionFields["clipboard"])
	}
	if raw.Audit != nil {
		cfg.Audit = mergeAuditConfig(raw.Audit, sectionFields["audit"])
	}
	if raw.Logging != nil {
		cfg.Logging = mergeLoggingConfig(raw.Logging, sectionFields["logging"])
	}
}

func loadAgentFields(doc *yaml.Node) map[string]map[string]bool {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	var agentsNode *yaml.Node
	for i := 0; i < len(root.Content)-1; i += 2 {
		if root.Content[i].Value == "agents" {
			agentsNode = root.Content[i+1]
			break
		}
	}
	if agentsNode == nil || agentsNode.Kind != yaml.MappingNode {
		return nil
	}
	result := make(map[string]map[string]bool)
	for i := 0; i < len(agentsNode.Content)-1; i += 2 {
		name := agentsNode.Content[i].Value
		profileNode := agentsNode.Content[i+1]
		if profileNode.Kind != yaml.MappingNode {
			continue
		}
		fields := make(map[string]bool)
		for j := 0; j < len(profileNode.Content)-1; j += 2 {
			fields[profileNode.Content[j].Value] = true
		}
		result[name] = fields
	}
	return result
}

// loadSectionFields walks the parsed YAML node tree to discover which fields
// were explicitly set under each sub-config section. Returns a map of section
// name → set of YAML field names present.
func loadSectionFields(doc *yaml.Node) map[string]map[string]bool {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	sections := []string{"vault", "git", "mcp", "update", "clipboard", "audit", "logging"}
	result := make(map[string]map[string]bool)
	for i := 0; i < len(root.Content)-1; i += 2 {
		key := root.Content[i].Value
		for _, sec := range sections {
			if key == sec {
				secNode := root.Content[i+1]
				if secNode.Kind == yaml.MappingNode {
					fields := make(map[string]bool)
					for j := 0; j < len(secNode.Content)-1; j += 2 {
						fieldKey := secNode.Content[j].Value
						fields[fieldKey] = true
						if fieldKey == "oauth" && sec == "mcp" {
							oAuthNode := secNode.Content[j+1]
							if oAuthNode.Kind == yaml.MappingNode {
								oAuthFields := make(map[string]bool)
								for k := 0; k < len(oAuthNode.Content)-1; k += 2 {
									oAuthFields[oAuthNode.Content[k].Value] = true
								}
								result["mcp_oauth"] = oAuthFields
							}
						}
					}
					result[sec] = fields
				}
				break
			}
		}
	}
	return result
}

func mergeAgentProfile(current AgentProfile, name string, yamlProfile AgentProfile, fields map[string]bool) AgentProfile {
	current.Name = name

	if fields["tier"] && yamlProfile.Tier != nil {
		ApplyTierPreset(&current, *yamlProfile.Tier)
		current.Tier = yamlProfile.Tier
	}

	if !fields["tier"] && !fields["exposeValueTools"] {
		v := true
		current.ExposeValueTools = &v
	}

	if fields["allowedPaths"] {
		if yamlProfile.AllowedPaths != nil {
			current.AllowedPaths = append([]string(nil), yamlProfile.AllowedPaths...)
		} else {
			current.AllowedPaths = []string{}
		}
	} else if current.AllowedPaths == nil {
		current.AllowedPaths = []string{}
	}

	current.CanWrite = mergeBoolPtr(current.CanWrite, yamlProfile.CanWrite)
	current.CanRunCommands = mergeBoolPtr(current.CanRunCommands, yamlProfile.CanRunCommands)
	current.CanManageConfig = mergeBoolPtr(current.CanManageConfig, yamlProfile.CanManageConfig)
	current.CanUseClipboard = mergeBoolPtr(current.CanUseClipboard, yamlProfile.CanUseClipboard)
	current.CanUseAutotype = mergeBoolPtr(current.CanUseAutotype, yamlProfile.CanUseAutotype)
	current.CanReadValues = mergeBoolPtr(current.CanReadValues, yamlProfile.CanReadValues)
	current.RequireApproval = mergeBoolPtr(current.RequireApproval, yamlProfile.RequireApproval)
	current.ApprovalTimeout = mergeDurationPtr(current.ApprovalTimeout, yamlProfile.ApprovalTimeout)

	if fields["approvalMode"] {
		current.ApprovalMode = yamlProfile.ApprovalMode
	} else if fields["requireApproval"] && yamlProfile.RequireApproval != nil {
		if *yamlProfile.RequireApproval {
			v := "prompt"
			current.ApprovalMode = &v
		} else {
			v := "none"
			current.ApprovalMode = &v
		}
	}

	if fields["redactFields"] {
		if yamlProfile.RedactFields != nil {
			current.RedactFields = append([]string(nil), yamlProfile.RedactFields...)
		} else {
			current.RedactFields = nil
		}
	}
	if fields["perToolRedactFields"] {
		if yamlProfile.PerToolRedactFields != nil {
			if current.PerToolRedactFields == nil {
				current.PerToolRedactFields = make(map[string][]string, len(yamlProfile.PerToolRedactFields))
			}
			for tool, fieldsList := range yamlProfile.PerToolRedactFields {
				current.PerToolRedactFields[tool] = append(current.PerToolRedactFields[tool], fieldsList...)
			}
		}
	}
	if fields["allowed_tools"] {
		if yamlProfile.AllowedTools != nil {
			current.AllowedTools = append([]string(nil), yamlProfile.AllowedTools...)
		}
	}
	current.MaxReadsPerHour = mergeIntPtr(current.MaxReadsPerHour, yamlProfile.MaxReadsPerHour)
	current.MaxReadsPerDay = mergeIntPtr(current.MaxReadsPerDay, yamlProfile.MaxReadsPerDay)
	current.MaxSecretsInSession = mergeIntPtr(current.MaxSecretsInSession, yamlProfile.MaxSecretsInSession)
	current.ExposeValueTools = mergeBoolPtr(current.ExposeValueTools, yamlProfile.ExposeValueTools)
	current.AutoUnseal = mergeBoolPtr(current.AutoUnseal, yamlProfile.AutoUnseal)
	if fields["dynamicProviders"] && yamlProfile.DynamicProviders != nil {
		current.DynamicProviders = mergeStringSliceMap(current.DynamicProviders, yamlProfile.DynamicProviders)
	}
	if fields["allowedEnvVars"] {
		current.AllowedEnvVars = mergeStringSlice(current.AllowedEnvVars, yamlProfile.AllowedEnvVars)
	}
	if fields["allowedExecutables"] {
		current.AllowedExecutables = mergeStringSlice(current.AllowedExecutables, yamlProfile.AllowedExecutables)
	}
	current.PromptInjectionMode = mergeStringPtr(current.PromptInjectionMode, yamlProfile.PromptInjectionMode)
	current.SkillPath = mergeStringPtr(current.SkillPath, yamlProfile.SkillPath)
	current.SkillVersion = mergeStringPtr(current.SkillVersion, yamlProfile.SkillVersion)

	return current
}

func validateAgents(agents map[string]AgentProfile) error {
	for name, profile := range agents {
		mode := ""
		if profile.ApprovalMode != nil {
			mode = *profile.ApprovalMode
		}
		switch mode {
		case "", "none", "deny", "prompt":
		default:
			return fmt.Errorf("agent %q: invalid approvalMode %q (valid: none, deny, prompt)", name, mode)
		}
	}
	for name, profile := range agents {
		mode := ""
		if profile.PromptInjectionMode != nil {
			mode = *profile.PromptInjectionMode
		}
		switch mode {
		case "", "off", "log-only", "wrap", "deny":
		default:
			return fmt.Errorf("agent %q: invalid promptInjectionMode %q (valid: off, log-only, wrap, deny)", name, mode)
		}
	}
	return nil
}

func ensureAgentDefaults(agents map[string]AgentProfile, defaultAgent string) map[string]AgentProfile {
	if agents == nil {
		agents = map[string]AgentProfile{}
	}
	for name, profile := range agents {
		profile.Name = name
		agents[name] = profile
	}
	if _, ok := agents[defaultAgent]; !ok {
		agents[defaultAgent] = newDefaultAgentProfile(defaultAgent)
	}
	return agents
}

func mergeVaultConfig(raw *VaultConfig, sf map[string]bool, rawAuthMethod string, cfgAuthMethod *string) *VaultConfig {
	defaults := defaultVaultConfig()
	if sf["path"] {
		defaults.Path = raw.Path
	}
	if sf["default_recipients"] && raw.DefaultRecipients != nil {
		defaults.DefaultRecipients = append([]string(nil), raw.DefaultRecipients...)
	}
	if sf["confirm_remove"] {
		defaults.ConfirmRemove = raw.ConfirmRemove
	}
	if sf["authMethod"] {
		defaults.AuthMethod = raw.AuthMethod
	}
	if sf["useTouchID"] {
		defaults.UseTouchID = raw.UseTouchID
	}
	if sf["legacy_mode"] && raw.LegacyMode != nil {
		defaults.LegacyMode = raw.LegacyMode
	}
	if sf["search_workers"] {
		defaults.SearchWorkers = raw.SearchWorkers
	}
	if sf["pseudonymize_paths"] {
		defaults.PseudonymizePaths = raw.PseudonymizePaths
	}
	if sf["scrypt_work_factor"] {
		defaults.ScryptWorkFactor = raw.ScryptWorkFactor
	}
	if sf["last_rotated"] {
		defaults.LastRotated = raw.LastRotated
	}
	if sf["format_version"] {
		defaults.FormatVersion = raw.FormatVersion
	}
	if sf["argon2id_time"] {
		defaults.Argon2idTime = raw.Argon2idTime
	}
	if sf["argon2id_memory"] {
		defaults.Argon2idMemory = raw.Argon2idMemory
	}
	if sf["argon2id_threads"] {
		defaults.Argon2idThreads = raw.Argon2idThreads
	}
	if sf["authMethod"] && defaults.AuthMethod != "" {
		authMethod, err := NormalizeAuthMethod(defaults.AuthMethod)
		if err == nil {
			defaults.AuthMethod = authMethod
			if rawAuthMethod == "" {
				*cfgAuthMethod = authMethod
			}
		}
	}
	if rawAuthMethod == "" && !sf["authMethod"] && raw.UseTouchID {
		*cfgAuthMethod = AuthMethodTouchID
	}
	return &defaults
}

func mergeGitConfig(raw *GitConfig, sf map[string]bool) *GitConfig {
	defaults := defaultGitConfig()
	if sf["auto_push"] {
		defaults.AutoPush = raw.AutoPush
	}
	if sf["auto_pull"] {
		defaults.AutoPull = raw.AutoPull
	}
	if sf["auto_pull_interval"] {
		defaults.AutoPullInterval = raw.AutoPullInterval
	}
	if sf["commit_template"] {
		defaults.CommitTemplate = raw.CommitTemplate
	}
	return &defaults
}

func mergeMCPConfig(raw *MCPConfig, sf, oaf map[string]bool) *MCPConfig {
	defaults := defaultMCPConfig()
	if raw.ApprovalRequired {
		fmt.Fprintln(os.Stderr, "Warning: approval_required is deprecated and will be removed in a future version")
	}
	if sf["port"] {
		defaults.Port = raw.Port
	}
	if sf["bind"] {
		defaults.Bind = raw.Bind
	}
	if sf["stdio"] {
		defaults.Stdio = raw.Stdio
	}
	if sf["httpTokenFile"] {
		defaults.HTTPTokenFile = raw.HTTPTokenFile
	}
	if sf["otlp_endpoint"] {
		defaults.OTLPEndpoint = raw.OTLPEndpoint
	}
	if sf["read_header_timeout"] {
		defaults.ReadHeaderTimeout = raw.ReadHeaderTimeout
	}
	if sf["read_timeout"] {
		defaults.ReadTimeout = raw.ReadTimeout
	}
	if sf["write_timeout"] {
		defaults.WriteTimeout = raw.WriteTimeout
	}
	if sf["shutdown_timeout"] {
		defaults.ShutdownTimeout = raw.ShutdownTimeout
	}
	if sf["approval_timeout"] {
		defaults.ApprovalTimeout = raw.ApprovalTimeout
	}
	if sf["rate_limit"] {
		defaults.RateLimit = raw.RateLimit
	}
	if sf["trusted_proxy_ips"] && raw.TrustedProxyIPs != nil {
		defaults.TrustedProxyIPs = append([]string(nil), raw.TrustedProxyIPs...)
	}
	if sf["metrics_auth_required"] {
		defaults.MetricsAuthRequired = raw.MetricsAuthRequired
	}
	if sf["tls_cert_file"] {
		defaults.TLSCertFile = raw.TLSCertFile
	}
	if sf["tls_key_file"] {
		defaults.TLSKeyFile = raw.TLSKeyFile
	}
	if sf["allow_insecure_bind"] {
		defaults.AllowInsecureBind = raw.AllowInsecureBind
	}
	if sf["oauth"] && raw.OAuth != nil {
		if defaults.OAuth == nil {
			defaults.OAuth = &OAuthConfig{}
		}
		if oaf["access_token_ttl"] && raw.OAuth.AccessTokenTTL > 0 {
			defaults.OAuth.AccessTokenTTL = raw.OAuth.AccessTokenTTL
		}
		if oaf["refresh_token_ttl"] && raw.OAuth.RefreshTokenTTL > 0 {
			defaults.OAuth.RefreshTokenTTL = raw.OAuth.RefreshTokenTTL
		}
	}
	return &defaults
}

func mergeUpdateConfig(raw *UpdateConfig, sf map[string]bool) *UpdateConfig {
	defaults := defaultUpdateConfig()
	if sf["cache_ttl"] {
		defaults.CacheTTL = raw.CacheTTL
	}
	return &defaults
}

func mergeClipboardConfig(raw *ClipboardConfig, sf map[string]bool) *ClipboardConfig {
	defaults := defaultClipboardConfig()
	if sf["auto_clear_duration"] {
		defaults.AutoClearDuration = raw.AutoClearDuration
	}
	if sf["printByDefault"] {
		defaults.PrintByDefault = raw.PrintByDefault
	}
	return &defaults
}

func mergeAuditConfig(raw *AuditConfig, sf map[string]bool) *AuditConfig {
	defaults := defaultAuditConfig()
	if sf["maxSizeMb"] {
		defaults.MaxFileSize = raw.MaxFileSize * 1024 * 1024
	}
	if sf["maxBackups"] {
		defaults.MaxBackups = raw.MaxBackups
	}
	if sf["maxAgeDays"] {
		defaults.MaxAgeDays = raw.MaxAgeDays
	}
	return &defaults
}

func mergeLoggingConfig(raw *LoggingConfig, sf map[string]bool) *LoggingConfig {
	defaults := defaultLoggingConfig()
	if sf["level"] {
		defaults.Level = raw.Level
	}
	if sf["format"] {
		defaults.Format = raw.Format
	}
	return &defaults
}

func (c *Config) Save() error {
	if c == nil {
		return errors.New("config is nil")
	}

	path, err := defaultConfigPath()
	if err != nil {
		return err
	}
	return c.SaveTo(path)
}

func (c *Config) SaveTo(path string) error {
	if c == nil {
		return errors.New("config is nil")
	}
	if err := validateConfigPath(path); err != nil {
		return err
	}

	if mkdirErr := os.MkdirAll(filepath.Dir(path), 0o700); mkdirErr != nil {
		return mkdirErr
	}

	authMethod := c.EffectiveAuthMethod()

	raw := Config{
		VaultDir:       c.VaultDir,
		DefaultAgent:   c.DefaultAgent,
		SessionTimeout: c.SessionTimeout,
		AuthMethod:     authMethod,
		DefaultProfile: c.DefaultProfile,
		Agents:         make(map[string]AgentProfile, len(c.Agents)),
	}

	if c.UseTouchID != nil && *c.UseTouchID {
		useTouchID := true
		raw.UseTouchID = &useTouchID
	} else if c.UseTouchID != nil {
		useTouchID := false
		raw.UseTouchID = &useTouchID
	}

	if c.Vault != nil {
		vaultAuthMethod := c.Vault.AuthMethod
		if vaultAuthMethod == "" && authMethod != "" {
			vaultAuthMethod = authMethod
		}
		raw.Vault = &VaultConfig{
			Path:              c.Vault.Path,
			DefaultRecipients: append([]string(nil), c.Vault.DefaultRecipients...),
			ConfirmRemove:     c.Vault.ConfirmRemove,
			AuthMethod:        vaultAuthMethod,
			UseTouchID:        c.Vault.UseTouchID,
			LegacyMode:        c.Vault.LegacyMode,
			SearchWorkers:     c.Vault.SearchWorkers,
			PseudonymizePaths: c.Vault.PseudonymizePaths,
			ScryptWorkFactor:  c.Vault.ScryptWorkFactor,
			LastRotated:       c.Vault.LastRotated,
			FormatVersion:     c.Vault.FormatVersion,
			Argon2idTime:      c.Vault.Argon2idTime,
			Argon2idMemory:    c.Vault.Argon2idMemory,
			Argon2idThreads:   c.Vault.Argon2idThreads,
		}
	}

	if c.Git != nil {
		raw.Git = &GitConfig{
			AutoPush:         c.Git.AutoPush,
			AutoPull:         c.Git.AutoPull,
			AutoPullInterval: c.Git.AutoPullInterval,
			CommitTemplate:   c.Git.CommitTemplate,
		}
	}

	if c.MCP != nil {
		raw.MCP = &MCPConfig{
			Port:                c.MCP.Port,
			Bind:                c.MCP.Bind,
			Stdio:               c.MCP.Stdio,
			HTTPTokenFile:       c.MCP.HTTPTokenFile,
			ReadHeaderTimeout:   c.MCP.ReadHeaderTimeout,
			ReadTimeout:         c.MCP.ReadTimeout,
			WriteTimeout:        c.MCP.WriteTimeout,
			ShutdownTimeout:     c.MCP.ShutdownTimeout,
			ApprovalTimeout:     c.MCP.ApprovalTimeout,
			RateLimit:           c.MCP.RateLimit,
			MetricsAuthRequired: c.MCP.MetricsAuthRequired,
			AllowInsecureBind:   c.MCP.AllowInsecureBind,
		}
		if c.MCP.OTLPEndpoint != "" {
			raw.MCP.OTLPEndpoint = c.MCP.OTLPEndpoint
		}
		if c.MCP.TrustedProxyIPs != nil {
			raw.MCP.TrustedProxyIPs = append([]string(nil), c.MCP.TrustedProxyIPs...)
		}
		if c.MCP.TLSCertFile != "" {
			raw.MCP.TLSCertFile = c.MCP.TLSCertFile
		}
		if c.MCP.TLSKeyFile != "" {
			raw.MCP.TLSKeyFile = c.MCP.TLSKeyFile
		}
	}

	if c.Update != nil {
		raw.Update = &UpdateConfig{
			CacheTTL: c.Update.CacheTTL,
		}
	}

	if c.Clipboard != nil {
		raw.Clipboard = &ClipboardConfig{
			AutoClearDuration: c.Clipboard.AutoClearDuration,
			PrintByDefault:    c.Clipboard.PrintByDefault,
		}
	}
	if c.Audit != nil {
		raw.Audit = &AuditConfig{
			MaxFileSize: c.Audit.MaxFileSize / (1024 * 1024),
			MaxBackups:  c.Audit.MaxBackups,
			MaxAgeDays:  c.Audit.MaxAgeDays,
		}
	}
	if c.Logging != nil {
		raw.Logging = &LoggingConfig{
			Level:  c.Logging.Level,
			Format: c.Logging.Format,
		}
	}
	if len(c.ScanPatterns) > 0 {
		raw.ScanPatterns = append([]CustomPattern(nil), c.ScanPatterns...)
	}
	raw.Agents = copyAgentProfiles(c.Agents)
	for name, profile := range c.Profiles {
		if profile != nil {
			if raw.Profiles == nil {
				raw.Profiles = make(map[string]*Profile)
			}
			raw.Profiles[name] = profile
		}
	}

	data, err := yaml.Marshal(&raw)
	if err != nil {
		return err
	}
	return fileutil.AtomicWriteFile(path, data, 0o600)
}

func copyAgentProfiles(agents map[string]AgentProfile) map[string]AgentProfile {
	result := make(map[string]AgentProfile, len(agents))
	for name, profile := range agents {
		data, err := json.Marshal(profile)
		if err != nil {
			// Marshal cannot fail for AgentProfile - all fields are JSON-safe types.
			panic("copyAgentProfiles: json.Marshal failed: " + err.Error())
		}
		var cp AgentProfile
		if err := json.Unmarshal(data, &cp); err != nil {
			// Unmarshal cannot fail for AgentProfile - round-trip through JSON is safe.
			panic("copyAgentProfiles: json.Unmarshal failed: " + err.Error())
		}
		result[name] = cp
	}
	return result
}

func defaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("unable to determine home directory")
	}
	return filepath.Join(home, defaultConfigDir, defaultConfigFile), nil
}

func NormalizeAuthMethod(method string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "", AuthMethodPassphrase:
		return AuthMethodPassphrase, nil
	case AuthMethodTouchID, "touch-id", "touch_id", "biometric", "biometrics":
		return AuthMethodTouchID, nil
	default:
		return "", fmt.Errorf("invalid authMethod %q (valid: passphrase, touchid)", method)
	}
}

func (c *Config) EffectiveAuthMethod() string {
	if c == nil {
		return AuthMethodPassphrase
	}
	if c.AuthMethod != "" {
		method, err := NormalizeAuthMethod(c.AuthMethod)
		if err == nil {
			return method
		}
	}
	if c.UseTouchID != nil && *c.UseTouchID {
		return AuthMethodTouchID
	}
	if c.Vault != nil {
		if c.Vault.AuthMethod != "" {
			method, err := NormalizeAuthMethod(c.Vault.AuthMethod)
			if err == nil {
				return method
			}
		}
		if c.Vault.UseTouchID {
			return AuthMethodTouchID
		}
	}
	return AuthMethodPassphrase
}

func (c *Config) SetAuthMethod(method string) error {
	normalized, err := NormalizeAuthMethod(method)
	if err != nil {
		return err
	}
	c.AuthMethod = normalized
	useTouchID := normalized == AuthMethodTouchID
	c.UseTouchID = &useTouchID
	if c.Vault != nil {
		c.Vault.AuthMethod = normalized
		c.Vault.UseTouchID = useTouchID
	}
	return nil
}

func newDefaultAgentProfile(name string) AgentProfile {
	canWrite := false
	canRunCommands := false
	exposeValueTools := true
	autoUnseal := true
	deny := "deny"
	return AgentProfile{
		Name:             name,
		AllowedPaths:     []string{},
		CanWrite:         &canWrite,
		CanRunCommands:   &canRunCommands,
		ApprovalMode:     &deny,
		ExposeValueTools: &exposeValueTools,
		AutoUnseal:       &autoUnseal,
	}
}

func builtinAgentProfiles() map[string]AgentProfile {
	canWriteTrue := true
	canWriteFalse := false
	canRunFalse := false
	exposeTrue := true
	autoUnsealTrue := true
	deny := "deny"
	return map[string]AgentProfile{
		"default":     {Name: "default", AllowedPaths: []string{}, CanWrite: &canWriteFalse, CanRunCommands: &canRunFalse, ApprovalMode: &deny, ExposeValueTools: &exposeTrue, AutoUnseal: &autoUnsealTrue},
		"claude-code": {Name: "claude-code", AllowedPaths: []string{}, CanWrite: &canWriteTrue, CanRunCommands: &canRunFalse, ApprovalMode: &deny, ExposeValueTools: &exposeTrue, AutoUnseal: &autoUnsealTrue, SkillPath: StrPtr("~/.claude/skills/openpass/SKILL.md")},
		"codex":       {Name: "codex", AllowedPaths: []string{}, CanWrite: &canWriteFalse, CanRunCommands: &canRunFalse, ApprovalMode: &deny, ExposeValueTools: &exposeTrue, AutoUnseal: &autoUnsealTrue, SkillPath: StrPtr("~/.codex/skills/openpass/AGENTS.md")},
		"hermes":      {Name: "hermes", AllowedPaths: []string{}, CanWrite: &canWriteTrue, CanRunCommands: &canRunFalse, ApprovalMode: &deny, ExposeValueTools: &exposeTrue, AutoUnseal: &autoUnsealTrue, SkillPath: StrPtr("~/.hermes/skills/openpass/SKILL.md")},
		"openclaw":    {Name: "openclaw", AllowedPaths: []string{}, CanWrite: &canWriteTrue, CanRunCommands: &canRunFalse, ApprovalMode: &deny, ExposeValueTools: &exposeTrue, AutoUnseal: &autoUnsealTrue, SkillPath: StrPtr("~/.openclaw/skills/openpass/SKILL.md")},
		"opencode":    {Name: "opencode", AllowedPaths: []string{}, CanWrite: &canWriteFalse, CanRunCommands: &canRunFalse, ApprovalMode: &deny, ExposeValueTools: &exposeTrue, AutoUnseal: &autoUnsealTrue, SkillPath: StrPtr("~/.opencode/skills/openpass/SKILL.md")},
	}
}

func (c *Config) Validate() error {
	var errs error

	if strings.TrimSpace(c.VaultDir) == "" {
		errs = errors.Join(errs, errors.New("vaultDir: must not be empty (set OPENPASS_VAULT environment variable or configure vaultDir in config.yaml)"))
	}

	if c.SessionTimeout <= 0 {
		errs = errors.Join(errs, errors.New("sessionTimeout: must be greater than 0 (default: 15m, configure sessionTimeout in config.yaml)"))
	}

	if c.AuthMethod != "" {
		if _, err := NormalizeAuthMethod(c.AuthMethod); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if c.Vault != nil && c.Vault.AuthMethod != "" {
		if _, err := NormalizeAuthMethod(c.Vault.AuthMethod); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if c.AuthMethod == "" && (c.Vault == nil || c.Vault.AuthMethod == "") {
		if _, err := NormalizeAuthMethod(c.EffectiveAuthMethod()); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	if c.DefaultAgent != "" {
		if _, ok := c.Agents[c.DefaultAgent]; !ok {
			errs = errors.Join(errs, fmt.Errorf("defaultAgent: %q not found in agents (define a matching agent profile in the agents section of config.yaml)", c.DefaultAgent))
		}
	}

	for name, agent := range c.Agents {
		mode := ""
		if agent.ApprovalMode != nil {
			mode = *agent.ApprovalMode
		}
		switch mode {
		case "", "none", "deny", "prompt", "auto":
		default:
			errs = errors.Join(errs, fmt.Errorf("agents.%s.approvalMode: invalid value %q (valid: none, deny, prompt, auto; configure in config.yaml)", name, mode))
		}
	}

	for name, agent := range c.Agents {
		for i, path := range agent.AllowedPaths {
			if _, err := filepath.Match(path, ""); err != nil {
				errs = errors.Join(errs, fmt.Errorf("agents.%s.allowedPaths[%d]: invalid glob pattern %q (use valid filepath.Match syntax, configure in config.yaml)", name, i, path))
			}
		}
	}

	if c.Audit != nil && c.Audit.MaxFileSize <= 0 {
		errs = errors.Join(errs, errors.New("audit.maxFileSize: must be greater than 0 (configure audit.maxFileSize in config.yaml)"))
	}

	if c.Clipboard != nil && c.Clipboard.AutoClearDuration < 0 {
		errs = errors.Join(errs, errors.New("clipboard.autoClearDuration: must be non-negative (configure clipboard.autoClearDuration in config.yaml)"))
	}

	return errs
}
