// Package config provides configuration loading, validation, and defaults for OpenPass.
package config

import (
	"bytes"
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

//nolint:gocyclo // Complex config loading with backward compatibility
func Load(path string) (*Config, error) {
	if err := validateConfigPath(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
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
		if err != nil {
			return nil, err
		}
		cfg.AuthMethod = authMethod
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
			cfg.Profiles[name] = &Profile{
				VaultPath: fp.VaultPath,
			}
		}
	}

	if raw.Agents != nil {
		for name, yamlProfile := range raw.Agents {
			current, ok := cfg.Agents[name]
			if !ok {
				current = newDefaultAgentProfile(name)
			}
			current.Name = name

			fields := agentFields[name]

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
			if fields["canWrite"] {
				current.CanWrite = yamlProfile.CanWrite
			}
			if fields["canRunCommands"] {
				current.CanRunCommands = yamlProfile.CanRunCommands
			}
			if fields["canManageConfig"] {
				current.CanManageConfig = yamlProfile.CanManageConfig
			}
			if fields["canUseClipboard"] {
				current.CanUseClipboard = yamlProfile.CanUseClipboard
			}
			if fields["canUseAutotype"] {
				current.CanUseAutotype = yamlProfile.CanUseAutotype
			}
			if fields["canReadValues"] {
				current.CanReadValues = yamlProfile.CanReadValues
			}
			if fields["requireApproval"] {
				current.RequireApproval = yamlProfile.RequireApproval
			}
			if fields["approvalTimeout"] {
				current.ApprovalTimeout = yamlProfile.ApprovalTimeout
			}
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
			if fields["max_reads_per_hour"] {
				current.MaxReadsPerHour = yamlProfile.MaxReadsPerHour
			}
			if fields["max_reads_per_day"] {
				current.MaxReadsPerDay = yamlProfile.MaxReadsPerDay
			}
			if fields["max_secrets_in_session"] {
				current.MaxSecretsInSession = yamlProfile.MaxSecretsInSession
			}
			if fields["exposeValueTools"] {
				current.ExposeValueTools = yamlProfile.ExposeValueTools
			}
			if fields["autoUnseal"] {
				current.AutoUnseal = yamlProfile.AutoUnseal
			}
			if fields["dynamicProviders"] {
				if yamlProfile.DynamicProviders != nil {
					current.DynamicProviders = make(map[string][]string, len(yamlProfile.DynamicProviders))
					for p, roles := range yamlProfile.DynamicProviders {
						rolesCopy := append([]string(nil), roles...)
						current.DynamicProviders[p] = rolesCopy
					}
				}
			}
			if fields["allowedEnvVars"] {
				if yamlProfile.AllowedEnvVars != nil {
					current.AllowedEnvVars = append([]string(nil), yamlProfile.AllowedEnvVars...)
				}
			}
			if fields["allowedExecutables"] {
				if yamlProfile.AllowedExecutables != nil {
					current.AllowedExecutables = append([]string(nil), yamlProfile.AllowedExecutables...)
				}
			}
			if fields["promptInjectionMode"] {
				current.PromptInjectionMode = yamlProfile.PromptInjectionMode
			}
			if fields["skillPath"] {
				current.SkillPath = yamlProfile.SkillPath
			}
			if fields["skillVersion"] {
				current.SkillVersion = yamlProfile.SkillVersion
			}
			cfg.Agents[name] = current
		}
	}

	for name, profile := range cfg.Agents {
		mode := ""
		if profile.ApprovalMode != nil {
			mode = *profile.ApprovalMode
		}
		switch mode {
		case "", "none", "deny", "prompt":
		default:
			return nil, fmt.Errorf("agent %q: invalid approvalMode %q (valid: none, deny, prompt)", name, mode)
		}
	}

	for name, profile := range cfg.Agents {
		mode := ""
		if profile.PromptInjectionMode != nil {
			mode = *profile.PromptInjectionMode
		}
		switch mode {
		case "", "off", "log-only", "wrap", "deny":
		default:
			return nil, fmt.Errorf("agent %q: invalid promptInjectionMode %q (valid: off, log-only, wrap, deny)", name, mode)
		}
	}

	if cfg.Agents == nil {
		cfg.Agents = map[string]AgentProfile{}
	}
	for name, profile := range cfg.Agents {
		profile.Name = name
		cfg.Agents[name] = profile
	}
	if _, ok := cfg.Agents[cfg.DefaultAgent]; !ok {
		cfg.Agents[cfg.DefaultAgent] = newDefaultAgentProfile(cfg.DefaultAgent)
	}

	if raw.Vault != nil {
		defaults := defaultVaultConfig()
		sf := sectionFields["vault"]
		if sf["path"] {
			defaults.Path = raw.Vault.Path
		}
		if sf["default_recipients"] && raw.Vault.DefaultRecipients != nil {
			defaults.DefaultRecipients = append([]string(nil), raw.Vault.DefaultRecipients...)
		}
		if sf["confirm_remove"] {
			defaults.ConfirmRemove = raw.Vault.ConfirmRemove
		}
		if sf["authMethod"] {
			defaults.AuthMethod = raw.Vault.AuthMethod
		}
		if sf["useTouchID"] {
			defaults.UseTouchID = raw.Vault.UseTouchID
		}
		if sf["legacy_mode"] && raw.Vault.LegacyMode != nil {
			defaults.LegacyMode = raw.Vault.LegacyMode
		}
		if sf["search_workers"] {
			defaults.SearchWorkers = raw.Vault.SearchWorkers
		}
		if sf["pseudonymize_paths"] {
			defaults.PseudonymizePaths = raw.Vault.PseudonymizePaths
		}
		if sf["scrypt_work_factor"] {
			defaults.ScryptWorkFactor = raw.Vault.ScryptWorkFactor
		}
		if sf["last_rotated"] {
			defaults.LastRotated = raw.Vault.LastRotated
		}
		if sf["format_version"] {
			defaults.FormatVersion = raw.Vault.FormatVersion
		}
		if sf["argon2id_time"] {
			defaults.Argon2idTime = raw.Vault.Argon2idTime
		}
		if sf["argon2id_memory"] {
			defaults.Argon2idMemory = raw.Vault.Argon2idMemory
		}
		if sf["argon2id_threads"] {
			defaults.Argon2idThreads = raw.Vault.Argon2idThreads
		}
		if sf["authMethod"] && defaults.AuthMethod != "" {
			authMethod, err := NormalizeAuthMethod(defaults.AuthMethod)
			if err != nil {
				return nil, err
			}
			defaults.AuthMethod = authMethod
			if raw.AuthMethod == "" {
				cfg.AuthMethod = authMethod
			}
		}
		if raw.AuthMethod == "" && !sf["authMethod"] && raw.Vault.UseTouchID {
			cfg.AuthMethod = AuthMethodTouchID
		}
		cfg.Vault = &defaults
	}
	if raw.Git != nil {
		defaults := defaultGitConfig()
		sf := sectionFields["git"]
		if sf["auto_push"] {
			defaults.AutoPush = raw.Git.AutoPush
		}
		if sf["auto_pull"] {
			defaults.AutoPull = raw.Git.AutoPull
		}
		if sf["auto_pull_interval"] {
			defaults.AutoPullInterval = raw.Git.AutoPullInterval
		}
		if sf["commit_template"] {
			defaults.CommitTemplate = raw.Git.CommitTemplate
		}
		cfg.Git = &defaults
	}
	if raw.MCP != nil {
		defaults := defaultMCPConfig()
		sf := sectionFields["mcp"]
		if raw.MCP.ApprovalRequired {
			fmt.Fprintln(os.Stderr, "Warning: approval_required is deprecated and will be removed in a future version")
		}
		if sf["port"] {
			defaults.Port = raw.MCP.Port
		}
		if sf["bind"] {
			defaults.Bind = raw.MCP.Bind
		}
		if sf["stdio"] {
			defaults.Stdio = raw.MCP.Stdio
		}
		if sf["httpTokenFile"] {
			defaults.HTTPTokenFile = raw.MCP.HTTPTokenFile
		}
		if sf["otlp_endpoint"] {
			defaults.OTLPEndpoint = raw.MCP.OTLPEndpoint
		}
		if sf["read_header_timeout"] {
			defaults.ReadHeaderTimeout = raw.MCP.ReadHeaderTimeout
		}
		if sf["read_timeout"] {
			defaults.ReadTimeout = raw.MCP.ReadTimeout
		}
		if sf["write_timeout"] {
			defaults.WriteTimeout = raw.MCP.WriteTimeout
		}
		if sf["shutdown_timeout"] {
			defaults.ShutdownTimeout = raw.MCP.ShutdownTimeout
		}
		if sf["approval_timeout"] {
			defaults.ApprovalTimeout = raw.MCP.ApprovalTimeout
		}
		if sf["rate_limit"] {
			defaults.RateLimit = raw.MCP.RateLimit
		}
		if sf["trusted_proxy_ips"] && raw.MCP.TrustedProxyIPs != nil {
			defaults.TrustedProxyIPs = append([]string(nil), raw.MCP.TrustedProxyIPs...)
		}
		if sf["metrics_auth_required"] {
			defaults.MetricsAuthRequired = raw.MCP.MetricsAuthRequired
		}
		if sf["tls_cert_file"] {
			defaults.TLSCertFile = raw.MCP.TLSCertFile
		}
		if sf["tls_key_file"] {
			defaults.TLSKeyFile = raw.MCP.TLSKeyFile
		}
		if sf["allow_insecure_bind"] {
			defaults.AllowInsecureBind = raw.MCP.AllowInsecureBind
		}
		if sf["oauth"] && raw.MCP.OAuth != nil {
			oAuthFields := raw.MCP.OAuth
			if defaults.OAuth == nil {
				defaults.OAuth = &OAuthConfig{}
			}
			oaf := sectionFields["mcp_oauth"]
			if oaf["access_token_ttl"] && oAuthFields.AccessTokenTTL > 0 {
				defaults.OAuth.AccessTokenTTL = oAuthFields.AccessTokenTTL
			}
			if oaf["refresh_token_ttl"] && oAuthFields.RefreshTokenTTL > 0 {
				defaults.OAuth.RefreshTokenTTL = oAuthFields.RefreshTokenTTL
			}
		}
		cfg.MCP = &defaults
	}
	if raw.Update != nil {
		defaults := defaultUpdateConfig()
		sf := sectionFields["update"]
		if sf["cache_ttl"] {
			defaults.CacheTTL = raw.Update.CacheTTL
		}
		cfg.Update = &defaults
	}
	if raw.Clipboard != nil {
		defaults := defaultClipboardConfig()
		sf := sectionFields["clipboard"]
		if sf["auto_clear_duration"] {
			defaults.AutoClearDuration = raw.Clipboard.AutoClearDuration
		}
		if sf["printByDefault"] {
			defaults.PrintByDefault = raw.Clipboard.PrintByDefault
		}
		cfg.Clipboard = &defaults
	}
	if raw.Audit != nil {
		defaults := defaultAuditConfig()
		sf := sectionFields["audit"]
		if sf["maxSizeMb"] {
			defaults.MaxFileSize = raw.Audit.MaxFileSize * 1024 * 1024
		}
		if sf["maxBackups"] {
			defaults.MaxBackups = raw.Audit.MaxBackups
		}
		if sf["maxAgeDays"] {
			defaults.MaxAgeDays = raw.Audit.MaxAgeDays
		}
		cfg.Audit = &defaults
	}
	if raw.Logging != nil {
		defaults := defaultLoggingConfig()
		sf := sectionFields["logging"]
		if sf["level"] {
			defaults.Level = raw.Logging.Level
		}
		if sf["format"] {
			defaults.Format = raw.Logging.Format
		}
		cfg.Logging = &defaults
	}

	if cfg.MCP != nil && cfg.MCP.Bind == "" {
		return nil, fmt.Errorf("mcp.bind must not be empty")
	}

	useTouchID := cfg.EffectiveAuthMethod() == AuthMethodTouchID
	cfg.UseTouchID = &useTouchID

	return cfg, nil
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
		cp := AgentProfile{
			Name:                profile.Name,
			Tier:                profile.Tier,
			ApprovalMode:        profile.ApprovalMode,
			CanWrite:            profile.CanWrite,
			CanRunCommands:      profile.CanRunCommands,
			CanManageConfig:     profile.CanManageConfig,
			CanUseClipboard:     profile.CanUseClipboard,
			CanUseAutotype:      profile.CanUseAutotype,
			CanReadValues:       profile.CanReadValues,
			ExposeValueTools:    profile.ExposeValueTools,
			AutoUnseal:          profile.AutoUnseal,
			RequireApproval:     profile.RequireApproval,
			ApprovalTimeout:     profile.ApprovalTimeout,
			MaxReadsPerHour:     profile.MaxReadsPerHour,
			MaxReadsPerDay:      profile.MaxReadsPerDay,
			MaxSecretsInSession: profile.MaxSecretsInSession,
			PromptInjectionMode: profile.PromptInjectionMode,
			SkillPath:           profile.SkillPath,
			SkillVersion:        profile.SkillVersion,
			DynamicProviders:    profile.DynamicProviders,
			AllowedEnvVars:      profile.AllowedEnvVars,
			AllowedExecutables:  profile.AllowedExecutables,
			PreCallHooks:        profile.PreCallHooks,
			PostCallHooks:       profile.PostCallHooks,
		}
		if profile.AllowedPaths != nil {
			cp.AllowedPaths = append([]string(nil), profile.AllowedPaths...)
		}
		if profile.RedactFields != nil {
			cp.RedactFields = append([]string(nil), profile.RedactFields...)
		}
		if profile.PerToolRedactFields != nil {
			cp.PerToolRedactFields = make(map[string][]string, len(profile.PerToolRedactFields))
			for tool, flds := range profile.PerToolRedactFields {
				cp.PerToolRedactFields[tool] = append([]string(nil), flds...)
			}
		}
		if profile.AllowedTools != nil {
			cp.AllowedTools = append([]string(nil), profile.AllowedTools...)
		}
		if profile.DynamicProviders != nil {
			cp.DynamicProviders = make(map[string][]string, len(profile.DynamicProviders))
			for p, roles := range profile.DynamicProviders {
				cp.DynamicProviders[p] = append([]string(nil), roles...)
			}
		}
		if profile.AllowedEnvVars != nil {
			cp.AllowedEnvVars = append([]string(nil), profile.AllowedEnvVars...)
		}
		if profile.AllowedExecutables != nil {
			cp.AllowedExecutables = append([]string(nil), profile.AllowedExecutables...)
		}
		if profile.PreCallHooks != nil {
			cp.PreCallHooks = append([]string(nil), profile.PreCallHooks...)
		}
		if profile.PostCallHooks != nil {
			cp.PostCallHooks = append([]string(nil), profile.PostCallHooks...)
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
		errs = errors.Join(errs, errors.New("vaultDir: must not be empty"))
	}

	if c.SessionTimeout <= 0 {
		errs = errors.Join(errs, errors.New("sessionTimeout: must be greater than 0"))
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
			errs = errors.Join(errs, fmt.Errorf("defaultAgent: %q not found in agents", c.DefaultAgent))
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
			errs = errors.Join(errs, fmt.Errorf("agents.%s.approvalMode: invalid value %q (valid: none, deny, prompt, auto)", name, mode))
		}
	}

	for name, agent := range c.Agents {
		for i, path := range agent.AllowedPaths {
			if _, err := filepath.Match(path, ""); err != nil {
				errs = errors.Join(errs, fmt.Errorf("agents.%s.allowedPaths[%d]: invalid glob pattern %q", name, i, path))
			}
		}
	}

	if c.Audit != nil && c.Audit.MaxFileSize <= 0 {
		errs = errors.Join(errs, errors.New("audit.maxFileSize: must be greater than 0"))
	}

	if c.Clipboard != nil && c.Clipboard.AutoClearDuration < 0 {
		errs = errors.Join(errs, errors.New("clipboard.autoClearDuration: must be non-negative"))
	}

	return errs
}
