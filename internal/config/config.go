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

// CustomPattern defines a user-provided PII/secret scan pattern for the
// masking/sanitizer. Patterns are compiled at runtime and merged with the
// built-in defaults.
type CustomPattern struct {
	Name        string `yaml:"name"`
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
}

type Config struct {
	Agents         map[string]AgentProfile `yaml:"agents"`
	Vault          *VaultConfig            `yaml:"vault,omitempty"`
	Git            *GitConfig              `yaml:"git,omitempty"`
	MCP            *MCPConfig              `yaml:"mcp,omitempty"`
	Update         *UpdateConfig           `yaml:"update,omitempty"`
	Clipboard      *ClipboardConfig        `yaml:"clipboard,omitempty"`
	Audit          *AuditConfig            `yaml:"audit,omitempty"`
	Logging        *LoggingConfig          `yaml:"logging,omitempty"`
	VaultDir       string                  `yaml:"vaultDir"`
	DefaultAgent   string                  `yaml:"defaultAgent"`
	SessionTimeout time.Duration           `yaml:"sessionTimeout"`
	AuthMethod     string                  `yaml:"authMethod,omitempty"`
	UseTouchID     bool                    `yaml:"useTouchID,omitempty"`
	Profiles       map[string]*Profile     `yaml:"profiles,omitempty"`
	DefaultProfile string                  `yaml:"defaultProfile,omitempty"`
	EnvWhitelist   []string                `yaml:"envWhitelist,omitempty"`
	ScanPatterns   []CustomPattern         `yaml:"scan_patterns,omitempty"`
}

type fileConfig struct {
	Agents         map[string]fileAgentProfile `yaml:"agents,omitempty"`
	Vault          *fileVaultConfig            `yaml:"vault,omitempty"`
	Git            *fileGitConfig              `yaml:"git,omitempty"`
	MCP            *fileMCPConfig              `yaml:"mcp,omitempty"`
	Update         *fileUpdateConfig           `yaml:"update,omitempty"`
	Clipboard      *fileClipboardConfig        `yaml:"clipboard,omitempty"`
	Audit          *fileAuditConfig            `yaml:"audit,omitempty"`
	Logging        *fileLoggingConfig          `yaml:"logging,omitempty"`
	VaultDir       string                      `yaml:"vaultDir,omitempty"`
	DefaultAgent   string                      `yaml:"defaultAgent,omitempty"`
	SessionTimeout time.Duration               `yaml:"sessionTimeout,omitempty"`
	AuthMethod     string                      `yaml:"authMethod,omitempty"`
	UseTouchID     *bool                       `yaml:"useTouchID,omitempty"`
	Profiles       map[string]fileProfile      `yaml:"profiles,omitempty"`
	DefaultProfile string                      `yaml:"defaultProfile,omitempty"`
	EnvWhitelist   []string                    `yaml:"envWhitelist,omitempty"`
	ScanPatterns   []CustomPattern             `yaml:"scan_patterns,omitempty"`
}

type AgentProfile struct {
	Name                string              `yaml:"-"`
	Tier                string              `yaml:"tier,omitempty"`
	ApprovalMode        string              `yaml:"approvalMode"`
	AllowedPaths        []string            `yaml:"allowedPaths"`
	RedactFields        []string            `yaml:"redactFields,omitempty"`
	PerToolRedactFields map[string][]string `yaml:"perToolRedactFields,omitempty"`
	CanWrite            bool                `yaml:"canWrite"`
	CanRunCommands      bool                `yaml:"canRunCommands,omitempty"`
	CanManageConfig     bool                `yaml:"canManageConfig,omitempty"`
	CanUseClipboard     bool                `yaml:"canUseClipboard,omitempty"`
	CanUseAutotype      bool                `yaml:"canUseAutotype,omitempty"`
	CanReadValues       bool                `yaml:"canReadValues,omitempty"`
	ExposeValueTools    bool                `yaml:"exposeValueTools,omitempty"`
	AutoUnseal          bool                `yaml:"autoUnseal,omitempty"`
	RequireApproval     bool                `yaml:"requireApproval"`
	ApprovalTimeout     time.Duration       `yaml:"approvalTimeout,omitempty"`
	AllowedTools        []string            `yaml:"allowed_tools,omitempty"`
	MaxReadsPerHour     int                 `yaml:"max_reads_per_hour,omitempty"`
	MaxReadsPerDay      int                 `yaml:"max_reads_per_day,omitempty"`
	MaxSecretsInSession int                 `yaml:"max_secrets_in_session,omitempty"`
	DynamicProviders    map[string][]string `yaml:"dynamicProviders,omitempty"` // provider → allowed roles; nil denies all
	AllowedEnvVars      []string            `yaml:"allowedEnvVars,omitempty"`
	AllowedExecutables  []string            `yaml:"allowedExecutables,omitempty"`
	PromptInjectionMode string              `yaml:"promptInjectionMode,omitempty"`
	PreCallHooks        []string            `yaml:"pre_call_hooks,omitempty"`
	PostCallHooks       []string            `yaml:"post_call_hooks,omitempty"`
}

type fileAgentProfile struct {
	Tier                *string             `yaml:"tier,omitempty"`
	ExposeValueTools    *bool               `yaml:"exposeValueTools,omitempty"`
	AutoUnseal          *bool               `yaml:"autoUnseal,omitempty"`
	ApprovalTimeout     *time.Duration      `yaml:"approvalTimeout,omitempty"`
	CanWrite            *bool               `yaml:"canWrite,omitempty"`
	CanRunCommands      *bool               `yaml:"canRunCommands,omitempty"`
	CanManageConfig     *bool               `yaml:"canManageConfig,omitempty"`
	CanUseClipboard     *bool               `yaml:"canUseClipboard,omitempty"`
	CanUseAutotype      *bool               `yaml:"canUseAutotype,omitempty"`
	CanReadValues       *bool               `yaml:"canReadValues,omitempty"`
	RequireApproval     *bool               `yaml:"requireApproval,omitempty"`
	ApprovalMode        *string             `yaml:"approvalMode,omitempty"`
	AllowedPaths        []string            `yaml:"allowedPaths,omitempty"`
	RedactFields        []string            `yaml:"redactFields,omitempty"`
	PerToolRedactFields map[string][]string `yaml:"perToolRedactFields,omitempty"`
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
}

type fileProfile struct {
	VaultPath string `yaml:"vault,omitempty"`
}

// EffectiveRedactFields returns the merged, deduplicated list of redact field
// patterns for toolName: global RedactFields always included, followed by any
// per-tool additions from PerToolRedactFields[toolName].
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

//nolint:gocyclo // Complex config loading with backwards compatibility and environment fallbacks
func Load(path string) (*Config, error) {
	if err := validateConfigPath(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path) //#nosec G304 -- path validated by validateConfigPath()
	if err != nil {
		return nil, err
	}

	cfg := Default()
	if len(bytes.TrimSpace(data)) == 0 {
		return cfg, nil
	}

	var raw fileConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
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
	if raw.UseTouchID != nil {
		cfg.UseTouchID = *raw.UseTouchID
		if raw.AuthMethod == "" && *raw.UseTouchID {
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
		for name, profile := range raw.Agents {
			current, ok := cfg.Agents[name]
			if !ok {
				current = newDefaultAgentProfile(name)
			}
			current.Name = name

			// Apply tier preset before explicit YAML overrides
			if profile.Tier != nil && *profile.Tier != "" {
				ApplyTierPreset(&current, *profile.Tier)
				current.Tier = *profile.Tier
			}

			// Backward compat: default ExposeValueTools to true when neither tier nor explicit value
			if (profile.Tier == nil || *profile.Tier == "") && profile.ExposeValueTools == nil {
				current.ExposeValueTools = true
			}

			if profile.AllowedPaths != nil {
				current.AllowedPaths = append([]string(nil), profile.AllowedPaths...)
			} else if current.AllowedPaths == nil {
				current.AllowedPaths = []string{}
			}
			if profile.CanWrite != nil {
				current.CanWrite = *profile.CanWrite
			}
			if profile.CanRunCommands != nil {
				current.CanRunCommands = *profile.CanRunCommands
			}
			if profile.CanManageConfig != nil {
				current.CanManageConfig = *profile.CanManageConfig
			}
			if profile.CanUseClipboard != nil {
				current.CanUseClipboard = *profile.CanUseClipboard
			}
			if profile.CanUseAutotype != nil {
				current.CanUseAutotype = *profile.CanUseAutotype
			}
			if profile.CanReadValues != nil {
				current.CanReadValues = *profile.CanReadValues
			}
			if profile.RequireApproval != nil {
				current.RequireApproval = *profile.RequireApproval
			}
			if profile.ApprovalTimeout != nil {
				current.ApprovalTimeout = *profile.ApprovalTimeout
			}
			if profile.ApprovalMode != nil {
				current.ApprovalMode = *profile.ApprovalMode
			} else if profile.RequireApproval != nil {
				if *profile.RequireApproval {
					current.ApprovalMode = "prompt"
				} else {
					current.ApprovalMode = "none"
				}
			}
			if profile.RedactFields != nil {
				current.RedactFields = append([]string(nil), profile.RedactFields...)
			}
			// PerToolRedactFields uses append semantics (unlike the scalar RedactFields replace)
			// so that stacked profile overrides can each add per-tool patterns additively.
			if profile.PerToolRedactFields != nil {
				if current.PerToolRedactFields == nil {
					current.PerToolRedactFields = make(map[string][]string, len(profile.PerToolRedactFields))
				}
				for tool, fields := range profile.PerToolRedactFields {
					current.PerToolRedactFields[tool] = append(current.PerToolRedactFields[tool], fields...)
				}
			}
			if profile.AllowedTools != nil {
				current.AllowedTools = append([]string(nil), profile.AllowedTools...)
			}
			if profile.MaxReadsPerHour != nil {
				current.MaxReadsPerHour = *profile.MaxReadsPerHour
			}
			if profile.MaxReadsPerDay != nil {
				current.MaxReadsPerDay = *profile.MaxReadsPerDay
			}
			if profile.MaxSecretsInSession != nil {
				current.MaxSecretsInSession = *profile.MaxSecretsInSession
			}
			if profile.ExposeValueTools != nil {
				current.ExposeValueTools = *profile.ExposeValueTools
			}
			if profile.AutoUnseal != nil {
				current.AutoUnseal = *profile.AutoUnseal
			}
			if profile.DynamicProviders != nil {
				current.DynamicProviders = make(map[string][]string, len(profile.DynamicProviders))
				for p, roles := range profile.DynamicProviders {
					rolesCopy := append([]string(nil), roles...)
					current.DynamicProviders[p] = rolesCopy
				}
			}
			if profile.AllowedEnvVars != nil {
				current.AllowedEnvVars = append([]string(nil), profile.AllowedEnvVars...)
			}
			if profile.AllowedExecutables != nil {
				current.AllowedExecutables = append([]string(nil), profile.AllowedExecutables...)
			}
			if profile.PromptInjectionMode != nil {
				current.PromptInjectionMode = *profile.PromptInjectionMode
			}
			cfg.Agents[name] = current
		}
	}

	// Validate ApprovalMode values
	for name, profile := range cfg.Agents {
		switch profile.ApprovalMode {
		case "", "none", "deny", "prompt":
			// valid
		default:
			return nil, fmt.Errorf("agent %q: invalid approvalMode %q (valid: none, deny, prompt)", name, profile.ApprovalMode)
		}
	}

	// Validate PromptInjectionMode values
	for name, profile := range cfg.Agents {
		switch profile.PromptInjectionMode {
		case "", "off", "log-only", "wrap", "deny":
			// valid
		default:
			return nil, fmt.Errorf("agent %q: invalid promptInjectionMode %q (valid: off, log-only, wrap, deny)", name, profile.PromptInjectionMode)
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
		merged := MergeFileVaultConfig(raw.Vault, defaults)
		if raw.Vault.AuthMethod != nil {
			authMethod, err := NormalizeAuthMethod(*raw.Vault.AuthMethod)
			if err != nil {
				return nil, err
			}
			merged.AuthMethod = authMethod
			if raw.AuthMethod == "" {
				cfg.AuthMethod = authMethod
			}
		}
		if raw.AuthMethod == "" && raw.Vault.AuthMethod == nil && raw.Vault.UseTouchID != nil && *raw.Vault.UseTouchID {
			cfg.AuthMethod = AuthMethodTouchID
		}
		cfg.Vault = &merged
	}
	if raw.Git != nil {
		defaults := defaultGitConfig()
		merged := MergeFileGitConfig(raw.Git, defaults)
		cfg.Git = &merged
	}
	if raw.MCP != nil {
		defaults := defaultMCPConfig()
		merged := MergeFileMCPConfig(raw.MCP, defaults)
		cfg.MCP = &merged
	}
	if raw.Update != nil {
		defaults := defaultUpdateConfig()
		merged := MergeFileUpdateConfig(raw.Update, defaults)
		cfg.Update = &merged
	}
	if raw.Clipboard != nil {
		defaults := defaultClipboardConfig()
		merged := MergeFileClipboardConfig(raw.Clipboard, defaults)
		cfg.Clipboard = &merged
	}
	if raw.Audit != nil {
		defaults := defaultAuditConfig()
		merged := MergeFileAuditConfig(raw.Audit, defaults)
		cfg.Audit = &merged
	}
	if raw.Logging != nil {
		defaults := defaultLoggingConfig()
		merged := MergeFileLoggingConfig(raw.Logging, defaults)
		cfg.Logging = &merged
	}

	if cfg.MCP != nil && cfg.MCP.Bind == "" {
		return nil, fmt.Errorf("mcp.bind must not be empty")
	}

	cfg.UseTouchID = cfg.EffectiveAuthMethod() == AuthMethodTouchID

	return cfg, nil
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
	raw := fileConfig{
		VaultDir:       c.VaultDir,
		DefaultAgent:   c.DefaultAgent,
		SessionTimeout: c.SessionTimeout,
		AuthMethod:     authMethod,
		Profiles:       make(map[string]fileProfile, len(c.Profiles)),
		DefaultProfile: c.DefaultProfile,
		Agents:         make(map[string]fileAgentProfile, len(c.Agents)),
	}

	if c.Vault != nil {
		confirmRemove := c.Vault.ConfirmRemove
		vaultAuthMethod := c.Vault.AuthMethod
		searchWorkers := c.Vault.SearchWorkers
		pseudonymizePaths := c.Vault.PseudonymizePaths
		if vaultAuthMethod == "" && authMethod != "" {
			vaultAuthMethod = authMethod
		}
		scryptWF := c.Vault.ScryptWorkFactor
		lastRotated := c.Vault.LastRotated
		raw.Vault = &fileVaultConfig{
			Path:              c.Vault.Path,
			DefaultRecipients: append([]string(nil), c.Vault.DefaultRecipients...),
			ConfirmRemove:     &confirmRemove,
			AuthMethod:        &vaultAuthMethod,
			LegacyMode:        c.Vault.LegacyMode,
			SearchWorkers:     &searchWorkers,
			PseudonymizePaths: &pseudonymizePaths,
			ScryptWorkFactor:  &scryptWF,
			LastRotated:       &lastRotated,
		}
	}

	if c.Git != nil {
		autoPush := c.Git.AutoPush
		autoPull := c.Git.AutoPull
		autoPullInterval := c.Git.AutoPullInterval
		commitTemplate := c.Git.CommitTemplate
		raw.Git = &fileGitConfig{
			AutoPush:         &autoPush,
			AutoPull:         &autoPull,
			AutoPullInterval: &autoPullInterval,
			CommitTemplate:   &commitTemplate,
		}
	}

	if c.MCP != nil {
		mcpPort := c.MCP.Port
		mcpBind := c.MCP.Bind
		mcpStdio := c.MCP.Stdio
		mcpTokenFile := c.MCP.HTTPTokenFile
		mcpRateLimit := c.MCP.RateLimit
		raw.MCP = &fileMCPConfig{
			Port:              &mcpPort,
			Bind:              &mcpBind,
			Stdio:             &mcpStdio,
			HTTPTokenFile:     &mcpTokenFile,
			ReadHeaderTimeout: &c.MCP.ReadHeaderTimeout,
			ReadTimeout:       &c.MCP.ReadTimeout,
			WriteTimeout:      &c.MCP.WriteTimeout,
			ShutdownTimeout:   &c.MCP.ShutdownTimeout,
			ApprovalTimeout:   &c.MCP.ApprovalTimeout,
			RateLimit:         &mcpRateLimit,
		}
		if c.MCP.OTLPEndpoint != "" {
			endpoint := c.MCP.OTLPEndpoint
			raw.MCP.OTLPEndpoint = &endpoint
		}
	}

	if c.Update != nil {
		raw.Update = &fileUpdateConfig{
			CacheTTL: &c.Update.CacheTTL,
		}
	}

	if c.Clipboard != nil {
		autoClear := c.Clipboard.AutoClearDuration
		raw.Clipboard = &fileClipboardConfig{
			AutoClearDuration: &autoClear,
		}
	}
	if c.Audit != nil {
		maxFileSize := c.Audit.MaxFileSize / (1024 * 1024)
		maxBackups := c.Audit.MaxBackups
		maxAgeDays := c.Audit.MaxAgeDays
		raw.Audit = &fileAuditConfig{
			MaxFileSize: &maxFileSize,
			MaxBackups:  &maxBackups,
			MaxAgeDays:  &maxAgeDays,
		}
	}
	if c.Logging != nil {
		level := c.Logging.Level
		format := c.Logging.Format
		raw.Logging = &fileLoggingConfig{
			Level:  &level,
			Format: &format,
		}
	}
	if len(c.ScanPatterns) > 0 {
		raw.ScanPatterns = append([]CustomPattern(nil), c.ScanPatterns...)
	}
	raw.Agents = buildFileAgents(c.Agents)
	for name, profile := range c.Profiles {
		if profile != nil {
			raw.Profiles[name] = fileProfile{VaultPath: profile.VaultPath}
		}
	}

	data, err := yaml.Marshal(&raw)
	if err != nil {
		return err
	}
	return fileutil.AtomicWriteFile(path, data, 0o600)
}

func buildFileAgents(agents map[string]AgentProfile) map[string]fileAgentProfile {
	result := make(map[string]fileAgentProfile, len(agents))
	for name, profile := range agents {
		allowed := append([]string(nil), profile.AllowedPaths...)
		canWrite := profile.CanWrite
		canRunCommands := profile.CanRunCommands
		canManageConfig := profile.CanManageConfig
		canUseClipboard := profile.CanUseClipboard
		canUseAutotype := profile.CanUseAutotype
		canReadValues := profile.CanReadValues
		exposeValueTools := profile.ExposeValueTools
		autoUnseal := profile.AutoUnseal
		requireApproval := profile.RequireApproval
		fap := fileAgentProfile{
			AllowedPaths:     allowed,
			CanWrite:         &canWrite,
			CanRunCommands:   &canRunCommands,
			CanManageConfig:  &canManageConfig,
			CanUseClipboard:  &canUseClipboard,
			CanUseAutotype:   &canUseAutotype,
			CanReadValues:    &canReadValues,
			ExposeValueTools: &exposeValueTools,
			AutoUnseal:       &autoUnseal,
			RequireApproval:  &requireApproval,
		}
		if profile.Tier != "" {
			t := profile.Tier
			fap.Tier = &t
		}
		if profile.ApprovalMode != "" {
			am := profile.ApprovalMode
			fap.ApprovalMode = &am
		}
		if profile.ApprovalTimeout > 0 {
			t := profile.ApprovalTimeout
			fap.ApprovalTimeout = &t
		}
		if profile.RedactFields != nil {
			fap.RedactFields = append([]string(nil), profile.RedactFields...)
		}
		if profile.PerToolRedactFields != nil {
			fap.PerToolRedactFields = make(map[string][]string, len(profile.PerToolRedactFields))
			for tool, fields := range profile.PerToolRedactFields {
				fap.PerToolRedactFields[tool] = append([]string(nil), fields...)
			}
		}
		if profile.AllowedTools != nil {
			fap.AllowedTools = append([]string(nil), profile.AllowedTools...)
		}
		if profile.MaxReadsPerHour != 0 {
			mrph := profile.MaxReadsPerHour
			fap.MaxReadsPerHour = &mrph
		}
		if profile.MaxReadsPerDay != 0 {
			mrpd := profile.MaxReadsPerDay
			fap.MaxReadsPerDay = &mrpd
		}
		if profile.MaxSecretsInSession != 0 {
			msis := profile.MaxSecretsInSession
			fap.MaxSecretsInSession = &msis
		}
		if profile.DynamicProviders != nil {
			fap.DynamicProviders = make(map[string][]string, len(profile.DynamicProviders))
			for p, roles := range profile.DynamicProviders {
				rolesCopy := append([]string(nil), roles...)
				fap.DynamicProviders[p] = rolesCopy
			}
		}
		if profile.AllowedEnvVars != nil {
			fap.AllowedEnvVars = append([]string(nil), profile.AllowedEnvVars...)
		}
		if profile.AllowedExecutables != nil {
			fap.AllowedExecutables = append([]string(nil), profile.AllowedExecutables...)
		}
		if profile.PromptInjectionMode != "" {
			pim := profile.PromptInjectionMode
			fap.PromptInjectionMode = &pim
		}
		result[name] = fap
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
	if c.UseTouchID {
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
	c.UseTouchID = normalized == AuthMethodTouchID
	if c.Vault != nil {
		c.Vault.AuthMethod = normalized
		c.Vault.UseTouchID = c.UseTouchID
	}
	return nil
}

func newDefaultAgentProfile(name string) AgentProfile {
	return AgentProfile{
		Name:             name,
		AllowedPaths:     []string{},
		CanWrite:         false,
		CanRunCommands:   false,
		ApprovalMode:     "none",
		ExposeValueTools: true,
		AutoUnseal:       true,
	}
}

func builtinAgentProfiles() map[string]AgentProfile {
	return map[string]AgentProfile{
		"default":     {Name: "default", AllowedPaths: []string{"*"}, CanWrite: false, CanRunCommands: false, ApprovalMode: "none", ExposeValueTools: true, AutoUnseal: true},
		"claude-code": {Name: "claude-code", AllowedPaths: []string{"*"}, CanWrite: true, CanRunCommands: false, ApprovalMode: "none", ExposeValueTools: true, AutoUnseal: true},
		"codex":       {Name: "codex", AllowedPaths: []string{"*"}, CanWrite: false, CanRunCommands: false, ApprovalMode: "none", ExposeValueTools: true, AutoUnseal: true},
		"hermes":      {Name: "hermes", AllowedPaths: []string{"*"}, CanWrite: true, CanRunCommands: false, ApprovalMode: "none", ExposeValueTools: true, AutoUnseal: true},
		"openclaw":    {Name: "openclaw", AllowedPaths: []string{"*"}, CanWrite: true, CanRunCommands: false, ApprovalMode: "none", ExposeValueTools: true, AutoUnseal: true},
		"opencode":    {Name: "opencode", AllowedPaths: []string{"*"}, CanWrite: false, CanRunCommands: false, ApprovalMode: "none", ExposeValueTools: true, AutoUnseal: true},
	}
}

//nolint:gocyclo // Validation logic must check every config field; splitting would obscure the full contract.
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
		switch agent.ApprovalMode {
		case "", "none", "deny", "prompt", "auto":
		default:
			errs = errors.Join(errs, fmt.Errorf("agents.%s.approvalMode: invalid value %q (valid: none, deny, prompt, auto)", name, agent.ApprovalMode))
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
