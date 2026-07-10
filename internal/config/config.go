// Package config provides configuration loading, validation, and defaults for Symaira Vault.
package config

import (
	"os"
	"path/filepath"
	"time"
)

const (
	// AppName is the canonical application name used for XDG paths.
	AppName = "symaira-vault"

	// Legacy paths (for migration detection from pre-XDG installs).
	LegacyVaultSubdir    = ".symvault"
	LegacyOpenpassSubdir = ".openpass"

	// XDG subdirectory names.
	ConfigSubdir = "symaira-vault" // under $XDG_CONFIG_HOME
	DataSubdir   = "symaira-vault" // under $XDG_DATA_HOME
	CacheSubdir  = "symaira-vault" // under $XDG_CACHE_HOME

	// Prefer DefaultConfigDir(), DefaultDataDir(), or DefaultCacheDir() for
	// new code. Kept for backward compatibility and migration detection.
	DefaultVaultSubdir       = ".symvault"
	LegacyDefaultVaultSubdir = ".openpass"
	defaultConfigDir         = DefaultVaultSubdir
	defaultConfigFile        = "config.yaml"
	defaultAgentName         = "default"
	defaultSessionTimeout    = 15 * time.Minute
	AuthMethodPassphrase     = "passphrase"
	AuthMethodTouchID        = "touchid"
)

// XDGConfigHome returns the XDG config directory ($XDG_CONFIG_HOME or
// ~/.config).
func XDGConfigHome() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config")
}

// XDGDataHome returns the XDG data directory ($XDG_DATA_HOME or
// ~/.local/share).
func XDGDataHome() string {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share")
}

// XDGCacheHome returns the XDG cache directory ($XDG_CACHE_HOME or
// ~/.cache).
func XDGCacheHome() string {
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cache")
}

// DefaultConfigDir returns the default XDG config directory for symaira-vault.
func DefaultConfigDir() string {
	return filepath.Join(XDGConfigHome(), ConfigSubdir)
}

// DefaultDataDir returns the default XDG data directory for symaira-vault.
func DefaultDataDir() string {
	return filepath.Join(XDGDataHome(), DataSubdir)
}

// DefaultCacheDir returns the default XDG cache directory for symaira-vault.
func DefaultCacheDir() string {
	return filepath.Join(XDGCacheHome(), CacheSubdir)
}

type CustomPattern struct {
	Name        string `yaml:"name"`
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
}

type Config struct {
	Agents          map[string]AgentProfile  `yaml:"agents,omitempty"`
	Vault           *VaultConfig             `yaml:"vault,omitempty"`
	Git             *GitConfig               `yaml:"git,omitempty"`
	MCP             *MCPConfig               `yaml:"mcp,omitempty"`
	Update          *UpdateConfig            `yaml:"update,omitempty"`
	Clipboard       *ClipboardConfig         `yaml:"clipboard,omitempty"`
	Audit           *AuditConfig             `yaml:"audit,omitempty"`
	Logging         *LoggingConfig           `yaml:"logging,omitempty"`
	Security        *SecurityConfig          `yaml:"security,omitempty"`
	VaultDir        string                   `yaml:"vaultDir,omitempty"`
	DefaultAgent    string                   `yaml:"defaultAgent,omitempty"`
	SessionTimeout  time.Duration            `yaml:"sessionTimeout,omitempty"`
	AuthMethod      string                   `yaml:"authMethod,omitempty"`
	UseTouchID      *bool                    `yaml:"useTouchID,omitempty"`
	Profiles        map[string]*Profile      `yaml:"profiles,omitempty"`
	DefaultProfile  string                   `yaml:"defaultProfile,omitempty"`
	EnvAllowlist    []string                 `yaml:"envAllowlist,omitempty"`
	EnvWhitelist    []string                 `yaml:"envWhitelist,omitempty"`
	ScanPatterns    []CustomPattern          `yaml:"scan_patterns,omitempty"`
	PaymentPolicies map[string]PaymentPolicy `yaml:"paymentPolicies,omitempty"`
}

// PaymentMaxAmount defines per-transaction and per-day spending limits.
// Both fields are strings to safely represent decimal amounts without
// floating-point rounding errors.
type PaymentMaxAmount struct {
	PerTransaction string `yaml:"per_transaction,omitempty"`
	PerDay         string `yaml:"per_day,omitempty"`
}

// PaymentPolicy constrains prepare_payment requests before the native
// approval prompt is shown. Each policy is referenced by name from an
// agent profile via the PaymentPolicy field.
type PaymentPolicy struct {
	// Instrument is the vault entry path of the payment instrument (card/bank
	// account) that this policy applies to.
	Instrument string `yaml:"instrument"`
	// AllowedMerchants is an allowlist of merchant names (case-insensitive).
	// When non-empty, only these merchants may proceed.
	AllowedMerchants []string `yaml:"allowed_merchants,omitempty"`
	// MaxAmount defines per-transaction and per-day spending limits.
	MaxAmount PaymentMaxAmount `yaml:"max_amount,omitempty"`
	// Currency is the required ISO-4217 currency code (e.g. "EUR", "USD").
	// Must be non-empty when any limit is set.
	Currency string `yaml:"currency,omitempty"`
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
	ExposePaymentValues *bool               `yaml:"exposePaymentValues,omitempty"`
	PaymentPolicy       *string             `yaml:"paymentPolicy,omitempty"`
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

// Default values applied by (*AgentProfile).Normalize when a pointer field
// is nil. Keep these conservative (deny-by-default, safe for an unknown
// agent). The defaults intentionally match the zero value of each type for
// fields where the zero value is the right default (numeric rate limits,
// string names).
const (
	defaultApprovalMode        = "deny"
	defaultPromptInjectionMode = "off"
	defaultApprovalTimeout     = 5 * time.Minute
)

// Normalize fills every nil pointer field on p with its documented default
// value, mutating p in place. Already-set fields are preserved. After
// Normalize, call sites can dereference any field without nil checks.
//
// The pointer-based layout is retained for YAML round-tripping (omitempty
// needs pointers to distinguish "set" from "absent"). Normalize is the
// runtime convenience layer that materializes the documented defaults
// without changing the on-disk format.
func (p *AgentProfile) Normalize() {
	if p == nil {
		return
	}
	if p.Tier == nil {
		p.Tier = StrPtr("")
	}
	if p.ApprovalMode == nil {
		p.ApprovalMode = StrPtr(defaultApprovalMode)
	}
	if p.PromptInjectionMode == nil {
		p.PromptInjectionMode = StrPtr(defaultPromptInjectionMode)
	}
	if p.SkillPath == nil {
		p.SkillPath = StrPtr("")
	}
	if p.SkillVersion == nil {
		p.SkillVersion = StrPtr("")
	}
	if p.ExposePaymentValues == nil {
		p.ExposePaymentValues = BoolPtr(false)
	}
	if p.CanWrite == nil {
		p.CanWrite = BoolPtr(false)
	}
	if p.CanRunCommands == nil {
		p.CanRunCommands = BoolPtr(false)
	}
	if p.CanManageConfig == nil {
		p.CanManageConfig = BoolPtr(false)
	}
	if p.CanUseClipboard == nil {
		p.CanUseClipboard = BoolPtr(false)
	}
	if p.CanUseAutotype == nil {
		p.CanUseAutotype = BoolPtr(false)
	}
	if p.CanReadValues == nil {
		p.CanReadValues = BoolPtr(false)
	}
	if p.ExposeValueTools == nil {
		p.ExposeValueTools = BoolPtr(false)
	}
	if p.AutoUnseal == nil {
		p.AutoUnseal = BoolPtr(false)
	}
	if p.RequireApproval == nil {
		p.RequireApproval = BoolPtr(false)
	}
	if p.ApprovalTimeout == nil {
		p.ApprovalTimeout = DurationPtr(defaultApprovalTimeout)
	}
	if p.MaxReadsPerHour == nil {
		p.MaxReadsPerHour = IntPtr(0)
	}
	if p.MaxReadsPerDay == nil {
		p.MaxReadsPerDay = IntPtr(0)
	}
	if p.MaxSecretsInSession == nil {
		p.MaxSecretsInSession = IntPtr(0)
	}
	if p.AllowedPaths == nil {
		p.AllowedPaths = []string{}
	}
	if p.AllowedTools == nil {
		p.AllowedTools = []string{}
	}
	if p.AllowedEnvVars == nil {
		p.AllowedEnvVars = []string{}
	}
	if p.AllowedExecutables == nil {
		p.AllowedExecutables = []string{}
	}
	if p.RedactFields == nil {
		p.RedactFields = []string{}
	}
	if p.PerToolRedactFields == nil {
		p.PerToolRedactFields = map[string][]string{}
	}
	if p.DynamicProviders == nil {
		p.DynamicProviders = map[string][]string{}
	}
	if p.PreCallHooks == nil {
		p.PreCallHooks = []string{}
	}
	if p.PostCallHooks == nil {
		p.PostCallHooks = []string{}
	}
}

// TierValue returns *p.Tier or "" when p is nil / p.Tier is nil.
func (p *AgentProfile) TierValue() string {
	if p == nil || p.Tier == nil {
		return ""
	}
	return *p.Tier
}

// ApprovalModeValue returns *p.ApprovalMode or "deny" when p is nil /
// p.ApprovalMode is nil.
func (p *AgentProfile) ApprovalModeValue() string {
	if p == nil || p.ApprovalMode == nil {
		return defaultApprovalMode
	}
	return *p.ApprovalMode
}

// SkillPathValue returns *p.SkillPath or "" when p is nil / p.SkillPath is nil.
func (p *AgentProfile) SkillPathValue() string {
	if p == nil || p.SkillPath == nil {
		return ""
	}
	return *p.SkillPath
}

// SkillVersionValue returns *p.SkillVersion or "" when p is nil /
// p.SkillVersion is nil.
func (p *AgentProfile) SkillVersionValue() string {
	if p == nil || p.SkillVersion == nil {
		return ""
	}
	return *p.SkillVersion
}

// CanWriteValue returns *p.CanWrite or false when p is nil / p.CanWrite is nil.
func (p *AgentProfile) CanWriteValue() bool {
	if p == nil || p.CanWrite == nil {
		return false
	}
	return *p.CanWrite
}

// CanRunCommandsValue returns *p.CanRunCommands or false when p is nil /
// p.CanRunCommands is nil.
func (p *AgentProfile) CanRunCommandsValue() bool {
	if p == nil || p.CanRunCommands == nil {
		return false
	}
	return *p.CanRunCommands
}

// CanManageConfigValue returns *p.CanManageConfig or false when p is nil /
// p.CanManageConfig is nil.
func (p *AgentProfile) CanManageConfigValue() bool {
	if p == nil || p.CanManageConfig == nil {
		return false
	}
	return *p.CanManageConfig
}

// CanUseClipboardValue returns *p.CanUseClipboard or false when p is nil /
// p.CanUseClipboard is nil.
func (p *AgentProfile) CanUseClipboardValue() bool {
	if p == nil || p.CanUseClipboard == nil {
		return false
	}
	return *p.CanUseClipboard
}

// CanUseAutotypeValue returns *p.CanUseAutotype or false when p is nil /
// p.CanUseAutotype is nil.
func (p *AgentProfile) CanUseAutotypeValue() bool {
	if p == nil || p.CanUseAutotype == nil {
		return false
	}
	return *p.CanUseAutotype
}

// CanReadValuesValue returns *p.CanReadValues or false when p is nil /
// p.CanReadValues is nil.
func (p *AgentProfile) CanReadValuesValue() bool {
	if p == nil || p.CanReadValues == nil {
		return false
	}
	return *p.CanReadValues
}

// ExposeValueToolsValue returns *p.ExposeValueTools or false when p is nil /
// p.ExposeValueTools is nil.
func (p *AgentProfile) ExposeValueToolsValue() bool {
	if p == nil || p.ExposeValueTools == nil {
		return false
	}
	return *p.ExposeValueTools
}

// ExposePaymentValuesValue returns *p.ExposePaymentValues or false when p is
// nil / p.ExposePaymentValues is nil.
func (p *AgentProfile) ExposePaymentValuesValue() bool {
	if p == nil || p.ExposePaymentValues == nil {
		return false
	}
	return *p.ExposePaymentValues
}

// PaymentPolicyValue returns *p.PaymentPolicy or "" when p is nil /
// p.PaymentPolicy is nil.
func (p *AgentProfile) PaymentPolicyValue() string {
	if p == nil || p.PaymentPolicy == nil {
		return ""
	}
	return *p.PaymentPolicy
}

// AutoUnsealValue returns *p.AutoUnseal or false when p is nil /
// p.AutoUnseal is nil.
func (p *AgentProfile) AutoUnsealValue() bool {
	if p == nil || p.AutoUnseal == nil {
		return false
	}
	return *p.AutoUnseal
}

// RequireApprovalValue returns *p.RequireApproval or false when p is nil /
// p.RequireApproval is nil.
func (p *AgentProfile) RequireApprovalValue() bool {
	if p == nil || p.RequireApproval == nil {
		return false
	}
	return *p.RequireApproval
}

// PromptInjectionModeValue returns *p.PromptInjectionMode or "off" when
// p is nil / p.PromptInjectionMode is nil.
func (p *AgentProfile) PromptInjectionModeValue() string {
	if p == nil || p.PromptInjectionMode == nil {
		return defaultPromptInjectionMode
	}
	return *p.PromptInjectionMode
}

// ApprovalTimeoutValue returns *p.ApprovalTimeout or the default timeout
// when p is nil / p.ApprovalTimeout is nil.
func (p *AgentProfile) ApprovalTimeoutValue() time.Duration {
	if p == nil || p.ApprovalTimeout == nil {
		return defaultApprovalTimeout
	}
	return *p.ApprovalTimeout
}
