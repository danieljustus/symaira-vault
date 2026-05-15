// Package config provides configuration management for OpenPass.
// It handles vault, git, and MCP server configuration with support for
// YAML serialization and default value merging.
package config

import (
	"fmt"
	"os"
	"time"
)

// VaultConfig holds vault-related configuration.
type VaultConfig struct {
	Path              string   `yaml:"path,omitempty"`
	DefaultRecipients []string `yaml:"default_recipients,omitempty"`
	ConfirmRemove     bool     `yaml:"confirm_remove,omitempty"`
	AuthMethod        string   `yaml:"authMethod,omitempty"`
	UseTouchID        bool     `yaml:"useTouchID,omitempty"`
	// LegacyMode indicates whether the vault may contain legacy top-level .age files
	// outside the entries/ directory. nil means "not yet detected" (assume legacy).
	// false means the vault has been confirmed to have no legacy entries, allowing
	// List to skip the legacy directory walk.
	LegacyMode *bool `yaml:"legacy_mode,omitempty"`
	// SearchWorkers controls the number of concurrent decryption workers for find
	// operations. 0 (default) enables auto-scaling based on vault size and CPU count.
	// Positive values set a fixed worker count.
	SearchWorkers int `yaml:"search_workers,omitempty"`
	// PseudonymizePaths, when true, stores entries at HMAC-SHA256-derived paths
	// instead of plaintext paths. This prevents leaking entry names via git filenames.
	// Default: false (opt-in). Requires migration via 'openpass migrate pseudonymize'.
	PseudonymizePaths bool `yaml:"pseudonymize_paths,omitempty"`
	// ScryptWorkFactor sets the scrypt KDF work factor for passphrase-based encryption.
	// Higher values are more secure but slower. Default: 18 (N=262144).
	// Set to 0 to use the default.
	ScryptWorkFactor int `yaml:"scrypt_work_factor,omitempty"`
	// LastRotated records when the vault passphrase was last rotated.
	// Zero value means never rotated.
	LastRotated time.Time `yaml:"last_rotated,omitempty"`
	// FormatVersion indicates the vault format version.
	// 1 = scrypt KDF (pre-argon2id), 2+ = argon2id.
	FormatVersion int `yaml:"format_version,omitempty"`
}

// GitConfig holds git-related configuration for automatic commits and pushes.
type GitConfig struct {
	CommitTemplate   string        `yaml:"commit_template,omitempty"`
	AutoPush         bool          `yaml:"auto_push,omitempty"`
	AutoPull         bool          `yaml:"auto_pull,omitempty"`
	AutoPullInterval time.Duration `yaml:"auto_pull_interval,omitempty"`
}

// OAuthConfig holds OAuth server configuration.
type OAuthConfig struct {
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl,omitempty"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl,omitempty"`
}

// MCPConfig holds MCP server-related configuration for AI agent integration.
type MCPConfig struct {
	Bind                string        `yaml:"bind,omitempty"`
	HTTPTokenFile       string        `yaml:"httpTokenFile,omitempty"`
	OTLPEndpoint        string        `yaml:"otlp_endpoint,omitempty"`
	Port                int           `yaml:"port,omitempty"`
	Stdio               bool          `yaml:"stdio,omitempty"`
	ApprovalRequired    bool          `yaml:"approval_required,omitempty"`
	ReadHeaderTimeout   time.Duration `yaml:"read_header_timeout,omitempty"`
	ReadTimeout         time.Duration `yaml:"read_timeout,omitempty"`
	WriteTimeout        time.Duration `yaml:"write_timeout,omitempty"`
	ShutdownTimeout     time.Duration `yaml:"shutdown_timeout,omitempty"`
	ApprovalTimeout     time.Duration `yaml:"approval_timeout,omitempty"`
	RateLimit           int           `yaml:"rate_limit,omitempty"` // requests per minute, 0 = disabled
	TrustedProxyIPs     []string      `yaml:"trusted_proxy_ips,omitempty"`
	MetricsAuthRequired bool          `yaml:"metrics_auth_required,omitempty"`
	TLSCertFile         string        `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile          string        `yaml:"tls_key_file,omitempty"`
	AllowInsecureBind   bool          `yaml:"allow_insecure_bind,omitempty"`
	OAuth               *OAuthConfig  `yaml:"oauth,omitempty"`
}

// UpdateConfig holds update check-related configuration.
type UpdateConfig struct {
	CacheTTL time.Duration `yaml:"cache_ttl,omitempty"`
}

// ClipboardConfig holds clipboard-related configuration.
type ClipboardConfig struct {
	AutoClearDuration int  `yaml:"auto_clear_duration,omitempty"` // seconds, 0 = disabled
	PrintByDefault    bool `yaml:"printByDefault,omitempty"`
}

// AuditConfig holds audit log rotation configuration.
type AuditConfig struct {
	MaxFileSize int64 `yaml:"maxSizeMb,omitempty"` // bytes (stored as MB in YAML)
	MaxBackups  int   `yaml:"maxBackups,omitempty"`
	MaxAgeDays  int   `yaml:"maxAgeDays,omitempty"`
}

// LoggingConfig holds logging configuration.
// Level and Format are primarily driven by environment variables
// (OPENPASS_LOG_LEVEL, OPENPASS_LOG_FORMAT) and are included here
// for documentation and future file-based configuration.
type LoggingConfig struct {
	Level  string `yaml:"level,omitempty"`
	Format string `yaml:"format,omitempty"`
}

// Profile holds a named vault profile configuration.
type Profile struct {
	VaultPath string `yaml:"vault,omitempty"`
}

// defaultVaultConfig returns the default vault configuration.
func defaultVaultConfig() VaultConfig {
	return VaultConfig{
		Path:              "",
		DefaultRecipients: []string{},
		AuthMethod:        AuthMethodPassphrase,
		ScryptWorkFactor:  18,
		FormatVersion:     1,
	}
}

// defaultGitConfig returns the default git configuration.
func defaultGitConfig() GitConfig {
	return GitConfig{
		AutoPush:         true,
		AutoPull:         true,
		AutoPullInterval: 10 * time.Second,
		CommitTemplate:   "Update from OpenPass",
	}
}

// defaultMCPConfig returns the default MCP server configuration.
func defaultMCPConfig() MCPConfig {
	return MCPConfig{
		Port:                8080,
		Bind:                "127.0.0.1",
		Stdio:               false,
		HTTPTokenFile:       "auto",
		ReadHeaderTimeout:   5 * time.Second,
		ReadTimeout:         10 * time.Second,
		WriteTimeout:        10 * time.Second,
		ShutdownTimeout:     5 * time.Second,
		ApprovalTimeout:     30 * time.Second,
		RateLimit:           60,
		MetricsAuthRequired: true,
		OAuth: &OAuthConfig{
			AccessTokenTTL:  24 * time.Hour,
			RefreshTokenTTL: 720 * time.Hour,
		},
	}
}

// defaultUpdateConfig returns the default update check configuration.
func defaultUpdateConfig() UpdateConfig {
	return UpdateConfig{
		CacheTTL: 24 * time.Hour,
	}
}

// defaultClipboardConfig returns the default clipboard configuration.
func defaultClipboardConfig() ClipboardConfig {
	return ClipboardConfig{
		AutoClearDuration: 30,
		PrintByDefault:    true,
	}
}

// defaultAuditConfig returns the default audit log configuration.
func defaultAuditConfig() AuditConfig {
	return AuditConfig{
		MaxFileSize: 100 * 1024 * 1024,
		MaxBackups:  5,
		MaxAgeDays:  30,
	}
}

// defaultLoggingConfig returns the default logging configuration.
func defaultLoggingConfig() LoggingConfig {
	return LoggingConfig{
		Level:  "warn",
		Format: "text",
	}
}

// fileVaultConfig is the file-based vault configuration with pointer fields
// for optional YAML unmarshaling.
type fileVaultConfig struct {
	ConfirmRemove     *bool      `yaml:"confirm_remove,omitempty"`
	AuthMethod        *string    `yaml:"authMethod,omitempty"`
	UseTouchID        *bool      `yaml:"useTouchID,omitempty"`
	LegacyMode        *bool      `yaml:"legacy_mode,omitempty"`
	Path              string     `yaml:"path,omitempty"`
	DefaultRecipients []string   `yaml:"default_recipients,omitempty"`
	SearchWorkers     *int       `yaml:"search_workers,omitempty"`
	PseudonymizePaths *bool      `yaml:"pseudonymize_paths,omitempty"`
	ScryptWorkFactor  *int       `yaml:"scrypt_work_factor,omitempty"`
	LastRotated       *time.Time `yaml:"last_rotated,omitempty"`
	FormatVersion     *int       `yaml:"format_version,omitempty"`
}

// fileGitConfig is the file-based git configuration with pointer fields
// for optional YAML unmarshaling.
type fileGitConfig struct {
	AutoPush         *bool          `yaml:"auto_push,omitempty"`
	AutoPull         *bool          `yaml:"auto_pull,omitempty"`
	AutoPullInterval *time.Duration `yaml:"auto_pull_interval,omitempty"`
	CommitTemplate   *string        `yaml:"commit_template,omitempty"`
}

// fileOAuthConfig is the file-based OAuth configuration with pointer fields
// for optional YAML unmarshaling.
type fileOAuthConfig struct {
	AccessTokenTTL  *time.Duration `yaml:"access_token_ttl,omitempty"`
	RefreshTokenTTL *time.Duration `yaml:"refresh_token_ttl,omitempty"`
}

// fileMCPConfig is the file-based MCP configuration with pointer fields
// for optional YAML unmarshaling.
type fileMCPConfig struct {
	Port                *int           `yaml:"port,omitempty"`
	Bind                *string        `yaml:"bind,omitempty"`
	Stdio               *bool          `yaml:"stdio,omitempty"`
	ApprovalRequired    *bool          `yaml:"approval_required,omitempty"` // deprecated, parsed but ignored
	HTTPTokenFile       *string        `yaml:"httpTokenFile,omitempty"`
	OTLPEndpoint        *string        `yaml:"otlp_endpoint,omitempty"`
	ReadHeaderTimeout   *time.Duration `yaml:"read_header_timeout,omitempty"`
	ReadTimeout         *time.Duration `yaml:"read_timeout,omitempty"`
	WriteTimeout        *time.Duration `yaml:"write_timeout,omitempty"`
	ShutdownTimeout     *time.Duration `yaml:"shutdown_timeout,omitempty"`
	ApprovalTimeout     *time.Duration `yaml:"approval_timeout,omitempty"`
	RateLimit           *int           `yaml:"rate_limit,omitempty"`
	TrustedProxyIPs     []string       `yaml:"trusted_proxy_ips,omitempty"`
	MetricsAuthRequired *bool          `yaml:"metrics_auth_required,omitempty"`
	TLSCertFile         *string        `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile          *string        `yaml:"tls_key_file,omitempty"`
	AllowInsecureBind   *bool          `yaml:"allow_insecure_bind,omitempty"`
	OAuth               *fileOAuthConfig `yaml:"oauth,omitempty"`
}

// fileUpdateConfig is the file-based update configuration with pointer fields
// for optional YAML unmarshaling.
type fileUpdateConfig struct {
	CacheTTL *time.Duration `yaml:"cache_ttl,omitempty"`
}

// fileClipboardConfig is the file-based clipboard configuration with pointer fields
// for optional YAML unmarshaling.
type fileClipboardConfig struct {
	AutoClearDuration *int  `yaml:"auto_clear_duration,omitempty"`
	PrintByDefault    *bool `yaml:"printByDefault,omitempty"`
}

// fileAuditConfig is the file-based audit configuration with pointer fields
// for optional YAML unmarshaling.
type fileAuditConfig struct {
	MaxFileSize *int64 `yaml:"maxSizeMb,omitempty"`
	MaxBackups  *int   `yaml:"maxBackups,omitempty"`
	MaxAgeDays  *int   `yaml:"maxAgeDays,omitempty"`
}

// MergeFileVaultConfig merges file config with defaults, returning the final
// VaultConfig. If fileCfg is nil, defaults are returned unchanged.
func MergeFileVaultConfig(fileCfg *fileVaultConfig, defaults VaultConfig) VaultConfig {
	if fileCfg == nil {
		return defaults
	}
	result := defaults
	if fileCfg.Path != "" {
		result.Path = fileCfg.Path
	}
	if fileCfg.DefaultRecipients != nil {
		result.DefaultRecipients = append([]string(nil), fileCfg.DefaultRecipients...)
	}
	if fileCfg.ConfirmRemove != nil {
		result.ConfirmRemove = *fileCfg.ConfirmRemove
	}
	if fileCfg.AuthMethod != nil {
		result.AuthMethod = *fileCfg.AuthMethod
	}
	if fileCfg.UseTouchID != nil {
		result.UseTouchID = *fileCfg.UseTouchID
	}
	if fileCfg.LegacyMode != nil {
		result.LegacyMode = fileCfg.LegacyMode
	}
	if fileCfg.SearchWorkers != nil {
		result.SearchWorkers = *fileCfg.SearchWorkers
	}
	if fileCfg.PseudonymizePaths != nil {
		result.PseudonymizePaths = *fileCfg.PseudonymizePaths
	}
	if fileCfg.ScryptWorkFactor != nil {
		result.ScryptWorkFactor = *fileCfg.ScryptWorkFactor
	}
	if fileCfg.LastRotated != nil {
		result.LastRotated = *fileCfg.LastRotated
	}
	if fileCfg.FormatVersion != nil {
		result.FormatVersion = *fileCfg.FormatVersion
	}
	return result
}

// MergeFileGitConfig merges file config with defaults, returning the final
// GitConfig. If fileCfg is nil, defaults are returned unchanged.
func MergeFileGitConfig(fileCfg *fileGitConfig, defaults GitConfig) GitConfig {
	if fileCfg == nil {
		return defaults
	}
	result := defaults
	if fileCfg.AutoPush != nil {
		result.AutoPush = *fileCfg.AutoPush
	}
	if fileCfg.AutoPull != nil {
		result.AutoPull = *fileCfg.AutoPull
	}
	if fileCfg.AutoPullInterval != nil {
		result.AutoPullInterval = *fileCfg.AutoPullInterval
	}
	if fileCfg.CommitTemplate != nil {
		result.CommitTemplate = *fileCfg.CommitTemplate
	}
	return result
}

// MergeFileMCPConfig merges file config with defaults, returning the final
// MCPConfig. If fileCfg is nil, defaults are returned unchanged.
func MergeFileMCPConfig(fileCfg *fileMCPConfig, defaults MCPConfig) MCPConfig {
	if fileCfg == nil {
		return defaults
	}
	result := defaults
	if fileCfg.ApprovalRequired != nil {
		fmt.Fprintln(os.Stderr, "Warning: approval_required is deprecated and will be removed in a future version")
	}
	if fileCfg.Port != nil {
		result.Port = *fileCfg.Port
	}
	if fileCfg.Bind != nil {
		result.Bind = *fileCfg.Bind
	}
	if fileCfg.Stdio != nil {
		result.Stdio = *fileCfg.Stdio
	}
	if fileCfg.HTTPTokenFile != nil {
		result.HTTPTokenFile = *fileCfg.HTTPTokenFile
	}
	if fileCfg.ReadHeaderTimeout != nil {
		result.ReadHeaderTimeout = *fileCfg.ReadHeaderTimeout
	}
	if fileCfg.ReadTimeout != nil {
		result.ReadTimeout = *fileCfg.ReadTimeout
	}
	if fileCfg.WriteTimeout != nil {
		result.WriteTimeout = *fileCfg.WriteTimeout
	}
	if fileCfg.ShutdownTimeout != nil {
		result.ShutdownTimeout = *fileCfg.ShutdownTimeout
	}
	if fileCfg.ApprovalTimeout != nil {
		result.ApprovalTimeout = *fileCfg.ApprovalTimeout
	}
	if fileCfg.RateLimit != nil {
		result.RateLimit = *fileCfg.RateLimit
	}
	if fileCfg.TrustedProxyIPs != nil {
		result.TrustedProxyIPs = append([]string(nil), fileCfg.TrustedProxyIPs...)
	}
	if fileCfg.OTLPEndpoint != nil {
		result.OTLPEndpoint = *fileCfg.OTLPEndpoint
	}
	if fileCfg.MetricsAuthRequired != nil {
		result.MetricsAuthRequired = *fileCfg.MetricsAuthRequired
	}
	if fileCfg.TLSCertFile != nil {
		result.TLSCertFile = *fileCfg.TLSCertFile
	}
	if fileCfg.TLSKeyFile != nil {
		result.TLSKeyFile = *fileCfg.TLSKeyFile
	}
	if fileCfg.AllowInsecureBind != nil {
		result.AllowInsecureBind = *fileCfg.AllowInsecureBind
	}
	if fileCfg.OAuth != nil {
		if result.OAuth == nil {
			result.OAuth = &OAuthConfig{}
		}
		if fileCfg.OAuth.AccessTokenTTL != nil {
			result.OAuth.AccessTokenTTL = *fileCfg.OAuth.AccessTokenTTL
		}
		if fileCfg.OAuth.RefreshTokenTTL != nil {
			result.OAuth.RefreshTokenTTL = *fileCfg.OAuth.RefreshTokenTTL
		}
	}
	return result
}

// MergeFileUpdateConfig merges file config with defaults, returning the final
// UpdateConfig. If fileCfg is nil, defaults are returned unchanged.
func MergeFileUpdateConfig(fileCfg *fileUpdateConfig, defaults UpdateConfig) UpdateConfig {
	if fileCfg == nil {
		return defaults
	}
	result := defaults
	if fileCfg.CacheTTL != nil {
		result.CacheTTL = *fileCfg.CacheTTL
	}
	return result
}

// MergeFileClipboardConfig merges file config with defaults, returning the final
// ClipboardConfig. If fileCfg is nil, defaults are returned unchanged.
func MergeFileClipboardConfig(fileCfg *fileClipboardConfig, defaults ClipboardConfig) ClipboardConfig {
	if fileCfg == nil {
		return defaults
	}
	result := defaults
	if fileCfg.AutoClearDuration != nil {
		result.AutoClearDuration = *fileCfg.AutoClearDuration
	}
	if fileCfg.PrintByDefault != nil {
		result.PrintByDefault = *fileCfg.PrintByDefault
	}
	return result
}

// MergeFileAuditConfig merges file config with defaults, returning the final
// AuditConfig. If fileCfg is nil, defaults are returned unchanged.
func MergeFileAuditConfig(fileCfg *fileAuditConfig, defaults AuditConfig) AuditConfig {
	if fileCfg == nil {
		return defaults
	}
	result := defaults
	if fileCfg.MaxFileSize != nil {
		result.MaxFileSize = *fileCfg.MaxFileSize * 1024 * 1024
	}
	if fileCfg.MaxBackups != nil {
		result.MaxBackups = *fileCfg.MaxBackups
	}
	if fileCfg.MaxAgeDays != nil {
		result.MaxAgeDays = *fileCfg.MaxAgeDays
	}
	return result
}

// fileLoggingConfig is the file-based logging configuration.
type fileLoggingConfig struct {
	Level  *string `yaml:"level,omitempty"`
	Format *string `yaml:"format,omitempty"`
}

// MergeFileLoggingConfig merges file config with defaults, returning the final
// LoggingConfig. If fileCfg is nil, defaults are returned unchanged.
func MergeFileLoggingConfig(fileCfg *fileLoggingConfig, defaults LoggingConfig) LoggingConfig {
	if fileCfg == nil {
		return defaults
	}
	result := defaults
	if fileCfg.Level != nil {
		result.Level = *fileCfg.Level
	}
	if fileCfg.Format != nil {
		result.Format = *fileCfg.Format
	}
	return result
}

// ProfileForName returns the profile with the given name, or nil if not found.
func (c *Config) ProfileForName(name string) *Profile {
	if c.Profiles == nil {
		return nil
	}
	return c.Profiles[name]
}

// VaultDirForProfile returns the vault directory for a profile, or empty string if not found.
func (c *Config) VaultDirForProfile(name string) string {
	profile := c.ProfileForName(name)
	if profile == nil {
		return ""
	}
	return profile.VaultPath
}

// IsLegacyMode reports whether the vault may contain legacy top-level .age files
// outside the entries/ directory. Returns true (assume legacy) when the mode is
// unknown (nil), matching the safe default for backward compatibility.
func (c *Config) IsLegacyMode() bool {
	if c == nil || c.Vault == nil || c.Vault.LegacyMode == nil {
		return true
	}
	return *c.Vault.LegacyMode
}
