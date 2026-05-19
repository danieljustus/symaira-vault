package config

import (
	"time"
)

// VaultConfig holds vault-related configuration.
type VaultConfig struct {
	Path              string    `yaml:"path,omitempty"`
	DefaultRecipients []string  `yaml:"default_recipients,omitempty"`
	ConfirmRemove     bool      `yaml:"confirm_remove,omitempty"`
	AuthMethod        string    `yaml:"authMethod,omitempty"`
	UseTouchID        bool      `yaml:"useTouchID,omitempty"`
	LegacyMode        *bool     `yaml:"legacy_mode,omitempty"`
	SearchWorkers     int       `yaml:"search_workers,omitempty"`
	PseudonymizePaths bool      `yaml:"pseudonymize_paths,omitempty"`
	ScryptWorkFactor  int       `yaml:"scrypt_work_factor,omitempty"`
	LastRotated       time.Time `yaml:"last_rotated,omitempty"`
	FormatVersion     int       `yaml:"format_version,omitempty"`
	Argon2idTime      int       `yaml:"argon2id_time,omitempty"`
	Argon2idMemory    int       `yaml:"argon2id_memory,omitempty"`
	Argon2idThreads   int       `yaml:"argon2id_threads,omitempty"`
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
	Port                int           `yaml:"port,omitempty"`
	Bind                string        `yaml:"bind,omitempty"`
	HTTPTokenFile       string        `yaml:"httpTokenFile,omitempty"`
	OTLPEndpoint        string        `yaml:"otlp_endpoint,omitempty"`
	Stdio               bool          `yaml:"stdio,omitempty"`
	ApprovalRequired    bool          `yaml:"approval_required,omitempty"`
	ReadHeaderTimeout   time.Duration `yaml:"read_header_timeout,omitempty"`
	ReadTimeout         time.Duration `yaml:"read_timeout,omitempty"`
	WriteTimeout        time.Duration `yaml:"write_timeout,omitempty"`
	ShutdownTimeout     time.Duration `yaml:"shutdown_timeout,omitempty"`
	ApprovalTimeout     time.Duration `yaml:"approval_timeout,omitempty"`
	RateLimit           int           `yaml:"rate_limit,omitempty"`
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
	AutoClearDuration int  `yaml:"auto_clear_duration,omitempty"`
	PrintByDefault    bool `yaml:"printByDefault,omitempty"`
}

// AuditConfig holds audit log rotation configuration.
type AuditConfig struct {
	MaxFileSize int64 `yaml:"maxSizeMb,omitempty"`
	MaxBackups  int   `yaml:"maxBackups,omitempty"`
	MaxAgeDays  int   `yaml:"maxAgeDays,omitempty"`
}

// LoggingConfig holds logging configuration.
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

// BoolPtr returns a pointer to v.
func BoolPtr(v bool) *bool { return &v }

// StrPtr returns a pointer to v.
func StrPtr(v string) *string { return &v }

// IntPtr returns a pointer to v.
func IntPtr(v int) *int { return &v }

// Int64Ptr returns a pointer to v.
func Int64Ptr(v int64) *int64 { return &v }

// DurationPtr returns a pointer to v.
func DurationPtr(v time.Duration) *time.Duration { return &v }

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

// MergeFromVault overwrites dst's zero-value fields with src's non-zero values.
func MergeFromVault(dst *VaultConfig, src VaultConfig) {
	if src.Path != "" {
		dst.Path = src.Path
	}
	if src.DefaultRecipients != nil {
		dst.DefaultRecipients = append([]string(nil), src.DefaultRecipients...)
	}
	if src.ConfirmRemove {
		dst.ConfirmRemove = true
	}
	if src.AuthMethod != "" {
		dst.AuthMethod = src.AuthMethod
	}
	if src.UseTouchID {
		dst.UseTouchID = true
	}
	if src.LegacyMode != nil {
		dst.LegacyMode = src.LegacyMode
	}
	if src.SearchWorkers > 0 {
		dst.SearchWorkers = src.SearchWorkers
	}
	if src.PseudonymizePaths {
		dst.PseudonymizePaths = true
	}
	if src.ScryptWorkFactor > 0 {
		dst.ScryptWorkFactor = src.ScryptWorkFactor
	}
	if !src.LastRotated.IsZero() {
		dst.LastRotated = src.LastRotated
	}
	if src.FormatVersion > 0 {
		dst.FormatVersion = src.FormatVersion
	}
	if src.Argon2idTime > 0 {
		dst.Argon2idTime = src.Argon2idTime
	}
	if src.Argon2idMemory > 0 {
		dst.Argon2idMemory = src.Argon2idMemory
	}
	if src.Argon2idThreads > 0 {
		dst.Argon2idThreads = src.Argon2idThreads
	}
}

// MergeFromGit overwrites dst's zero-value fields with src's non-zero values.
func MergeFromGit(dst *GitConfig, src GitConfig) {
	if src.AutoPush {
		dst.AutoPush = true
	}
	if src.AutoPull {
		dst.AutoPull = true
	}
	if src.AutoPullInterval > 0 {
		dst.AutoPullInterval = src.AutoPullInterval
	}
	if src.CommitTemplate != "" {
		dst.CommitTemplate = src.CommitTemplate
	}
}

// MergeFromMCP overwrites dst's zero-value fields with src's non-zero values.
func MergeFromMCP(dst *MCPConfig, src MCPConfig) {
	if src.Port > 0 {
		dst.Port = src.Port
	}
	if src.Bind != "" {
		dst.Bind = src.Bind
	}
	if src.Stdio {
		dst.Stdio = true
	}
	if src.HTTPTokenFile != "" {
		dst.HTTPTokenFile = src.HTTPTokenFile
	}
	if src.OTLPEndpoint != "" {
		dst.OTLPEndpoint = src.OTLPEndpoint
	}
	if src.ReadHeaderTimeout > 0 {
		dst.ReadHeaderTimeout = src.ReadHeaderTimeout
	}
	if src.ReadTimeout > 0 {
		dst.ReadTimeout = src.ReadTimeout
	}
	if src.WriteTimeout > 0 {
		dst.WriteTimeout = src.WriteTimeout
	}
	if src.ShutdownTimeout > 0 {
		dst.ShutdownTimeout = src.ShutdownTimeout
	}
	if src.ApprovalTimeout > 0 {
		dst.ApprovalTimeout = src.ApprovalTimeout
	}
	if src.RateLimit > 0 {
		dst.RateLimit = src.RateLimit
	}
	if src.TrustedProxyIPs != nil {
		dst.TrustedProxyIPs = append([]string(nil), src.TrustedProxyIPs...)
	}
	if src.MetricsAuthRequired {
		dst.MetricsAuthRequired = true
	}
	if src.TLSCertFile != "" {
		dst.TLSCertFile = src.TLSCertFile
	}
	if src.TLSKeyFile != "" {
		dst.TLSKeyFile = src.TLSKeyFile
	}
	if src.AllowInsecureBind {
		dst.AllowInsecureBind = true
	}
	if src.OAuth != nil {
		if dst.OAuth == nil {
			dst.OAuth = &OAuthConfig{}
		}
		if src.OAuth.AccessTokenTTL > 0 {
			dst.OAuth.AccessTokenTTL = src.OAuth.AccessTokenTTL
		}
		if src.OAuth.RefreshTokenTTL > 0 {
			dst.OAuth.RefreshTokenTTL = src.OAuth.RefreshTokenTTL
		}
	}
}

// MergeFromUpdate overwrites dst's zero-value fields with src's non-zero values.
func MergeFromUpdate(dst *UpdateConfig, src UpdateConfig) {
	if src.CacheTTL > 0 {
		dst.CacheTTL = src.CacheTTL
	}
}

// MergeFromClipboard overwrites dst's zero-value fields with src's non-zero values.
func MergeFromClipboard(dst *ClipboardConfig, src ClipboardConfig) {
	if src.AutoClearDuration > 0 {
		dst.AutoClearDuration = src.AutoClearDuration
	}
	if src.PrintByDefault {
		dst.PrintByDefault = true
	}
}

// MergeFromAudit overwrites dst's zero-value fields with src's non-zero values.
// src.MaxFileSize is expected in bytes (already converted from YAML MB).
func MergeFromAudit(dst *AuditConfig, src AuditConfig) {
	if src.MaxFileSize > 0 {
		dst.MaxFileSize = src.MaxFileSize
	}
	if src.MaxBackups > 0 {
		dst.MaxBackups = src.MaxBackups
	}
	if src.MaxAgeDays > 0 {
		dst.MaxAgeDays = src.MaxAgeDays
	}
}

// MergeFromLogging overwrites dst's zero-value fields with src's non-zero values.
func MergeFromLogging(dst *LoggingConfig, src LoggingConfig) {
	if src.Level != "" {
		dst.Level = src.Level
	}
	if src.Format != "" {
		dst.Format = src.Format
	}
}
