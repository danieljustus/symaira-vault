package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/danieljustus/symaira-vault/internal/fsutil"
)

// Save persists the config to the default config file path (~/.symvault/config.yaml).
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

// SaveTo persists the config to the given file path, creating parent directories
// as needed. The file is written atomically to prevent corruption.
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
	return fsutil.AtomicWriteFile(path, data, 0o600)
}
