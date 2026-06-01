package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

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
	if raw.EnvAllowlist != nil {
		cfg.EnvAllowlist = append([]string(nil), raw.EnvAllowlist...)
	}
	if raw.EnvWhitelist != nil {
		cfg.EnvAllowlist = append([]string(nil), raw.EnvWhitelist...)
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
		cfg.MCP = mergeMCPConfig(raw.MCP, sectionFields["mcp"], sectionFields["mcp_oauth"], sectionFields["mcp_perplexity"])
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
	if raw.Security != nil {
		cfg.Security = mergeSecurityConfig(raw.Security, sectionFields["security"])
	}
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
			v := approvalModePrompt
			current.ApprovalMode = &v
		} else {
			v := approvalModeNone
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
	if sf["search_index"] {
		defaults.SearchIndex = raw.SearchIndex
	}
	if sf["search_workers"] {
		defaults.SearchWorkers = raw.SearchWorkers
	}
	if sf["config_cache_entries"] {
		defaults.ConfigCacheEntries = raw.ConfigCacheEntries
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

//nolint:gocyclo // merging many config fields is inherently sequential
func mergeMCPConfig(raw *MCPConfig, sf, oaf, ppf map[string]bool) *MCPConfig {
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
	if sf["tls_client_ca_file"] {
		defaults.TLSClientCAFile = raw.TLSClientCAFile
	}
	if sf["mtls_enabled"] {
		defaults.MTLSEnabled = raw.MTLSEnabled
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
	if sf["perplexity"] && raw.Perplexity != nil {
		if defaults.Perplexity == nil {
			defaults.Perplexity = &PerplexityConfig{}
		}
		if ppf["api_key"] && raw.Perplexity.APIKey != "" {
			defaults.Perplexity.APIKey = raw.Perplexity.APIKey
		}
		if ppf["base_url"] && raw.Perplexity.BaseURL != "" {
			defaults.Perplexity.BaseURL = raw.Perplexity.BaseURL
		}
		if ppf["rate_limit_per_min"] && raw.Perplexity.RateLimitPerMin > 0 {
			defaults.Perplexity.RateLimitPerMin = raw.Perplexity.RateLimitPerMin
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

func mergeSecurityConfig(raw *SecurityConfig, sf map[string]bool) *SecurityConfig {
	defaults := defaultSecurityConfig()
	if sf["disable_env_passphrase"] {
		defaults.DisableEnvPassphrase = raw.DisableEnvPassphrase
	}
	return &defaults
}

// copyAgentProfiles performs a deep copy of the agent profiles map by
// round-tripping through JSON. All AgentProfile fields are JSON-safe.
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
