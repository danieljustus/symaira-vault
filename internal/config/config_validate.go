package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Approval mode constants
const (
	approvalModeDeny   = "deny"
	approvalModeAuto   = "auto"
	approvalModeNone   = "none"
	approvalModePrompt = "prompt"
)

func validateAgents(agents map[string]AgentProfile) error {
	for name, profile := range agents {
		mode := ""
		if profile.ApprovalMode != nil {
			mode = *profile.ApprovalMode
		}
		switch mode {
		case "", approvalModeNone, approvalModeDeny, approvalModePrompt:
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
		case "", "off", "log-only", "wrap", approvalModeDeny:
		default:
			return fmt.Errorf("agent %q: invalid promptInjectionMode %q (valid: off, log-only, wrap, deny)", name, mode)
		}
	}
	return nil
}

// Validate checks the config for semantic correctness and returns all errors
// joined together. Each error includes a remediation hint pointing the user to
// the relevant config field or environment variable.
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
		case "", approvalModeNone, approvalModeDeny, approvalModePrompt, approvalModeAuto:
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
