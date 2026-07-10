package config

import (
	"errors"
	"fmt"
	"math/big"
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
		case "", defaultPromptInjectionMode, "log-only", "wrap", approvalModeDeny:
		default:
			return fmt.Errorf("agent %q: invalid promptInjectionMode %q (valid: off, log-only, wrap, deny)", name, mode)
		}
	}
	return nil
}

func validateDecimalString(s, field string) error {
	if len(s) == 0 || len(s) > 30 {
		return fmt.Errorf("%s: %q is not a valid decimal amount", field, s)
	}
	sawDot := false
	hasDigit := false
	for i, r := range s {
		switch r {
		case '-':
			if i != 0 {
				return fmt.Errorf("%s: %q is not a valid decimal amount (minus sign must be leading)", field, s)
			}
		case '.':
			if sawDot {
				return fmt.Errorf("%s: %q is not a valid decimal amount (multiple decimal points)", field, s)
			}
			sawDot = true
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			hasDigit = true
		default:
			return fmt.Errorf("%s: %q is not a valid decimal amount", field, s)
		}
	}
	if !hasDigit {
		return fmt.Errorf("%s: %q is not a valid decimal amount (no digits)", field, s)
	}
	// Length and format are validated above, so the input cannot trigger the
	// malformed-string memory blowup described in CVE-2022-23772.
	// #nosec G113
	if _, ok := new(big.Rat).SetString(s); !ok {
		return fmt.Errorf("%s: %q is not a valid decimal amount", field, s)
	}
	return nil
}

func validatePaymentPolicies(policies map[string]PaymentPolicy) error {
	for name, policy := range policies {
		if strings.TrimSpace(policy.Instrument) == "" {
			return fmt.Errorf("paymentPolicies.%s.instrument: must not be empty", name)
		}
		hasAllowlist := len(policy.AllowedMerchants) > 0
		hasLimits := policy.MaxAmount.PerTransaction != "" || policy.MaxAmount.PerDay != ""
		if !hasAllowlist && !hasLimits {
			return fmt.Errorf("paymentPolicies.%s: must have at least one allowed_merchant or max_amount limit", name)
		}
		if hasLimits && strings.TrimSpace(policy.Currency) == "" {
			return fmt.Errorf("paymentPolicies.%s.currency: required when max_amount limits are set", name)
		}
		if policy.MaxAmount.PerTransaction != "" {
			if err := validateDecimalString(policy.MaxAmount.PerTransaction, fmt.Sprintf("paymentPolicies.%s.max_amount.per_transaction", name)); err != nil {
				return err
			}
		}
		if policy.MaxAmount.PerDay != "" {
			if err := validateDecimalString(policy.MaxAmount.PerDay, fmt.Sprintf("paymentPolicies.%s.max_amount.per_day", name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateAgentPaymentPolicies(agents map[string]AgentProfile, policies map[string]PaymentPolicy) error {
	for name, profile := range agents {
		policyName := profile.PaymentPolicyValue()
		if policyName == "" {
			continue
		}
		if _, ok := policies[policyName]; !ok {
			return fmt.Errorf("agents.%s.paymentPolicy: policy %q not found in paymentPolicies", name, policyName)
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
		errs = errors.Join(errs, errors.New("vaultDir: must not be empty (set SYMVAULT_VAULT environment variable or configure vaultDir in config.yaml)"))
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

	if err := validatePaymentPolicies(c.PaymentPolicies); err != nil {
		errs = errors.Join(errs, err)
	}

	if err := validateAgentPaymentPolicies(c.Agents, c.PaymentPolicies); err != nil {
		errs = errors.Join(errs, err)
	}

	return errs
}
