package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/danieljustus/OpenPass/internal/pathutil"
)

func validateConfigPath(path string) error {
	if pathutil.HasTraversal(path) {
		return errors.New("config file path escapes expected directory")
	}
	return nil
}

// Default returns a Config populated with sensible defaults, including built-in
// agent profiles.
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

func defaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("unable to determine home directory")
	}
	return filepath.Join(home, defaultConfigDir, defaultConfigFile), nil
}

// NormalizeAuthMethod normalizes an auth method string to a canonical value.
// Acceptable inputs: "passphrase" (or empty), "touchid", "touch-id", "touch_id",
// "biometric", "biometrics".
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

// EffectiveAuthMethod returns the resolved auth method from the config,
// falling back through nested defaults.
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

// SetAuthMethod sets the auth method on the config, normalizing it first.
// It also updates the UseTouchID flag and the vault sub-config when set.
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

// newDefaultAgentProfile creates an AgentProfile with safe defaults (deny-all).
func newDefaultAgentProfile(name string) AgentProfile {
	canWrite := false
	canRunCommands := false
	exposeValueTools := true
	autoUnseal := true
	deny := approvalModeDeny
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

// builtinAgentProfiles returns the built-in set of known agent profiles.
func builtinAgentProfiles() map[string]AgentProfile {
	canWriteTrue := true
	canWriteFalse := false
	canRunTrue := true
	canRunFalse := false
	exposeTrue := true
	autoUnsealFalse := false
	deny := approvalModeDeny
	return map[string]AgentProfile{
		"default":     {Name: "default", AllowedPaths: []string{}, CanWrite: &canWriteFalse, CanRunCommands: &canRunFalse, ApprovalMode: &deny, ExposeValueTools: &exposeTrue, AutoUnseal: &autoUnsealFalse},
		"claude-code": {Name: "claude-code", AllowedPaths: []string{}, CanWrite: &canWriteTrue, CanRunCommands: &canRunTrue, ApprovalMode: &deny, ExposeValueTools: &exposeTrue, AutoUnseal: &autoUnsealFalse, SkillPath: StrPtr("~/.claude/skills/openpass/SKILL.md")},
		"codex":       {Name: "codex", AllowedPaths: []string{}, CanWrite: &canWriteFalse, CanRunCommands: &canRunTrue, ApprovalMode: &deny, ExposeValueTools: &exposeTrue, AutoUnseal: &autoUnsealFalse, SkillPath: StrPtr("~/.codex/skills/openpass/AGENTS.md")},
		"hermes":      {Name: "hermes", AllowedPaths: []string{}, CanWrite: &canWriteTrue, CanRunCommands: &canRunTrue, ApprovalMode: &deny, ExposeValueTools: &exposeTrue, AutoUnseal: &autoUnsealFalse, SkillPath: StrPtr("~/.hermes/skills/openpass/SKILL.md")},
		"openclaw":    {Name: "openclaw", AllowedPaths: []string{}, CanWrite: &canWriteTrue, CanRunCommands: &canRunTrue, ApprovalMode: &deny, ExposeValueTools: &exposeTrue, AutoUnseal: &autoUnsealFalse, SkillPath: StrPtr("~/.openclaw/skills/openpass/SKILL.md")},
		"opencode":    {Name: "opencode", AllowedPaths: []string{}, CanWrite: &canWriteFalse, CanRunCommands: &canRunTrue, ApprovalMode: &deny, ExposeValueTools: &exposeTrue, AutoUnseal: &autoUnsealFalse, SkillPath: StrPtr("~/.opencode/skills/openpass/SKILL.md")},
	}
}

// Load reads and parses a YAML config file at the given path, applies defaults,
// merges user-provided values, and returns the resulting Config.
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

	if raw.EnvWhitelist != nil {
		fmt.Fprintln(os.Stderr, "Warning: envWhitelist is deprecated and will be removed in a future version; use envAllowlist instead")
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

// loadAgentFields walks the parsed YAML node tree to discover which fields
// were explicitly set under each agent profile.
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
