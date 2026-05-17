// Package agentskill manages per-agent skill packages via embed.FS templates.
// It provides rendering, install, refresh, uninstall, and export operations
// for agent skill files with integrity verification via SHA-256 hashes.
package agentskill

import (
	"bytes"
	"embed"
	"fmt"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed assets/**/*.tmpl
var assetFS embed.FS

const (
	commonTmpl = "assets/common/SKILL.md.tmpl"
)

// agentEntry describes a single agent's template and output filename.
type agentEntry struct {
	tmplPath string // template file path within embed.FS
	outName  string // output filename (SKILL.md or AGENTS.md)
}

// agentTemplates maps agent names to their template configuration.
var agentTemplates = map[string]agentEntry{
	"hermes":      {tmplPath: "assets/hermes/SKILL.md.tmpl", outName: "SKILL.md"},
	"claude-code": {tmplPath: "assets/claude-code/SKILL.md.tmpl", outName: "SKILL.md"},
	"codex":       {tmplPath: "assets/codex/AGENTS.md.tmpl", outName: "AGENTS.md"},
	"opencode":    {tmplPath: "assets/opencode/SKILL.md.tmpl", outName: "SKILL.md"},
	"openclaw":    {tmplPath: "assets/openclaw/SKILL.md.tmpl", outName: "SKILL.md"},
}

// SupportedAgents returns the list of agent names that have skill templates.
func SupportedAgents() []string {
	agents := make([]string, 0, len(agentTemplates))
	for name := range agentTemplates {
		agents = append(agents, name)
	}
	return agents
}

// OutputFileName returns the output file name for the given agent
// (e.g., "SKILL.md" or "AGENTS.md").
func OutputFileName(agentName string) (string, error) {
	entry, ok := agentTemplates[agentName]
	if !ok {
		return "", fmt.Errorf("unknown agent: %s", agentName)
	}
	return entry.outName, nil
}

// loadTemplate parses the common template and the agent-specific template
// into a single template set, then returns the parsed template.
func loadAgentTemplate(agentTemplatePath string) (*template.Template, error) {
	commonData, err := assetFS.ReadFile(commonTmpl)
	if err != nil {
		return nil, fmt.Errorf("read common template: %w", err)
	}

	agentData, err := assetFS.ReadFile(agentTemplatePath)
	if err != nil {
		return nil, fmt.Errorf("read agent template %s: %w", agentTemplatePath, err)
	}

	tmpl, err := template.New("").Funcs(template.FuncMap{
		"now": func() string { return time.Now().UTC().Format(time.RFC3339) },
	}).Parse(string(commonData))
	if err != nil {
		return nil, fmt.Errorf("parse common template: %w", err)
	}

	tmpl, err = tmpl.Parse(string(agentData))
	if err != nil {
		return nil, fmt.Errorf("parse agent template: %w", err)
	}

	return tmpl, nil
}

// TemplateVars holds all variables available during skill template rendering.
// All fields are required unless marked optional.
type TemplateVars struct {
	// AgentName is the agent identifier (e.g., "hermes", "claude-code").
	AgentName string

	// ToolPrefix is the MCP tool prefix (e.g., "mcp_openpass_", "mcp__openpass__").
	ToolPrefix string

	// SlashPrefix is the slash command prefix (e.g., "/openpass:", "/mcp__openpass__").
	// May be empty for agents that do not support slash commands.
	SlashPrefix string

	// OpenPassVersion is the version of OpenPass (e.g., "4.0.0").
	OpenPassVersion string

	// ProfileTier is the agent profile tier (safe, standard, admin, custom).
	ProfileTier string

	// VaultPath is the path to the OpenPass vault directory (e.g., "~/.openpass").
	VaultPath string

	// InstalledAt is the installation timestamp in RFC3339 format.
	// If empty, time.Now().UTC().Format(time.RFC3339) is used.
	InstalledAt string

	// SkillSchemaVersion is the skill schema version.
	// If empty, DefaultSkillSchemaVersion is used.
	SkillSchemaVersion string
}

const (
	// DefaultSkillSchemaVersion is the schema version used when SkillSchemaVersion is empty.
	DefaultSkillSchemaVersion = "1"

	// SentinelValue is the managed_by marker that identifies OpenPass-managed files.
	SentinelValue = "openpass"
)

// Render renders a skill template for the given agent and returns the complete
// file content including YAML frontmatter with integrity metadata.
//
// The hash in the frontmatter is computed from the rendered body (everything
// after the closing --- of the frontmatter). This enables integrity checks
// without being affected by frontmatter fields that may change between
// installs (timestamps, versions).
func Render(agentName string, vars TemplateVars) ([]byte, error) {
	entry, ok := agentTemplates[agentName]
	if !ok {
		return nil, fmt.Errorf("unknown agent: %s", agentName)
	}

	if vars.AgentName == "" {
		vars.AgentName = agentName
	}
	if vars.InstalledAt == "" {
		vars.InstalledAt = time.Now().UTC().Format(time.RFC3339)
	}
	if vars.SkillSchemaVersion == "" {
		vars.SkillSchemaVersion = DefaultSkillSchemaVersion
	}

	tmpl, err := loadAgentTemplate(entry.tmplPath)
	if err != nil {
		return nil, err
	}

	var bodyBuf bytes.Buffer
	if execErr := tmpl.Execute(&bodyBuf, vars); execErr != nil {
		return nil, fmt.Errorf("render %s skill template: %w", agentName, execErr)
	}
	body := bodyBuf.Bytes()

	hashStr := HashBytes(body)

	manifest := Manifest{
		Name:               "openpass",
		Description:        "Use OpenPass as the credential manager via native MCP tools and CLI.",
		ManagedBy:          SentinelValue,
		ManagedVersion:     vars.OpenPassVersion,
		ManagedHash:        hashStr,
		ManagedInstalledAt: vars.InstalledAt,
		ManagedProfileTier: vars.ProfileTier,
	}

	fmYAML, err := yaml.Marshal(&manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal frontmatter: %w", err)
	}

	var out bytes.Buffer
	out.WriteString("---\n")
	out.Write(fmYAML)
	out.WriteString("---\n\n")
	out.Write(body)

	// Normalize to LF-only for cross-platform consistency.
	result := bytes.ReplaceAll(out.Bytes(), []byte("\r\n"), []byte("\n"))
	return result, nil
}

// VerifyRender re-renders the skill and returns true if the body hash matches
// the one in the provided rendered content. This detects user modifications
// or template drift.
func VerifyRender(agentName string, vars TemplateVars, rendered []byte) (bool, error) {
	renderedHash, err := extractBodyHash(rendered)
	if err != nil {
		return false, err
	}

	currentHash, err := computeBodyHash(agentName, vars)
	if err != nil {
		return false, err
	}

	return renderedHash == currentHash, nil
}

// renderForExport renders a skill and creates INSTALL.md content
// for tar.gz export. Returns a map of filename to content.
func renderForExport(agentName string, vars TemplateVars) (map[string][]byte, error) {
	entry, ok := agentTemplates[agentName]
	if !ok {
		return nil, fmt.Errorf("unknown agent: %s", agentName)
	}

	skillData, err := Render(agentName, vars)
	if err != nil {
		return nil, err
	}

	installMD := fmt.Sprintf(`# %s OpenPass Skill — Manual Install

This skill was exported by OpenPass v%s.

## Steps

1. Place %[3]s in your agent's skill directory.
2. Create a scoped access token:
   openpass mcp token create --agent %[1]s --tools list,get --expires 90d
3. Restart your agent.

## Verification

Run the agent's MCP discovery command to verify OpenPass tools are available.
`, agentName, vars.OpenPassVersion, entry.outName)

	return map[string][]byte{
		entry.outName: skillData,
		"INSTALL.md":  []byte(installMD),
	}, nil
}

// computeBodyHash renders the body (without frontmatter) and returns its hash.
func computeBodyHash(agentName string, vars TemplateVars) (string, error) {
	entry, ok := agentTemplates[agentName]
	if !ok {
		return "", fmt.Errorf("unknown agent: %s", agentName)
	}

	tmpl, err := loadAgentTemplate(entry.tmplPath)
	if err != nil {
		return "", err
	}

	var bodyBuf bytes.Buffer
	if execErr := tmpl.Execute(&bodyBuf, vars); execErr != nil {
		return "", fmt.Errorf("render %s skill body: %w", agentName, execErr)
	}

	return HashBytes(bodyBuf.Bytes()), nil
}

// PrefixResult holds the MCP tool prefix and slash prefix for an agent.
type PrefixResult struct {
	ToolPrefix  string
	SlashPrefix string
}

// agentPrefixes maps agent names to their MCP tool and slash command prefixes.
var agentPrefixes = map[string]PrefixResult{
	"hermes":      {ToolPrefix: "mcp_openpass_", SlashPrefix: "/openpass:"},
	"claude-code": {ToolPrefix: "mcp__openpass__", SlashPrefix: "/mcp__openpass__"},
	"codex":       {ToolPrefix: "", SlashPrefix: ""},
	"opencode":    {ToolPrefix: "", SlashPrefix: ""},
	"openclaw":    {ToolPrefix: "", SlashPrefix: ""},
}

// PrefixConfig returns the tool and slash prefix configuration for an agent.
// Returns empty strings for unknown agents.
func PrefixConfig(agentName string) PrefixResult {
	if pc, ok := agentPrefixes[agentName]; ok {
		return pc
	}
	return PrefixResult{}
}

// extractBodyHash parses the frontmatter from rendered content and returns
// the managed_hash value.
func extractBodyHash(rendered []byte) (string, error) {
	manifest, err := ParseManifest(rendered)
	if err != nil {
		return "", err
	}
	if manifest.ManagedHash == "" {
		return "", fmt.Errorf("no managed_hash in frontmatter")
	}
	return manifest.ManagedHash, nil
}
