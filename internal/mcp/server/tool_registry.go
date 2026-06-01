package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	auth "github.com/danieljustus/symaira-vault/internal/mcp/auth"
	"github.com/danieljustus/symaira-vault/internal/mcp/errors"
)

type toolHandler func(*Server, context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error)
type toolAvailable func(*Server) bool

type toolDefinition struct {
	Name        string
	Description string
	InputSchema map[string]any
	Handler     toolHandler
	Available   toolAvailable
	Deprecated  bool
	AliasFor    string
	RiskLevel   RiskLevel
}

type schemaProperty struct {
	Type        string
	Description string
}

func objectSchema(required []string, properties map[string]schemaProperty) map[string]any {
	props := make(map[string]any, len(properties))
	for name, prop := range properties {
		props[name] = map[string]any{
			"type":        prop.Type,
			"description": prop.Description,
		}
	}

	schema := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

// MaxToolDefinitions is the maximum number of tools allowed in the registry.
// Adding a tool beyond this cap requires explicit architectural review (see
// ARCHITECTURE.md § Tool Addition Review). The cap balances functionality
// against the prompt injection attack surface — each additional tool is another
// vector an attacker-controlled agent can exploit.
const MaxToolDefinitions = 32

var (
	toolRegistry   []toolDefinition
	toolRegistryMu sync.Mutex
)

// RegisterTool adds a tool definition to the global registry. It is called from
// init() functions in individual tool files, enabling auto-discovery: adding a
// new tool requires only creating a single file with a RegisterTool call, with
// no edits to the central registry. Duplicate names or exceeding the
// MaxToolDefinitions cap cause a panic at init time.
func RegisterTool(def toolDefinition) {
	toolRegistryMu.Lock()
	defer toolRegistryMu.Unlock()

	for _, existing := range toolRegistry {
		if existing.Name == def.Name {
			panic(fmt.Sprintf("tool %q already registered", def.Name))
		}
	}

	if len(toolRegistry) >= MaxToolDefinitions {
		panic(fmt.Sprintf("cannot register tool %q: registry at %d, max %d; see ARCHITECTURE.md § Tool Addition Review", def.Name, len(toolRegistry), MaxToolDefinitions))
	}

	toolRegistry = append(toolRegistry, def)
}

// toolDefinitions returns a snapshot of all registered tool definitions.
func toolDefinitions() []toolDefinition {
	toolRegistryMu.Lock()
	defer toolRegistryMu.Unlock()
	result := make([]toolDefinition, len(toolRegistry))
	copy(result, toolRegistry)
	return result
}

func availableToolDefinitions(s *Server) []toolDefinition {
	definitions := toolDefinitions()
	available := make([]toolDefinition, 0, len(definitions))
	for _, def := range definitions {
		if def.Available != nil && !def.Available(s) {
			continue
		}
		if s != nil && isToolBlockedByAgent(s.agent, def.Name) != nil {
			continue
		}
		available = append(available, def)
	}
	return available
}

// isToolBlockedByAgent returns nil if the tool is allowed, or an *errors.MCPError
// describing why the tool is blocked based on the agent's profile and tier.
// This is used both at list-time (availableToolDefinitions) and at call-time
// (executeTool) for defense-in-depth.
//
// Returns nil (not blocked) when agent is nil (non-agent mode).
func isToolBlockedByAgent(agent *config.AgentProfile, toolName string) *errors.MCPError {
	if agent == nil {
		return nil
	}

	// Tier-based blocking (primary defense)
	if agent.Tier != nil && *agent.Tier != "" {
		if err := checkToolBlockedByTier(agent, toolName); err != nil {
			return err
		}
	}

	// Additional safeguard: ExposeValueTools specifically controls get_entry_value
	// regardless of tier. This preserves backward compatibility and provides
	// an extra layer of defense if tier-based rules are bypassed.
	if (agent.ExposeValueTools == nil || !*agent.ExposeValueTools) && toolName == "get_entry_value" {
		return errors.ToolNotAllowed(toolName, "standard", upgradeCmdForAgent(agent))
	}

	return nil
}

// checkToolBlockedByTier applies tier-based tool blocking rules.
// Returns an *errors.MCPError describing the block, or nil if allowed.
func checkToolBlockedByTier(agent *config.AgentProfile, toolName string) *errors.MCPError {
	tier := ""
	if agent.Tier != nil {
		tier = *agent.Tier
	}
	switch tier {
	case "read-only":
		blocked := map[string]bool{
			"set_entry_field":     true,
			"delete_entry":        true,
			"run_command":         true,
			"execute_with_secret": true,
			"execute_api_request": true,
			"secure_input":        true,
			"request_credential":  true,
			"copy_to_clipboard":   true,
			"autotype":            true,
		}
		if blocked[toolName] {
			return errors.ToolNotAllowed(toolName, "standard", upgradeCmdForAgent(agent))
		}

	case "standard":
		blocked := map[string]bool{
			"delete_entry":        true,
			"run_command":         true,
			"execute_with_secret": true,
			"execute_api_request": true,
		}
		if blocked[toolName] {
			return errors.ToolNotAllowed(toolName, "admin", upgradeCmdForAgent(agent))
		}

	case "admin":
		return nil
	}

	return nil
}

// upgradeCmdForAgent returns a CLI command string to guide the user toward
// upgrading the agent's tier. When the agent name is unknown or generic it
// returns a template with placeholders.
func upgradeCmdForAgent(agent *config.AgentProfile) string {
	if agent == nil || agent.Name == "" || agent.Name == "default" {
		return "symvault config set agents.<name>.tier <tier>"
	}
	return fmt.Sprintf("symvault config set agents.%s.tier <tier>", agent.Name)
}

func findToolDefinition(name string) (toolDefinition, bool) {
	for _, def := range toolDefinitions() {
		if def.Name == name {
			return def, true
		}
	}
	return toolDefinition{}, false
}

func toolsListPayload(s *Server) []map[string]any {
	definitions := availableToolDefinitions(s)
	tools := make([]map[string]any, 0, len(definitions))
	for _, def := range definitions {
		inputSchema := def.InputSchema
		if def.Name == "get_entry" && s != nil && s.agent != nil && s.agent.ExposeValueTools != nil && !*s.agent.ExposeValueTools {
			inputSchema = withoutSchemaProperty(def.InputSchema, "include_value")
		}

		payload := map[string]any{
			"name":        def.Name,
			"description": def.Description,
			"inputSchema": inputSchema,
		}
		if def.Deprecated {
			payload["deprecated"] = true
		}
		if def.AliasFor != "" {
			payload["aliasFor"] = def.AliasFor
		}
		tools = append(tools, payload)
	}
	return tools
}

func withoutSchemaProperty(schema map[string]any, property string) map[string]any {
	if schema == nil {
		return nil
	}

	cloned := make(map[string]any, len(schema))
	for key, value := range schema {
		cloned[key] = value
	}

	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return cloned
	}

	clonedProperties := make(map[string]any, len(properties))
	for key, value := range properties {
		if key == property {
			continue
		}
		clonedProperties[key] = value
	}
	cloned["properties"] = clonedProperties

	return cloned
}

func callToolResultPayload(result *mcp.CallToolResult) map[string]any {
	if result == nil {
		result = mcp.NewToolResultText("")
	}
	sanitized := globalChokepoint.SanitizeForMCP(result.Text)
	return map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": sanitized,
			},
		},
		"isError": result.IsError,
	}
}

func decodeToolRequest(args json.RawMessage) (mcp.CallToolRequest, error) {
	req := mcp.CallToolRequest{Arguments: map[string]any{}}
	if len(args) == 0 || string(args) == "null" {
		return req, nil
	}
	if err := json.Unmarshal(args, &req.Arguments); err != nil {
		return req, err
	}
	if req.Arguments == nil {
		req.Arguments = map[string]any{}
	}
	return req, nil
}

func computeToolRegistryHashDefs(defs []toolDefinition) string {
	hashDefs := make([]mcp.ToolHashDef, len(defs))
	for i, d := range defs {
		hashDefs[i] = mcp.ToolHashDef{
			Name:        d.Name,
			Description: d.Description,
			InputSchema: d.InputSchema,
		}
	}
	return mcp.ComputeToolRegistryHash(hashDefs)
}

// resolveToolAlias looks up a tool by name and returns its canonical name if
// it is an alias. If the tool is not found or is not an alias, the original
// name is returned.
func resolveToolAlias(name string) string {
	if def, ok := findToolDefinition(name); ok && def.AliasFor != "" {
		return def.AliasFor
	}
	return name
}

// isToolAllowed returns true when the given tool is permitted for the token.
// A nil token means legacy mode — all tools are allowed. Revoked or expired
// tokens deny all tools. Alias resolution is applied so that a token that
// allows the canonical name also allows the alias (and vice-versa).
func isToolAllowed(token *auth.ScopedToken, toolName string) bool {
	if token == nil {
		return true
	}
	if token.Revoked || token.IsExpired() {
		return false
	}
	canonicalName := resolveToolAlias(toolName)
	if token.IsToolAllowed(toolName) || token.IsToolAllowed(canonicalName) {
		return true
	}
	for _, def := range toolDefinitions() {
		if def.AliasFor == canonicalName && token.IsToolAllowed(def.Name) {
			return true
		}
	}
	return false
}
