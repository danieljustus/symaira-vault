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
	Name            string
	Description     string
	InputSchema     map[string]any
	Handler         toolHandler
	Available       toolAvailable
	Deprecated      bool
	AliasFor        string
	RiskLevel       RiskLevel
	ReadOnlyHint    bool
	DestructiveHint bool
	// Capabilities describes runtime requirements and alternatives for this tool.
	// When set, it is included in the tools/list response so agents can make
	// informed decisions about tool selection and fallback strategies.
	Capabilities *ToolCapabilities
}

// ToolCapabilities describes a tool's runtime requirements and fallback options.
// This metadata helps agents understand when a tool might be unavailable and
// what alternatives exist.
type ToolCapabilities struct {
	// RequiresTTY indicates the tool needs an interactive terminal.
	RequiresTTY bool `json:"requires_tty,omitempty"`
	// RequiresGUI indicates the tool needs a native OS dialog backend.
	RequiresGUI bool `json:"requires_gui,omitempty"`
	// Alternatives lists tool names that can achieve a similar goal when this
	// tool is unavailable. Agents should try these in order.
	Alternatives []string `json:"alternatives,omitempty"`
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
const MaxToolDefinitions = 35

var (
	toolRegistry   []toolDefinition
	toolRegistryMu sync.Mutex
)

// RegisterTools explicitly registers all MCP tools in the global registry.
// It is called once during server setup (see setup.go) rather than relying on
// init()-based auto-registration. This provides deterministic registration
// order, easier testability, and a single place to see all available tools.
//
// Duplicate names or exceeding the MaxToolDefinitions cap cause a panic.
func RegisterTools() {
	// -- tools_auth.go
	RegisterTool(toolDefinition{
		Name:         "get_auth_status",
		Description:  "Return Symaira Vault unlock authentication status",
		InputSchema:  objectSchema(nil, map[string]schemaProperty{}),
		Handler:      (*Server).handleGetAuthStatus,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "set_auth_method",
		Description: "Set Symaira Vault unlock authentication method (requires canManageConfig)",
		InputSchema: objectSchema([]string{"method"}, map[string]schemaProperty{
			"method": {Type: "string", Description: "Authentication method: passphrase or touchid"},
		}),
		Handler:         (*Server).handleSetAuthMethod,
		RiskLevel:       RiskLevelHigh,
		DestructiveHint: true,
	})

	// -- tools_audit_self.go
	RegisterTool(toolDefinition{
		Name:        "symaira_audit_self",
		Description: "Return recent audit events for this agent",
		InputSchema: objectSchema(nil, map[string]schemaProperty{
			"limit": {Type: "number", Description: "Maximum number of events to return (default 50, max 100)"},
		}),
		Handler:      (*Server).handleAuditSelf,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})

	// -- tools_autotype.go
	RegisterTool(toolDefinition{
		Name:        "autotype",
		Description: "Type a vault entry field value as keyboard input into the currently focused application without exposing the value to the agent",
		InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
			"path":  {Type: "string", Description: "Entry path"},
			"field": {Type: "string", Description: "Field name to type (default: password)"},
		}),
		Handler:         (*Server).handleAutotype,
		RiskLevel:       RiskLevelHigh,
		DestructiveHint: true,
	})

	// -- tools_prepare_payment.go
	RegisterTool(toolDefinition{
		Name:        "prepare_payment",
		Description: "Prepare a payment by validating a payment entry, showing a native approval prompt with merchant/amount/currency, and on approval autotyping card or bank account fields into the focused checkout window. Card values are never returned to the agent.",
		InputSchema: objectSchema([]string{"entry_path", "merchant", "amount", "currency"}, map[string]schemaProperty{
			"entry_path":  {Type: "string", Description: "Vault path of the payment entry"},
			"merchant":    {Type: "string", Description: "Merchant name or origin (e.g. shop.example)"},
			"amount":      {Type: "string", Description: "Payment amount (e.g. 75.00)"},
			"currency":    {Type: "string", Description: "Currency code (e.g. EUR, USD)"},
			"description": {Type: "string", Description: "Optional description shown in the approval prompt"},
		}),
		Handler:         (*Server).handlePreparePayment,
		RiskLevel:       RiskLevelCritical,
		DestructiveHint: true,
	})

	// -- tools_clipboard.go
	RegisterTool(toolDefinition{
		Name:        "copy_to_clipboard",
		Description: "Copy a vault entry password field to the system clipboard without exposing the value to the agent",
		InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
			"path": {Type: "string", Description: "Entry path"},
		}),
		Handler:         (*Server).handleCopyToClipboard,
		RiskLevel:       RiskLevelHigh,
		DestructiveHint: true,
	})

	// -- tools_delete.go
	RegisterTool(toolDefinition{
		Name:        "delete_entry",
		Description: "Delete a password entry by path",
		InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
			"path": {Type: "string", Description: "Entry path to delete"},
		}),
		Handler:         (*Server).handleDelete,
		RiskLevel:       RiskLevelCritical,
		DestructiveHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "symaira_delete",
		Description: "Deprecated alias for delete_entry. Use delete_entry for new clients.",
		InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
			"path": {Type: "string", Description: "Entry path to delete"},
		}),
		Handler:         (*Server).handleDelete,
		Deprecated:      true,
		AliasFor:        "delete_entry",
		RiskLevel:       RiskLevelCritical,
		DestructiveHint: true,
	})

	// -- tools_execute_api_request.go
	RegisterTool(toolDefinition{
		Name:        "execute_api_request",
		Description: "Execute an HTTP API request using a named template with vault-injected credentials. The agent never sees the credential values. Requires command execution permission.",
		InputSchema: objectSchema([]string{"template", "endpoint"}, map[string]schemaProperty{
			"template": {Type: "string", Description: "API template name (e.g. github, openai, anthropic, slack)"},
			"endpoint": {Type: "string", Description: "API endpoint path (e.g. /repos/owner/repo)"},
			"method":   {Type: "string", Description: "HTTP method (default: GET)"},
			"body":     {Type: "string", Description: "Request body (optional)"},
			"headers":  {Type: "object", Description: "Additional request headers (optional)"},
			"timeout":  {Type: "number", Description: "Timeout in seconds (default: 30)"},
		}),
		Handler:         (*Server).handleExecuteAPIRequest,
		Available:       executeAPIAvailable,
		RiskLevel:       RiskLevelCritical,
		DestructiveHint: true,
	})

	// -- tools_execute_with_secret.go
	RegisterTool(toolDefinition{
		Name:        "execute_with_secret",
		Description: "Execute a command with vault secrets injected as environment variables. The agent never sees the secret values. Requires command execution permission.",
		InputSchema: objectSchema([]string{"command", "secret_refs"}, map[string]schemaProperty{
			"command":     {Type: "array", Description: "\"Command and arguments as an array (e.g. [\"terraform\", \"apply\"])"},
			"secret_refs": {Type: "array", Description: "\"Array of op:// vault references (e.g. [\"op://vault/aws/access_key\"])"},
			"working_dir": {Type: "string", Description: "Working directory for the command"},
			"env_vars":    {Type: "object", Description: "Additional non-secret environment variables"},
			"timeout":     {Type: "number", Description: "Timeout in seconds (default: 30)"},
		}),
		Handler:         (*Server).handleExecuteWithSecret,
		RiskLevel:       RiskLevelHigh,
		DestructiveHint: true,
	})

	// -- tools_find.go
	RegisterTool(toolDefinition{
		Name:        "find_entries",
		Description: "Search entries by query string",
		InputSchema: objectSchema([]string{"query"}, map[string]schemaProperty{
			"query": {Type: "string", Description: "Search query"},
		}),
		Handler:      (*Server).handleFind,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})

	// -- tools_generate.go
	RegisterTool(toolDefinition{
		Name:        "generate_password",
		Description: "Generate a secure password",
		InputSchema: objectSchema(nil, map[string]schemaProperty{
			"length":  {Type: "number", Description: "Password length"},
			"symbols": {Type: "boolean", Description: "Include symbols. Default: true."},
		}),
		Handler:      (*Server).handleGenerate,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})

	// -- tools_get.go
	RegisterTool(toolDefinition{
		Name:        "get_entry",
		Description: "Get metadata for a vault entry. Returns type, usage hints, and field names without secret values. Use get_entry_value to retrieve actual values.",
		InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
			"path":          {Type: "string", Description: "Entry path"},
			"include_value": {Type: "boolean", Description: "When true, returns the full entry with secret values. Default: false."},
		}),
		Handler:      (*Server).handleGet,
		RiskLevel:    RiskLevelMedium,
		ReadOnlyHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "get_entry_value",
		Description: "Get the actual secret values for a vault entry. Use with caution - only request values when absolutely needed.",
		InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
			"path": {Type: "string", Description: "Entry path"},
		}),
		Handler:      (*Server).handleGetValue,
		RiskLevel:    RiskLevelHigh,
		ReadOnlyHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "get_entry_metadata",
		Description: "Get metadata for a vault entry without retrieving sensitive data",
		InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
			"path": {Type: "string", Description: "Entry path"},
		}),
		Handler:      (*Server).handleGetMetadata,
		RiskLevel:    RiskLevelMedium,
		ReadOnlyHint: true,
	})

	// -- tools_health.go
	RegisterTool(toolDefinition{
		Name:         "health",
		Description:  "Return Symaira Vault MCP server health information",
		InputSchema:  objectSchema(nil, map[string]schemaProperty{}),
		Handler:      (*Server).handleHealth,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})

	// -- tools_list.go
	RegisterTool(toolDefinition{
		Name:        "list_entries",
		Description: "List vault entries matching a prefix with metadata",
		InputSchema: objectSchema(nil, map[string]schemaProperty{
			"prefix":          {Type: "string", Description: "Path prefix to filter"},
			"include_details": {Type: "boolean", Description: "When true, returns metadata for each entry. Default: false to avoid expensive decryption on large vaults."},
		}),
		Handler:      (*Server).handleList,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})

	// -- tools_perplexity.go
	RegisterTool(toolDefinition{
		Name:        "perplexity_search",
		Description: "Search the web using Perplexity AI. Returns synthesized search results with citations from the web.",
		InputSchema: objectSchema([]string{"query"}, map[string]schemaProperty{
			"query": {Type: "string", Description: "Natural language search query"},
		}),
		Handler:      (*Server).handlePerplexitySearch,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "perplexity_ask",
		Description: "Ask Perplexity AI a question with optional vault entry context. Returns an AI-generated answer with citations.",
		InputSchema: objectSchema([]string{"question"}, map[string]schemaProperty{
			"question": {Type: "string", Description: "Question to ask Perplexity AI"},
			"context":  {Type: "string", Description: "Optional context from vault entries to include in the question"},
		}),
		Handler:      (*Server).handlePerplexityAsk,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})

	// -- tools_request_credential.go
	RegisterTool(toolDefinition{
		Name: "request_credential",
		Description: "Request the user to securely enter a credential the agent needs " +
			"but cannot find in the vault. Opens a native input dialog (TTY box or " +
			"OS-native popup). The value is stored in the vault and never exposed to " +
			"the agent. Use this after find_entries / get_entry returns nothing for an " +
			"expected path, instead of asking the user for the secret in chat.",
		InputSchema: objectSchema([]string{"path", "field", "reason"}, map[string]schemaProperty{
			"path":   {Type: "string", Description: "Vault path to store the new credential, e.g. \"github/api-token\""},
			"field":  {Type: "string", Description: "Field name, e.g. \"token\", \"password\", \"api_key\""},
			"reason": {Type: "string", Description: "Short human-readable reason shown in the dialog (why does the agent need this?)"},
		}),
		Handler:         (*Server).handleRequestCredential,
		Available:       secureInputToolAvailable,
		RiskLevel:       RiskLevelCritical,
		DestructiveHint: true,
		Capabilities: &ToolCapabilities{
			RequiresTTY:  true,
			RequiresGUI:  true,
			Alternatives: []string{"set_entry_field"},
		},
	})

	// -- tools_run.go
	RegisterTool(toolDefinition{
		Name:        "run_command",
		Description: "Execute a command on the host with secrets injected as environment variables. Requires write permission.",
		InputSchema: objectSchema([]string{"command"}, map[string]schemaProperty{
			"command":     {Type: "array", Description: "\"Command and arguments as an array (e.g. [\"curl\", \"https://api.example.com\"])"},
			"env":         {Type: "object", Description: "\"Map of environment variable names to secret references (e.g. {\"API_KEY\": \"github.api_key\"})"},
			"working_dir": {Type: "string", Description: "Working directory for the command"},
			"timeout":     {Type: "number", Description: "Timeout in seconds (default: 30)"},
		}),
		Handler:         (*Server).handleRunCommand,
		RiskLevel:       RiskLevelHigh,
		DestructiveHint: true,
	})

	// -- tools_sanitize.go
	RegisterTool(toolDefinition{
		Name:        "sanitize_output",
		Description: "Scan text for secrets and replace them with masked values. Use before sending output to LLM chat.",
		InputSchema: objectSchema([]string{"text"}, map[string]schemaProperty{
			"text":              {Type: "string", Description: "Text to scan for secrets"},
			"mask_with_op_refs": {Type: "boolean", Description: "Replace vault-known secrets with op:// references"},
			"mask":              {Type: "string", Description: "Custom mask string (default: ***)"},
		}),
		Handler:      (*Server).handleSanitizeOutput,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})

	// -- tools_search.go
	RegisterTool(toolDefinition{
		Name:        "symaira_search",
		Description: "Discover tools by intent matching. Returns tools whose name or description matches the intent.",
		InputSchema: objectSchema([]string{"intent"}, map[string]schemaProperty{
			"intent": {Type: "string", Description: "Natural language intent or keyword to search for"},
			"return": {Type: "string", Description: "Output format: \"spec\" (full tool specs) or \"names\" (just tool names). Default: \"spec\"."},
		}),
		Handler:      (*Server).handleSearch,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})

	// -- tools_search_openai.go
	RegisterTool(toolDefinition{
		Name:        "search",
		Description: "Search vault entries by query. Returns results with id, title, and url for each matching entry.",
		InputSchema: objectSchema([]string{"query"}, map[string]schemaProperty{
			"query": {Type: "string", Description: "Search query to match against entry paths and field values"},
		}),
		Handler:      (*Server).handleSearchOpenAI,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "fetch",
		Description: "Fetch a vault entry by path/id. Returns the full entry content with metadata and values.",
		InputSchema: objectSchema([]string{"id"}, map[string]schemaProperty{
			"id": {Type: "string", Description: "Entry path or id to fetch (e.g., 'github' or 'work/aws')"},
		}),
		Handler:      (*Server).handleFetchOpenAI,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})

	// -- tools_secure_input.go
	RegisterTool(toolDefinition{
		Name:        "secure_input",
		Description: "Prompt the user for sensitive data via TTY or native GUI dialog and store it without exposing the value to the agent",
		InputSchema: objectSchema([]string{"path", "field"}, map[string]schemaProperty{
			"path":        {Type: "string", Description: "Entry path to store the value"},
			"field":       {Type: "string", Description: "Field name to store the value under"},
			"description": {Type: "string", Description: "Optional description shown to the user in the prompt"},
		}),
		Handler:         (*Server).handleSecureInput,
		Available:       secureInputToolAvailable,
		RiskLevel:       RiskLevelCritical,
		DestructiveHint: true,
		Capabilities: &ToolCapabilities{
			RequiresTTY:  true,
			RequiresGUI:  true,
			Alternatives: []string{"set_entry_field"},
		},
	})

	// -- tools_set.go
	RegisterTool(toolDefinition{
		Name:        "set_entry_field",
		Description: "Set a field on an entry (requires write scope)",
		InputSchema: objectSchema([]string{"path", "field", "value"}, map[string]schemaProperty{
			"path":  {Type: "string", Description: "Entry path"},
			"field": {Type: "string", Description: "Field name"},
			"value": {Type: "string", Description: "Field value"},
			"force": {Type: "boolean", Description: "Skip password strength validation. Default: false."},
		}),
		Handler:         (*Server).handleSet,
		RiskLevel:       RiskLevelCritical,
		DestructiveHint: true,
	})

	// -- tools_sharing.go
	RegisterTool(toolDefinition{
		Name:        "request_share",
		Description: "Request to share a secret with another agent. Creates a pending share grant that requires human approval.",
		InputSchema: objectSchema([]string{"to_agent", "secret_path"}, map[string]schemaProperty{
			"to_agent":     {Type: "string", Description: "Name of the agent to share the secret with"},
			"secret_path":  {Type: "string", Description: "Path to the secret entry (e.g., \"api-keys/stripe\")"},
			"secret_field": {Type: "string", Description: "Specific field to share (optional, shares entire entry if omitted)"},
			"ttl":          {Type: "string", Description: "Time-to-live duration (e.g., \"1h\", \"30m\"). Share expires after this duration."},
		}),
		Handler:         (*Server).handleRequestShare,
		RiskLevel:       RiskLevelMedium,
		DestructiveHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "approve_share",
		Description: "Approve a pending share request. Requires human confirmation.",
		InputSchema: objectSchema([]string{"grant_id"}, map[string]schemaProperty{
			"grant_id": {Type: "string", Description: "ID of the share grant to approve"},
		}),
		Handler:         (*Server).handleApproveShare,
		RiskLevel:       RiskLevelHigh,
		DestructiveHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "revoke_share",
		Description: "Revoke an active share grant, immediately removing access.",
		InputSchema: objectSchema([]string{"grant_id"}, map[string]schemaProperty{
			"grant_id": {Type: "string", Description: "ID of the share grant to revoke"},
		}),
		Handler:         (*Server).handleRevokeShare,
		RiskLevel:       RiskLevelHigh,
		DestructiveHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "list_shares",
		Description: "List share grants. Can filter by status, agent, or secret path.",
		InputSchema: objectSchema([]string{}, map[string]schemaProperty{
			"status":      {Type: "string", Description: "Filter by status: pending, approved, revoked, expired, rejected"},
			"from_agent":  {Type: "string", Description: "Filter by source agent name"},
			"to_agent":    {Type: "string", Description: "Filter by target agent name"},
			"secret_path": {Type: "string", Description: "Filter by secret path"},
		}),
		Handler:      (*Server).handleListShares,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})

	// -- tools_template.go
	RegisterTool(toolDefinition{
		Name:        "generate_template",
		Description: "Generate a configuration file from a template",
		InputSchema: objectSchema([]string{"template_type"}, map[string]schemaProperty{
			"template_type": {Type: "string", Description: "Template type (env, docker-compose, k8s-secret, github-actions, terraform)"},
			"name":          {Type: "string", Description: "Name of the resource being generated. Default: app"},
			"output_path":   {Type: "string", Description: "Output file path (optional)"},
			"secret_refs":   {Type: "object", Description: "Map of template variable names to vault references"},
			"dry_run":       {Type: "boolean", Description: "Show template with masked values. Default: false"},
		}),
		Handler:      (*Server).handleGenerateTemplate,
		RiskLevel:    RiskLevelMedium,
		ReadOnlyHint: true,
	})

	// -- tools_totp.go
	RegisterTool(toolDefinition{
		Name:        "generate_totp",
		Description: "Generate a TOTP code for an entry with TOTP configuration. By default the code is copied to the clipboard without being returned in the response. Use destination=\"autotype\" to type the code directly, or destination=\"return\" with return_code=true to return the code in the response (requires approval).",
		InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
			"path":        {Type: "string", Description: "Entry path with TOTP configuration"},
			"destination": {Type: "string", Description: "Where to send the code: \"clipboard\" (default, not returned), \"autotype\" (type directly), \"return\" (return in response, requires approval)"},
			"return_code": {Type: "boolean", Description: "Must be true when destination=\"return\""},
		}),
		Handler:      (*Server).handleGenerateTOTP,
		Available:    generateTOTPAvailable,
		RiskLevel:    RiskLevelHigh,
		ReadOnlyHint: true,
	})

	// -- tools_unseal.go
	RegisterTool(toolDefinition{
		Name:        "secret_unseal",
		Description: "Unseal a secret handle to reveal its value. High-sensitivity entries return handles (op://path/field) instead of plaintext. This tool resolves those handles. Requires user approval per handle.",
		InputSchema: objectSchema([]string{"handle"}, map[string]schemaProperty{
			"handle": {Type: "string", Description: "Secret handle to unseal (e.g. op://github/password)"},
		}),
		Handler:      (*Server).handleSecretUnseal,
		RiskLevel:    RiskLevelHigh,
		ReadOnlyHint: true,
	})

	// -- tools_whoami.go
	RegisterTool(toolDefinition{
		Name:         "symaira_whoami",
		Description:  "Return the agent profile, available/unavailable tools, quotas, and vault status",
		InputSchema:  objectSchema(nil, map[string]schemaProperty{}),
		Handler:      (*Server).handleWhoami,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})
}

// RegisterTool adds a tool definition to the global registry. Duplicate names
// or exceeding the MaxToolDefinitions cap cause a panic at registration time.
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

// authorizeTool performs a single-pass authorization check that evaluates
// agent tier, token scope, and special flags. Returns nil when the tool is
// allowed, or an *errors.MCPError describing the denial reason.
func authorizeTool(agent *config.AgentProfile, token *auth.ScopedToken, toolName string) *errors.MCPError {
	if err := isToolBlockedByAgent(agent, toolName); err != nil {
		return err
	}
	if !isToolAllowed(token, toolName) {
		return errors.ToolNotAllowed(toolName, "token_scope", "")
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
			"prepare_payment":     true,
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
		if def.ReadOnlyHint {
			payload["readOnlyHint"] = true
		}
		if def.DestructiveHint {
			payload["destructiveHint"] = true
		}
		if def.Capabilities != nil {
			payload["capabilities"] = def.Capabilities
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
	payload := map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": sanitized,
			},
		},
		"isError": result.IsError,
	}
	if result.StructuredContent != nil {
		payload["structuredContent"] = result.StructuredContent
	}
	return payload
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
			Name:            d.Name,
			Description:     d.Description,
			InputSchema:     d.InputSchema,
			ReadOnlyHint:    d.ReadOnlyHint,
			DestructiveHint: d.DestructiveHint,
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
