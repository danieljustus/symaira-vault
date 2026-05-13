package mcp

import (
	"context"
	"encoding/json"
)

type toolHandler func(*Server, context.Context, CallToolRequest) (*CallToolResult, error)
type toolAvailable func(*Server) bool

type toolDefinition struct {
	Name        string
	Description string
	InputSchema map[string]any
	Handler     toolHandler
	Available   toolAvailable
	Deprecated  bool
	AliasFor    string
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

func toolDefinitions() []toolDefinition {
	return []toolDefinition{
		{
			Name:        "list_entries",
			Description: "List vault entries matching a prefix with metadata",
			InputSchema: objectSchema(nil, map[string]schemaProperty{
				"prefix":          {Type: "string", Description: "Path prefix to filter"},
				"include_details": {Type: "boolean", Description: "When true, returns metadata for each entry. Default: true."},
			}),
			Handler: (*Server).handleList,
		},
		{
			Name:        "get_entry",
			Description: "Get metadata for a vault entry. Returns type, usage hints, and field names without secret values. Use get_entry_value to retrieve actual values.",
			InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
				"path":          {Type: "string", Description: "Entry path"},
				"include_value": {Type: "boolean", Description: "When true, returns the full entry with secret values. Default: false."},
			}),
			Handler: (*Server).handleGet,
		},
		{
			Name:        "get_entry_value",
			Description: "Get the actual secret values for a vault entry. Use with caution - only request values when absolutely needed.",
			InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
				"path": {Type: "string", Description: "Entry path"},
			}),
			Handler: (*Server).handleGetValue,
		},
		{
			Name:        "get_entry_metadata",
			Description: "Get metadata for a vault entry without retrieving sensitive data",
			InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
				"path": {Type: "string", Description: "Entry path"},
			}),
			Handler: (*Server).handleGetMetadata,
		},
		{
			Name:        "find_entries",
			Description: "Search entries by query string",
			InputSchema: objectSchema([]string{"query"}, map[string]schemaProperty{
				"query": {Type: "string", Description: "Search query"},
			}),
			Handler: (*Server).handleFind,
		},
		{
			Name:        "set_entry_field",
			Description: "Set a field on an entry (requires write scope)",
			InputSchema: objectSchema([]string{"path", "field", "value"}, map[string]schemaProperty{
				"path":  {Type: "string", Description: "Entry path"},
				"field": {Type: "string", Description: "Field name"},
				"value": {Type: "string", Description: "Field value"},
				"force": {Type: "boolean", Description: "Skip password strength validation. Default: false."},
			}),
			Handler: (*Server).handleSet,
		},
		{
			Name:        "run_command",
			Description: "Execute a command on the host with secrets injected as environment variables. Requires write permission.",
			InputSchema: objectSchema([]string{"command"}, map[string]schemaProperty{
				"command":     {Type: "array", Description: "Command and arguments as an array (e.g. [\"curl\", \"https://api.example.com\"])"},
				"env":         {Type: "object", Description: "Map of environment variable names to secret references (e.g. {\"API_KEY\": \"github.api_key\"})"},
				"working_dir": {Type: "string", Description: "Working directory for the command"},
				"timeout":     {Type: "number", Description: "Timeout in seconds (default: 30)"},
			}),
			Handler: (*Server).handleRunCommand,
		},
		{
			Name:        "execute_with_secret",
			Description: "Execute a command with vault secrets injected as environment variables. The agent never sees the secret values. Requires command execution permission.",
			InputSchema: objectSchema([]string{"command", "secret_refs"}, map[string]schemaProperty{
				"command":     {Type: "array", Description: "Command and arguments as an array (e.g. [\"terraform\", \"apply\"])"},
				"secret_refs": {Type: "array", Description: "Array of op:// vault references (e.g. [\"op://vault/aws/access_key\"])"},
				"working_dir": {Type: "string", Description: "Working directory for the command"},
				"env_vars":    {Type: "object", Description: "Additional non-secret environment variables"},
				"timeout":     {Type: "number", Description: "Timeout in seconds (default: 30)"},
			}),
			Handler: (*Server).handleExecuteWithSecret,
		},
		{
			Name:        "sanitize_output",
			Description: "Scan text for secrets and replace them with masked values. Use before sending output to LLM chat.",
			InputSchema: objectSchema([]string{"text"}, map[string]schemaProperty{
				"text":              {Type: "string", Description: "Text to scan for secrets"},
				"mask_with_op_refs": {Type: "boolean", Description: "Replace vault-known secrets with op:// references"},
				"mask":              {Type: "string", Description: "Custom mask string (default: ***)"},
			}),
			Handler: (*Server).handleSanitizeOutput,
		},
		{
			Name:        "generate_password",
			Description: "Generate a secure password",
			InputSchema: objectSchema(nil, map[string]schemaProperty{
				"length":  {Type: "number", Description: "Password length"},
				"symbols": {Type: "boolean", Description: "Include symbols. Default: true."},
			}),
			Handler: (*Server).handleGenerate,
		},
		{
			Name:        "generate_template",
			Description: "Generate a configuration file from a template",
			InputSchema: objectSchema([]string{"template_type"}, map[string]schemaProperty{
				"template_type": {Type: "string", Description: "Template type (env, docker-compose, k8s-secret, github-actions, terraform)"},
				"name":          {Type: "string", Description: "Name of the resource being generated. Default: app"},
				"output_path":   {Type: "string", Description: "Output file path (optional)"},
				"secret_refs":   {Type: "object", Description: "Map of template variable names to vault references"},
				"dry_run":       {Type: "boolean", Description: "Show template with masked values. Default: false"},
			}),
			Handler: (*Server).handleGenerateTemplate,
		},
		{
			Name:        "delete_entry",
			Description: "Delete a password entry by path",
			InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
				"path": {Type: "string", Description: "Entry path to delete"},
			}),
			Handler: (*Server).handleDelete,
		},
		{
			Name:        "openpass_delete",
			Description: "Deprecated alias for delete_entry. Use delete_entry for new clients.",
			InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
				"path": {Type: "string", Description: "Entry path to delete"},
			}),
			Handler:    (*Server).handleDelete,
			Deprecated: true,
			AliasFor:   "delete_entry",
		},
		{
			Name:        "generate_totp",
			Description: "Generate a TOTP code for an entry with TOTP configuration",
			InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
				"path": {Type: "string", Description: "Entry path with TOTP configuration"},
			}),
			Handler: (*Server).handleGenerateTOTP,
		},
		{
			Name:        "health",
			Description: "Return OpenPass MCP server health information",
			InputSchema: objectSchema(nil, map[string]schemaProperty{}),
			Handler:     (*Server).handleHealth,
		},
		{
			Name:        "get_auth_status",
			Description: "Return OpenPass unlock authentication status",
			InputSchema: objectSchema(nil, map[string]schemaProperty{}),
			Handler:     (*Server).handleGetAuthStatus,
		},
		{
			Name:        "set_auth_method",
			Description: "Set OpenPass unlock authentication method (requires canManageConfig)",
			InputSchema: objectSchema([]string{"method"}, map[string]schemaProperty{
				"method": {Type: "string", Description: "Authentication method: passphrase or touchid"},
			}),
			Handler: (*Server).handleSetAuthMethod,
		},
		{
			Name:        "copy_to_clipboard",
			Description: "Copy a vault entry's password field to the system clipboard without exposing the value to the agent",
			InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
				"path": {Type: "string", Description: "Entry path"},
			}),
			Handler: (*Server).handleCopyToClipboard,
		},
		{
			Name:        "autotype",
			Description: "Type a vault entry's field value as keyboard input into the currently focused application without exposing the value to the agent",
			InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
				"path":  {Type: "string", Description: "Entry path"},
				"field": {Type: "string", Description: "Field name to type (default: password)"},
			}),
			Handler: (*Server).handleAutotype,
		},
		{
			Name:        "secure_input",
			Description: "Prompt the user for sensitive data via TTY or native GUI dialog and store it without exposing the value to the agent",
			InputSchema: objectSchema([]string{"path", "field"}, map[string]schemaProperty{
				"path":        {Type: "string", Description: "Entry path to store the value"},
				"field":       {Type: "string", Description: "Field name to store the value under"},
				"description": {Type: "string", Description: "Optional description shown to the user in the prompt"},
			}),
			Handler:   (*Server).handleSecureInput,
			Available: secureInputToolAvailable,
		},
		{
			Name: "request_credential",
			Description: "Request the user to securely enter a credential the agent needs " +
				"but cannot find in the vault. Opens a native input dialog (TTY box or " +
				"OS-native popup). The value is stored in the vault and never exposed to " +
				"the agent. Use this after find_entries / get_entry returns nothing for an " +
				"expected path, instead of asking the user for the secret in chat.",
			InputSchema: objectSchema([]string{"path", "field", "reason"}, map[string]schemaProperty{
				"path":   {Type: "string", Description: "Vault path to store the new credential, e.g. 'github/api-token'"},
				"field":  {Type: "string", Description: "Field name, e.g. 'token', 'password', 'api_key'"},
				"reason": {Type: "string", Description: "Short human-readable reason shown in the dialog (why does the agent need this?)"},
			}),
			Handler:   (*Server).handleRequestCredential,
			Available: secureInputToolAvailable,
		},
		{
			Name:        "request_share",
			Description: "Request to share a secret with another agent. Creates a pending share grant that requires human approval.",
			InputSchema: objectSchema([]string{"to_agent", "secret_path"}, map[string]schemaProperty{
				"to_agent":     {Type: "string", Description: "Name of the agent to share the secret with"},
				"secret_path":  {Type: "string", Description: "Path to the secret entry (e.g., 'api-keys/stripe')"},
				"secret_field": {Type: "string", Description: "Specific field to share (optional, shares entire entry if omitted)"},
				"ttl":          {Type: "string", Description: "Time-to-live duration (e.g., '1h', '30m'). Share expires after this duration."},
			}),
			Handler: (*Server).handleRequestShare,
		},
		{
			Name:        "approve_share",
			Description: "Approve a pending share request. Requires human confirmation.",
			InputSchema: objectSchema([]string{"grant_id"}, map[string]schemaProperty{
				"grant_id": {Type: "string", Description: "ID of the share grant to approve"},
			}),
			Handler: (*Server).handleApproveShare,
		},
		{
			Name:        "revoke_share",
			Description: "Revoke an active share grant, immediately removing access.",
			InputSchema: objectSchema([]string{"grant_id"}, map[string]schemaProperty{
				"grant_id": {Type: "string", Description: "ID of the share grant to revoke"},
			}),
			Handler: (*Server).handleRevokeShare,
		},
		{
			Name:        "list_shares",
			Description: "List share grants. Can filter by status, agent, or secret path.",
			InputSchema: objectSchema([]string{}, map[string]schemaProperty{
				"status":      {Type: "string", Description: "Filter by status: pending, approved, revoked, expired, rejected"},
				"from_agent":  {Type: "string", Description: "Filter by source agent name"},
				"to_agent":    {Type: "string", Description: "Filter by target agent name"},
				"secret_path": {Type: "string", Description: "Filter by secret path"},
			}),
			Handler: (*Server).handleListShares,
		},
	}
}

func availableToolDefinitions(s *Server) []toolDefinition {
	definitions := toolDefinitions()
	available := make([]toolDefinition, 0, len(definitions))
	for _, def := range definitions {
		if def.Available != nil && !def.Available(s) {
			continue
		}
		available = append(available, def)
	}
	return available
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
		payload := map[string]any{
			"name":        def.Name,
			"description": def.Description,
			"inputSchema": def.InputSchema,
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

func callToolResultPayload(result *CallToolResult) map[string]any {
	if result == nil {
		result = NewToolResultText("")
	}
	return map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": result.Text,
			},
		},
		"isError": result.IsError,
	}
}

func decodeToolRequest(args json.RawMessage) (CallToolRequest, error) {
	req := CallToolRequest{Arguments: map[string]any{}}
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
func isToolAllowed(token *ScopedToken, toolName string) bool {
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
