package server

import (
	"strings"
)

// promptArgument describes one parameter that an MCP client may pass when
// invoking a prompt via prompts/get.
type promptArgument struct {
	Name        string
	Description string
	Required    bool
}

// promptMessage is one entry in the rendered prompt body. The MCP spec models
// content as typed blocks; OpenPass prompts use only text content.
type promptMessage struct {
	Role string // "user" | "assistant"
	Text string
}

// promptDefinition registers a single MCP prompt. Builder receives the
// caller's argument map (already string-coerced) and returns the rendered
// messages.
type promptDefinition struct {
	Name        string
	Description string
	Arguments   []promptArgument
	Builder     func(args map[string]string) []promptMessage
}

// promptDefinitions returns the static list of MCP prompts the server exposes.
// In Claude Code these surface as slash commands like /mcp__openpass__add-credential.
func promptDefinitions() []promptDefinition {
	return []promptDefinition{
		{
			Name: "add-credential",
			Description: "Guided workflow to add a new credential to the OpenPass vault. " +
				"Sensitive fields are collected via secure dialog so the agent never sees the value.",
			Arguments: []promptArgument{
				{Name: "service_name", Description: "Friendly name of the service, e.g. 'GitHub' or 'AWS prod'"},
				{Name: "path", Description: "Vault entry path. If omitted, derive a slug from service_name."},
			},
			Builder: buildAddCredentialPrompt,
		},
		{
			Name: "rotate-credential",
			Description: "Rotate the password/token on an existing OpenPass entry by generating a new value, " +
				"storing it, and reminding the user to update it server-side.",
			Arguments: []promptArgument{
				{Name: "path", Description: "Vault entry path to rotate", Required: true},
				{Name: "length", Description: "New password length (default 32)"},
			},
			Builder: buildRotateCredentialPrompt,
		},
		{
			Name: "find-and-use",
			Description: "Find an OpenPass entry by query and suggest the right consumption tool " +
				"(copy_to_clipboard, autotype, execute_with_secret) based on the user's stated task.",
			Arguments: []promptArgument{
				{Name: "query", Description: "Search query", Required: true},
				{Name: "task", Description: "What the user wants to do with the credential (login / curl / terraform / ...)"},
			},
			Builder: buildFindAndUsePrompt,
		},
		{
			Name:        "share-credential",
			Description: "Create a share grant for another agent and explain the human-approval flow.",
			Arguments: []promptArgument{
				{Name: "path", Description: "Vault entry path to share", Required: true},
				{Name: "to_agent", Description: "Name of the receiving agent profile", Required: true},
				{Name: "ttl", Description: "Time-to-live for the grant, default '1h'"},
				{Name: "secret_field", Description: "Optional single field to share instead of the whole entry"},
			},
			Builder: buildShareCredentialPrompt,
		},
	}
}

func findPromptDefinition(name string) (promptDefinition, bool) {
	for _, def := range promptDefinitions() {
		if def.Name == name {
			return def, true
		}
	}
	return promptDefinition{}, false
}

func promptsListPayload() []map[string]any {
	defs := promptDefinitions()
	out := make([]map[string]any, 0, len(defs))
	for _, def := range defs {
		args := make([]map[string]any, 0, len(def.Arguments))
		for _, a := range def.Arguments {
			args = append(args, map[string]any{
				"name":        a.Name,
				"description": a.Description,
				"required":    a.Required,
			})
		}
		out = append(out, map[string]any{
			"name":        def.Name,
			"description": def.Description,
			"arguments":   args,
		})
	}
	return out
}

func promptGetPayload(def promptDefinition, args map[string]string) map[string]any {
	messages := def.Builder(args)
	rendered := make([]map[string]any, 0, len(messages))
	for _, m := range messages {
		rendered = append(rendered, map[string]any{
			"role": m.Role,
			"content": map[string]any{
				"type": "text",
				"text": m.Text,
			},
		})
	}
	return map[string]any{
		"description": def.Description,
		"messages":    rendered,
	}
}

// slugify produces a vault-friendly path segment from a free-text service name.
func slugify(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	var sb strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			sb.WriteRune(r)
			prevDash = false
		case r == '-' || r == '/' || r == '.':
			if !prevDash && sb.Len() > 0 {
				sb.WriteRune('-')
				prevDash = true
			}
		default:
			if !prevDash && sb.Len() > 0 {
				sb.WriteRune('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(sb.String(), "-")
}

func argOr(args map[string]string, key, def string) string {
	if v, ok := args[key]; ok && v != "" {
		return v
	}
	return def
}

// --- prompt builders ----------------------------------------------------

func buildAddCredentialPrompt(args map[string]string) []promptMessage {
	service := argOr(args, "service_name", "")
	suggested := argOr(args, "path", slugify(service))
	if suggested == "" {
		suggested = "<choose-a-path>"
	}
	var sb strings.Builder
	sb.WriteString("Add a new credential to the OpenPass vault.\n\n")
	if service != "" {
		sb.WriteString("Service: ")
		sb.WriteString(EmbedAsData("service_name", service))
		sb.WriteString(" (data)\n")
	}
	sb.WriteString("Suggested vault path: ")
	sb.WriteString(EmbedAsData("vault_path", suggested))
	sb.WriteString(" (data)\n\n")
	sb.WriteString("Workflow:\n")
	sb.WriteString("1. Confirm the entry path with me (suggested above).\n")
	sb.WriteString("2. For every sensitive field (password / token / api_key / secret / private_key):\n")
	sb.WriteString("   - Call the `request_credential` MCP tool with path, field name, and a one-line reason.\n")
	sb.WriteString("   - The user enters the value securely; you never see it.\n")
	sb.WriteString("3. For non-sensitive fields (username, url, notes), ask me directly and store them with `set_entry_field`.\n")
	sb.WriteString("4. Confirm the entry exists with `get_entry_metadata`.\n\n")
	sb.WriteString("Important: do NOT call `set_entry_field` for sensitive fields — always use `request_credential` so the value never enters the chat transcript.")
	return []promptMessage{{Role: "user", Text: sb.String()}}
}

func buildRotateCredentialPrompt(args map[string]string) []promptMessage {
	path := argOr(args, "path", "<path>")
	length := argOr(args, "length", "32")
	var sb strings.Builder
	sb.WriteString("Rotate the credential at OpenPass path ")
	sb.WriteString(EmbedAsData("vault_path", path))
	sb.WriteString(" (data).\n\n")
	sb.WriteString("Workflow:\n")
	sb.WriteString("1. Call `get_entry_metadata` for ")
	sb.WriteString(EmbedAsData("vault_path", path))
	sb.WriteString(" (data) to confirm it exists and note the current version.\n")
	sb.WriteString("2. Call `generate_password` with length=")
	sb.WriteString(EmbedAsData("length", length))
	sb.WriteString(" (data) (and symbols=true unless the target service rejects symbols).\n")
	sb.WriteString("3. Call `set_entry_field` to store the new password at ")
	sb.WriteString(EmbedAsData("vault_path", path))
	sb.WriteString(" (data).password.\n")
	sb.WriteString("4. Tell me which remote service needs the password updated and offer to help (e.g. open the service's password-change URL, prepare an `execute_with_secret` command if there is an API).\n")
	sb.WriteString("5. Do NOT print the new password in chat. Reference it as <path>.password from now on.")
	return []promptMessage{{Role: "user", Text: sb.String()}}
}

func buildFindAndUsePrompt(args map[string]string) []promptMessage {
	query := argOr(args, "query", "")
	task := argOr(args, "task", "")
	var sb strings.Builder
	sb.WriteString("Find an OpenPass credential and use it without printing the secret.\n\n")
	if query != "" {
		sb.WriteString("Search query: ")
		sb.WriteString(EmbedAsData("search_query", query))
		sb.WriteString(" (data)\n")
	}
	if task != "" {
		sb.WriteString("Intended task: ")
		sb.WriteString(EmbedAsData("task", task))
		sb.WriteString(" (data)\n")
	}
	sb.WriteString("\nWorkflow:\n")
	sb.WriteString("1. Call `find_entries` with query=")
	sb.WriteString(EmbedAsData("search_query", query))
	sb.WriteString(" (data).\n")
	sb.WriteString("2. If zero matches: suggest creating the entry with `/openpass:add-credential` or call `request_credential` directly.\n")
	sb.WriteString("3. If one match: pick the right consumption tool based on the task:\n")
	sb.WriteString("   - Web login / GUI app → `autotype` or `copy_to_clipboard`.\n")
	sb.WriteString("   - Shell/API call → `execute_with_secret` with the appropriate `secret_refs`.\n")
	sb.WriteString("4. If multiple matches: list the candidates and ask me which to use.\n")
	sb.WriteString("5. Never print the credential value itself.")
	return []promptMessage{{Role: "user", Text: sb.String()}}
}

func buildShareCredentialPrompt(args map[string]string) []promptMessage {
	path := argOr(args, "path", "<path>")
	toAgent := argOr(args, "to_agent", "<agent>")
	ttl := argOr(args, "ttl", "1h")
	field := argOr(args, "secret_field", "")
	var sb strings.Builder
	sb.WriteString("Share OpenPass credential ")
	sb.WriteString(EmbedAsData("vault_path", path))
	sb.WriteString(" (data) with agent ")
	sb.WriteString(EmbedAsData("target_agent", toAgent))
	sb.WriteString(" (data).\n\n")
	sb.WriteString("Workflow:\n")
	if field != "" {
		sb.WriteString("1. Call `request_share` with to_agent=")
		sb.WriteString(EmbedAsData("target_agent", toAgent))
		sb.WriteString(" (data), secret_path=")
		sb.WriteString(EmbedAsData("vault_path", path))
		sb.WriteString(" (data), secret_field=")
		sb.WriteString(EmbedAsData("field_name", field))
		sb.WriteString(" (data), ttl=")
		sb.WriteString(EmbedAsData("ttl", ttl))
		sb.WriteString(" (data).\n")
	} else {
		sb.WriteString("1. Call `request_share` with to_agent=")
		sb.WriteString(EmbedAsData("target_agent", toAgent))
		sb.WriteString(" (data), secret_path=")
		sb.WriteString(EmbedAsData("vault_path", path))
		sb.WriteString(" (data), ttl=")
		sb.WriteString(EmbedAsData("ttl", ttl))
		sb.WriteString(" (data).\n")
	}
	sb.WriteString("2. Show the returned grant_id and remind me that the share is PENDING until a human approves it.\n")
	sb.WriteString("3. Tell me to run `approve_share` with the grant_id when ready (this can also be triggered from another agent session — the approval is per-grant, not per-agent).\n")
	sb.WriteString("4. After approval, the receiving agent can read the credential for the TTL window.\n")
	sb.WriteString("5. Use `revoke_share` to cut access early if needed.")
	return []promptMessage{{Role: "user", Text: sb.String()}}
}
