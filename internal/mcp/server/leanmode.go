package server

import (
	"encoding/json"

	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
)

// LeanToolSet is the default lean mode set. When a client does not
// request all tools (include_all_tools: true), only tools in this set are
// returned in tools/list responses. This set includes the most commonly needed
// tools for agent workflows while keeping the prompt surface small.
var LeanToolSet = []string{
	"symaira_whoami",
	"symaira_search",
	"health",
	"find_entries",
	"get_entry",
	"get_entry_metadata",
	"request_credential",
	"set_entry_field",
	"generate_password",
	"symaira_audit_self",
}

func filterLeanTools(tools []map[string]any) []map[string]any {
	leanSet := make(map[string]bool, len(LeanToolSet))
	for _, t := range LeanToolSet {
		leanSet[t] = true
	}
	filtered := make([]map[string]any, 0, len(tools))
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if leanSet[name] {
			filtered = append(filtered, tool)
		}
	}
	return filtered
}

func includeAllTools(msg *transport.Message) bool {
	if msg == nil || msg.Params == nil {
		return false
	}
	var params map[string]any
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return false
	}
	all, _ := params["include_all_tools"].(bool)
	return all
}
