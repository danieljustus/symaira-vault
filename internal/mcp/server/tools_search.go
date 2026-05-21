package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	mcp "github.com/danieljustus/OpenPass/internal/mcp"
)

type searchResultSpec struct {
	Name           string         `json:"name"`
	Description    string         `json:"description"`
	InputSchema    map[string]any `json:"input_schema,omitempty"`
	RiskLevel      string         `json:"risk_level"`
	CLIAlternative string         `json:"cli_alternative,omitempty"`
	TierRequired   string         `json:"tier_required,omitempty"`
}

var cliAlternatives = map[string]string{
	"list_entries":       "openpass list [prefix]",
	"get_entry":          "openpass get <path>",
	"get_entry_value":    "openpass get <path>",
	"get_entry_metadata": "openpass get <path>",
	"find_entries":       "openpass find <query>",
	"set_entry_field":    "openpass set <path>.<field> --value <value>",
	"delete_entry":       "openpass delete <path>",
	"generate_password":  "openpass generate --length N --symbols",
	"generate_totp":      "openpass get <path> --totp",
	"copy_to_clipboard":  "openpass get <path>.password --clip",
	"autotype":           "openpass get <path>.password --autotype",
	"health":             "openpass serve --stdio (health is automatic)",
	"run_command":        "openpass run --env KEY=path.field -- <command>",
}

func riskLevelTier(level RiskLevel) string {
	switch level {
	case RiskLevelLow:
		return "any"
	case RiskLevelMedium:
		return "standard"
	case RiskLevelHigh:
		return "admin"
	case RiskLevelCritical:
		return "admin"
	default:
		return "any"
	}
}

func (s *Server) handleSearch(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_ = ctx

	intent, err := req.RequireString("intent")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("missing required argument: %s", err.Error())), nil
	}

	returnMode := req.GetString("return", "spec")
	if returnMode != "spec" && returnMode != "names" {
		returnMode = "spec"
	}

	intentLower := strings.ToLower(intent)

	var matched []toolDefinition
	for _, def := range toolDefinitions() {
		if def.Deprecated {
			continue
		}
		nameLower := strings.ToLower(def.Name)
		descLower := strings.ToLower(def.Description)
		if strings.Contains(nameLower, intentLower) || strings.Contains(descLower, intentLower) {
			matched = append(matched, def)
		}
	}

	if returnMode == "names" {
		names := make([]string, 0, len(matched))
		for _, def := range matched {
			names = append(names, def.Name)
		}
		resultJSON, marshalErr := json.Marshal(names)
		if marshalErr != nil {
			return nil, marshalErr
		}
		return mcp.NewToolResultText(string(resultJSON)), nil
	}

	results := make([]searchResultSpec, 0, len(matched))
	for _, def := range matched {
		r := searchResultSpec{
			Name:           def.Name,
			Description:    def.Description,
			InputSchema:    def.InputSchema,
			RiskLevel:      riskLevelName(def.RiskLevel),
			CLIAlternative: cliAlternatives[def.Name],
			TierRequired:   riskLevelTier(def.RiskLevel),
		}
		results = append(results, r)
	}

	resultJSON, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(resultJSON)), nil
}

func riskLevelName(level RiskLevel) string {
	switch level {
	case RiskLevelLow:
		return "low"
	case RiskLevelMedium:
		return "medium"
	case RiskLevelHigh:
		return "high"
	case RiskLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}
