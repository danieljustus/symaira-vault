package server

import (
	"context"
	"encoding/json"
	"fmt"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func (s *Server) handleList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	prefix, err := req.RequireString("prefix")
	if err != nil {
		prefix = ""
	}

	if !s.checkScope(prefix) {
		s.logAudit(ctx, "list", prefix, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", prefix)
	}

	_, span := metrics.StartSpan(ctx, "vault.List")
	paths, err := s.vaultService.ListEntries(prefix)
	span.End()
	if err != nil {
		s.logAudit(ctx, "list", prefix, false)
		metrics.RecordVaultOperation("list", "error")
		return vaultServiceErrorResult(err)
	}

	s.logAudit(ctx, "list", prefix, true)
	metrics.RecordVaultOperation("list", "success")

	includeDetails := req.GetBool("include_details", false)

	if !includeDetails {
		result, marshalErr := json.Marshal(paths)
		if marshalErr != nil {
			return nil, marshalErr
		}
		return mcp.NewToolResultText(string(result)), nil
	}

	summaries := make([]vaultpkg.ListEntryInfo, 0, len(paths))
	for _, path := range paths {
		entry, getErr := s.vaultService.GetEntry(path)
		if getErr != nil {
			continue
		}

		summary := vaultpkg.ListEntryInfo{
			Path:       globalChokepoint.SanitizeForMCP(path),
			Type:       string(entry.SecretMetadata.Type),
			UsageHint:  globalChokepoint.SanitizeForMCP(entry.SecretMetadata.UsageHint),
			AutoRotate: entry.SecretMetadata.AutoRotate,
			HasValue:   len(entry.Data) > 0,
			FieldCount: len(entry.Data),
		}
		summaries = append(summaries, summary)
	}

	result, err := json.Marshal(summaries)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(result)), nil
}

func init() {
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
}
