package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

type listEntrySummary struct {
	Path       string `json:"path"`
	Type       string `json:"type,omitempty"`
	UsageHint  string `json:"usage_hint,omitempty"`
	AutoRotate bool   `json:"auto_rotate,omitempty"`
	HasValue   bool   `json:"has_value,omitempty"`
	FieldCount int    `json:"field_count,omitempty"`
}

func (s *Server) handleList(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	prefix, err := req.RequireString("prefix")
	if err != nil {
		prefix = ""
	}

	if !s.checkScope(prefix) {
		s.logAudit(ctx, "list", prefix, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", prefix)
	}

	svc := vaultsvc.New(slog.Default(), s.vault)
	_, span := metrics.StartSpan(ctx, "vault.List")
	paths, err := svc.List(prefix)
	span.End()
	if err != nil {
		s.logAudit(ctx, "list", prefix, false)
		metrics.RecordVaultOperation("list", "error")
		return vaultServiceErrorResult(err)
	}

	s.logAudit(ctx, "list", prefix, true)
	metrics.RecordVaultOperation("list", "success")

	includeDetails := req.GetBool("include_details", true)

	if !includeDetails {
		result, marshalErr := json.Marshal(paths)
		if marshalErr != nil {
			return nil, marshalErr
		}
		return NewToolResultText(string(result)), nil
	}

	summaries := make([]listEntrySummary, 0, len(paths))
	for _, path := range paths {
		entry, getErr := svc.GetEntry(path)
		if getErr != nil {
			continue
		}

		summary := listEntrySummary{
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
	return NewToolResultText(string(result)), nil
}
