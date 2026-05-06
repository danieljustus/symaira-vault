package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

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

	svc := vaultsvc.New(s.vault)
	_, span := metrics.StartSpan(ctx, "vault.List")
	entries, err := svc.List(prefix)
	span.End()
	if err != nil {
		s.logAudit(ctx, "list", prefix, false)
		metrics.RecordVaultOperation("list", "error")
		return vaultServiceErrorResult(err)
	}

	s.logAudit(ctx, "list", prefix, true)
	metrics.RecordVaultOperation("list", "success")
	result, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(result)), nil
}
