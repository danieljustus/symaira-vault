package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vault"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

func vaultServiceErrorResult(err error) (*CallToolResult, error) {
	var cliErr *errorspkg.CLIError
	if errors.As(err, &cliErr) {
		if cliErr.Kind == errorspkg.ErrNotFound || cliErr.Kind == errorspkg.ErrFieldNotFound {
			return NewToolResultError(cliErr.Message), nil
		}
		return nil, fmt.Errorf("vault operation failed: %w", err)
	}
	return nil, err
}

func buildSecretMetadataResponse(entry *vault.Entry, path string) map[string]any {
	fields := make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		fields = append(fields, k)
	}

	response := map[string]any{
		"path":         path,
		"type":         entry.SecretMetadata.Type,
		"usage_hint":   entry.SecretMetadata.UsageHint,
		"auto_rotate":  entry.SecretMetadata.AutoRotate,
		"fields":       fields,
		"has_value":    len(entry.Data) > 0,
		"meta": map[string]any{
			"created": entry.Metadata.Created.Format(time.RFC3339),
			"updated": entry.Metadata.Updated.Format(time.RFC3339),
			"version": entry.Metadata.Version,
		},
	}

	if entry.SecretMetadata.ExpiresAt != nil {
		response["expires_at"] = entry.SecretMetadata.ExpiresAt.Format(time.RFC3339)
	}

	return response
}

func (s *Server) handleGet(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		s.logAudit(ctx, "get", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}

	if !s.checkScope(path) {
		s.logAudit(ctx, "get", path, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	svc := vaultsvc.New(slog.Default(), s.vault)
	_, span := metrics.StartSpan(ctx, "vault.GetEntry")
	entry, err := svc.GetEntry(path)
	span.End()
	if err != nil {
		s.logAudit(ctx, "get", path, false)
		metrics.RecordVaultOperation("read", "error")
		return vaultServiceErrorResult(err)
	}

	s.logAudit(ctx, "get", path, true)
	metrics.RecordVaultOperation("read", "success")

	includeValue := req.GetBool("include_value", false)

	if includeValue {
		if s.agent != nil && s.agent.RedactFields != nil && len(s.agent.RedactFields) > 0 {
			entry = redactEntry(entry, s.agent.RedactFields)
		}
		result, err := json.Marshal(entry)
		if err != nil {
			return nil, err
		}
		return NewToolResultText(string(result)), nil
	}

	response := buildSecretMetadataResponse(entry, path)
	result, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(result)), nil
}

func (s *Server) handleGetValue(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		s.logAudit(ctx, "get_value", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}

	if !s.checkScope(path) {
		s.logAudit(ctx, "get_value", path, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	svc := vaultsvc.New(slog.Default(), s.vault)
	_, span := metrics.StartSpan(ctx, "vault.GetEntry")
	entry, err := svc.GetEntry(path)
	span.End()
	if err != nil {
		s.logAudit(ctx, "get_value", path, false)
		metrics.RecordVaultOperation("read", "error")
		return vaultServiceErrorResult(err)
	}

	if s.agent != nil && s.agent.RedactFields != nil && len(s.agent.RedactFields) > 0 {
		entry = redactEntry(entry, s.agent.RedactFields)
	}

	s.logAudit(ctx, "get_value", path, true)
	metrics.RecordVaultOperation("read", "success")

	result, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(result)), nil
}

func (s *Server) handleGetMetadata(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		s.logAudit(ctx, "get_metadata", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}

	if !s.checkScope(path) {
		s.logAudit(ctx, "get_metadata", path, false)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	svc := vaultsvc.New(slog.Default(), s.vault)
	entry, err := svc.GetEntry(path)
	if err != nil {
		s.logAudit(ctx, "get_metadata", path, false)
		return vaultServiceErrorResult(err)
	}

	s.logAudit(ctx, "get_metadata", path, true)

	result := buildSecretMetadataResponse(entry, path)
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(resultJSON)), nil
}
