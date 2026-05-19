package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	gopath "path"
	"strings"
	"time"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vault"
	"github.com/danieljustus/OpenPass/internal/vault/taint"
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
	fields := make([]map[string]any, 0, len(entry.Data))
	for k, v := range entry.Data {
		fields = append(fields, map[string]any{
			"name":   k,
			"handle": (taint.SecretHandle{Path: path, Field: k}).String(),
			"kind":   inferFieldKind(v),
		})
	}

	wrappedTags := make([]string, len(entry.Metadata.Tags))
	for i, tag := range entry.Metadata.Tags {
		wrappedTags[i] = EmbedAsData("tag", globalChokepoint.SanitizeForMCP(tag))
	}

	response := map[string]any{
		"path":        path,
		"type":        entry.SecretMetadata.Type,
		"usage_hint":  EmbedAsData("usage_hint", globalChokepoint.SanitizeForMCP(entry.SecretMetadata.UsageHint)),
		"auto_rotate": entry.SecretMetadata.AutoRotate,
		"fields":      fields,
		"has_value":   len(entry.Data) > 0,
		"tags":        wrappedTags,
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

	response := buildSecretMetadataResponse(entry, path)
	result, marshalErr := json.Marshal(response)
	if marshalErr != nil {
		return nil, marshalErr
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

	// Block value access for quarantined entries. Normalize path first to prevent
	// traversal bypasses (e.g., "quarantine/../secrets/foo" normalizes to
	// "secrets/foo", correctly bypassing the check — that path is not quarantined).
	{
		cleanedPath := gopath.Clean(path)
		if cleanedPath == "quarantine" || strings.HasPrefix(cleanedPath, "quarantine/") {
			s.logAudit(ctx, "quarantine_block", path, false)
			return NewToolResultError("entry is in quarantine — run 'openpass import review promote' to make it accessible"), nil
		}
	}

	if !s.canReadValues() {
		if approvalErr := s.requireApproval(ctx, Intent{
			Action:    "get_entry_value",
			EntryPath: path,
			Summary:   RenderSummary("read secret values", path, ""),
		}); approvalErr != nil {
			return NewToolResultError(approvalErr.Error()), nil
		}
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

	if s.agent != nil {
		if patterns := s.agent.EffectiveRedactFields("get_entry_value"); len(patterns) > 0 {
			entry = redactEntry(entry, patterns)
		}
	}

	// Sanitize tags to prevent prompt injection via tag metadata.
	for i, tag := range entry.Metadata.Tags {
		entry.Metadata.Tags[i] = globalChokepoint.SanitizeForMCP(tag)
	}

	s.logAudit(ctx, "get_value", path, true)
	metrics.RecordVaultOperation("read", "success")

	shouldSeal := entry.Classification >= taint.Secret && (s.agent == nil || s.agent.AutoUnseal == nil || !*s.agent.AutoUnseal)

	if shouldSeal {
		return s.sealEntryResponse(ctx, entry, path), nil
	}

	maxSecrets := 0
	if s.agent.MaxSecretsInSession != nil {
		maxSecrets = *s.agent.MaxSecretsInSession
	}
	if maxSecrets > 0 {
		accessed := s.secretsAccessed.Load()
		fieldCount := int64(len(entry.Data))
		if accessed+fieldCount > int64(maxSecrets) {
			return NewToolResultError(
				fmt.Sprintf("max secrets per session exceeded (%d/%d)", accessed+fieldCount, maxSecrets)), nil
		}
	}

	for range entry.Data {
		s.secretsAccessed.Add(1)
	}

	// Wrap string Data values with EmbedAsData to prevent prompt injection
	// via high-risk untrusted fields (notes, description, custom fields).
	entry.Data = wrapDataFields(entry.Data)

	piMode := ""
	if s.agent != nil && s.agent.PromptInjectionMode != nil {
		piMode = *s.agent.PromptInjectionMode
	}
	if piMode != "" && piMode != "off" {
		for k, v := range entry.Data {
			if str, ok := v.(string); ok {
				checked, checkErr := s.applySemanticInjectionCheck(str)
				if checkErr != nil {
					return NewToolResultError(checkErr.Error()), nil
				}
				entry.Data[k] = checked
			}
		}
	}

	result, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(result)), nil
}

func (s *Server) sealEntryResponse(_ context.Context, entry *vault.Entry, path string) *CallToolResult {
	var fieldName string
	for k := range entry.Data {
		fieldName = k
		break
	}
	handle := (taint.SecretHandle{Path: path, Field: fieldName}).String()

	resp := map[string]any{
		"handle":         handle,
		"classification": entry.Classification.String(),
		"note":           "Use secret_unseal tool to reveal the value",
	}
	result, err := json.Marshal(resp)
	if err != nil {
		return NewToolResultError("failed to marshal sealed response")
	}
	return NewToolResultText(string(result))
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

// wrapDataFields recursively wraps string values in a map with EmbedAsData.
// This prevents prompt injection via high-risk untrusted fields (notes,
// description, usage_hint, tags, and all custom string fields).
func wrapDataFields(data map[string]any) map[string]any {
	wrapped := make(map[string]any, len(data))
	for k, v := range data {
		switch val := v.(type) {
		case string:
			wrapped[k] = EmbedAsData(k, val)
		case map[string]any:
			wrapped[k] = wrapDataFields(val)
		default:
			wrapped[k] = v
		}
	}
	return wrapped
}

// inferFieldKind returns a type label for a field value based on its Go type.
func inferFieldKind(v any) string {
	switch val := v.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case map[string]any:
		if secret, ok := val["secret"].(string); ok && secret != "" {
			if typ, ok := val["type"].(string); ok && typ == "totp" {
				return "totp"
			}
		}
		return "object"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%T", val)
	}
}
