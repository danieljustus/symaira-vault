package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/danieljustus/OpenPass/internal/masking"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

func (s *Server) handleSanitizeOutput(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	text, err := req.RequireString("text")
	if err != nil {
		s.logAudit(ctx, "sanitize_output", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}

	maskWithOPRefs := req.GetBool("mask_with_op_refs", false)
	customMask := req.GetString("mask", "")

	s.logAudit(ctx, "sanitize_output", "<scan>", true)
	metrics.RecordVaultOperation("sanitize", "success")

	opts := masking.MaskOptions{
		MaskWithOPRefs: maskWithOPRefs,
		CustomMask:     customMask,
	}

	if maskWithOPRefs {
		opts.VaultResolver = s.buildVaultResolver()
	}

	sanitizer := masking.NewSanitizer()
	sanitized := sanitizer.Sanitize(text, opts)

	result := map[string]any{
		"original_length":  len(text),
		"sanitized_length": len(sanitized),
		"sanitized":        sanitized,
		"was_modified":     sanitized != text,
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal sanitize result: %w", err)
	}

	return NewToolResultText(string(resultJSON)), nil
}

func (s *Server) buildVaultResolver() func(string) (string, bool) {
	return func(secretValue string) (string, bool) {
		if s.vault == nil {
			return "", false
		}

		svc := vaultsvc.New(slog.Default(), s.vault)
		entries, err := svc.List("")
		if err != nil {
			return "", false
		}

		for _, path := range entries {
			entry, err := svc.GetEntry(path)
			if err != nil {
				continue
			}
			for fieldName, fieldValue := range entry.Data {
				if fmt.Sprintf("%v", fieldValue) == secretValue {
					return path + "." + fieldName, true
				}
			}
		}
		return "", false
	}
}

func (s *Server) sanitizeRunOutput(stdout, stderr string, resolvedEnv map[string]string) (string, string) {
	return s.sanitizeKnownSecretValues(stdout, resolvedEnv), s.sanitizeKnownSecretValues(stderr, resolvedEnv)
}

func (s *Server) sanitizeKnownSecretValues(text string, resolvedEnv map[string]string) string {
	if len(resolvedEnv) == 0 {
		return text
	}

	return masking.SanitizeWithKnownSecrets(text, resolvedEnv, "***")
}
