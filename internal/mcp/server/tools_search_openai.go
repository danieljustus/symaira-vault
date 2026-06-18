package server

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/metrics"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
	"github.com/danieljustus/symaira-vault/internal/vault/taint"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

type openAISearchResult struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	URL     string `json:"url"`
	Content string `json:"content,omitempty"`
}

type openAISearchResponse struct {
	Results []openAISearchResult `json:"results"`
}

type openAIFetchResponse struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	URL      string         `json:"url"`
	Metadata map[string]any `json:"metadata,omitempty"`
	Values   map[string]any `json:"values,omitempty"`
}

func entryURL(path string) string {
	return "symvault://entry/" + path
}

func entryTitle(p string) string {
	_, name := path.Split(p)
	if name == "" {
		return p
	}
	return name
}

func (s *Server) handleSearchOpenAI(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		s.logAudit(ctx, "search_openai", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	matches, err := s.findEntries(ctx, query)
	if err != nil {
		s.logAudit(ctx, "search_openai", query, false)
		return nil, err
	}

	s.logAudit(ctx, "search_openai", query, true)

	results := make([]openAISearchResult, 0, len(matches))
	for _, m := range matches {
		sanitizedPath := globalChokepoint.SanitizeForMCP(m.Path)
		result := openAISearchResult{
			ID:    sanitizedPath,
			Title: globalChokepoint.SanitizeForMCP(entryTitle(m.Path)),
			URL:   entryURL(sanitizedPath),
		}
		if len(m.Fields) > 0 {
			result.Content = "Matching fields: " + strings.Join(m.Fields, ", ")
		}
		results = append(results, result)
	}

	structured := openAISearchResponse{Results: results}

	textJSON, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}

	return mcp.NewToolResultStructured(string(textJSON), structured), nil
}

func (s *Server) handleFetchOpenAI(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := req.RequireString("id")
	if err != nil {
		s.logAudit(ctx, "fetch_openai", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	if !s.checkScope(id) {
		s.logAudit(ctx, "fetch_openai", id, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return mcp.NewToolResultError(fmt.Sprintf("access denied: path %q outside allowed scope", id)), nil
	}

	_, span := metrics.StartSpan(ctx, "vault.ReadEntry")
	entry, vaultErr := vaultpkg.ReadEntry(s.vault.Dir, id, s.vault.Identity)
	span.End()
	if vaultErr != nil {
		s.logAudit(ctx, "fetch_openai", id, false)
		metrics.RecordVaultOperation("read", "error")
		return vaultServiceErrorResult(vaultErr)
	}

	s.logAudit(ctx, "fetch_openai", id, true)
	metrics.RecordVaultOperation("read", "success")

	sanitizedPath := globalChokepoint.SanitizeForMCP(id)

	response := openAIFetchResponse{
		ID:    sanitizedPath,
		Title: globalChokepoint.SanitizeForMCP(entryTitle(id)),
		URL:   entryURL(sanitizedPath),
		Metadata: map[string]any{
			"created": entry.Metadata.Created.Format(time.RFC3339),
			"updated": entry.Metadata.Updated.Format(time.RFC3339),
			"version": entry.Metadata.Version,
			"type":    entry.SecretMetadata.Type,
		},
	}

	// Block value access for quarantined entries. Normalize path first to prevent
	// traversal bypasses (e.g., "quarantine/../secrets/foo" normalizes to
	// "secrets/foo", correctly bypassing the check — that path is not quarantined).
	{
		cleanedPath := path.Clean(id)
		if cleanedPath == "quarantine" || strings.HasPrefix(cleanedPath, "quarantine/") {
			s.logAudit(ctx, "quarantine_block", id, false)
			return mcp.NewToolResultError("entry is in quarantine — run 'symvault import review promote' to make it accessible"), nil
		}
	}

	// Gate value exposure on ExposeValueTools: when false, fetch returns metadata-only.
	// ExposeValueTools controls whether the get_entry_value tool is registered at all;
	// fetch must respect the same gate to avoid a side-channel bypass.
	exposeValues := s.agent != nil && s.agent.ExposeValueTools != nil && *s.agent.ExposeValueTools

	if exposeValues && s.canReadValues() && len(entry.Data) > 0 {
		// Apply the same security controls as handleGetValue for value exposure.

		if s.agent != nil {
			if patterns := s.agent.EffectiveRedactFields("fetch_openai"); len(patterns) > 0 {
				entry = redactEntry(entry, patterns)
			}
		}

		shouldSeal := entry.Classification >= taint.Secret && (s.agent == nil || s.agent.AutoUnseal == nil || !*s.agent.AutoUnseal)
		if shouldSeal {
			return s.sealEntryResponse(ctx, entry, id), nil
		}

		maxSecrets := 0
		if s.agent.MaxSecretsInSession != nil {
			maxSecrets = *s.agent.MaxSecretsInSession
		}
		if maxSecrets > 0 {
			accessed := s.secretsAccessed.Load()
			fieldCount := int64(len(entry.Data))
			if accessed+fieldCount > int64(maxSecrets) {
				return mcp.NewToolResultError(
					fmt.Sprintf("max secrets per session exceeded (%d/%d)", accessed+fieldCount, maxSecrets)), nil
			}
		}

		for range entry.Data {
			s.secretsAccessed.Add(1)
		}

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
						return mcp.NewToolResultError(checkErr.Error()), nil
					}
					entry.Data[k] = checked
				}
			}
		}

		response.Values = entry.Data
	}

	textJSON, marshalErr := json.Marshal(response)
	if marshalErr != nil {
		return nil, marshalErr
	}

	return mcp.NewToolResultStructured(string(textJSON), response), nil
}
