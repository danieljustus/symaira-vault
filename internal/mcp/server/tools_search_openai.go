package server

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
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

	if s.canReadValues() && len(entry.Data) > 0 {
		response.Values = entry.Data
	}

	textJSON, marshalErr := json.Marshal(response)
	if marshalErr != nil {
		return nil, marshalErr
	}

	return mcp.NewToolResultStructured(string(textJSON), response), nil
}
