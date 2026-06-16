package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	perplexityDefaultBaseURL   = "https://api.perplexity.ai"
	perplexityChatEndpoint     = "/chat/completions"
	perplexityDefaultModel     = "sonar-pro"
	perplexityDefaultTimeout   = 60
	perplexityDefaultRateLimit = 10
	perplexityMaxTokens        = 2048
	perplexityAPIKeyEntry      = "perplexity"
)

type perplexityRateLimiter struct {
	mu      sync.Mutex
	count   int
	resetAt time.Time
}

var globalPerplexityRL = &perplexityRateLimiter{}

func (rl *perplexityRateLimiter) Allow(maxPerMin int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	if now.After(rl.resetAt) {
		rl.count = 0
		rl.resetAt = now.Add(time.Minute)
	}
	rl.count++
	return rl.count <= maxPerMin
}

type perplexityMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type perplexityChatRequest struct {
	Model     string              `json:"model"`
	Messages  []perplexityMessage `json:"messages"`
	MaxTokens int                 `json:"max_tokens,omitempty"`
}

type perplexityChatChoice struct {
	Index        int               `json:"index"`
	Message      perplexityMessage `json:"message"`
	FinishReason string            `json:"finish_reason"`
}

type perplexityUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type perplexityChatResponse struct {
	ID        string                 `json:"id"`
	Model     string                 `json:"model"`
	Choices   []perplexityChatChoice `json:"choices"`
	Citations []string               `json:"citations"`
	Usage     perplexityUsage        `json:"usage,omitempty"`
}

type perplexitySearchResult struct {
	Query     string   `json:"query"`
	Answer    string   `json:"answer"`
	Model     string   `json:"model,omitempty"`
	Citations []string `json:"citations,omitempty"`
}

type perplexityAskResult struct {
	Question  string   `json:"question"`
	Answer    string   `json:"answer"`
	Model     string   `json:"model,omitempty"`
	Citations []string `json:"citations,omitempty"`
	Context   []string `json:"context,omitempty"`
}

func (s *Server) resolvePerplexityAPIKey(_ context.Context) (string, error) {
	if s.vault != nil && s.vault.Config != nil && s.vault.Config.MCP != nil &&
		s.vault.Config.MCP.Perplexity != nil && s.vault.Config.MCP.Perplexity.APIKey != "" {
		return s.vault.Config.MCP.Perplexity.APIKey, nil
	}

	entry, err := vaultpkg.ReadEntry(s.vault.Dir, perplexityAPIKeyEntry, s.vault.Identity)
	if err != nil {
		return "", fmt.Errorf("perplexity API key not found: try adding a vault entry %q with a credential field, or set mcp.perplexity.api_key in config", perplexityAPIKeyEntry)
	}
	for _, key := range []string{"credential", "token", "password", "api_key"} {
		if v, ok := entry.Data[key]; ok {
			if vStr, ok := v.(string); ok && vStr != "" {
				return vStr, nil
			}
		}
	}
	return "", fmt.Errorf("perplexity vault entry %q exists but no credential field found (expected: credential, token, password, or api_key)", perplexityAPIKeyEntry)
}

func (s *Server) getPerplexityBaseURL() string {
	if s.vault != nil && s.vault.Config != nil && s.vault.Config.MCP != nil &&
		s.vault.Config.MCP.Perplexity != nil && s.vault.Config.MCP.Perplexity.BaseURL != "" {
		return s.vault.Config.MCP.Perplexity.BaseURL
	}
	return perplexityDefaultBaseURL
}

func (s *Server) getPerplexityRateLimit() int {
	if s.vault != nil && s.vault.Config != nil && s.vault.Config.MCP != nil &&
		s.vault.Config.MCP.Perplexity != nil && s.vault.Config.MCP.Perplexity.RateLimitPerMin > 0 {
		return s.vault.Config.MCP.Perplexity.RateLimitPerMin
	}
	return perplexityDefaultRateLimit
}

func (s *Server) callPerplexityChat(ctx context.Context, apiKey, baseURL, model string, messages []perplexityMessage) (*perplexityChatResponse, error) {
	rateLimit := s.getPerplexityRateLimit()
	if !globalPerplexityRL.Allow(rateLimit) {
		return nil, fmt.Errorf("perplexity rate limit exceeded: max %d requests per minute", rateLimit)
	}

	reqBody := perplexityChatRequest{
		Model:     model,
		Messages:  messages,
		MaxTokens: perplexityMaxTokens,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(baseURL, "/") + perplexityChatEndpoint
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: perplexityDefaultTimeout * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("perplexity API call failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("perplexity API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp perplexityChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &chatResp, nil
}

func (s *Server) handlePerplexitySearch(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		s.logAudit(ctx, "perplexity_search", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	apiKey, err := s.resolvePerplexityAPIKey(ctx)
	if err != nil {
		s.logAudit(ctx, "perplexity_search", "<api-key-error>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	baseURL := s.getPerplexityBaseURL()

	messages := []perplexityMessage{
		{Role: "system", Content: "You are a search assistant. Synthesize search results for the user's query. Provide accurate, up-to-date information with citations where applicable. Be concise and direct."},
		{Role: "user", Content: query},
	}

	resp, apiErr := s.callPerplexityChat(ctx, apiKey, baseURL, perplexityDefaultModel, messages)
	if apiErr != nil {
		s.logAudit(ctx, "perplexity_search", fmt.Sprintf("query=%q, error=%v", query, apiErr), false)
		metrics.RecordMCPRequest("perplexity_search", s.agent.Name, "error", 0)
		return mcp.NewToolResultError(fmt.Sprintf("Perplexity search failed: %v", apiErr)), nil
	}

	if len(resp.Choices) == 0 {
		s.logAudit(ctx, "perplexity_search", fmt.Sprintf("query=%q, error=empty-response", query), false)
		metrics.RecordMCPRequest("perplexity_search", s.agent.Name, "error", 0)
		return mcp.NewToolResultError("Perplexity returned an empty response"), nil
	}

	answer := resp.Choices[0].Message.Content

	result := perplexitySearchResult{
		Query:     query,
		Answer:    answer,
		Model:     resp.Model,
		Citations: resp.Citations,
	}

	s.logAudit(ctx, "perplexity_search", fmt.Sprintf("query=%q, model=%s, citations=%d", query, resp.Model, len(resp.Citations)), true)
	metrics.RecordMCPRequest("perplexity_search", s.agent.Name, "success", 0)

	resultJSON, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return nil, marshalErr
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

func (s *Server) handlePerplexityAsk(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	question, err := req.RequireString("question")
	if err != nil {
		s.logAudit(ctx, "perplexity_ask", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	apiKey, err := s.resolvePerplexityAPIKey(ctx)
	if err != nil {
		s.logAudit(ctx, "perplexity_ask", "<api-key-error>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	baseURL := s.getPerplexityBaseURL()
	contextEntries := req.GetString("context", "")

	systemPrompt := "You are a helpful AI assistant. Answer the user's question clearly and accurately. Provide citations for your answers where applicable."
	var contextParts []string
	if contextEntries != "" {
		systemPrompt = "You are a helpful AI assistant with access to the user's vault entries as context. Use the provided vault context to answer the user's question. If the vault context is insufficient, supplement with your own knowledge and cite sources. Provide citations for your answers where applicable."
		contextParts = strings.Split(contextEntries, "\n")
	}

	userMessage := question
	if contextEntries != "" {
		userMessage = fmt.Sprintf("Context from vault entries:\n%s\n\nQuestion: %s", contextEntries, question)
	}

	messages := []perplexityMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userMessage},
	}

	resp, apiErr := s.callPerplexityChat(ctx, apiKey, baseURL, perplexityDefaultModel, messages)
	if apiErr != nil {
		s.logAudit(ctx, "perplexity_ask", fmt.Sprintf("question=%q, error=%v", question, apiErr), false)
		metrics.RecordMCPRequest("perplexity_ask", s.agent.Name, "error", 0)
		return mcp.NewToolResultError(fmt.Sprintf("Perplexity ask failed: %v", apiErr)), nil
	}

	if len(resp.Choices) == 0 {
		s.logAudit(ctx, "perplexity_ask", fmt.Sprintf("question=%q, error=empty-response", question), false)
		metrics.RecordMCPRequest("perplexity_ask", s.agent.Name, "error", 0)
		return mcp.NewToolResultError("Perplexity returned an empty response"), nil
	}

	answer := resp.Choices[0].Message.Content

	result := perplexityAskResult{
		Question:  question,
		Answer:    answer,
		Model:     resp.Model,
		Citations: resp.Citations,
		Context:   contextParts,
	}

	s.logAudit(ctx, "perplexity_ask", fmt.Sprintf("question=%q, model=%s, citations=%d, context=%t", question, resp.Model, len(resp.Citations), contextEntries != ""), true)
	metrics.RecordMCPRequest("perplexity_ask", s.agent.Name, "success", 0)

	resultJSON, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return nil, marshalErr
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}


