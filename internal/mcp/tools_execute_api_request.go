package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/danieljustus/OpenPass/internal/mcp/apitemplates"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

// handleExecuteAPIRequest executes an HTTP API request using a named template.
// Credentials are loaded from the vault and injected into the request without
// exposing their values to the agent.
//
//nolint:gocyclo,gocognit // complexity inherent to auth resolution and request building
func (s *Server) handleExecuteAPIRequest(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	if !s.canRunCommands() {
		s.logAudit(ctx, "execute_api_request", "<run-denied>", false)
		metrics.RecordAuthDenial("run_denied", s.agent.Name)
		return nil, fmt.Errorf("command execution not permitted for this agent")
	}

	templateName, err := req.RequireString("template")
	if err != nil {
		s.logAudit(ctx, "execute_api_request", "<invalid:missing-template>", false)
		return NewToolResultError("missing required argument \"template\""), nil
	}

	endpoint, err := req.RequireString("endpoint")
	if err != nil {
		s.logAudit(ctx, "execute_api_request", "<invalid:missing-endpoint>", false)
		return NewToolResultError("missing required argument \"endpoint\""), nil
	}

	method := req.GetString("method", "GET")
	bodyStr := req.GetString("body", "")
	timeoutSec := int(req.GetFloat("timeout", 30))

	// Load template
	vaultDir := ""
	if s.vault != nil {
		vaultDir = s.vault.Dir
	}
	tmpl, loadErr := apitemplates.Load(templateName, vaultDir)
	if loadErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<template-error:%s>", templateName), false)
		return NewToolResultError(fmt.Sprintf("cannot load template %q: %v", templateName, loadErr)), nil
	}

	// Validate endpoint against allowed patterns
	if !matchAnyGlob(endpoint, tmpl.AllowedEndpoints) {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<endpoint-denied:%s>", tmpl.Name), false)
		return NewToolResultError(fmt.Sprintf("endpoint not allowed: %s", endpoint)), nil
	}

	// Validate method against allowed methods
	if !isMethodAllowed(method, tmpl.AllowedMethods) {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<method-denied:%s>", tmpl.Name), false)
		return NewToolResultError(fmt.Sprintf("method not allowed: %s", method)), nil
	}

	// Approval check before vault access
	approvalErr := s.checkExecuteAPIRequestApproval(ctx)
	if approvalErr != nil {
		s.logAudit(ctx, "execute_api_request", "<approval-denied>", false)
		metrics.RecordApproval(s.agent.Name, "denied")
		return nil, approvalErr
	}

	// Load vault entry for credentials
	svc := vaultsvc.New(slog.Default(), s.vault)
	entry, entryErr := svc.GetEntry(tmpl.EntryRef)
	if entryErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<vault-error:%s>", tmpl.Name), false)
		return NewToolResultError(fmt.Sprintf("cannot load credentials for %q: %v", tmpl.Name, entryErr)), nil
	}

	// Build the request
	requestURL := tmpl.BaseURL + endpoint
	var requestBody io.Reader
	if bodyStr != "" {
		requestBody = strings.NewReader(bodyStr)
	}

	httpReq, reqErr := http.NewRequestWithContext(ctx, method, requestURL, requestBody)
	if reqErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<request-build-error:%s>", tmpl.Name), false)
		return NewToolResultError(fmt.Sprintf("cannot build request: %v", reqErr)), nil
	}

	// Apply default headers
	for k, v := range tmpl.DefaultHeaders {
		httpReq.Header.Set(k, v)
	}

	// Apply additional headers from agent request (before auth, so auth can't be overridden)
	if headersRaw, ok := req.Arguments["headers"]; ok {
		if headersMap, ok := headersRaw.(map[string]any); ok {
			for k, v := range headersMap {
				if vStr, ok := v.(string); ok {
					httpReq.Header.Set(k, vStr)
				}
			}
		}
	}

	// Resolve and inject auth header
	authErr := injectAuthHeader(httpReq, tmpl, entry.Data)
	if authErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<auth-error:%s>", tmpl.Name), false)
		return NewToolResultError(fmt.Sprintf("cannot resolve auth for %q: %v", tmpl.Name, authErr)), nil
	}

	// Set Content-Type for JSON body
	if bodyStr != "" && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	// Execute request
	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}
	resp, respErr := client.Do(httpReq)
	if respErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("template=%s, endpoint=%s, method=%s, status=error",
			tmpl.Name, endpoint, method), false)
		return NewToolResultError(fmt.Sprintf("request failed: %v", respErr)), nil
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("template=%s, endpoint=%s, method=%s, status=error",
			tmpl.Name, endpoint, method), false)
		return NewToolResultError(fmt.Sprintf("cannot read response: %v", readErr)), nil
	}

	// Sanitize response body to mask any credential values
	resolvedSecrets := make(map[string]string)
	for k, v := range entry.Data {
		if vStr, ok := v.(string); ok {
			resolvedSecrets[k] = vStr
		}
	}
	sanitizedBody := s.sanitizeKnownSecretValues(string(respBody), resolvedSecrets)

	// Collect response headers (safe subset)
	safeHeaders := make(map[string]string)
	for k := range resp.Header {
		// Skip potentially sensitive headers
		lower := strings.ToLower(k)
		if lower == "set-cookie" || lower == "authorization" || lower == "www-authenticate" ||
			lower == "proxy-authenticate" || lower == "proxy-authorization" {
			continue
		}
		safeHeaders[k] = resp.Header.Get(k)
	}

	// Determine content type
	contentType := resp.Header.Get("Content-Type")

	// Audit log: template + endpoint + method + status code only
	auditMsg := fmt.Sprintf("template=%s, endpoint=%s, method=%s, status=%d",
		tmpl.Name, endpoint, method, resp.StatusCode)
	s.logAudit(ctx, "execute_api_request", auditMsg, resp.StatusCode < 500)

	resultJSON, err := json.Marshal(map[string]any{
		"status_code":  resp.StatusCode,
		"headers":      safeHeaders,
		"body":         sanitizedBody,
		"content_type": contentType,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}

	return NewToolResultText(string(resultJSON)), nil
}

// injectAuthHeader resolves the credential from the vault entry data and
// injects the appropriate auth header (or query param) into the HTTP request.
//
//nolint:gocyclo // auth type dispatch is intentionally structured as switch
func injectAuthHeader(httpReq *http.Request, tmpl *apitemplates.APITemplate, entryData map[string]any) error {
	switch tmpl.AuthType {
	case apitemplates.AuthBearer:
		token := resolveField(entryData, "credential", "token", "password")
		if token == "" {
			return fmt.Errorf("no bearer token found in vault entry (expected fields: credential, token, or password)")
		}
		httpReq.Header.Set("Authorization", "Bearer "+token)

	case apitemplates.AuthBasic:
		username := resolveField(entryData, "username")
		password := resolveField(entryData, "credential", "password")
		if username == "" || password == "" {
			return fmt.Errorf("basic auth requires username and password fields in vault entry")
		}
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		httpReq.Header.Set("Authorization", "Basic "+auth)

	case apitemplates.AuthHeader:
		// For header auth type, we look for the header name and value in entry data
		// The convention is: header_name and header_value in the vault entry
		headerName := resolveField(entryData, "header_name")
		headerValue := resolveField(entryData, "header_value", "credential", "token", "password")
		if headerName == "" || headerValue == "" {
			return fmt.Errorf("header auth requires header_name and header_value (or credential/token/password) fields in vault entry")
		}
		httpReq.Header.Set(headerName, headerValue)

	case apitemplates.AuthQueryParam:
		// For query_param auth type, we look for the param name and value in entry data
		// The convention is: param_name and param_value in the vault entry
		paramName := resolveField(entryData, "param_name")
		paramValue := resolveField(entryData, "param_value", "credential", "token", "password")
		if paramName == "" || paramValue == "" {
			return fmt.Errorf("query_param auth requires param_name and param_value (or credential/token/password) fields in vault entry")
		}
		q := httpReq.URL.Query()
		q.Set(paramName, paramValue)
		httpReq.URL.RawQuery = q.Encode()

	default:
		return fmt.Errorf("unsupported auth type: %s", tmpl.AuthType)
	}

	return nil
}

// resolveField returns the first non-empty string value from the entry data
// for the given field keys, in order.
func resolveField(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := data[key]; ok {
			if vStr, ok := v.(string); ok && vStr != "" {
				return vStr
			}
		}
	}
	return ""
}

// matchAnyGlob checks if the given path matches any of the glob patterns.
// Uses path.Match for single-segment matching, with multi-segment support
// for patterns ending in /* which should match any sub-path.
func matchAnyGlob(endpoint string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		if matchGlob(pattern, endpoint) {
			return true
		}
	}
	return false
}

// matchGlob reports whether the endpoint matches the glob pattern.
// It uses path.Match for standard shell pattern matching, and adds
// multi-segment support for patterns ending with /* — these match
// any sub-path beneath the prefix.
func matchGlob(pattern, endpoint string) bool {
	// Try standard path.Match first (handles single-segment *)
	if matched, err := path.Match(pattern, endpoint); err == nil && matched {
		return true
	}
	// Multi-segment: patterns like /v1/* should match /v1/chat/completions
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if prefix == "" || prefix == "/" {
			// /* matches any absolute path
			return strings.HasPrefix(endpoint, "/")
		}
		if strings.HasPrefix(endpoint, prefix+"/") {
			return true
		}
	}
	return false
}

// isMethodAllowed checks if the given HTTP method is in the allowed list.
func isMethodAllowed(method string, allowed []string) bool {
	method = strings.ToUpper(method)
	for _, m := range allowed {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// checkExecuteAPIRequestApproval checks the agent's approval mode and either
// allows execution, denies it, or prompts the user for confirmation.
func (s *Server) checkExecuteAPIRequestApproval(_ context.Context) error {
	if s == nil || s.agent == nil {
		return fmt.Errorf("server not initialized")
	}

	mode := s.agent.ApprovalMode
	if mode == "" {
		if s.agent.RequireApproval {
			mode = "prompt"
		} else {
			mode = "none"
		}
	}

	switch mode {
	case "none", "auto":
		return nil
	case "deny":
		return fmt.Errorf("execute_api_request denied: approval mode is 'deny'")
	case "prompt":
		timeout := s.agent.ApprovalTimeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		result := RequestApproval(ApprovalRequest{
			Operation: "execute_api_request",
			Details:   fmt.Sprintf("agent %q requests to execute an API request", s.agent.Name),
			Timeout:   timeout,
		})
		if result.Error != nil {
			return fmt.Errorf("execute_api_request approval failed: %w", result.Error)
		}
		if !result.Approved {
			return fmt.Errorf("execute_api_request denied: user did not approve")
		}
		metrics.RecordApproval(s.agent.Name, "granted")
		return nil
	default:
		return nil
	}
}

// executeAPIAvailable returns true when the agent has command execution permission.
func executeAPIAvailable(s *Server) bool {
	return s != nil && s.agent != nil && s.agent.CanRunCommands
}
