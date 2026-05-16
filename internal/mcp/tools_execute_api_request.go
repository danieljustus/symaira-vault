package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/danieljustus/OpenPass/internal/masking"
	"github.com/danieljustus/OpenPass/internal/mcp/apitemplates"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

const (
	defaultAPITimeoutSeconds = 30
	minAPITimeoutSeconds     = 1
	maxAPITimeoutSeconds     = 300
	maxAPIResponseBodyBytes  = 100 * 1024
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
	timeoutSec, timeoutErr := parseTimeoutSeconds(req.Arguments["timeout"])
	if timeoutErr != nil {
		s.logAudit(ctx, "execute_api_request", "<invalid:timeout>", false)
		return NewToolResultError(timeoutErr.Error()), nil
	}
	method = strings.ToUpper(method)

	normalizedEndpoint, endpointErr := normalizeEndpoint(endpoint)
	if endpointErr != nil {
		s.logAudit(ctx, "execute_api_request", "<invalid:endpoint>", false)
		return NewToolResultError(fmt.Sprintf("invalid endpoint %q: %v", endpoint, endpointErr)), nil
	}

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
	if !matchAnyGlob(normalizedEndpoint, tmpl.AllowedEndpoints) {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<endpoint-denied:%s>", tmpl.Name), false)
		return NewToolResultError(fmt.Sprintf("endpoint not allowed: %s", normalizedEndpoint)), nil
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
	entryPath, parseErr := parseTemplateEntryRef(tmpl.EntryRef)
	if parseErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<template-error:%s>", tmpl.Name), false)
		return NewToolResultError(fmt.Sprintf("invalid entry_ref for %q: %v", tmpl.Name, parseErr)), nil
	}
	if !s.checkScope(entryPath) {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<scope-denied:%s>", tmpl.Name), false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: template entry path %q outside allowed scope", entryPath)
	}
	svc := vaultsvc.New(slog.Default(), s.vault)
	entry, entryErr := svc.GetEntry(entryPath)
	if entryErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<vault-error:%s>", tmpl.Name), false)
		return NewToolResultError(fmt.Sprintf("cannot load credentials for %q: %v", tmpl.Name, entryErr)), nil
	}

	// Build the request
	requestURL := tmpl.BaseURL + normalizedEndpoint
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
		headersMap, ok := headersRaw.(map[string]any)
		if !ok {
			s.logAudit(ctx, "execute_api_request", "<invalid:headers-not-object>", false)
			return NewToolResultError("argument \"headers\" must be an object"), nil
		}
		for k, v := range headersMap {
			vStr, ok := v.(string)
			if !ok {
				s.logAudit(ctx, "execute_api_request", "<invalid:header-value-not-string>", false)
				return NewToolResultError(fmt.Sprintf("headers[%q] must be a string", k)), nil
			}
			httpReq.Header.Set(k, vStr)
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
			tmpl.Name, normalizedEndpoint, method), false)
		return NewToolResultError(fmt.Sprintf("request failed: %v", respErr)), nil
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, bodyTruncated, readErr := readLimitedBody(resp.Body, maxAPIResponseBodyBytes)
	if readErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("template=%s, endpoint=%s, method=%s, status=error",
			tmpl.Name, normalizedEndpoint, method), false)
		return NewToolResultError(fmt.Sprintf("cannot read response: %v", readErr)), nil
	}

	// Sanitize response body: pattern-based detection + known-value masking
	respText := string(respBody)

	// Step 1: Pattern-based sanitization (detects ghp_xxx, sk-xxx, AKIAxxx, etc.)
	sanitizer := masking.NewSanitizer()
	patternSanitized := sanitizer.Sanitize(respText, masking.MaskOptions{CustomMask: "***"})

	// Step 2: Known-value sanitization (vault entry data as known secrets)
	resolvedSecrets := make(map[string]string)
	for k, v := range entry.Data {
		if vStr, ok := v.(string); ok {
			resolvedSecrets[k] = vStr
		}
	}
	sanitizedBody := s.sanitizeKnownSecretValues(patternSanitized, resolvedSecrets)

	// Audit log if any secrets were stripped
	if sanitizedBody != respText {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("template=%s, endpoint=%s, method=%s, status=%d, sanitized=true",
			tmpl.Name, normalizedEndpoint, method, resp.StatusCode), true)
	}

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
		tmpl.Name, normalizedEndpoint, method, resp.StatusCode)
	s.logAudit(ctx, "execute_api_request", auditMsg, resp.StatusCode < 400)

	resultJSON, err := json.Marshal(map[string]any{
		"status_code":    resp.StatusCode,
		"headers":        safeHeaders,
		"body":           sanitizedBody,
		"body_truncated": bodyTruncated,
		"content_type":   contentType,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}

	return NewToolResultText(string(resultJSON)), nil
}

func parseTemplateEntryRef(entryRef string) (string, error) {
	ref := strings.TrimSpace(entryRef)
	if ref == "" {
		return "", fmt.Errorf("entry_ref is required")
	}
	if strings.HasPrefix(ref, "op://") {
		entryPath, field, err := parseOpRef(ref)
		if err != nil {
			return "", err
		}
		if field != "" {
			return "", fmt.Errorf("entry_ref must reference an entry, not a field")
		}
		return entryPath, nil
	}
	return ref, nil
}

func normalizeEndpoint(endpoint string) (string, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return "", fmt.Errorf("endpoint is required")
	}
	if !strings.HasPrefix(trimmed, "/") {
		return "", fmt.Errorf("endpoint must start with '/'")
	}
	decoded, err := url.PathUnescape(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid URL encoding")
	}
	if hasDotSegment(trimmed) || hasDotSegment(decoded) {
		return "", fmt.Errorf("dot-segments are not allowed")
	}
	return path.Clean(trimmed), nil
}

func hasDotSegment(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." {
			return true
		}
	}
	return false
}

func parseTimeoutSeconds(raw any) (int, error) {
	if raw == nil {
		return defaultAPITimeoutSeconds, nil
	}

	var timeoutValue float64
	switch v := raw.(type) {
	case float64:
		timeoutValue = v
	case float32:
		timeoutValue = float64(v)
	case int:
		timeoutValue = float64(v)
	case int32:
		timeoutValue = float64(v)
	case int64:
		timeoutValue = float64(v)
	case string:
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("argument \"timeout\" must be numeric")
		}
		timeoutValue = parsed
	default:
		return 0, fmt.Errorf("argument \"timeout\" must be numeric")
	}

	if math.IsNaN(timeoutValue) || math.IsInf(timeoutValue, 0) {
		return 0, fmt.Errorf("argument \"timeout\" must be a finite number")
	}
	if timeoutValue != math.Trunc(timeoutValue) {
		return 0, fmt.Errorf("argument \"timeout\" must be a whole number of seconds")
	}

	timeoutSec := int(timeoutValue)
	if timeoutSec < minAPITimeoutSeconds {
		timeoutSec = minAPITimeoutSeconds
	}
	if timeoutSec > maxAPITimeoutSeconds {
		timeoutSec = maxAPITimeoutSeconds
	}
	return timeoutSec, nil
}

func readLimitedBody(r io.Reader, limit int) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > limit {
		return body[:limit], true, nil
	}
	return body, false, nil
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

// checkExecuteAPIRequestApproval checks the agent's approval mode for API request execution.
func (s *Server) checkExecuteAPIRequestApproval(ctx context.Context) error {
	return s.checkApproval(ctx, "execute_api_request",
		"agent %q requests to execute an API request")
}

// checkApproval is a shared helper that checks the agent's approval mode and either
// allows execution, denies it, or prompts the user for confirmation.
func (s *Server) checkApproval(_ context.Context, operation, detailFmt string) error {
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
		return fmt.Errorf("%s denied: approval mode is 'deny'", operation)
	case "prompt":
		timeout := s.agent.ApprovalTimeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		result := RequestApproval(ApprovalRequest{
			Operation: operation,
			Details:   fmt.Sprintf(detailFmt, s.agent.Name),
			Timeout:   timeout,
		})
		if result.Error != nil {
			return fmt.Errorf("%s approval failed: %w", operation, result.Error)
		}
		if !result.Approved {
			return fmt.Errorf("%s denied: user did not approve", operation)
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
