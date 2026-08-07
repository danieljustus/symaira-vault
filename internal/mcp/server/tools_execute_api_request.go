package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/mcp/apitemplates"
	"github.com/danieljustus/symaira-vault/internal/mcp/masking"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	"github.com/danieljustus/symaira-vault/internal/ssrf"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
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
func (s *Server) handleExecuteAPIRequest(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if !s.canRunCommands() {
		s.logAudit(ctx, "execute_api_request", "<run-denied>", false)
		metrics.RecordAuthDenial("run_denied", s.agent.Name)
		return nil, runCommandDeniedError(s.agent.Name, "execute_api_request")
	}

	templateName, err := req.RequireString("template")
	if err != nil {
		s.logAudit(ctx, "execute_api_request", "<invalid:missing-template>", false)
		return mcp.NewToolResultError("missing required argument \"template\""), nil
	}

	endpoint, err := req.RequireString("endpoint")
	if err != nil {
		s.logAudit(ctx, "execute_api_request", "<invalid:missing-endpoint>", false)
		return mcp.NewToolResultError("missing required argument \"endpoint\""), nil
	}

	method := req.GetString("method", "GET")
	bodyStr := req.GetString("body", "")
	timeoutSec, timeoutErr := parseTimeoutSeconds(req.Arguments["timeout"])
	if timeoutErr != nil {
		s.logAudit(ctx, "execute_api_request", "<invalid:timeout>", false)
		return mcp.NewToolResultError(timeoutErr.Error()), nil
	}
	method = strings.ToUpper(method)

	normalizedEndpoint, endpointErr := normalizeEndpoint(endpoint)
	if endpointErr != nil {
		s.logAudit(ctx, "execute_api_request", "<invalid:endpoint>", false)
		return mcp.NewToolResultError(fmt.Sprintf("invalid endpoint %q: %v", endpoint, endpointErr)), nil
	}

	// Load template
	vaultDir := ""
	if s.vault != nil {
		vaultDir = s.vault.Dir
	}
	tmpl, loadErr := apitemplates.Load(templateName, vaultDir)
	if loadErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<template-error:%s>", templateName), false)
		return mcp.NewToolResultError(fmt.Sprintf("cannot load template %q: %v", templateName, loadErr)), nil
	}

	// Validate endpoint against allowed patterns (query string excluded —
	// patterns describe paths; query substitutions live in the query part).
	endpointPath := strings.SplitN(normalizedEndpoint, "?", 2)[0]
	if !matchAnyGlob(endpointPath, tmpl.AllowedEndpoints) {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<endpoint-denied:%s>", tmpl.Name), false)
		return mcp.NewToolResultError(fmt.Sprintf("endpoint not allowed: %s", normalizedEndpoint)), nil
	}

	// Validate method against allowed methods
	if !isMethodAllowed(method, tmpl.AllowedMethods) {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<method-denied:%s>", tmpl.Name), false)
		return mcp.NewToolResultError(fmt.Sprintf("method not allowed: %s", method)), nil
	}

	requestURL := tmpl.BaseURL + normalizedEndpoint
	if targetErr := ssrf.ValidateURL(ctx, requestURL, tmpl.AllowPrivate, net.DefaultResolver.LookupIPAddr); targetErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<blocked-target:%s>", tmpl.Name), false)
		return mcp.NewToolResultError(targetErr.Error()), nil
	}

	// Approval check before vault access
	approvalErr := s.checkExecuteAPIRequestApproval(ctx)
	if approvalErr != nil {
		s.logAudit(ctx, "execute_api_request", "<approval-denied>", false)
		metrics.RecordApproval(s.agent.Name, "denied")
		return nil, approvalErr
	}

	// Load vault entry for credentials
	entryPath, parseErr := apitemplates.EntryRefPath(tmpl.EntryRef)
	if parseErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<template-error:%s>", tmpl.Name), false)
		return mcp.NewToolResultError(fmt.Sprintf("invalid entry_ref for %q: %v", tmpl.Name, parseErr)), nil
	}
	if !s.checkScope(entryPath) {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<scope-denied:%s>", tmpl.Name), false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: template entry path %q outside allowed scope", entryPath)
	}
	entry, entryErr := vaultpkg.ReadEntry(s.vault.Dir, entryPath, s.vault.Identity)
	if entryErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<vault-error:%s>", tmpl.Name), false)
		return mcp.NewToolResultError(fmt.Sprintf("cannot load credentials for %q: %v", tmpl.Name, entryErr)), nil
	}

	// Resolve template substitutions (path/query/header/body) from the vault
	// entry. Values never enter logs or audit entries; any error message that
	// could carry a substituted value is redacted below.
	var substitutionValues map[string]string
	var redactVals []string
	if len(tmpl.Substitutions) > 0 {
		values, redactList, subErr := apitemplates.ResolveSubstitutionValues(tmpl, entry.Data)
		if subErr != nil {
			s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<substitution-error:%s>", tmpl.Name), false)
			return mcp.NewToolResultError(fmt.Sprintf("cannot resolve substitutions for %q: %v", tmpl.Name, subErr)), nil
		}
		substitutionValues = values
		redactVals = redactList
		requestURL = apitemplates.ApplyURLSubstitutions(requestURL, tmpl.Substitutions, values)
		bodyStr = apitemplates.ApplyBodySubstitutions(bodyStr, tmpl.Substitutions, values)
	}

	// Build the request
	var requestBody io.Reader
	if bodyStr != "" {
		requestBody = strings.NewReader(bodyStr)
	}

	httpReq, reqErr := http.NewRequestWithContext(ctx, method, requestURL, requestBody)
	if reqErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<request-build-error:%s>", tmpl.Name), false)
		return mcp.NewToolResultError(fmt.Sprintf("cannot build request: %s", apitemplates.RedactValues(reqErr.Error(), redactVals))), nil
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
			return mcp.NewToolResultError("argument \"headers\" must be an object"), nil
		}
		for k, v := range headersMap {
			vStr, ok := v.(string)
			if !ok {
				s.logAudit(ctx, "execute_api_request", "<invalid:header-value-not-string>", false)
				return mcp.NewToolResultError(fmt.Sprintf("headers[%q] must be a string", k)), nil
			}
			httpReq.Header.Set(k, vStr)
		}
	}

	// Apply header-surface substitutions (after agent headers, before auth so
	// auth_type always wins on the Authorization header).
	if len(tmpl.Substitutions) > 0 {
		apitemplates.ApplyHeaderSubstitutions(httpReq, tmpl.Substitutions, substitutionValues)
	}

	// Resolve and inject auth header
	authErr := apitemplates.InjectAuth(httpReq, tmpl, entry.Data)
	if authErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("<auth-error:%s>", tmpl.Name), false)
		return mcp.NewToolResultError(fmt.Sprintf("cannot resolve auth for %q: %v", tmpl.Name, authErr)), nil
	}

	// Set Content-Type for JSON body
	if bodyStr != "" && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	// Execute request
	client := ssrf.NewHTTPClient(time.Duration(timeoutSec)*time.Second, tmpl.AllowPrivate)
	resp, respErr := client.Do(httpReq)
	if respErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("template=%s, endpoint=%s, method=%s, status=error",
			tmpl.Name, normalizedEndpoint, method), false)
		return mcp.NewToolResultError(fmt.Sprintf("request failed: %s", apitemplates.RedactValues(respErr.Error(), redactVals))), nil
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, bodyTruncated, readErr := readLimitedBody(resp.Body, maxAPIResponseBodyBytes)
	if readErr != nil {
		s.logAudit(ctx, "execute_api_request", fmt.Sprintf("template=%s, endpoint=%s, method=%s, status=error",
			tmpl.Name, normalizedEndpoint, method), false)
		return mcp.NewToolResultError(fmt.Sprintf("cannot read response: %v", readErr)), nil
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

	return mcp.NewToolResultText(string(resultJSON)), nil
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

// checkApproval is a thin wrapper around requireApproval that takes a format
// string for the summary. It preserves backward compatibility for callers
// that use this helper.
func (s *Server) checkApproval(ctx context.Context, operation, detailFmt string) error {
	return s.requireApproval(ctx, Intent{
		Action:  operation,
		Summary: fmt.Sprintf(detailFmt, s.agent.Name),
	})
}

// executeAPIAvailable returns true when the agent has command execution permission.
func executeAPIAvailable(s *Server) bool {
	return s != nil && s.agent != nil && s.agent.CanRunCommands != nil && *s.agent.CanRunCommands
}
