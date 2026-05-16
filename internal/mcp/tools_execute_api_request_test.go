package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp/apitemplates"
)

// --- Template loading tests ---

func TestAPITemplateLoad_Builtin(t *testing.T) {
	tests := []struct {
		name    string
		wantURL string
		wantRef string
	}{
		{"github", "https://api.github.com", "op:///github"},
		{"openai", "https://api.openai.com", "op:///openai"},
		{"anthropic", "https://api.anthropic.com", "op:///anthropic"},
		{"slack", "https://slack.com/api", "op:///slack"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl, err := apitemplates.Load(tt.name, "")
			if err != nil {
				t.Fatalf("Load(%q) error = %v", tt.name, err)
			}
			if tmpl == nil {
				t.Fatal("Load() returned nil template")
			}
			if tmpl.Name != tt.name {
				t.Errorf("Name = %q, want %q", tmpl.Name, tt.name)
			}
			if tmpl.BaseURL != tt.wantURL {
				t.Errorf("BaseURL = %q, want %q", tmpl.BaseURL, tt.wantURL)
			}
			if tmpl.EntryRef != tt.wantRef {
				t.Errorf("EntryRef = %q, want %q", tmpl.EntryRef, tt.wantRef)
			}
			if tmpl.AuthType != apitemplates.AuthBearer {
				t.Errorf("AuthType = %q, want %q", tmpl.AuthType, apitemplates.AuthBearer)
			}
			if len(tmpl.AllowedEndpoints) == 0 {
				t.Error("AllowedEndpoints is empty")
			}
			if len(tmpl.AllowedMethods) == 0 {
				t.Error("AllowedMethods is empty")
			}
		})
	}
}

func TestAPITemplateLoad_Unknown(t *testing.T) {
	_, err := apitemplates.Load("nonexistent", "")
	if err == nil {
		t.Fatal("Load() expected error for unknown template, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v, want 'not found'", err)
	}
}

func TestAPITemplateLoad_EmptyName(t *testing.T) {
	_, err := apitemplates.Load("", "")
	if err == nil {
		t.Fatal("Load() expected error for empty name, got nil")
	}
}

func TestAPITemplateLoadAll(t *testing.T) {
	templates, err := apitemplates.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() error = %v", err)
	}
	if len(templates) != 4 {
		t.Fatalf("LoadAll() returned %d templates, want 4", len(templates))
	}
	names := make(map[string]bool)
	for _, tmpl := range templates {
		names[tmpl.Name] = true
	}
	for _, name := range []string{"github", "openai", "anthropic", "slack"} {
		if !names[name] {
			t.Errorf("LoadAll() missing template %q", name)
		}
	}
}

// --- Endpoint and method validation tests ---

func TestMatchAnyGlob(t *testing.T) {
	tests := []struct {
		endpoint string
		patterns []string
		want     bool
	}{
		{"/repos/owner/repo", []string{"/*"}, true},
		{"/repos/owner/repo", []string{"/repos/*"}, true},
		{"/repos/owner/repo", []string{"/v1/*"}, false},
		{"/v1/chat/completions", []string{"/v1/*"}, true},
		{"/v2/models", []string{"/v1/*"}, false},
		{"/api/test", []string{"/api/*", "/other/*"}, true},
		{"/test", []string{}, false},
		{"/api/abc", []string{"/api/???"}, true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_in_%v", tt.endpoint, tt.patterns), func(t *testing.T) {
			got := matchAnyGlob(tt.endpoint, tt.patterns)
			if got != tt.want {
				t.Errorf("matchAnyGlob(%q, %v) = %v, want %v", tt.endpoint, tt.patterns, got, tt.want)
			}
		})
	}
}

func TestIsMethodAllowed(t *testing.T) {
	tests := []struct {
		method  string
		allowed []string
		want    bool
	}{
		{"GET", []string{"GET", "POST"}, true},
		{"POST", []string{"GET", "POST"}, true},
		{"DELETE", []string{"GET", "POST"}, false},
		{"get", []string{"GET", "POST"}, true},
		{"Get", []string{"GET", "POST"}, true},
		{"PUT", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := isMethodAllowed(tt.method, tt.allowed)
			if got != tt.want {
				t.Errorf("isMethodAllowed(%q, %v) = %v, want %v", tt.method, tt.allowed, got, tt.want)
			}
		})
	}
}

// --- Auth injection tests ---

func TestInjectAuthHeader_Bearer(t *testing.T) {
	tmpl := &apitemplates.APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: apitemplates.AuthBearer,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := injectAuthHeader(req, tmpl, map[string]any{
		"credential": "test-token-123",
	})
	if err != nil {
		t.Fatalf("injectAuthHeader() error = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-token-123" {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer test-token-123")
	}
}

func TestInjectAuthHeader_BearerFallbackFields(t *testing.T) {
	tests := []struct {
		name  string
		data  map[string]any
		token string
	}{
		{"credential field", map[string]any{"credential": "token-1"}, "token-1"},
		{"token field", map[string]any{"token": "token-2"}, "token-2"},
		{"password field", map[string]any{"password": "token-3"}, "token-3"},
	}
	tmpl := &apitemplates.APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: apitemplates.AuthBearer,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/test", nil)
			err := injectAuthHeader(req, tmpl, tt.data)
			if err != nil {
				t.Fatalf("injectAuthHeader() error = %v", err)
			}
			want := "Bearer " + tt.token
			if got := req.Header.Get("Authorization"); got != want {
				t.Errorf("Authorization header = %q, want %q", got, want)
			}
		})
	}
}

func TestInjectAuthHeader_BearerMissing(t *testing.T) {
	tmpl := &apitemplates.APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: apitemplates.AuthBearer,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := injectAuthHeader(req, tmpl, map[string]any{"username": "user"})
	if err == nil {
		t.Fatal("injectAuthHeader() expected error for missing token, got nil")
	}
}

func TestInjectAuthHeader_Basic(t *testing.T) {
	tmpl := &apitemplates.APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: apitemplates.AuthBasic,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := injectAuthHeader(req, tmpl, map[string]any{
		"username":   "testuser",
		"credential": "testpass",
	})
	if err != nil {
		t.Fatalf("injectAuthHeader() error = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Basic dGVzdHVzZXI6dGVzdHBhc3M=" {
		t.Errorf("Authorization header = %q, want %q", got, "Basic dGVzdHVzZXI6dGVzdHBhc3M=")
	}
}

func TestInjectAuthHeader_BasicMissing(t *testing.T) {
	tmpl := &apitemplates.APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: apitemplates.AuthBasic,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := injectAuthHeader(req, tmpl, map[string]any{"username": "user"})
	if err == nil {
		t.Fatal("injectAuthHeader() expected error for missing password, got nil")
	}
}

func TestInjectAuthHeader_Header(t *testing.T) {
	tmpl := &apitemplates.APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: apitemplates.AuthHeader,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := injectAuthHeader(req, tmpl, map[string]any{
		"header_name":  "X-API-Key",
		"header_value": "my-api-key-123",
	})
	if err != nil {
		t.Fatalf("injectAuthHeader() error = %v", err)
	}
	if got := req.Header.Get("X-API-Key"); got != "my-api-key-123" {
		t.Errorf("X-API-Key header = %q, want %q", got, "my-api-key-123")
	}
}

func TestInjectAuthHeader_QueryParam(t *testing.T) {
	tmpl := &apitemplates.APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: apitemplates.AuthQueryParam,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := injectAuthHeader(req, tmpl, map[string]any{
		"param_name":  "api_key",
		"param_value": "secret-param-val",
	})
	if err != nil {
		t.Fatalf("injectAuthHeader() error = %v", err)
	}
	if got := req.URL.Query().Get("api_key"); got != "secret-param-val" {
		t.Errorf("query param api_key = %q, want %q", got, "secret-param-val")
	}
}

// --- Handler tests with mocked HTTP ---

func TestHandleExecuteAPIRequest_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q, want Bearer test-token", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login": "testuser", "id": 123}`))
	}))
	defer ts.Close()

	vaultDir, identity := mockVaultWithEntry(t, "testapi", map[string]any{
		"credential": "test-token",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	writeTemplateOverride(t, vaultDir, "testapi", fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: op:///testapi
allowed_endpoints:
  - /*
allowed_methods:
  - GET
`, ts.URL))

	req := CallToolRequest{
		Arguments: map[string]any{
			"template": "testapi",
			"endpoint": "/test",
			"method":   "GET",
		},
	}
	result, err := srv.handleExecuteAPIRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteAPIRequest() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleExecuteAPIRequest() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleExecuteAPIRequest() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if code, _ := output["status_code"].(float64); code != 200 {
		t.Errorf("status_code = %v, want 200", code)
	}
	body, _ := output["body"].(string)
	if !strings.Contains(body, "testuser") {
		t.Errorf("body = %q, want to contain testuser", body)
	}
	ct, _ := output["content_type"].(string)
	if ct != "application/json" {
		t.Errorf("content_type = %q, want application/json", ct)
	}
}

func TestHandleExecuteAPIRequest_PostWithBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %q, want POST", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status": "created"}`))
	}))
	defer ts.Close()

	vaultDir, identity := mockVaultWithEntry(t, "myapi", map[string]any{
		"credential": "token-post",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	writeTemplateOverride(t, vaultDir, "myapi", fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: myapi
allowed_endpoints:
  - /*
allowed_methods:
  - POST
`, ts.URL))

	req := CallToolRequest{
		Arguments: map[string]any{
			"template": "myapi",
			"endpoint": "/create",
			"method":   "POST",
			"body":     `{"name": "test"}`,
		},
	}
	result, err := srv.handleExecuteAPIRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteAPIRequest() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteAPIRequest() returned error: %s", result.Text)
	}
	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if code, _ := output["status_code"].(float64); code != 201 {
		t.Errorf("status_code = %v, want 201", code)
	}
}

func TestHandleExecuteAPIRequest_MissingTemplate(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio")
	req := CallToolRequest{
		Arguments: map[string]any{
			"endpoint": "/test",
		},
	}
	result, err := srv.handleExecuteAPIRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteAPIRequest() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("handleExecuteAPIRequest() expected error result")
	}
	if !strings.Contains(result.Text, "missing required argument") {
		t.Errorf("result text = %q, want 'missing required argument'", result.Text)
	}
}

func TestHandleExecuteAPIRequest_MissingEndpoint(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio")
	req := CallToolRequest{
		Arguments: map[string]any{
			"template": "github",
		},
	}
	result, err := srv.handleExecuteAPIRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteAPIRequest() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("handleExecuteAPIRequest() expected error result")
	}
	if !strings.Contains(result.Text, "missing required argument") {
		t.Errorf("result text = %q, want 'missing required argument'", result.Text)
	}
}

func TestHandleExecuteAPIRequest_DeniedEndpointMethod(t *testing.T) {
	tests := []struct {
		name       string
		entryName  string
		tmplConfig string
		endpoint   string
		method     string
		wantErrSub string
	}{
		{
			name:      "endpoint denied",
			entryName: "restricted",
			tmplConfig: `base_url: %s
auth_type: bearer
entry_ref: restricted
allowed_endpoints:
  - /v1/*
allowed_methods:
  - GET
`,
			endpoint:   "/admin/delete",
			method:     "GET",
			wantErrSub: "endpoint not allowed",
		},
		{
			name:      "method denied",
			entryName: "readonly",
			tmplConfig: `base_url: %s
auth_type: bearer
entry_ref: readonly
allowed_endpoints:
  - /*
allowed_methods:
  - GET
`,
			endpoint:   "/test",
			method:     "DELETE",
			wantErrSub: "method not allowed",
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vaultDir, identity := mockVaultWithEntry(t, tc.entryName, map[string]any{
				"credential": "token",
			})
			srv := newTestServerWithVault(t, config.AgentProfile{
				Name:           "test",
				AllowedPaths:   []string{"*"},
				CanRunCommands: true,
				ApprovalMode:   "none",
			}, "stdio", vaultDir)
			srv.vault.Identity = identity

			writeTemplateOverride(t, vaultDir, tc.entryName, fmt.Sprintf(tc.tmplConfig, ts.URL))

			req := CallToolRequest{
				Arguments: map[string]any{
					"template": tc.entryName,
					"endpoint": tc.endpoint,
					"method":   tc.method,
				},
			}
			result, err := srv.handleExecuteAPIRequest(context.Background(), req)
			if err != nil {
				t.Fatalf("handleExecuteAPIRequest() error = %v", err)
			}
			if !result.IsError {
				t.Fatal("handleExecuteAPIRequest() expected error result for " + tc.name)
			}
			if !strings.Contains(result.Text, tc.wantErrSub) {
				t.Errorf("result text = %q, want %q", result.Text, tc.wantErrSub)
			}
		})
	}
}

func TestHandleExecuteAPIRequest_RunDenied(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "readonly",
		AllowedPaths:   []string{"*"},
		CanRunCommands: false,
		ApprovalMode:   "none",
	}, "stdio")
	req := CallToolRequest{
		Arguments: map[string]any{
			"template": "github",
			"endpoint": "/test",
		},
	}
	_, err := srv.handleExecuteAPIRequest(context.Background(), req)
	if err == nil {
		t.Fatal("handleExecuteAPIRequest() expected error for run-denied agent, got nil")
	}
	if !strings.Contains(err.Error(), "command execution not permitted") {
		t.Fatalf("error = %v, want 'command execution not permitted'", err)
	}
}

func TestHandleExecuteAPIRequest_ResponseSanitized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": "my-super-secret-token-value"}`))
	}))
	defer ts.Close()

	vaultDir, identity := mockVaultWithEntry(t, "sanitize-test", map[string]any{
		"credential": "my-super-secret-token-value",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	writeTemplateOverride(t, vaultDir, "sanitize-test", fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: sanitize-test
allowed_endpoints:
  - /*
allowed_methods:
  - GET
`, ts.URL))

	req := CallToolRequest{
		Arguments: map[string]any{
			"template": "sanitize-test",
			"endpoint": "/test",
			"method":   "GET",
		},
	}
	result, err := srv.handleExecuteAPIRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteAPIRequest() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteAPIRequest() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	body, _ := output["body"].(string)
	if strings.Contains(body, "my-super-secret-token-value") {
		t.Errorf("body contains secret value: %q", body)
	}
}

func TestHandleExecuteAPIRequest_CustomHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "custom-value" {
			t.Errorf("X-Custom header = %q, want custom-value", r.Header.Get("X-Custom"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer ts.Close()

	vaultDir, identity := mockVaultWithEntry(t, "custom-headers", map[string]any{
		"credential": "token",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	writeTemplateOverride(t, vaultDir, "custom-headers", fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: custom-headers
allowed_endpoints:
  - /*
allowed_methods:
  - GET
`, ts.URL))

	req := CallToolRequest{
		Arguments: map[string]any{
			"template": "custom-headers",
			"endpoint": "/test",
			"method":   "GET",
			"headers": map[string]any{
				"X-Custom": "custom-value",
			},
		},
	}
	result, err := srv.handleExecuteAPIRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteAPIRequest() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteAPIRequest() returned error: %s", result.Text)
	}
}

func TestHandleExecuteAPIRequest_HeadersValidation(t *testing.T) {
	tests := []struct {
		name       string
		headersArg any
		wantErrSub string
	}{
		{
			name:       "headers must be object",
			headersArg: []any{"invalid"},
			wantErrSub: `argument "headers" must be an object`,
		},
		{
			name: "header value must be string",
			headersArg: map[string]any{
				"X-Number": 123,
			},
			wantErrSub: `headers["X-Number"] must be a string`,
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer ts.Close()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vaultDir, identity := mockVaultWithEntry(t, "headers-validation", map[string]any{
				"credential": "token",
			})
			srv := newTestServerWithVault(t, config.AgentProfile{
				Name:           "test",
				AllowedPaths:   []string{"*"},
				CanRunCommands: true,
				ApprovalMode:   "none",
			}, "stdio", vaultDir)
			srv.vault.Identity = identity

			writeTemplateOverride(t, vaultDir, "headers-validation", fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: op:///headers-validation
allowed_endpoints:
  - /*
allowed_methods:
  - GET
`, ts.URL))

			req := CallToolRequest{
				Arguments: map[string]any{
					"template": "headers-validation",
					"endpoint": "/test",
					"method":   "GET",
					"headers":  tc.headersArg,
				},
			}
			result, err := srv.handleExecuteAPIRequest(context.Background(), req)
			if err != nil {
				t.Fatalf("handleExecuteAPIRequest() error = %v", err)
			}
			if !result.IsError {
				t.Fatal("handleExecuteAPIRequest() expected error result")
			}
			if !strings.Contains(result.Text, tc.wantErrSub) {
				t.Errorf("result text = %q, want %q", result.Text, tc.wantErrSub)
			}
		})
	}
}

func TestHandleExecuteAPIRequest_EndpointDotSegmentsRejected(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
	}{
		{name: "literal dot segments", endpoint: "/v1/../admin"},
		{name: "encoded dot segments", endpoint: "/v1/%2E%2e/admin"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vaultDir, identity := mockVaultWithEntry(t, "dot-segments", map[string]any{
				"credential": "token",
			})
			srv := newTestServerWithVault(t, config.AgentProfile{
				Name:           "test",
				AllowedPaths:   []string{"*"},
				CanRunCommands: true,
				ApprovalMode:   "none",
			}, "stdio", vaultDir)
			srv.vault.Identity = identity

			writeTemplateOverride(t, vaultDir, "dot-segments", `base_url: https://example.com
auth_type: bearer
entry_ref: op:///dot-segments
allowed_endpoints:
  - /v1/*
allowed_methods:
  - GET
`)

			req := CallToolRequest{
				Arguments: map[string]any{
					"template": "dot-segments",
					"endpoint": tc.endpoint,
					"method":   "GET",
				},
			}
			result, err := srv.handleExecuteAPIRequest(context.Background(), req)
			if err != nil {
				t.Fatalf("handleExecuteAPIRequest() error = %v", err)
			}
			if !result.IsError {
				t.Fatal("handleExecuteAPIRequest() expected error result")
			}
			if !strings.Contains(result.Text, "invalid endpoint") {
				t.Errorf("result text = %q, want invalid endpoint error", result.Text)
			}
		})
	}
}

func TestHandleExecuteAPIRequest_EntryRefScopeDenied(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "github", map[string]any{
		"credential": "token",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"other"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	writeTemplateOverride(t, vaultDir, "scope-denied", `base_url: https://example.com
auth_type: bearer
entry_ref: op:///github
allowed_endpoints:
  - /*
allowed_methods:
  - GET
`)

	req := CallToolRequest{
		Arguments: map[string]any{
			"template": "scope-denied",
			"endpoint": "/test",
			"method":   "GET",
		},
	}

	result, err := srv.handleExecuteAPIRequest(context.Background(), req)
	if err == nil {
		t.Fatal("handleExecuteAPIRequest() expected scope error, got nil")
	}
	if result != nil {
		t.Fatal("handleExecuteAPIRequest() result = non-nil, want nil on scope denial")
	}
	if !strings.Contains(err.Error(), "outside allowed scope") {
		t.Fatalf("error = %v, want outside allowed scope", err)
	}
}

func TestHandleExecuteAPIRequest_ResponseBodyTruncated(t *testing.T) {
	largeBody := strings.Repeat("a", maxAPIResponseBodyBytes+128)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(largeBody))
	}))
	defer ts.Close()

	vaultDir, identity := mockVaultWithEntry(t, "large-response", map[string]any{
		"credential": "token",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	writeTemplateOverride(t, vaultDir, "large-response", fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: op:///large-response
allowed_endpoints:
  - /*
allowed_methods:
  - GET
`, ts.URL))

	req := CallToolRequest{
		Arguments: map[string]any{
			"template": "large-response",
			"endpoint": "/test",
			"method":   "GET",
		},
	}

	result, err := srv.handleExecuteAPIRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteAPIRequest() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleExecuteAPIRequest() returned error: %s", result.Text)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	body, _ := output["body"].(string)
	if len(body) != maxAPIResponseBodyBytes {
		t.Errorf("len(body) = %d, want %d", len(body), maxAPIResponseBodyBytes)
	}
	if truncated, _ := output["body_truncated"].(bool); !truncated {
		t.Errorf("body_truncated = %v, want true", truncated)
	}
}

func TestHandleExecuteAPIRequest_UnknownTemplate(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio")
	req := CallToolRequest{
		Arguments: map[string]any{
			"template": "nonexistent-template",
			"endpoint": "/test",
		},
	}
	result, err := srv.handleExecuteAPIRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("handleExecuteAPIRequest() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("handleExecuteAPIRequest() expected error for unknown template")
	}
	if !strings.Contains(result.Text, "cannot load template") {
		t.Errorf("result text = %q, want 'cannot load template'", result.Text)
	}
}

func TestHandleExecuteAPIRequest_ApprovalDeny(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "deny",
	}, "stdio")
	req := CallToolRequest{
		Arguments: map[string]any{
			"template": "github",
			"endpoint": "/test",
		},
	}
	_, err := srv.handleExecuteAPIRequest(context.Background(), req)
	if err == nil {
		t.Fatal("handleExecuteAPIRequest() expected error for approval-deny, got nil")
	}
	if !strings.Contains(err.Error(), "approval mode is 'deny'") {
		t.Fatalf("error = %v, want 'approval mode is 'deny''", err)
	}
}

func TestExecuteAPIAvailable(t *testing.T) {
	tests := []struct {
		name           string
		canRunCommands bool
		want           bool
	}{
		{"can run commands", true, true},
		{"cannot run commands", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, config.AgentProfile{
				Name:           "test",
				AllowedPaths:   []string{"*"},
				CanRunCommands: tt.canRunCommands,
				ApprovalMode:   "none",
			}, "stdio")
			got := executeAPIAvailable(srv)
			if got != tt.want {
				t.Errorf("executeAPIAvailable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExecuteAPIAvailable_NilAgent(t *testing.T) {
	srv := &Server{}
	if executeAPIAvailable(srv) {
		t.Error("executeAPIAvailable() = true, want false for nil agent")
	}
}

func TestExecuteAPIAvailable_NilServer(t *testing.T) {
	if executeAPIAvailable(nil) {
		t.Error("executeAPIAvailable() = true, want false for nil server")
	}
}

func TestHandleExecuteAPIRequest_ToolRegistered(t *testing.T) {
	_, ok := findToolDefinition("execute_api_request")
	if !ok {
		t.Fatal("execute_api_request tool not found in registry")
	}
}

func TestHandleExecuteAPIRequest_ToolListed(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		ApprovalMode:   "none",
	}, "stdio")
	tools := toolsListPayload(srv)
	found := false
	for _, tool := range tools {
		if name, _ := tool["name"].(string); name == "execute_api_request" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("execute_api_request not in tools list payload")
	}
}

func TestHandleExecuteAPIRequest_NotListedWhenUnavailable(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:           "readonly",
		AllowedPaths:   []string{"*"},
		CanRunCommands: false,
		ApprovalMode:   "none",
	}, "stdio")
	tools := toolsListPayload(srv)
	for _, tool := range tools {
		if name, _ := tool["name"].(string); name == "execute_api_request" {
			t.Fatal("execute_api_request should not be listed when CanRunCommands=false")
		}
	}
}

func TestParseTemplateEntryRef(t *testing.T) {
	tests := []struct {
		name      string
		ref       string
		wantPath  string
		wantError bool
	}{
		{name: "plain path", ref: "github", wantPath: "github"},
		{name: "op ref", ref: "op:///github", wantPath: "github"},
		{name: "field ref rejected", ref: "op://vault/github/token", wantError: true},
		{name: "empty ref rejected", ref: " ", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTemplateEntryRef(tt.ref)
			if tt.wantError {
				if err == nil {
					t.Fatal("parseTemplateEntryRef() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTemplateEntryRef() error = %v", err)
			}
			if got != tt.wantPath {
				t.Errorf("parseTemplateEntryRef() = %q, want %q", got, tt.wantPath)
			}
		})
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		want      string
		wantError bool
	}{
		{name: "double slashes normalized", endpoint: "/v1//chat/completions", want: "/v1/chat/completions"},
		{name: "dot segment rejected", endpoint: "/v1/../admin", wantError: true},
		{name: "encoded dot segment rejected", endpoint: "/v1/%2e%2e/admin", wantError: true},
		{name: "invalid encoding rejected", endpoint: "/path/%ZZ", wantError: true},
		{name: "must start with slash", endpoint: "v1/chat", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeEndpoint(tt.endpoint)
			if tt.wantError {
				if err == nil {
					t.Fatal("normalizeEndpoint() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeEndpoint() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("normalizeEndpoint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseTimeoutSeconds(t *testing.T) {
	tests := []struct {
		name      string
		input     any
		want      int
		wantError bool
	}{
		{name: "default timeout", input: nil, want: defaultAPITimeoutSeconds},
		{name: "minimum clamped", input: 0, want: minAPITimeoutSeconds},
		{name: "maximum clamped", input: 9999, want: maxAPITimeoutSeconds},
		{name: "string integer", input: "45", want: 45},
		{name: "non-integer rejected", input: 1.5, wantError: true},
		{name: "nan rejected", input: math.NaN(), wantError: true},
		{name: "infinity rejected", input: math.Inf(1), wantError: true},
		{name: "invalid type rejected", input: map[string]any{}, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTimeoutSeconds(tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatal("parseTimeoutSeconds() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTimeoutSeconds() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("parseTimeoutSeconds() = %d, want %d", got, tt.want)
			}
		})
	}
}

// writeTemplateOverride writes a user template override to the vault's template directory.
func writeTemplateOverride(t *testing.T, vaultDir, name, content string) {
	t.Helper()
	templatesDir := filepath.Join(vaultDir, "templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		t.Fatalf("mkdir templates: %v", err)
	}
	if err := os.WriteFile(filepath.Join(templatesDir, name+".yaml"), []byte(content), 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}
}
