package apitemplates

import (
	"net/http"
	"testing"
)

func TestInjectAuth_Bearer(t *testing.T) {
	tmpl := &APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: AuthBearer,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := InjectAuth(req, tmpl, map[string]any{
		"credential": "test-token-123",
	})
	if err != nil {
		t.Fatalf("InjectAuth() error = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-token-123" {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer test-token-123")
	}
}

func TestInjectAuth_BearerFallbackFields(t *testing.T) {
	tests := []struct {
		name  string
		data  map[string]any
		token string
	}{
		{"credential field", map[string]any{"credential": "token-1"}, "token-1"},
		{"token field", map[string]any{"token": "token-2"}, "token-2"},
		{"password field", map[string]any{"password": "token-3"}, "token-3"},
	}
	tmpl := &APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: AuthBearer,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/test", nil)
			err := InjectAuth(req, tmpl, tt.data)
			if err != nil {
				t.Fatalf("InjectAuth() error = %v", err)
			}
			want := "Bearer " + tt.token
			if got := req.Header.Get("Authorization"); got != want {
				t.Errorf("Authorization header = %q, want %q", got, want)
			}
		})
	}
}

func TestInjectAuth_BearerMissing(t *testing.T) {
	tmpl := &APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: AuthBearer,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := InjectAuth(req, tmpl, map[string]any{"username": "user"})
	if err == nil {
		t.Fatal("InjectAuth() expected error for missing token, got nil")
	}
}

func TestInjectAuth_Basic(t *testing.T) {
	tmpl := &APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: AuthBasic,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := InjectAuth(req, tmpl, map[string]any{
		"username":   "testuser",
		"credential": "testpass",
	})
	if err != nil {
		t.Fatalf("InjectAuth() error = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Basic dGVzdHVzZXI6dGVzdHBhc3M=" {
		t.Errorf("Authorization header = %q, want %q", got, "Basic dGVzdHVzZXI6dGVzdHBhc3M=")
	}
}

func TestInjectAuth_BasicMissing(t *testing.T) {
	tmpl := &APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: AuthBasic,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := InjectAuth(req, tmpl, map[string]any{"username": "user"})
	if err == nil {
		t.Fatal("InjectAuth() expected error for missing password, got nil")
	}
}

func TestInjectAuth_Header(t *testing.T) {
	tmpl := &APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: AuthHeader,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := InjectAuth(req, tmpl, map[string]any{
		"header_name":  "X-API-Key",
		"header_value": "my-api-key-123",
	})
	if err != nil {
		t.Fatalf("InjectAuth() error = %v", err)
	}
	if got := req.Header.Get("X-API-Key"); got != "my-api-key-123" {
		t.Errorf("X-API-Key header = %q, want %q", got, "my-api-key-123")
	}
}

func TestInjectAuth_QueryParam(t *testing.T) {
	tmpl := &APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: AuthQueryParam,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := InjectAuth(req, tmpl, map[string]any{
		"param_name":  "api_key",
		"param_value": "secret-param-val",
	})
	if err != nil {
		t.Fatalf("InjectAuth() error = %v", err)
	}
	if got := req.URL.Query().Get("api_key"); got != "secret-param-val" {
		t.Errorf("query param api_key = %q, want %q", got, "secret-param-val")
	}
}

func TestInjectAuth_None(t *testing.T) {
	tmpl := &APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: AuthNone,
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := InjectAuth(req, tmpl, map[string]any{"credential": "secret"})
	if err != nil {
		t.Fatalf("InjectAuth() error = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization header = %q, want empty for auth_type none", got)
	}
}

func TestInjectAuth_Unsupported(t *testing.T) {
	tmpl := &APITemplate{
		Name:     "test",
		BaseURL:  "https://example.com",
		AuthType: AuthType("magic"),
	}
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	err := InjectAuth(req, tmpl, nil)
	if err == nil {
		t.Fatal("InjectAuth() expected error for unsupported auth type, got nil")
	}
}
