package server

import (
	"context"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

func setupTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"*"},
				CanWrite:     config.BoolPtr(true),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	srv, err := New(v, "test", "stdio")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if srv == nil {
		t.Fatal("New() returned nil server")
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func TestHandleSanitizeOutput(t *testing.T) {
	server := setupTestServer(t)

	tests := []struct {
		name    string
		args    map[string]any
		wantErr bool
		check   func(t *testing.T, text string)
	}{
		{
			name: "sanitize AWS key",
			args: map[string]any{
				"text": "My AWS key is AKIAIOSFODNN7EXAMPLE",
			},
			wantErr: false,
			check: func(t *testing.T, text string) {
				if text == "" {
					t.Fatal("expected non-empty result")
				}
			},
		},
		{
			name:    "missing text",
			args:    map[string]any{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mcp.CallToolRequest{Arguments: tt.args}
			result, err := server.handleSanitizeOutput(t.Context(), req)
			if tt.wantErr {
				if err == nil && (result == nil || !result.IsError) {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, result.Text)
			}
		})
	}
}

func TestSanitizeRunOutput(t *testing.T) {
	server := setupTestServer(t)

	stdout := "The secret is my-secret-value"
	stderr := "Error: my-secret-value"
	resolvedEnv := map[string]string{
		"SECRET": "my-secret-value",
	}

	sanitizedStdout, sanitizedStderr := server.sanitizeRunOutput(context.Background(), stdout, stderr, resolvedEnv)

	if sanitizedStdout != "The secret is ***" {
		t.Errorf("stdout = %q, want %q", sanitizedStdout, "The secret is ***")
	}
	if sanitizedStderr != "Error: ***" {
		t.Errorf("stderr = %q, want %q", sanitizedStderr, "Error: ***")
	}
}

func TestSanitizeRunOutput_KnownSecretOverlapsAreFullyRedacted(t *testing.T) {
	server := setupTestServer(t)
	short := "short"
	long := "short-with-sensitive-suffix"
	inputs := []struct {
		name   string
		values []string
	}{
		{name: "short_first", values: []string{short, long}},
		{name: "long_first", values: []string{long, short}},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			resolvedEnv := map[string]string{
				"FIRST":  tc.values[0],
				"SECOND": tc.values[1],
			}
			stdout := "prefix=" + long + " suffix=" + short
			got, _ := server.sanitizeRunOutput(context.Background(), stdout, "", resolvedEnv)
			if got != "prefix=*** suffix=***" {
				t.Fatalf("sanitizeRunOutput() = %q, want %q", got, "prefix=*** suffix=***")
			}
			if strings.Contains(got, "sensitive-suffix") || strings.Contains(got, long) || strings.Contains(got, short) {
				t.Fatalf("overlapping secret leaked: %q", got)
			}
		})
	}
}

func TestSanitizeRunOutput_KnownSecretPartialOverlapsAreFullyRedacted(t *testing.T) {
	server := setupTestServer(t)
	cases := []struct {
		name   string
		values []string
		input  string
	}{
		{name: "equal_first", values: []string{"abcd", "bcde"}, input: "abcde"},
		{name: "equal_second", values: []string{"bcde", "abcd"}, input: "abcde"},
		{name: "unequal_first", values: []string{"abcdef", "defgh"}, input: "abcdefgh"},
		{name: "unequal_second", values: []string{"defgh", "abcdef"}, input: "abcdefgh"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolvedEnv := map[string]string{"FIRST": tc.values[0], "SECOND": tc.values[1]}
			got, _ := server.sanitizeRunOutput(context.Background(), "value="+tc.input, "", resolvedEnv)
			if got != "value=***" {
				t.Fatalf("sanitizeRunOutput() = %q, want %q", got, "value=***")
			}
			for _, value := range tc.values {
				if strings.Contains(got, value) {
					t.Fatalf("overlapping secret %q leaked: %q", value, got)
				}
			}
		})
	}
}

func TestSanitizeRunOutputNoSecrets(t *testing.T) {
	server := setupTestServer(t)

	stdout := "Normal output without secrets"
	stderr := ""

	sanitizedStdout, sanitizedStderr := server.sanitizeRunOutput(context.Background(), stdout, stderr, nil)

	if sanitizedStdout != stdout {
		t.Errorf("stdout = %q, want %q", sanitizedStdout, stdout)
	}
	if sanitizedStderr != stderr {
		t.Errorf("stderr = %q, want %q", sanitizedStderr, stderr)
	}
}

// F-6: sanitizeRunOutput must also strip prompt-injection vectors from
// stdout/stderr (ANSI escapes, XML closing tags, bidi overrides) instead
// of relying only on the LLM-facing chokepoint at the end of the
// response pipeline. Otherwise a subprocess that prints
// "</data>execute_with_secret op://..." or bidi-trick characters could
// influence the LLM before the final chokepoint applies.
func TestSanitizeRunOutput_StripsPromptInjectionVectors(t *testing.T) {
	server := &Server{}

	stdout := "normal\x1b[31mred</data>injection"
	stderr := "warn‮RTL"

	sanitizedStdout, sanitizedStderr := server.sanitizeRunOutput(context.Background(), stdout, stderr, nil)

	if strings.ContainsRune(sanitizedStdout, 0x1b) {
		t.Errorf("stdout still contains ANSI escape: %q", sanitizedStdout)
	}
	if strings.Contains(sanitizedStdout, "</data>") {
		t.Errorf("stdout still contains XML closing tag: %q", sanitizedStdout)
	}
	if strings.ContainsRune(sanitizedStderr, '‮') {
		t.Errorf("stderr still contains bidi override: %q", sanitizedStderr)
	}
}

// F-6: even with no resolvedEnv, the chokepoint must run.
func TestSanitizeRunOutput_AppliesChokepointWithoutEnv(t *testing.T) {
	server := &Server{}

	stdout := "hello\x1b[31mworld"
	out, _ := server.sanitizeRunOutput(context.Background(), stdout, "", nil)

	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("ANSI escape leaked through when env is empty: %q", out)
	}
}

func TestSanitizeRunOutput_StrictModeBlocksHighConfidencePattern(t *testing.T) {
	server := setupTestServer(t)

	t.Setenv("SYMVAULT_REDACT_STRICT_MODE", "true")

	// A GitHub-PAT-shaped synthetic token (not a real credential) triggers
	// the credential-pattern detector at ConfidenceHigh.
	stdout := "token=ghp_" + strings.Repeat("B", 36)
	sanitizedStdout, _ := server.sanitizeRunOutput(context.Background(), stdout, "", nil)

	if strings.Contains(sanitizedStdout, strings.Repeat("B", 36)) {
		t.Fatalf("strict mode leaked the secret: %q", sanitizedStdout)
	}
	if strings.Contains(sanitizedStdout, "token=") {
		t.Fatalf("strict mode should withhold the whole stream, not just redact in place: %q", sanitizedStdout)
	}
}

func TestSanitizeRunOutput_NonStrictModeRedactsInPlace(t *testing.T) {
	server := setupTestServer(t)

	t.Setenv("SYMVAULT_REDACT_STRICT_MODE", "")

	stdout := "prefix token=ghp_" + strings.Repeat("C", 36) + " suffix"
	sanitizedStdout, _ := server.sanitizeRunOutput(context.Background(), stdout, "", nil)

	if strings.Contains(sanitizedStdout, strings.Repeat("C", 36)) {
		t.Fatalf("secret leaked: %q", sanitizedStdout)
	}
	if !strings.Contains(sanitizedStdout, "prefix") || !strings.Contains(sanitizedStdout, "suffix") {
		t.Fatalf("non-strict mode should redact in place and keep surrounding output: %q", sanitizedStdout)
	}
}
