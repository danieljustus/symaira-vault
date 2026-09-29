package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

type executeAPIRequestFixture struct {
	SchemaVersion  int                          `json:"schema_version"`
	Oracle         executeAPIRequestFixtureRefs `json:"oracle"`
	Normalizations []string                     `json:"normalizations"`
	Cases          []executeAPIRequestCase      `json:"cases"`
}

type executeAPIRequestFixtureRefs struct {
	Commit         string   `json:"commit"`
	CommitSHA      string   `json:"commit_sha"`
	SourceFiles    []string `json:"source_files"`
	SourceDigest   string   `json:"source_digest"`
	GeneratorFiles []string `json:"generator_files"`
	GeneratorHash  string   `json:"generator_hash"`
}

type executeAPIRequestCase struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
	Text      string         `json:"text"`
	IsError   bool           `json:"is_error"`
	Error     string         `json:"error,omitempty"`
	Requests  int            `json:"requests"`
}

const executeAPIRequestOracleCommit = "c94a10d78181caa91e7f3b977139e9d977315735"

var executeAPIRequestSourceFiles = []string{
	"internal/mcp/server/approval.go",
	"internal/mcp/server/approval_helper.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/server.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_execute_api_request.go",
	"internal/mcp/apitemplates/auth.go",
	"internal/mcp/apitemplates/template.go",
	"internal/mcp/masking/sanitizer.go",
	"internal/mcp/masking/validator.go",
	"internal/ssrf/ssrf.go",
	"internal/vault/entry.go",
	"internal/vault/entry_readwrite.go",
}

func TestGenerateMCPExecuteAPIRequestFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_EXECUTE_API_REQUEST_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_EXECUTE_API_REQUEST_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_EXECUTE_API_REQUEST_FIXTURE=1 or SYMAIRA_CHECK_MCP_EXECUTE_API_REQUEST_FIXTURE=1")
	}
	root := executeAPIRequestRepoRoot(t)
	files := append([]string(nil), executeAPIRequestSourceFiles...)
	// Verify immutable production blobs before any production handler is called.
	sourceDigest := executeAPIRequestGitDigest(t, root, executeAPIRequestOracleCommit, files)
	if got := executeAPIRequestWorkingDigest(t, root, files); got != sourceDigest {
		t.Fatalf("Go production sources differ from pinned oracle %s: working=%s pinned=%s", executeAPIRequestOracleCommit, got, sourceDigest)
	}
	generatorFiles := []string{
		"internal/mcp/server/mcp_execute_api_request_fixture_generator_test.go",
		"internal/mcp/server/tools_execute_api_request_test.go",
		"internal/mcp/server/tools_test_helpers.go",
	}
	generatorHash := executeAPIRequestWorkingDigest(t, root, generatorFiles)

	var requests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer fixture-api-token" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/v1/large" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(strings.Repeat("a", 102398) + "€"))
			return
		}
		if r.URL.Path != "/v1/status" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Token", "fixture-api-token")
		w.Header().Set("X-Long", "fixture-api-token-extra")
		w.Header().Set("Set-Cookie", "private=cookie")
		w.Header().Set("WWW-Authenticate", "Bearer private-challenge")
		w.Header().Set("Authorization", "Bearer private-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"fixture-api-token","long":"fixture-api-token-extra","note":"fixture-private-note","card":"4111111111111111","existing":"[REDACTED]"}`))
	}))
	defer upstream.Close()

	inputs := []struct {
		name     string
		args     map[string]any
		canRun   bool
		approval string
		scope    []string
		wantHits int
	}{
		{name: "bearer_get_response_redaction", args: map[string]any{"template": "fixture", "endpoint": "/v1/status"}, canRun: true, approval: "none", wantHits: 1},
		{name: "response_truncated_invalid_utf8", args: map[string]any{"template": "fixture", "endpoint": "/v1/large"}, canRun: true, approval: "none", wantHits: 1},
		{name: "endpoint_denied_no_request", args: map[string]any{"template": "fixture", "endpoint": "/private"}, canRun: true, approval: "none"},
		{name: "method_denied_no_request", args: map[string]any{"template": "fixture", "endpoint": "/v1/status", "method": "POST"}, canRun: true, approval: "none"},
		{name: "capability_denied_no_request", args: map[string]any{"template": "fixture", "endpoint": "/v1/status"}, canRun: false, approval: "none"},
		{name: "approval_denied_no_request", args: map[string]any{"template": "fixture", "endpoint": "/v1/status"}, canRun: true, approval: "deny"},
		{name: "scope_denied_no_request", args: map[string]any{"template": "fixture", "endpoint": "/v1/status"}, canRun: true, approval: "none", scope: []string{"elsewhere/*"}},
	}
	cases := make([]executeAPIRequestCase, 0, len(inputs))
	for _, input := range inputs {
		vaultDir, identity := mockVaultWithEntry(t, "api-fixture", map[string]any{
			"credential": "fixture-api-token", "nested": map[string]any{"private_note": "fixture-private-note", "long_secret": "fixture-api-token-extra"},
		})
		allowedPaths := []string{"*"}
		if input.scope != nil {
			allowedPaths = input.scope
		}
		profile := config.AgentProfile{
			Name: "api-fixture", AllowedPaths: allowedPaths,
			CanRunCommands: config.BoolPtr(input.canRun), ApprovalMode: config.StrPtr(input.approval),
		}
		srv := newTestServerWithVault(t, profile, "stdio", vaultDir)
		srv.vault.Identity = identity
		writeTemplateOverride(t, vaultDir, "fixture", fmt.Sprintf("base_url: %s\nauth_type: bearer\nentry_ref: api-fixture\nallowed_endpoints:\n  - /v1/*\nallowed_methods:\n  - GET\nallow_private: true\n", upstream.URL))
		before := requests.Load()
		result, callErr := srv.handleExecuteAPIRequest(context.Background(), mcp.CallToolRequest{Arguments: input.args})
		item := executeAPIRequestCase{Name: input.name, Arguments: input.args}
		if callErr != nil {
			item.Error, item.IsError = callErr.Error(), true
		} else if result == nil {
			t.Fatalf("%s: handler returned nil result", input.name)
		} else {
			item.Text, item.IsError = result.Text, result.IsError
		}
		item.Requests = int(requests.Load() - before)
		if item.Requests != input.wantHits {
			t.Fatalf("%s: upstream requests=%d want %d", input.name, item.Requests, input.wantHits)
		}
		if !item.IsError && item.Error == "" {
			var output map[string]any
			if err := json.Unmarshal([]byte(item.Text), &output); err != nil {
				t.Fatalf("decode Go response projection: %v", err)
			}
			headers, ok := output["headers"].(map[string]any)
			if !ok {
				t.Fatalf("Go response headers have unexpected type: %T", output["headers"])
			}
			if _, exists := headers["Date"]; exists {
				headers["Date"] = "<fixture-date>"
			}
			data, err := json.Marshal(output)
			if err != nil {
				t.Fatalf("normalize Go response projection: %v", err)
			}
			item.Text = string(data)
		}
		if input.name == "bearer_get_response_redaction" {
			if strings.Contains(item.Text, "fixture-api-token") || strings.Contains(item.Text, "fixture-private-note") || strings.Contains(item.Text, "4111111111111111") {
				t.Fatalf("Go handler failed to redact response values: %s", item.Text)
			}
		}
		if input.name == "response_truncated_invalid_utf8" {
			var output map[string]any
			if err := json.Unmarshal([]byte(item.Text), &output); err != nil {
				t.Fatalf("decode truncated Go response: %v", err)
			}
			if output["body_truncated"] != true || !strings.Contains(output["body"].(string), "�") {
				t.Fatalf("Go truncation/UTF-8 projection did not match fixture intent: %#v", output)
			}
		}
		cases = append(cases, item)
	}
	fixture := executeAPIRequestFixture{SchemaVersion: 1, Normalizations: []string{"response.headers.Date: replace the local httptest server's wall-clock Date with <fixture-date>"}, Oracle: executeAPIRequestFixtureRefs{
		Commit: executeAPIRequestOracleCommit, CommitSHA: executeAPIRequestOracleCommit,
		SourceFiles: files, SourceDigest: sourceDigest, GeneratorFiles: generatorFiles, GeneratorHash: generatorHash,
	}, Cases: cases}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata/port/mcp/execute-api-request.json")
	if check {
		actual, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != string(data) {
			t.Fatal("execute API request fixture is stale; run the source-bound generator")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func executeAPIRequestRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate generator source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func executeAPIRequestWorkingDigest(t *testing.T, root string, files []string) string {
	t.Helper()
	h := sha256.New()
	for _, file := range files {
		contents, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatalf("read source %s: %v", file, err)
		}
		fmt.Fprintf(h, "%s\x00", file)
		_, _ = h.Write(contents)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func executeAPIRequestGitDigest(t *testing.T, root, commit string, files []string) string {
	t.Helper()
	h := sha256.New()
	for _, file := range files {
		cmd := exec.Command("git", "show", commit+":"+file)
		cmd.Dir = root
		contents, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned source blob %s:%s: %v", commit, file, err)
		}
		fmt.Fprintf(h, "%s\x00", file)
		_, _ = h.Write(contents)
	}
	return hex.EncodeToString(h.Sum(nil))
}
