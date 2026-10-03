package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/ssrf"
)

type executeAPIHTTPSFixture struct {
	SchemaVersion int                       `json:"schema_version"`
	Oracle        executeAPIHTTPSFixtureRef `json:"oracle"`
	Cases         []executeAPIHTTPSCase     `json:"cases"`
}

type executeAPIHTTPSFixtureRef struct {
	Commit         string   `json:"commit"`
	CommitSHA      string   `json:"commit_sha"`
	SourceFiles    []string `json:"source_files"`
	SourceDigest   string   `json:"source_digest"`
	GeneratorFiles []string `json:"generator_files"`
	GeneratorHash  string   `json:"generator_hash"`
}

type executeAPIHTTPSCase struct {
	Name      string `json:"name"`
	Host      string `json:"host"`
	IsError   bool   `json:"is_error"`
	Requests  int    `json:"requests"`
	Status    int    `json:"status,omitempty"`
	Body      string `json:"body,omitempty"`
	ErrorKind string `json:"error_kind,omitempty"`
}

const executeAPIHTTPSOracleCommit = "55da4ca13ead39d4000cf6f866ac8671ca86d8f2"

var executeAPIHTTPSSourceFiles = []string{
	"internal/mcp/server/tools_execute_api_request.go",
	"internal/ssrf/ssrf.go",
}

func TestGenerateMCPExecuteAPIHTTPSFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_EXECUTE_API_HTTPS_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_EXECUTE_API_HTTPS_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_EXECUTE_API_HTTPS_FIXTURE=1 or SYMAIRA_CHECK_MCP_EXECUTE_API_HTTPS_FIXTURE=1")
	}
	root := executeAPIRequestRepoRoot(t)
	files := append([]string(nil), executeAPIHTTPSSourceFiles...)
	sourceDigest := executeAPIRequestGitDigest(t, root, executeAPIHTTPSOracleCommit, files)
	if working := executeAPIRequestWorkingDigest(t, root, files); working != sourceDigest {
		t.Fatalf("Go HTTPS production sources differ from pinned oracle %s: working=%s pinned=%s", executeAPIHTTPSOracleCommit, working, sourceDigest)
	}
	generatorFiles := []string{
		"internal/mcp/server/mcp_execute_api_https_fixture_generator_test.go",
		"internal/mcp/server/mcp_execute_api_request_fixture_generator_test.go",
		"internal/mcp/server/tools_execute_api_request_test.go",
		"internal/mcp/server/tools_test_helpers.go",
		"crates/symvault-mcp/tests/fixtures/tls-ca.pem",
		"crates/symvault-mcp/tests/fixtures/tls-server.pem",
		"crates/symvault-mcp/tests/fixtures/tls-server.key",
	}
	generatorHash := executeAPIRequestWorkingDigest(t, root, generatorFiles)

	oldFactory := newExecuteAPIRequestHTTPClient
	t.Cleanup(func() { newExecuteAPIRequestHTTPClient = oldFactory })
	rootPEM, err := os.ReadFile(filepath.Join(root, "crates/symvault-mcp/tests/fixtures/tls-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("load fixture TLS root")
	}
	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join(root, "crates/symvault-mcp/tests/fixtures/tls-server.pem"),
		filepath.Join(root, "crates/symvault-mcp/tests/fixtures/tls-server.key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	inputs := []struct {
		name  string
		host  string
		bind  string
		trust bool
	}{
		{name: "valid_local_tls", host: "127.0.0.1", bind: "127.0.0.1:0", trust: true},
		{name: "wrong_hostname_tls", host: "wrong.example.test", bind: "127.0.0.1:0", trust: true},
		{name: "untrusted_root_tls", host: "127.0.0.1", bind: "127.0.0.1:0"},
	}
	cases := make([]executeAPIHTTPSCase, 0, len(inputs))
	for _, input := range inputs {
		listener, err := net.Listen("tcp", input.bind)
		if err != nil {
			t.Fatalf("bind synthetic TLS listener %s: %v", input.bind, err)
		}
		var requests atomic.Int64
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.Method != http.MethodGet || r.URL.Path != "/v1/status" {
				http.Error(w, "unexpected request", http.StatusBadRequest)
				return
			}
			if r.Header.Get("Authorization") != "Bearer synthetic-only" {
				http.Error(w, "missing synthetic credential", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "fixture tls ok")
		}))
		server.Listener = listener
		server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
		server.StartTLS()
		baseURL := fmt.Sprintf("https://%s:%d", input.host, listener.Addr().(*net.TCPAddr).Port)
		if input.trust {
			newExecuteAPIRequestHTTPClient = func(timeout time.Duration, allowPrivate bool) *http.Client {
				client := ssrf.NewHTTPClientWithTLSConfig(timeout, allowPrivate, &tls.Config{
					RootCAs: roots, MinVersion: tls.VersionTLS12,
				})
				if input.name == "wrong_hostname_tls" {
					transport := client.Transport.(*http.Transport)
					destination := listener.Addr().String()
					dialer := &net.Dialer{Timeout: timeout}
					transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
						return dialer.DialContext(ctx, network, destination)
					}
				}
				return client
			}
		} else {
			newExecuteAPIRequestHTTPClient = ssrf.NewHTTPClient
		}

		vaultDir, identity := mockVaultWithEntry(t, "api-fixture", map[string]any{"credential": "synthetic-only"})
		profile := config.AgentProfile{
			Name: "api-fixture", AllowedPaths: []string{"*"},
			CanRunCommands: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
		}
		srv := newTestServerWithVault(t, profile, "stdio", vaultDir)
		srv.vault.Identity = identity
		writeTemplateOverride(t, vaultDir, "fixture", fmt.Sprintf(
			"base_url: %s\nauth_type: bearer\nentry_ref: api-fixture\nallowed_endpoints: [/v1/*]\nallowed_methods: [GET]\nallow_private: true\n", baseURL))
		result, callErr := srv.handleExecuteAPIRequest(context.Background(), mcp.CallToolRequest{Arguments: map[string]any{
			"template": "fixture", "endpoint": "/v1/status",
		}})
		item := executeAPIHTTPSCase{Name: input.name, Host: input.host, Requests: int(requests.Load())}
		var handlerError string
		if callErr != nil {
			item.IsError, item.ErrorKind = true, "handler_error"
		} else if result == nil {
			t.Fatalf("%s: nil handler result", input.name)
		} else if result.IsError {
			item.IsError, item.ErrorKind = true, "request_failed"
			handlerError = result.Text
		} else {
			var response struct {
				Status int    `json:"status_code"`
				Body   string `json:"body"`
			}
			if err := json.Unmarshal([]byte(result.Text), &response); err != nil {
				t.Fatalf("%s: decode handler result: %v", input.name, err)
			}
			item.Status, item.Body = response.Status, response.Body
		}
		wantError := input.name != "valid_local_tls"
		wantRequests := 1
		if wantError {
			wantRequests = 0
		}
		if item.IsError != wantError || item.Requests != wantRequests {
			t.Fatalf("%s: result=%+v handler_error=%q want error=%t requests=%d", input.name, item, handlerError, wantError, wantRequests)
		}
		cases = append(cases, item)
		server.Close()
	}

	fixture := executeAPIHTTPSFixture{SchemaVersion: 1, Oracle: executeAPIHTTPSFixtureRef{
		Commit: executeAPIHTTPSOracleCommit, CommitSHA: executeAPIHTTPSOracleCommit,
		SourceFiles: files, SourceDigest: sourceDigest, GeneratorFiles: generatorFiles, GeneratorHash: generatorHash,
	}, Cases: cases}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata/port/mcp/execute-api-https.json")
	if check {
		actual, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != string(data) {
			t.Fatal("execute API HTTPS fixture is stale; run the source-bound generator")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
