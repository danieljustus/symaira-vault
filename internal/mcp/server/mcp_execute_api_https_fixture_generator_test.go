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

const executeAPIHTTPSOracleCommit = "d1cd0f97ac550bc3020bc86b0514989f8d28d95c"

var executeAPIHTTPSSourceFiles = []string{
	"internal/approval/enroll.go",
	"internal/approval/http.go",
	"internal/approval/local.go",
	"internal/approval/queue.go",
	"internal/config/config.go",
	"internal/config/config_load.go",
	"internal/config/config_merge.go",
	"internal/config/config_save.go",
	"internal/config/config_validate.go",
	"internal/config/dottedpath.go",
	"internal/config/migrate.go",
	"internal/config/migrate_copy_unix.go",
	"internal/config/migrate_copy_windows.go",
	"internal/config/migrate_source_unix.go",
	"internal/config/migrate_source_windows.go",
	"internal/config/paths.go",
	"internal/config/presets.go",
	"internal/config/schema.go",
	"internal/config/warn.go",
	"internal/crypto/age.go",
	"internal/crypto/argon2_resources.go",
	"internal/crypto/argon2id.go",
	"internal/crypto/diceware.go",
	"internal/crypto/hmac.go",
	"internal/crypto/interop.go",
	"internal/crypto/keygen.go",
	"internal/crypto/keystore.go",
	"internal/crypto/password.go",
	"internal/crypto/secstring_other.go",
	"internal/crypto/secstring_unix.go",
	"internal/crypto/symmetric.go",
	"internal/crypto/totp.go",
	"internal/fsutil/createsensitiveoutput.go",
	"internal/fsutil/doc.go",
	"internal/fsutil/reexport.go",
	"internal/fsutil/safepath/doc.go",
	"internal/fsutil/safepath/manager_unix.go",
	"internal/fsutil/safepath/manager_windows.go",
	"internal/fsutil/safepath/safepath.go",
	"internal/fsutil/safewrite_windows.go",
	"internal/mcp/apitemplates/auth.go",
	"internal/mcp/apitemplates/template.go",
	"internal/mcp/auth/auth.go",
	"internal/mcp/auth/token.go",
	"internal/mcp/auth/token_ratelimit.go",
	"internal/mcp/errors/codes.go",
	"internal/mcp/install/agent.go",
	"internal/mcp/install/config.go",
	"internal/mcp/install/detect.go",
	"internal/mcp/install/installer.go",
	"internal/mcp/masking/doc.go",
	"internal/mcp/masking/sanitizer.go",
	"internal/mcp/masking/validator.go",
	"internal/mcp/mcptypes.go",
	"internal/mcp/server/approval.go",
	"internal/mcp/server/approval_helper.go",
	"internal/mcp/server/command_policy.go",
	"internal/mcp/server/grant_keys.go",
	"internal/mcp/server/grant_keys_fallback.go",
	"internal/mcp/server/hooks.go",
	"internal/mcp/server/hooks_builtin.go",
	"internal/mcp/server/http_helpers.go",
	"internal/mcp/server/leanmode.go",
	"internal/mcp/server/prompt_registry.go",
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/render.go",
	"internal/mcp/server/secure_input.go",
	"internal/mcp/server/server.go",
	"internal/mcp/server/server_approval.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/setup.go",
	"internal/mcp/server/sharing_store.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_audit_self.go",
	"internal/mcp/server/tools_auth.go",
	"internal/mcp/server/tools_autotype.go",
	"internal/mcp/server/tools_clipboard.go",
	"internal/mcp/server/tools_delete.go",
	"internal/mcp/server/tools_execute_api_request.go",
	"internal/mcp/server/tools_execute_with_secret.go",
	"internal/mcp/server/tools_find.go",
	"internal/mcp/server/tools_generate.go",
	"internal/mcp/server/tools_get.go",
	"internal/mcp/server/tools_health.go",
	"internal/mcp/server/tools_list.go",
	"internal/mcp/server/tools_perplexity.go",
	"internal/mcp/server/tools_prepare_payment.go",
	"internal/mcp/server/tools_request_credential.go",
	"internal/mcp/server/tools_run.go",
	"internal/mcp/server/tools_sanitize.go",
	"internal/mcp/server/tools_search.go",
	"internal/mcp/server/tools_search_openai.go",
	"internal/mcp/server/tools_secure_input.go",
	"internal/mcp/server/tools_set.go",
	"internal/mcp/server/tools_sharing.go",
	"internal/mcp/server/tools_template.go",
	"internal/mcp/server/tools_test_helpers.go",
	"internal/mcp/server/tools_totp.go",
	"internal/mcp/server/tools_unseal.go",
	"internal/mcp/server/tools_whoami.go",
	"internal/mcp/serverbootstrap/http.go",
	"internal/mcp/serverbootstrap/http_lifecycle.go",
	"internal/mcp/serverbootstrap/http_metrics.go",
	"internal/mcp/serverbootstrap/http_nometrics.go",
	"internal/mcp/serverbootstrap/http_setup.go",
	"internal/mcp/serverbootstrap/oauth.go",
	"internal/mcp/serverbootstrap/stdio.go",
	"internal/mcp/serverbootstrap/tls.go",
	"internal/mcp/serverbootstrap/wellknown.go",
	"internal/mcp/sharing_types.go",
	"internal/mcp/toolhash.go",
	"internal/mcp/transport/stdio.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/util.go",
	"internal/policy/authorizer.go",
	"internal/policy/context.go",
	"internal/policy/engine.go",
	"internal/policy/parser.go",
	"internal/policy/ratelimit.go",
	"internal/policy/ratelimit_transition.go",
	"internal/policy/types.go",
	"internal/secureui/backend.go",
	"internal/secureui/backend_darwin.go",
	"internal/secureui/backend_other.go",
	"internal/secureui/backend_tty.go",
	"internal/secureui/backend_unix.go",
	"internal/secureui/backend_windows.go",
	"internal/secureui/capslock.go",
	"internal/secureui/capslock_darwin.go",
	"internal/secureui/capslock_linux.go",
	"internal/secureui/capslock_other.go",
	"internal/secureui/runner.go",
	"internal/secureui/secureui.go",
	"internal/ssrf/ssrf.go",
	"internal/template/builtins.go",
	"internal/template/engine.go",
	"internal/template/funcs.go",
	"internal/template/resolver.go",
	"internal/vault/backup_codes.go",
	"internal/vault/cache.go",
	"internal/vault/devices.go",
	"internal/vault/entry.go",
	"internal/vault/entry_canary.go",
	"internal/vault/entry_metadata.go",
	"internal/vault/entry_readwrite.go",
	"internal/vault/entry_resources.go",
	"internal/vault/entry_validate.go",
	"internal/vault/file_digest.go",
	"internal/vault/git.go",
	"internal/vault/index_resources.go",
	"internal/vault/kdf_resource_migration.go",
	"internal/vault/lock_unix.go",
	"internal/vault/lock_windows.go",
	"internal/vault/manifest.go",
	"internal/vault/manifest_updater.go",
	"internal/vault/metrics.go",
	"internal/vault/payment.go",
	"internal/vault/read_admission.go",
	"internal/vault/recipients.go",
	"internal/vault/reencrypt.go",
	"internal/vault/reencrypt_journal.go",
	"internal/vault/reencrypt_journal_unix.go",
	"internal/vault/reencrypt_journal_windows.go",
	"internal/vault/reencrypt_unix.go",
	"internal/vault/reencrypt_windows.go",
	"internal/vault/retention_budget.go",
	"internal/vault/search.go",
	"internal/vault/search_index.go",
	"internal/vault/service.go",
	"internal/vault/symlink_harden.go",
	"internal/vault/symlink_harden_windows.go",
	"internal/vault/sync/sync.go",
	"internal/vault/taint/taint.go",
	"internal/vault/types.go",
	"internal/vault/url.go",
	"internal/vault/vault.go",
	"internal/vault/vault_sync_reconcile.go",
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
