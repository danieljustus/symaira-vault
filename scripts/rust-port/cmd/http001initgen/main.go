// Command http001initgen captures the Go MCP HTTP initialize response over
// loopback and binds it to the production handler source at the pinned commit.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/auth"
	mcpserver "github.com/danieljustus/symaira-vault/internal/mcp/server"
	"github.com/danieljustus/symaira-vault/internal/mcp/serverbootstrap"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const oracleCommit = "d1cd0f97ac550bc3020bc86b0514989f8d28d95c"

var sources = []string{
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

type fixture struct {
	SchemaVersion int           `json:"schema_version"`
	Oracle        oracle        `json:"oracle"`
	ServerName    string        `json:"server_name"`
	ServerVersion string        `json:"server_version"`
	Cases         []caseFixture `json:"cases"`
}

type caseFixture struct {
	Name            string   `json:"name"`
	GoAuthenticated bool     `json:"go_authenticated"`
	Request         request  `json:"request"`
	Response        response `json:"response"`
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

type request struct {
	Method                 string   `json:"method"`
	Path                   string   `json:"path"`
	Host                   string   `json:"host,omitempty"`
	Origin                 string   `json:"origin,omitempty"`
	ContentType            string   `json:"content_type"`
	Accept                 string   `json:"accept"`
	ProtocolVersion        string   `json:"protocol_version"`
	Agent                  string   `json:"agent"`
	TokenName              string   `json:"token_name,omitempty"`
	TokenAgent             string   `json:"token_agent,omitempty"`
	AllowedTools           []string `json:"allowed_tools,omitempty"`
	Authenticated          bool     `json:"authenticated"`
	Body                   string   `json:"body"`
	BodyRepeat             int      `json:"body_repeat,omitempty"`
	HeaderRepeat           int      `json:"header_repeat,omitempty"`
	HTTPVersion            string   `json:"http_version,omitempty"`
	RequestLineRepeat      int      `json:"request_line_repeat,omitempty"`
	DuplicateAuthorization bool     `json:"duplicate_authorization,omitempty"`
	DuplicateContentLength bool     `json:"duplicate_content_length,omitempty"`
}

type response struct {
	Status           int               `json:"status"`
	Headers          map[string]string `json:"headers"`
	AbsentHeader     []string          `json:"absent_headers"`
	Body             string            `json:"body"`
	ConnectionReused bool              `json:"connection_reused,omitempty"`
}

func main() {
	checkOnly := flag.Bool("check", false, "verify the committed fixture without writing it")
	outputPath := flag.String("output", "testdata/port/mcp/http-initialize.json", "fixture output path")
	flag.Parse()
	root, err := os.Getwd()
	check(err)
	sha, err := provenance.Verify(root, oracleCommit, sources)
	check(err)
	digest, err := provenance.Digest(root, sources)
	check(err)

	vaultDir, err := os.MkdirTemp("", "http001-init-oracle-")
	check(err)
	defer func() { _ = os.RemoveAll(vaultDir) }()
	// In-process selection is not package-init isolation: imported packages may
	// already have selected a backend. Make targets set memory before `go run`;
	// this setting protects runtime lookups that happen later.
	oldEnvironment := make(map[string]*string)
	for key, value := range map[string]string{
		"HOME":                  filepath.Join(vaultDir, "home"),
		"USERPROFILE":           filepath.Join(vaultDir, "home"),
		"XDG_CONFIG_HOME":       filepath.Join(vaultDir, "config"),
		"XDG_DATA_HOME":         filepath.Join(vaultDir, "data"),
		"XDG_CACHE_HOME":        filepath.Join(vaultDir, "cache"),
		"SYMVAULT_TEST_KEYRING": "memory",
	} {
		if previous, present := os.LookupEnv(key); present {
			oldEnvironment[key] = &previous
		} else {
			oldEnvironment[key] = nil
		}
		check(os.Setenv(key, value))
	}
	defer func() {
		for key, previous := range oldEnvironment {
			if previous == nil {
				check(os.Unsetenv(key))
			} else {
				check(os.Setenv(key, *previous))
			}
		}
	}()
	registry := auth.NewTokenRegistry(auth.TokenRegistryFilePath(vaultDir))
	check(registry.Load())
	tokens := map[string]string{}
	for _, scoped := range []struct {
		name  string
		agent string
		tools []string
	}{
		{name: "default", agent: "default", tools: []string{"*"}},
		{name: "health", agent: "default", tools: []string{"health"}},
		{name: "limited", agent: "default", tools: []string{"list_entries"}},
	} {
		_, raw, createErr := registry.Create(scoped.name, scoped.tools, scoped.agent, time.Hour)
		check(createErr)
		tokens[scoped.name] = raw
	}
	token := tokens["default"]
	cfg := config.Default()
	cfg.MCP = &config.MCPConfig{AllowInsecureBind: true}
	vault := &vaultpkg.Vault{Dir: vaultDir, Config: cfg}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	check(err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serverbootstrap.RunHTTPServerOnListener(ctx, listener, vault, vaultDir, "fixture", func(*vaultpkg.Vault, string, string) (*mcpserver.Server, error) {
			return &mcpserver.Server{}, nil
		})
	}()
	defer func() {
		cancel()
		select {
		case serverErr := <-done:
			if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
				fmt.Fprintln(os.Stderr, serverErr)
				os.Exit(1)
			}
		case <-time.After(8 * time.Second):
			_ = listener.Close()
			check(errors.New("HTTP oracle server did not complete its bounded shutdown"))
		}
	}()

	client := &http.Client{Timeout: 4 * time.Second}
	requests := []caseFixture{
		{
			Name:            "initialize",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "text/event-stream, application/json", ProtocolVersion: "2025-11-25", Agent: "default", Authenticated: true, Body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`},
		},
		{
			Name:            "authenticated_prompts_list_after_initialize",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Authenticated: true, Body: `{"jsonrpc":"2.0","id":2,"method":"prompts/list"}`},
		},
		{
			Name:            "authenticated_sse_only_prompts_list_rejected",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Authenticated: true, Body: `{"jsonrpc":"2.0","id":22,"method":"prompts/list"}`},
		},
		{
			Name:            "authenticated_initialized_notification_accepted",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Authenticated: true, Body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`},
		},
		{
			Name:            "authenticated_prompts_list_after_initialized_notification",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Authenticated: true, Body: `{"jsonrpc":"2.0","id":21,"method":"prompts/list"}`},
		},
		{
			Name:            "authenticated_sse_get_rejected_with_allow_post",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodGet, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Authenticated: true, Body: ""},
		},
		{
			Name:            "authenticated_unsupported_protocol_version",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "1999-01-01", Agent: "default", Authenticated: true, Body: `{"jsonrpc":"2.0","id":3,"method":"prompts/list"}`},
		},
		{
			Name:            "missing_bearer_rejected",
			GoAuthenticated: false,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Body: `{"jsonrpc":"2.0","id":4,"method":"initialize"}`},
		},
		{
			Name:            "initialize_health_token",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", TokenAgent: "default", AllowedTools: []string{"health"}, Authenticated: true, Body: `{"jsonrpc":"2.0","id":8,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`},
		},
		{
			Name:            "authenticated_allowed_health_tool",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "text/event-stream, application/json", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", TokenAgent: "default", AllowedTools: []string{"health"}, Authenticated: true, Body: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"health","arguments":{}}}`},
		},
		{
			Name:            "authenticated_sse_only_health_tool_rejected",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", TokenAgent: "default", AllowedTools: []string{"health"}, Authenticated: true, Body: `{"jsonrpc":"2.0","id":24,"method":"tools/call","params":{"name":"health","arguments":{}}}`},
		},
		{
			Name:            "token_agent_mismatch_rejected",
			GoAuthenticated: false,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "other", TokenName: "health", TokenAgent: "default", AllowedTools: []string{"health"}, Authenticated: true, Body: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"health","arguments":{}}}`},
		},
		{
			Name:            "initialize_limited_token",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "limited", TokenAgent: "default", AllowedTools: []string{"list_entries"}, Authenticated: true, Body: `{"jsonrpc":"2.0","id":9,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`},
		},
		{
			Name:            "authenticated_tool_scope_denied",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "limited", TokenAgent: "default", AllowedTools: []string{"list_entries"}, Authenticated: true, Body: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_entry","arguments":{"path":"fixture"}}}`},
		},
		{
			Name:            "foreign_origin_rejected",
			GoAuthenticated: false,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "127.0.0.1", Origin: "https://attacker.example", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Body: `{"jsonrpc":"2.0","id":10,"method":"initialize"}`},
		},
		{
			Name:            "malformed_origin_rejected",
			GoAuthenticated: false,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "127.0.0.1", Origin: "http://%", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Body: `{"jsonrpc":"2.0","id":11,"method":"initialize"}`},
		},
		{
			Name:            "matching_host_and_origin_reaches_authentication",
			GoAuthenticated: false,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "attacker.example", Origin: "https://attacker.example", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Body: `{"jsonrpc":"2.0","id":12,"method":"initialize"}`},
		},
		{
			Name:            "malformed_content_type_rejected",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "127.0.0.1", Origin: "http://127.0.0.1", ContentType: `application/json; charset="broken;still`, Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", Authenticated: true, Body: `{"jsonrpc":"2.0","id":13,"method":"prompts/list"}`},
		},
		{
			Name:            "malformed_accept_rejected",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "127.0.0.1", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: `text/event-stream, application/json; q="broken,still`, ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", Authenticated: true, Body: `{"jsonrpc":"2.0","id":14,"method":"prompts/list"}`},
		},
		{
			Name:            "oversized_body_rejected",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "127.0.0.1", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", Authenticated: true, BodyRepeat: (1 << 20) + 1},
		},
		{
			Name:            "oversized_header_reaches_mcp_handler",
			GoAuthenticated: false,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "127.0.0.1", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", Authenticated: true, HeaderRepeat: 17 * 1024, Body: `{"jsonrpc":"2.0","id":15,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`},
		},
		{
			Name:            "content_type_quoted_semicolon_accepted",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "127.0.0.1", Origin: "http://127.0.0.1", ContentType: `application/json; profile="a;b"`, Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", Authenticated: true, Body: `{"jsonrpc":"2.0","id":16,"method":"prompts/list"}`},
		},
		{
			Name:            "accept_quoted_comma_rejected",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "127.0.0.1", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: `application/json; q="a,b", text/event-stream`, ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", Authenticated: true, Body: `{"jsonrpc":"2.0","id":17,"method":"prompts/list"}`},
		},
		{
			Name:            "duplicate_authorization_first_value_reaches_handler",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "127.0.0.1", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", Authenticated: true, DuplicateAuthorization: true, Body: `{"jsonrpc":"2.0","id":18,"method":"prompts/list"}`},
		},
		{
			Name:            "duplicate_content_length_rejected_by_go_parser",
			GoAuthenticated: false,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", DuplicateContentLength: true, Body: ""},
		},
		{
			Name:            "http_10_initialize_accepted",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "127.0.0.1", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", Authenticated: true, HTTPVersion: "HTTP/1.0", Body: `{"jsonrpc":"2.0","id":19,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`},
		},
		{
			Name:            "oversized_request_line_reaches_handler",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Host: "127.0.0.1", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", Authenticated: true, RequestLineRepeat: 16 * 1024, Body: `{"jsonrpc":"2.0","id":20,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`},
		},
	}
	for i := range requests {
		if usesRawRequest(requests[i].Request) {
			requests[i].Response = doRawRequest(listener.Addr().String(), token, tokens, requests[i].Request)
		} else {
			requests[i].Response = doRequest(client, listener.Addr().String(), token, tokens, requests[i].Request)
		}
	}

	out := fixture{
		SchemaVersion: 1,
		Oracle:        oracle{Commit: oracleCommit, CommitSHA: sha, SourceFiles: sources, SourceDigest: digest},
		ServerName:    "symaira",
		ServerVersion: "1.0.0",
		Cases:         requests,
	}
	out.Oracle.GeneratorFiles = []string{"scripts/rust-port/cmd/http001initgen/main.go"}
	out.Oracle.GeneratorDigest, err = provenance.Digest(root, out.Oracle.GeneratorFiles)
	check(err)
	encoded, err := json.MarshalIndent(out, "", "  ")
	check(err)
	encoded = append(encoded, '\n')
	if *checkOnly {
		current, readErr := os.ReadFile(*outputPath)
		check(readErr)
		if string(current) != string(encoded) {
			check(fmt.Errorf("HTTP-001 fixture drift: regenerate with make mcp-http-init-fixtures-generate (set PORT_MCP_HTTP_INIT_FIXTURE for a custom output)"))
		}
		return
	}
	check(os.WriteFile(*outputPath, encoded, 0o600))
}

func doRequest(client *http.Client, addr, token string, scopedTokens map[string]string, req request) response {
	body := req.Body
	if req.BodyRepeat > 0 {
		body = strings.Repeat("x", req.BodyRepeat)
	}
	httpReq, err := http.NewRequest(req.Method, "http://"+addr+req.Path, strings.NewReader(body))
	check(err)
	if req.Host != "" {
		httpReq.Host = req.Host
	}
	httpReq.Header.Set("Content-Type", req.ContentType)
	httpReq.Header.Set("Accept", req.Accept)
	httpReq.Header.Set("MCP-Protocol-Version", req.ProtocolVersion)
	if req.Authenticated {
		bearer := token
		if req.TokenName != "" {
			bearer = scopedTokens[req.TokenName]
		}
		httpReq.Header.Set("Authorization", "Bearer "+bearer)
	}
	if req.Origin != "" {
		httpReq.Header.Set("Origin", req.Origin)
	}
	httpReq.Header.Set("X-Symaira-Agent", req.Agent)
	if req.HeaderRepeat > 0 {
		httpReq.Header.Set("X-Rust-Port-Fixture", strings.Repeat("x", req.HeaderRepeat))
	}
	connectionReused := false
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		connectionReused = info.Reused
	}}
	httpReq = httpReq.WithContext(httptrace.WithClientTrace(httpReq.Context(), trace))
	httpResp, err := client.Do(httpReq)
	check(err)
	return captureResponse(httpResp, connectionReused)
}

func captureResponse(httpResp *http.Response, connectionReused bool) response {
	responseBody, err := io.ReadAll(httpResp.Body)
	_ = httpResp.Body.Close()
	check(err)
	headers := map[string]string{"Content-Length": strconv.FormatInt(httpResp.ContentLength, 10)}
	if value := httpResp.Header.Get("Content-Type"); value != "" {
		headers["Content-Type"] = value
	}
	if value := httpResp.Header.Get("Allow"); value != "" {
		headers["Allow"] = value
	}
	absent := []string{}
	if httpResp.Header.Get("MCP-Protocol-Version") == "" {
		absent = append(absent, "MCP-Protocol-Version")
	}
	sort.Strings(absent)
	return response{Status: httpResp.StatusCode, Headers: headers, AbsentHeader: absent, Body: string(responseBody), ConnectionReused: connectionReused}
}

func usesRawRequest(req request) bool {
	return req.HTTPVersion != "" || req.RequestLineRepeat > 0 || req.DuplicateAuthorization || req.DuplicateContentLength
}

func doRawRequest(addr, token string, scopedTokens map[string]string, req request) response {
	version := req.HTTPVersion
	if version == "" {
		version = "HTTP/1.1"
	}
	path := req.Path
	if req.RequestLineRepeat > 0 {
		path += "?x=" + strings.Repeat("x", req.RequestLineRepeat)
	}
	body := req.Body
	if req.BodyRepeat > 0 {
		body = strings.Repeat("x", req.BodyRepeat)
	}
	var wire strings.Builder
	fmt.Fprintf(&wire, "%s %s %s\r\nHost: %s\r\n", req.Method, path, version, req.Host)
	if req.Origin != "" {
		fmt.Fprintf(&wire, "Origin: %s\r\n", req.Origin)
	}
	if req.Authenticated {
		bearer := token
		if req.TokenName != "" {
			bearer = scopedTokens[req.TokenName]
		}
		fmt.Fprintf(&wire, "Authorization: Bearer %s\r\n", bearer)
		if req.DuplicateAuthorization {
			wire.WriteString("Authorization: Bearer invalid-second-value\r\n")
		}
	}
	fmt.Fprintf(&wire, "X-Symaira-Agent: %s\r\nContent-Type: %s\r\nAccept: %s\r\nMCP-Protocol-Version: %s\r\nContent-Length: %d\r\n", req.Agent, req.ContentType, req.Accept, req.ProtocolVersion, len(body))
	if req.DuplicateContentLength {
		fmt.Fprintf(&wire, "Content-Length: %d\r\n", len(body)+1)
	}
	wire.WriteString("Connection: close\r\n\r\n")
	wire.WriteString(body)
	conn, err := net.DialTimeout("tcp", addr, 4*time.Second)
	check(err)
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	_, err = io.WriteString(conn, wire.String())
	check(err)
	httpResp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: req.Method})
	check(err)
	return captureResponse(httpResp, false)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
