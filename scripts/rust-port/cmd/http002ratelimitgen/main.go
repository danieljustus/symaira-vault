// Command http002ratelimitgen records the Go MCP HTTP per-client rate limiter
// (HTTP-002 / HTTP-001 residual) from the production code and binds the
// fixture to the pinned oracle sources.
//
// Three groups of observations are recorded:
//
//   - stack scenarios drive the real serverbootstrap.RunHTTPServerOnListener
//     over loopback with a configured mcp.rate_limit / mcp.trusted_proxy_ips,
//     so route coverage, order relative to Origin/bearer checks, the 429
//     response bytes and the config defaults are the production wiring;
//   - limiter scenarios drive the production auth.RateLimiterMiddleware with
//     auth.NewRateLimiter on a short real-clock window (window recovery) and
//     over a table of RemoteAddr / proxy-header / trusted-proxy combinations
//     (the client key), canonicalising time to "sleep longer than the
//     window";
//   - eviction scenarios drive auth.RateLimiter directly at a reduced entry cap.
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
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/approval"
	"github.com/danieljustus/symaira-vault/internal/config"
	mcputil "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/mcp/auth"
	mcpserver "github.com/danieljustus/symaira-vault/internal/mcp/server"
	"github.com/danieljustus/symaira-vault/internal/mcp/serverbootstrap"
	"github.com/danieljustus/symaira-vault/internal/pairing"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

// oracleCommit is the first commit that contains the rate-limiter sources
// below unchanged; provenance.Verify refuses to run on any other bytes.
const oracleCommit = "b1da45d1332fdb118b702dedf4addfb28b890cdf"

var sources = []string{
	"internal/approval/http.go",
	"internal/approval/local.go",
	"internal/config/config_merge.go",
	"internal/config/schema.go",
	"internal/mcp/auth/auth.go",
	"internal/mcp/serverbootstrap/http.go",
	"internal/mcp/serverbootstrap/http_setup.go",
	"internal/mcp/util.go",
}

// baseConfigYAML opts into plaintext loopback so the stack can be driven
// without the auto-generated TLS certificate; it states no rate limit.
const baseConfigYAML = "mcp:\n  allow_insecure_bind: true\n"

const generatorFile = "scripts/rust-port/cmd/http002ratelimitgen/main.go"

const (
	initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`
	pingBody       = `{"jsonrpc":"2.0","id":2,"method":"ping"}`
)

type fixture struct {
	SchemaVersion int                `json:"schema_version"`
	Oracle        oracle             `json:"oracle"`
	ServerName    string             `json:"server_name"`
	ServerVersion string             `json:"server_version"`
	Defaults      defaults           `json:"defaults"`
	Stack         []stackScenario    `json:"stack_scenarios"`
	Limiter       []limiterScenario  `json:"limiter_scenarios"`
	Eviction      []evictionScenario `json:"eviction_scenarios"`
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

// defaults are read from the production config constructor, not typed in.
type defaults struct {
	ConfigRateLimit   int    `json:"config_rate_limit"`
	WindowSeconds     int    `json:"window_seconds"`
	MaxEntries        int    `json:"max_entries"`
	CleanupIntervalMs int    `json:"cleanup_interval_ms"`
	Status            int    `json:"status"`
	Body              string `json:"body"`
}

type stackScenario struct {
	Name string `json:"name"`
	// ConfigYAML is loaded by the production config loader (Go) and by the
	// Rust config loader; it is the only source of the knobs.
	ConfigYAML         string      `json:"config_yaml"`
	EffectiveRateLimit int         `json:"effective_config_rate_limit"`
	Steps              []stackStep `json:"steps"`
}

type stackStep struct {
	Note     string       `json:"note"`
	Request  stackRequest `json:"request"`
	Repeat   int          `json:"repeat"`
	Compare  string       `json:"compare"`
	Response response     `json:"response"`
}

type stackRequest struct {
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Headers       map[string]string `json:"headers,omitempty"`
	Authenticated bool              `json:"authenticated,omitempty"`
	Body          string            `json:"body,omitempty"`
}

type response struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type limiterScenario struct {
	Name            string        `json:"name"`
	Limit           int           `json:"limit"`
	WindowMs        int           `json:"window_ms"`
	TrustedProxies  []string      `json:"trusted_proxies,omitempty"`
	Steps           []limiterStep `json:"steps"`
	CanonicalTiming string        `json:"canonical_timing,omitempty"`
}

type limiterStep struct {
	Op         string            `json:"op"`
	SleepMs    int               `json:"sleep_ms,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Allowed    *bool             `json:"allowed,omitempty"`
}

type evictionScenario struct {
	Name          string         `json:"name"`
	Limit         int            `json:"limit"`
	WindowMs      int            `json:"window_ms"`
	MaxEntries    int            `json:"max_entries"`
	Steps         []evictionStep `json:"steps"`
	EvictionCount int64          `json:"eviction_count"`
}

type evictionStep struct {
	Op      string `json:"op"`
	IP      string `json:"ip,omitempty"`
	SleepMs int    `json:"sleep_ms,omitempty"`
	Allowed *bool  `json:"allowed,omitempty"`
}

func main() {
	checkOnly := flag.Bool("check", false, "verify the committed fixture without writing it")
	outputPath := flag.String("output", "testdata/port/mcp/http-ratelimit.json", "fixture output path")
	flag.Parse()
	root, err := os.Getwd()
	check(err)
	sha, err := provenance.Verify(root, oracleCommit, sources)
	check(err)
	digest, err := provenance.Digest(root, sources)
	check(err)

	scratch, err := os.MkdirTemp("", "http002-ratelimit-oracle-")
	check(err)
	defer func() { _ = os.RemoveAll(scratch) }()
	restore := isolateEnvironment(scratch)
	defer restore()

	def, err := config.LoadFromBytes([]byte(baseConfigYAML))
	check(err)
	out := fixture{
		SchemaVersion: 1,
		Oracle:        oracle{Commit: oracleCommit, CommitSHA: sha, SourceFiles: sources, SourceDigest: digest},
		ServerName:    "symaira",
		ServerVersion: "1.0.0",
		Defaults: defaults{
			ConfigRateLimit:   def.MCP.RateLimit,
			WindowSeconds:     60,
			MaxEntries:        auth.MaxRateLimiterEntries,
			CleanupIntervalMs: 5 * 60 * 1000,
		},
	}
	// The 429 bytes come from the production middleware, not from a literal.
	{
		rl := auth.NewRateLimiter(1, time.Minute)
		handler := auth.RateLimiterMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		for i := 0; i < 2; i++ {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mcp", nil))
			if i == 1 {
				out.Defaults.Status = rec.Code
				out.Defaults.Body = rec.Body.String()
			}
		}
		_ = rl.Close()
	}
	out.Stack = stackScenarios(scratch)
	out.Limiter = limiterScenarios()
	out.Eviction = evictionScenarios()
	out.Oracle.GeneratorFiles = []string{generatorFile}
	out.Oracle.GeneratorDigest, err = provenance.Digest(root, out.Oracle.GeneratorFiles)
	check(err)

	encoded, err := json.MarshalIndent(out, "", "  ")
	check(err)
	encoded = append(encoded, '\n')
	if *checkOnly {
		current, readErr := os.ReadFile(*outputPath)
		check(readErr)
		if string(current) != string(encoded) {
			check(fmt.Errorf("HTTP rate-limit fixture drift: regenerate with go run ./scripts/rust-port/cmd/http002ratelimitgen --output %s", *outputPath))
		}
		return
	}
	check(os.WriteFile(*outputPath, encoded, 0o600))
}

func isolateEnvironment(dir string) func() {
	previous := map[string]*string{}
	for key, value := range map[string]string{
		"HOME":                  filepath.Join(dir, "home"),
		"USERPROFILE":           filepath.Join(dir, "home"),
		"XDG_CONFIG_HOME":       filepath.Join(dir, "config"),
		"XDG_DATA_HOME":         filepath.Join(dir, "data"),
		"XDG_CACHE_HOME":        filepath.Join(dir, "cache"),
		"SYMVAULT_TEST_KEYRING": "memory",
	} {
		if old, ok := os.LookupEnv(key); ok {
			previous[key] = &old
		} else {
			previous[key] = nil
		}
		check(os.Setenv(key, value))
	}
	return func() {
		for key, old := range previous {
			if old == nil {
				check(os.Unsetenv(key))
			} else {
				check(os.Setenv(key, *old))
			}
		}
	}
}

// --- stack scenarios ---------------------------------------------------

func mcpHeaders(extra map[string]string) map[string]string {
	h := map[string]string{
		"Content-Type":         "application/json",
		"Accept":               "application/json, text/event-stream",
		"MCP-Protocol-Version": "2025-11-25",
		"Origin":               "http://127.0.0.1",
		"X-Symaira-Agent":      "default",
	}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

func unauthMCP(extra map[string]string) stackRequest {
	return stackRequest{Method: http.MethodPost, Path: "/mcp", Headers: mcpHeaders(extra), Body: pingBody}
}

func authMCP() stackRequest {
	return stackRequest{Method: http.MethodPost, Path: "/mcp", Headers: mcpHeaders(nil), Authenticated: true, Body: initializeBody}
}

func localApprovals(method, path string) stackRequest {
	return stackRequest{Method: method, Path: path}
}

// deviceApprovals targets the device-token approval transport. No bearer is
// sent: an unauthenticated request is answered 401 by the handler, which has
// still consumed a limiter slot, and a wrong method is the handler's own 404.
func deviceApprovals(method, path string) stackRequest {
	return stackRequest{Method: method, Path: path}
}

type plannedStep struct {
	note    string
	request stackRequest
	repeat  int
	compare string
}

func step(note string, req stackRequest, repeat int, compare string) plannedStep {
	return plannedStep{note: note, request: req, repeat: repeat, compare: compare}
}

func stackScenarios(scratch string) []stackScenario {
	type planned struct {
		name    string
		limit   int
		trusted []string
		useDef  bool
		steps   []plannedStep
	}
	loop := []string{"127.0.0.1"}
	plan := []planned{
		{name: "default_config_is_sixty_per_minute", useDef: true, limit: -1, steps: []plannedStep{
			step("60 requests inside one window are served (here: rejected by the bearer check, which still consumes a slot)", unauthMCP(nil), 60, "full"),
			step("the 61st request is limited", unauthMCP(nil), 1, "full"),
			step("a limited client stays limited", unauthMCP(nil), 1, "full"),
			step("health is not behind the limiter", stackRequest{Method: http.MethodGet, Path: "/health"}, 1, "status"),
			step("unrouted paths are not behind the limiter", stackRequest{Method: http.MethodGet, Path: "/nonexistent"}, 1, "full"),
			step("OAuth discovery is not behind the limiter", stackRequest{Method: http.MethodGet, Path: "/.well-known/oauth-protected-resource"}, 1, "status"),
			step("OAuth dynamic registration is not behind the limiter", stackRequest{Method: http.MethodPost, Path: "/oauth/register", Headers: map[string]string{"Content-Type": "application/json", "Origin": "http://127.0.0.1"}, Body: `{}`}, 1, "status"),
			step("OAuth token endpoint is not behind the limiter", stackRequest{Method: http.MethodPost, Path: "/mcp/oauth/token", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "http://127.0.0.1"}, Body: "grant_type=authorization_code"}, 1, "status"),
		}},
		{name: "limit_three_shared_bucket_and_check_order", limit: 3, steps: []plannedStep{
			step("slot 1: /mcp without a bearer is answered by the bearer check", unauthMCP(nil), 1, "full"),
			step("slot 2: the local approval API shares the bucket", localApprovals(http.MethodGet, "/api/v1/local/approvals"), 1, "full"),
			step("slot 3: a valid authenticated initialize is still served", authMCP(), 1, "full"),
			step("a valid authenticated request is limited before authentication", authMCP(), 1, "full"),
			step("the local approval list is limited", localApprovals(http.MethodGet, "/api/v1/local/approvals"), 1, "full"),
			step("a local approval action is limited", localApprovals(http.MethodPost, "/api/v1/local/approvals/x/approve"), 1, "full"),
			step("limiting does not look at the method", stackRequest{Method: http.MethodDelete, Path: "/mcp"}, 1, "full"),
			step("a HEAD request is limited with the same headers and no body", stackRequest{Method: http.MethodHead, Path: "/mcp"}, 1, "full"),
			step("the Origin check runs after the limiter", unauthMCP(map[string]string{"Origin": "https://attacker.example"}), 1, "full"),
			step("a missing Content-Type is never inspected once limited", stackRequest{Method: http.MethodPost, Path: "/mcp", Headers: map[string]string{"Origin": "http://127.0.0.1"}, Body: pingBody}, 1, "full"),
			step("health stays reachable", stackRequest{Method: http.MethodGet, Path: "/health"}, 1, "status"),
			step("unrouted paths stay reachable", stackRequest{Method: http.MethodGet, Path: "/missing"}, 1, "full"),
		}},
		{name: "limit_three_device_approval_routes_share_the_bucket", limit: 3, steps: []plannedStep{
			step("slot 1: the device list without a bearer is answered 401 by the handler, which still consumes a slot", deviceApprovals(http.MethodGet, "/api/v1/approvals"), 1, "full"),
			step("slot 2: a device decision without a bearer shares the bucket", deviceApprovals(http.MethodPost, "/api/v1/approvals/x/approve"), 1, "full"),
			step("slot 3: a method the handler does not route is its own 404 inside the limiter", deviceApprovals(http.MethodDelete, "/api/v1/approvals"), 1, "full"),
			step("the device list is limited", deviceApprovals(http.MethodGet, "/api/v1/approvals"), 1, "full"),
			step("a device decision is limited", deviceApprovals(http.MethodPost, "/api/v1/approvals/x/deny"), 1, "full"),
			step("the device subtree root with a trailing slash is limited", deviceApprovals(http.MethodPost, "/api/v1/approvals/"), 1, "full"),
			step("a device list with a query string is limited", deviceApprovals(http.MethodGet, "/api/v1/approvals?status=pending"), 1, "full"),
			step("/mcp shares the device bucket", unauthMCP(nil), 1, "full"),
			step("the local approval API shares the device bucket", localApprovals(http.MethodGet, "/api/v1/local/approvals"), 1, "full"),
			step("a path the mux cleans is redirected before the limiter", deviceApprovals(http.MethodGet, "/api/v1/./approvals"), 1, "full"),
			step("a sibling prefix is no device route and is not limited", deviceApprovals(http.MethodGet, "/api/v1/approvalsx"), 1, "full"),
			step("the enrollment paths are not mounted here and are not limited", deviceApprovals(http.MethodPost, "/api/v1/devices/enroll"), 1, "full"),
			step("health stays reachable", stackRequest{Method: http.MethodGet, Path: "/health"}, 1, "status"),
		}},
		{name: "zero_disables_the_limiter", limit: 0, steps: []plannedStep{
			step("70 requests exceed the default of 60 yet none is limited", unauthMCP(nil), 70, "full"),
			step("the local approval API is not limited either", localApprovals(http.MethodGet, "/api/v1/local/approvals"), 70, "full"),
			step("the device approval API is not limited either", deviceApprovals(http.MethodGet, "/api/v1/approvals"), 70, "full"),
		}},
		{name: "negative_limit_falls_back_to_sixty", limit: -5, steps: []plannedStep{
			step("60 requests are served", unauthMCP(nil), 60, "full"),
			step("the 61st is limited", unauthMCP(nil), 1, "full"),
		}},
		{name: "proxy_headers_ignored_without_trusted_proxies", limit: 2, steps: []plannedStep{
			step("first request, X-Forwarded-For 10.0.0.1", unauthMCP(map[string]string{"X-Forwarded-For": "10.0.0.1"}), 1, "full"),
			step("second request, a different X-Forwarded-For", unauthMCP(map[string]string{"X-Forwarded-For": "10.0.0.2"}), 1, "full"),
			step("third request, yet another X-Forwarded-For, shares the socket-address bucket", unauthMCP(map[string]string{"X-Forwarded-For": "10.0.0.3"}), 1, "full"),
			step("X-Real-IP does not help either", unauthMCP(map[string]string{"X-Real-IP": "10.0.0.4"}), 1, "full"),
		}},
		{name: "trusted_proxy_keys_by_forwarded_for_then_real_ip", limit: 2, trusted: loop, steps: []plannedStep{
			step("10.0.0.1 slot 1", unauthMCP(map[string]string{"X-Forwarded-For": "10.0.0.1"}), 1, "full"),
			step("only the first X-Forwarded-For element is the key: 10.0.0.1 slot 2", unauthMCP(map[string]string{"X-Forwarded-For": "10.0.0.1, 192.0.2.9"}), 1, "full"),
			step("10.0.0.1 is exhausted", unauthMCP(map[string]string{"X-Forwarded-For": "10.0.0.1"}), 1, "full"),
			step("10.0.0.2 has its own bucket, slot 1", unauthMCP(map[string]string{"X-Forwarded-For": "10.0.0.2"}), 1, "full"),
			step("no header: the socket address 127.0.0.1 is the key, slot 1", unauthMCP(nil), 1, "full"),
			step("X-Real-IP is used when X-Forwarded-For is absent: 10.0.0.2 slot 2", unauthMCP(map[string]string{"X-Real-IP": "10.0.0.2"}), 1, "full"),
			step("10.0.0.2 is exhausted via X-Real-IP", unauthMCP(map[string]string{"X-Real-IP": "10.0.0.2"}), 1, "full"),
			step("X-Forwarded-For wins over X-Real-IP", unauthMCP(map[string]string{"X-Forwarded-For": "10.0.0.2", "X-Real-IP": "10.0.0.9"}), 1, "full"),
			step("whitespace around the first element is trimmed", unauthMCP(map[string]string{"X-Forwarded-For": "  10.0.0.1 , x"}), 1, "full"),
			step("a non-IP value is used verbatim as the key, slot 1", unauthMCP(map[string]string{"X-Forwarded-For": "not-an-ip"}), 1, "full"),
			step("a non-IP value, slot 2", unauthMCP(map[string]string{"X-Forwarded-For": "not-an-ip"}), 1, "full"),
			step("a non-IP value is exhausted", unauthMCP(map[string]string{"X-Forwarded-For": "not-an-ip"}), 1, "full"),
			step("an empty first element is the empty key, slot 1", unauthMCP(map[string]string{"X-Forwarded-For": ", 1.2.3.4"}), 1, "full"),
			step("the empty key, slot 2", unauthMCP(map[string]string{"X-Forwarded-For": ", 1.2.3.4"}), 1, "full"),
			step("the empty key is exhausted", unauthMCP(map[string]string{"X-Forwarded-For": ", 1.2.3.4"}), 1, "full"),
			step("the socket-address bucket is still at slot 1: slot 2", unauthMCP(nil), 1, "full"),
			step("the socket-address bucket is exhausted", unauthMCP(nil), 1, "full"),
			step("the local approval API honours the same key", localApprovals(http.MethodGet, "/api/v1/local/approvals"), 1, "full"),
			step("the device approval API honours the same key", deviceApprovals(http.MethodGet, "/api/v1/approvals"), 1, "full"),
			step("a device decision for another forwarded client has its own bucket, slot 1", stackRequest{Method: http.MethodPost, Path: "/api/v1/approvals/x/approve", Headers: map[string]string{"X-Forwarded-For": "10.0.0.7"}}, 1, "full"),
			step("a device decision for that forwarded client, slot 2", stackRequest{Method: http.MethodPost, Path: "/api/v1/approvals/x/approve", Headers: map[string]string{"X-Forwarded-For": "10.0.0.7"}}, 1, "full"),
			step("a device decision for that forwarded client is exhausted", stackRequest{Method: http.MethodPost, Path: "/api/v1/approvals/x/approve", Headers: map[string]string{"X-Forwarded-For": "10.0.0.7"}}, 1, "full"),
		}},
		{name: "trusted_cidr_with_invalid_entries_ignored", limit: 1, trusted: []string{"bogus", "127.0.0.0/8", "10.0.0.0/33"}, steps: []plannedStep{
			step("10.1.1.1 slot 1", unauthMCP(map[string]string{"X-Forwarded-For": "10.1.1.1"}), 1, "full"),
			step("10.1.1.1 is exhausted", unauthMCP(map[string]string{"X-Forwarded-For": "10.1.1.1"}), 1, "full"),
			step("10.1.1.2 has its own bucket", unauthMCP(map[string]string{"X-Forwarded-For": "10.1.1.2"}), 1, "full"),
		}},
		{name: "only_invalid_or_foreign_trusted_entries_trust_nobody", limit: 1, trusted: []string{"bogus", "10.0.0.0/33", "::1", "10.0.0.0/8"}, steps: []plannedStep{
			step("slot 1 for the socket address", unauthMCP(map[string]string{"X-Forwarded-For": "10.1.1.1"}), 1, "full"),
			step("a different forwarded address is ignored and the socket bucket is exhausted", unauthMCP(map[string]string{"X-Forwarded-For": "10.1.1.2"}), 1, "full"),
		}},
	}

	var scenarios []stackScenario
	for _, p := range plan {
		yaml := baseConfigYAML
		if !p.useDef {
			yaml += fmt.Sprintf("  rate_limit: %d\n", p.limit)
		}
		if len(p.trusted) > 0 {
			yaml += "  trusted_proxy_ips:\n"
			for _, entry := range p.trusted {
				yaml += fmt.Sprintf("    - %q\n", entry)
			}
		}
		cfg, err := config.LoadFromBytes([]byte(yaml))
		check(err)
		sc := stackScenario{Name: p.name, ConfigYAML: yaml, EffectiveRateLimit: cfg.MCP.RateLimit}
		sc.Steps = runStack(scratch, p.name, cfg, p.steps)
		scenarios = append(scenarios, sc)
	}
	return scenarios
}

func runStack(scratch, name string, cfg *config.Config, steps []plannedStep) []stackStep {
	vaultDir, err := os.MkdirTemp(scratch, "stack-")
	check(err)
	registry := auth.NewTokenRegistry(auth.TokenRegistryFilePath(vaultDir))
	check(registry.Load())
	_, token, err := registry.Create("default", []string{"*"}, "default", time.Hour)
	check(err)
	vault := &vaultpkg.Vault{Dir: vaultDir, Config: cfg}
	deviceSessions, err := pairing.NewDeviceSessionStore(vaultDir)
	check(err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	check(err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serverbootstrap.RunHTTPServerOnListener(ctx, listener, vault, vaultDir, "fixture",
			func(*vaultpkg.Vault, string, string) (*mcpserver.Server, error) { return &mcpserver.Server{}, nil },
			serverbootstrap.WithApprovalAPI(approval.NewHTTPHandler(approval.NewQueue(), deviceSessions)),
			serverbootstrap.WithLocalApprovalAPI(approval.NewLocalHTTPHandler(approval.NewQueue(), []byte("fixture-enroll-secret"), mcputil.IsLoopbackHost)))
	}()
	defer func() {
		cancel()
		select {
		case serverErr := <-done:
			if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
				check(serverErr)
			}
		case <-time.After(8 * time.Second):
			_ = listener.Close()
			check(errors.New("HTTP oracle server did not complete its bounded shutdown"))
		}
	}()

	addr := listener.Addr().String()
	out := make([]stackStep, 0, len(steps))
	for _, s := range steps {
		var first response
		for i := 0; i < s.repeat; i++ {
			got := roundTrip(addr, token, s.request)
			if i == 0 {
				first = got
				continue
			}
			if !sameResponse(first, got) {
				check(fmt.Errorf("%s: %q repeat %d differs from the first response: %+v vs %+v", name, s.note, i, first, got))
			}
		}
		rec := first
		if s.compare == "status" {
			rec = response{Status: first.Status}
		}
		out = append(out, stackStep{Note: s.note, Request: s.request, Repeat: s.repeat, Compare: s.compare, Response: rec})
	}
	return out
}

func sameResponse(a, b response) bool {
	if a.Status != b.Status || a.Body != b.Body || len(a.Headers) != len(b.Headers) {
		return false
	}
	for k, v := range a.Headers {
		if b.Headers[k] != v {
			return false
		}
	}
	return true
}

func roundTrip(addr, token string, req stackRequest) response {
	var wire strings.Builder
	fmt.Fprintf(&wire, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, req.Path, addr)
	names := make([]string, 0, len(req.Headers))
	for name := range req.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&wire, "%s: %s\r\n", name, req.Headers[name])
	}
	if req.Authenticated {
		fmt.Fprintf(&wire, "Authorization: Bearer %s\r\n", token)
	}
	if req.Body != "" || req.Method == http.MethodPost {
		fmt.Fprintf(&wire, "Content-Length: %d\r\n", len(req.Body))
	}
	wire.WriteString("Connection: close\r\n\r\n")
	wire.WriteString(req.Body)

	conn, err := net.DialTimeout("tcp", addr, 4*time.Second)
	check(err)
	defer func() { _ = conn.Close() }()
	check(conn.SetDeadline(time.Now().Add(6 * time.Second)))
	_, err = io.WriteString(conn, wire.String())
	check(err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: req.Method})
	check(err)
	body, err := io.ReadAll(resp.Body)
	check(err)
	_ = resp.Body.Close()
	headers := map[string]string{}
	for name, values := range resp.Header {
		if name == "Date" || name == "Connection" {
			continue
		}
		headers[name] = strings.Join(values, ", ")
	}
	return response{Status: resp.StatusCode, Headers: headers, Body: string(body)}
}

// --- limiter scenarios -------------------------------------------------

func boolPtr(v bool) *bool { return &v }

type limiterRequest struct {
	remote  string
	headers map[string]string
}

func runLimiter(name string, limit, windowMs int, trusted []string, ops []limiterStep, canonical string) limiterScenario {
	rl := auth.NewRateLimiter(limit, time.Duration(windowMs)*time.Millisecond, trusted...)
	defer func() { _ = rl.Close() }()
	handler := auth.RateLimiterMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	sc := limiterScenario{Name: name, Limit: limit, WindowMs: windowMs, TrustedProxies: trusted, CanonicalTiming: canonical}
	for _, op := range ops {
		switch op.Op {
		case "sleep":
			time.Sleep(time.Duration(op.SleepMs) * time.Millisecond)
			sc.Steps = append(sc.Steps, limiterStep{Op: "sleep", SleepMs: op.SleepMs})
		case "request":
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			req.RemoteAddr = op.RemoteAddr
			for k, v := range op.Headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			switch rec.Code {
			case http.StatusNoContent:
				op.Allowed = boolPtr(true)
			case http.StatusTooManyRequests:
				op.Allowed = boolPtr(false)
				if rec.Body.String() != "too many requests\n" {
					check(fmt.Errorf("%s: unexpected limiter body %q", name, rec.Body.String()))
				}
			default:
				check(fmt.Errorf("%s: unexpected status %d", name, rec.Code))
			}
			sc.Steps = append(sc.Steps, limiterStep{Op: "request", RemoteAddr: op.RemoteAddr, Headers: op.Headers, Allowed: op.Allowed})
		}
	}
	return sc
}

func req(remote string, headers map[string]string) limiterStep {
	return limiterStep{Op: "request", RemoteAddr: remote, Headers: headers}
}

func sleep(ms int) limiterStep { return limiterStep{Op: "sleep", SleepMs: ms} }

func limiterScenarios() []limiterScenario {
	const longWindow = 60_000
	a := "192.0.2.1:1000"
	var out []limiterScenario
	timing := "real clock; every gap is at least 150 ms away from the window edge, recorded as 'outcome only'"
	out = append(out,
		runLimiter("fixed_window_recovers_after_expiry", 2, 500, nil, []limiterStep{
			req(a, nil), req(a, nil), req(a, nil), req("192.0.2.2:1", nil),
			sleep(700),
			req(a, nil), req(a, nil), req(a, nil),
		}, timing),
		runLimiter("denied_requests_do_not_extend_the_window", 1, 500, nil, []limiterStep{
			req(a, nil), sleep(300), req(a, nil), sleep(300), req(a, nil), req(a, nil),
		}, timing),
		runLimiter("window_is_fixed_from_the_first_request_not_sliding", 2, 600, nil, []limiterStep{
			req(a, nil), sleep(300), req(a, nil), req(a, nil), sleep(450), req(a, nil), req(a, nil), req(a, nil),
		}, timing),
	)

	type keyCase struct {
		name    string
		trusted []string
		first   limiterStep
		second  limiterStep
	}
	h := func(kv ...string) map[string]string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	cases := []keyCase{
		{"socket_port_is_not_part_of_the_key", nil, req("192.0.2.1:1000", nil), req("192.0.2.1:2000", nil)},
		{"different_socket_hosts_have_different_keys", nil, req("192.0.2.1:1000", nil), req("192.0.2.2:1000", nil)},
		{"ipv6_socket_port_is_not_part_of_the_key", nil, req("[2001:db8::1]:80", nil), req("[2001:db8::1]:81", nil)},
		{"ipv6_socket_hosts_differ", nil, req("[2001:db8::1]:80", nil), req("[2001:db8::2]:80", nil)},
		{"forwarded_for_ignored_without_trusted_list", nil, req("192.0.2.1:1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.2.1:2", h("X-Forwarded-For", "2.2.2.2"))},
		{"real_ip_ignored_without_trusted_list", nil, req("192.0.2.1:1", h("X-Real-IP", "1.1.1.1")), req("192.0.2.1:2", h("X-Real-IP", "2.2.2.2"))},
		{"trusted_exact_ip_honours_forwarded_for", []string{"192.0.2.1"}, req("192.0.2.1:1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.2.1:2", h("X-Forwarded-For", "2.2.2.2"))},
		{"trusted_exact_ip_same_forwarded_client_shares_a_key", []string{"192.0.2.1"}, req("192.0.2.1:1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.2.1:2", h("X-Forwarded-For", "1.1.1.1, 9.9.9.9"))},
		{"untrusted_peer_cannot_spoof_forwarded_for", []string{"192.0.2.9"}, req("192.0.2.1:1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.2.1:2", h("X-Forwarded-For", "2.2.2.2"))},
		{"trusted_cidr_v4", []string{"192.0.2.0/24"}, req("192.0.2.77:1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.2.88:1", h("X-Forwarded-For", "2.2.2.2"))},
		{"trusted_cidr_v4_outside_range_is_untrusted", []string{"192.0.2.0/24"}, req("192.0.3.1:1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.3.1:2", h("X-Forwarded-For", "2.2.2.2"))},
		{"trusted_cidr_with_host_bits_set_still_matches", []string{"192.0.2.5/24"}, req("192.0.2.200:1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.2.201:1", h("X-Forwarded-For", "2.2.2.2"))},
		{"trusted_cidr_v6", []string{"2001:db8::/32"}, req("[2001:db8:1::5]:1", h("X-Forwarded-For", "1.1.1.1")), req("[2001:db8:2::5]:1", h("X-Forwarded-For", "2.2.2.2"))},
		{"trusted_exact_v6", []string{"2001:db8::1"}, req("[2001:db8::1]:1", h("X-Forwarded-For", "1.1.1.1")), req("[2001:db8::1]:2", h("X-Forwarded-For", "2.2.2.2"))},
		{"trusted_v4_list_does_not_trust_v6_peer", []string{"192.0.2.0/24"}, req("[2001:db8::1]:1", h("X-Forwarded-For", "1.1.1.1")), req("[2001:db8::1]:2", h("X-Forwarded-For", "2.2.2.2"))},
		{"invalid_prefix_length_is_ignored", []string{"192.0.2.0/33"}, req("192.0.2.1:1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.2.1:2", h("X-Forwarded-For", "2.2.2.2"))},
		{"leading_zero_prefix_length_is_ignored", []string{"192.0.2.0/08"}, req("192.0.2.1:1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.2.1:2", h("X-Forwarded-For", "2.2.2.2"))},
		{"leading_zero_octet_trusted_entry_is_ignored", []string{"192.000.2.1"}, req("192.0.2.1:1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.2.1:2", h("X-Forwarded-For", "2.2.2.2"))},
		{"garbage_trusted_entry_is_ignored", []string{"not-an-ip"}, req("192.0.2.1:1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.2.1:2", h("X-Forwarded-For", "2.2.2.2"))},
		{"empty_trusted_entry_is_ignored", []string{""}, req("192.0.2.1:1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.2.1:2", h("X-Forwarded-For", "2.2.2.2"))},
		{"trusted_forwarded_for_beats_real_ip", []string{"192.0.2.1"}, req("192.0.2.1:1", h("X-Forwarded-For", "1.1.1.1", "X-Real-IP", "8.8.8.8")), req("192.0.2.1:2", h("X-Forwarded-For", "1.1.1.1", "X-Real-IP", "9.9.9.9"))},
		{"trusted_real_ip_used_without_forwarded_for", []string{"192.0.2.1"}, req("192.0.2.1:1", h("X-Real-IP", "8.8.8.8")), req("192.0.2.1:2", h("X-Real-IP", "9.9.9.9"))},
		{"trusted_forwarded_for_first_element_trimmed", []string{"192.0.2.1"}, req("192.0.2.1:1", h("X-Forwarded-For", "  1.1.1.1  , 2.2.2.2")), req("192.0.2.1:2", h("X-Forwarded-For", "1.1.1.1"))},
		{"trusted_forwarded_for_not_validated_as_an_ip", []string{"192.0.2.1"}, req("192.0.2.1:1", h("X-Forwarded-For", "not-an-ip")), req("192.0.2.1:2", h("X-Forwarded-For", "not-an-ip"))},
		{"trusted_forwarded_for_empty_first_element_is_the_empty_key", []string{"192.0.2.1"}, req("192.0.2.1:1", h("X-Forwarded-For", ", 1.1.1.1")), req("192.0.2.1:2", h("X-Forwarded-For", ", 2.2.2.2"))},
		{"trusted_without_headers_keys_by_socket_host", []string{"192.0.2.1"}, req("192.0.2.1:1", nil), req("192.0.2.1:2", nil)},
		{"forwarded_client_shares_the_key_space_with_socket_hosts", []string{"10.0.0.0/8"}, req("10.0.0.1:1", h("X-Forwarded-For", "1.1.1.1")), req("1.1.1.1:9", nil)},
		{"socket_address_without_port_is_the_whole_string", nil, req("192.0.2.1", nil), req("192.0.2.1", nil)},
		{"socket_address_without_port_shares_the_key_of_the_same_host_with_a_port", nil, req("192.0.2.1", nil), req("192.0.2.1:80", nil)},
		{"trusted_peer_without_port_is_matched_by_host", []string{"192.0.2.1"}, req("192.0.2.1", h("X-Forwarded-For", "1.1.1.1")), req("192.0.2.1", h("X-Forwarded-For", "2.2.2.2"))},
	}
	for _, c := range cases {
		out = append(out, runLimiter(c.name, 1, longWindow, c.trusted, []limiterStep{c.first, c.second}, "single window; no clock involved"))
	}
	return out
}

// --- eviction scenarios ------------------------------------------------

func evictionScenarios() []evictionScenario {
	type op = evictionStep
	allow := func(ip string) op { return op{Op: "allow", IP: ip} }
	pause := func(ms int) op { return op{Op: "sleep", SleepMs: ms} }
	run := func(name string, limit, windowMs, maxEntries int, ops []op) evictionScenario {
		rl := auth.NewRateLimiter(limit, time.Duration(windowMs)*time.Millisecond)
		defer func() { _ = rl.Close() }()
		rl.SetMaxEntriesForTests(maxEntries)
		sc := evictionScenario{Name: name, Limit: limit, WindowMs: windowMs, MaxEntries: maxEntries}
		for _, o := range ops {
			switch o.Op {
			case "sleep":
				time.Sleep(time.Duration(o.SleepMs) * time.Millisecond)
			case "allow":
				o.Allowed = boolPtr(rl.Allow(o.IP))
			}
			sc.Steps = append(sc.Steps, o)
		}
		sc.EvictionCount = rl.EvictionCount()
		return sc
	}
	gap := pause(3) // distinct reset times so "oldest" is unambiguous
	return []evictionScenario{
		run("oldest_live_entry_is_evicted_at_the_cap", 1, 60_000, 3, []op{
			allow("a"), gap, allow("b"), gap, allow("c"), gap,
			allow("d"), gap,
			allow("a"), gap,
			allow("c"), allow("d"),
			allow("b"),
		}),
		run("expired_entries_are_dropped_before_live_ones", 1, 150, 3, []op{
			allow("a"), allow("b"), allow("c"),
			pause(350),
			allow("d"), allow("d"),
		}),
		run("under_the_cap_nothing_is_evicted", 1, 60_000, 10, []op{
			allow("a"), gap, allow("b"), gap, allow("c"), allow("a"), allow("b"),
		}),
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
