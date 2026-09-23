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
	"os"
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

const oracleCommit = "08c162e5"

var sources = []string{
	"internal/mcp/auth/auth.go",
	"internal/mcp/auth/token.go",
	"internal/mcp/server/http_helpers.go",
	"internal/mcp/server/prompt_registry.go",
	"internal/mcp/server/protocol.go",
	"internal/mcp/serverbootstrap/http.go",
	"internal/mcp/serverbootstrap/http_setup.go",
	"internal/mcp/transport/transport.go",
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
	Commit       string   `json:"commit"`
	CommitSHA    string   `json:"commit_sha"`
	SourceFiles  []string `json:"source_files"`
	SourceDigest string   `json:"source_digest"`
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
	Status       int               `json:"status"`
	Headers      map[string]string `json:"headers"`
	AbsentHeader []string          `json:"absent_headers"`
	Body         string            `json:"body"`
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
	registry := auth.NewTokenRegistry(auth.TokenRegistryFilePath(vaultDir))
	check(registry.Load())
	_, token, err := registry.Create("baseline", []string{"*"}, "default", time.Hour)
	check(err)
	tokens := map[string]string{}
	for _, scoped := range []struct {
		name  string
		agent string
		tools []string
	}{
		{name: "health", agent: "default", tools: []string{"health"}},
		{name: "limited", agent: "default", tools: []string{"list_entries"}},
	} {
		_, raw, createErr := registry.Create(scoped.name, scoped.tools, scoped.agent, time.Hour)
		check(createErr)
		tokens[scoped.name] = raw
	}
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
		case <-time.After(3 * time.Second):
			_ = listener.Close()
		}
	}()

	client := &http.Client{Timeout: 4 * time.Second}
	requests := []caseFixture{
		{
			Name:            "initialize",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Authenticated: true, Body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`},
		},
		{
			Name:            "authenticated_prompts_list_after_initialize",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Authenticated: true, Body: `{"jsonrpc":"2.0","id":2,"method":"prompts/list"}`},
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
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "health", TokenAgent: "default", AllowedTools: []string{"health"}, Authenticated: true, Body: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"health","arguments":{}}}`},
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
	encoded, err := json.MarshalIndent(out, "", "  ")
	check(err)
	encoded = append(encoded, '\n')
	if *checkOnly {
		current, readErr := os.ReadFile(*outputPath)
		check(readErr)
		if string(current) != string(encoded) {
			check(fmt.Errorf("HTTP-001 fixture drift: regenerate with go run ./scripts/rust-port/cmd/http001initgen --output %s", *outputPath))
		}
		return
	}
	// #nosec G306 -- the generated oracle transcript is public testdata.
	check(os.WriteFile(*outputPath, encoded, 0o644))
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
	httpResp, err := client.Do(httpReq)
	check(err)
	return captureResponse(httpResp)
}

func captureResponse(httpResp *http.Response) response {
	responseBody, err := io.ReadAll(httpResp.Body)
	_ = httpResp.Body.Close()
	check(err)
	headers := map[string]string{"Content-Length": strconv.FormatInt(httpResp.ContentLength, 10)}
	if value := httpResp.Header.Get("Content-Type"); value != "" {
		headers["Content-Type"] = value
	}
	absent := []string{}
	if httpResp.Header.Get("MCP-Protocol-Version") == "" {
		absent = append(absent, "MCP-Protocol-Version")
	}
	sort.Strings(absent)
	return response{Status: httpResp.StatusCode, Headers: headers, AbsentHeader: absent, Body: string(responseBody)}
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
	return captureResponse(httpResp)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
