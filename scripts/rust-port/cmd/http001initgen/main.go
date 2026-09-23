// Command http001initgen captures the Go MCP HTTP initialize response over
// loopback and binds it to the production handler source at the pinned commit.
package main

import (
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
	Method          string   `json:"method"`
	Path            string   `json:"path"`
	Origin          string   `json:"origin,omitempty"`
	ContentType     string   `json:"content_type"`
	Accept          string   `json:"accept"`
	ProtocolVersion string   `json:"protocol_version"`
	Agent           string   `json:"agent"`
	TokenName       string   `json:"token_name,omitempty"`
	TokenAgent      string   `json:"token_agent,omitempty"`
	AllowedTools    []string `json:"allowed_tools,omitempty"`
	Authenticated   bool     `json:"authenticated"`
	Body            string   `json:"body"`
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
			Name:            "authenticated_tool_scope_denied",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", Origin: "http://127.0.0.1", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", TokenName: "limited", TokenAgent: "default", AllowedTools: []string{"list_entries"}, Authenticated: true, Body: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_entry","arguments":{"path":"fixture"}}}`},
		},
	}
	for i := range requests {
		requests[i].Response = doRequest(client, listener.Addr().String(), token, tokens, requests[i].Request)
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
	check(os.WriteFile(*outputPath, encoded, 0o644))
}

func doRequest(client *http.Client, addr, token string, scopedTokens map[string]string, req request) response {
	httpReq, err := http.NewRequest(req.Method, "http://"+addr+req.Path, strings.NewReader(req.Body))
	check(err)
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
	httpResp, err := client.Do(httpReq)
	check(err)
	body, err := io.ReadAll(httpResp.Body)
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
	return response{Status: httpResp.StatusCode, Headers: headers, AbsentHeader: absent, Body: string(body)}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
