// Command http001initgen captures the Go MCP HTTP initialize response over
// loopback and binds it to the production handler source at the pinned commit.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
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
	Method          string `json:"method"`
	Path            string `json:"path"`
	ContentType     string `json:"content_type"`
	Accept          string `json:"accept"`
	ProtocolVersion string `json:"protocol_version"`
	Agent           string `json:"agent"`
	Body            string `json:"body"`
}

type response struct {
	Status       int               `json:"status"`
	Headers      map[string]string `json:"headers"`
	AbsentHeader []string          `json:"absent_headers"`
	Body         string            `json:"body"`
}

func main() {
	root, err := os.Getwd()
	check(err)
	sha, err := provenance.Verify(root, oracleCommit, sources)
	check(err)
	digest, err := provenance.Digest(root, sources)
	check(err)

	vaultDir, err := os.MkdirTemp("", "http001-init-oracle-")
	check(err)
	defer os.RemoveAll(vaultDir)
	const token = "http001-fixture-token"
	check(os.WriteFile(filepath.Join(vaultDir, "mcp-token"), []byte(token), 0o600))
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
		case err := <-done:
			if err != nil && err != http.ErrServerClosed {
				fmt.Fprintln(os.Stderr, err)
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
			Request:         request{Method: http.MethodPost, Path: "/mcp", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`},
		},
		{
			Name:            "authenticated_prompts_list_after_initialize",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "2025-11-25", Agent: "default", Body: `{"jsonrpc":"2.0","id":2,"method":"prompts/list"}`},
		},
		{
			Name:            "authenticated_unsupported_protocol_version",
			GoAuthenticated: true,
			Request:         request{Method: http.MethodPost, Path: "/mcp", ContentType: "application/json", Accept: "application/json, text/event-stream", ProtocolVersion: "1999-01-01", Agent: "default", Body: `{"jsonrpc":"2.0","id":3,"method":"prompts/list"}`},
		},
	}
	for i := range requests {
		requests[i].Response = doRequest(client, listener.Addr().String(), token, requests[i].Request)
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
	check(os.WriteFile("testdata/port/mcp/http-initialize.json", encoded, 0o644))
}

func doRequest(client *http.Client, addr, token string, req request) response {
	httpReq, err := http.NewRequest(req.Method, "http://"+addr+req.Path, strings.NewReader(req.Body))
	check(err)
	httpReq.Header.Set("Content-Type", req.ContentType)
	httpReq.Header.Set("Accept", req.Accept)
	httpReq.Header.Set("MCP-Protocol-Version", req.ProtocolVersion)
	httpReq.Header.Set("Authorization", "Bearer "+token)
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
