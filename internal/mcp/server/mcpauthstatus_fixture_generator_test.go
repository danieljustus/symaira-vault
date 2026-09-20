package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/session"
)

// This opt-in generator invokes the production Go tools/call dispatcher. The
// session package is already forced to its memory fallback under go test, so
// the fixture never probes the developer's keychain.
type mcpAuthStatusFixture struct {
	SchemaVersion int                 `json:"schema_version"`
	Oracle        mcpAuthStatusOracle `json:"oracle"`
	ServerName    string              `json:"server_name"`
	ServerVersion string              `json:"server_version"`
	Cases         []mcpAuthStatusCase `json:"cases"`
}

type mcpAuthStatusOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpAuthStatusCase struct {
	Name   string            `json:"name"`
	Input  []string          `json:"input"`
	Output []json.RawMessage `json:"output"`
}

type authStatusFixtureBiometricStore struct{}

func (authStatusFixtureBiometricStore) IsAvailable() bool { return false }
func (authStatusFixtureBiometricStore) Save(context.Context, string, []byte) error {
	return session.ErrBiometricNotAvailable
}
func (authStatusFixtureBiometricStore) Load(context.Context, string) ([]byte, error) {
	return nil, session.ErrBiometricNotAvailable
}
func (authStatusFixtureBiometricStore) Delete(string) error {
	return session.ErrBiometricNotAvailable
}

var mcpAuthStatusSourceFiles = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_auth.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/mcptypes.go",
	"internal/config/config.go",
	"internal/config/config_load.go",
	"internal/session/session.go",
	"internal/session/biometric.go",
	"internal/session/oskeyring.go",
}

func TestGenerateMCPAuthStatusFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_AUTH_STATUS_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_AUTH_STATUS_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_AUTH_STATUS_FIXTURE=1 or SYMAIRA_CHECK_MCP_AUTH_STATUS_FIXTURE=1")
	}

	const serverName = "symvault"
	const serverVersion = "0.0.0-auth-status-fixture"
	base := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	// Touch ID availability is an injected fixture capability. Keep the Go
	// oracle independent of the host Mac's biometric hardware and restore the
	// package global before the test returns.
	session.SetBiometricPassphraseStore(authStatusFixtureBiometricStore{})
	defer session.SetBiometricPassphraseStore(nil)
	cases := []struct {
		name       string
		authMethod string
		callID     int
	}{
		{name: "passphrase", authMethod: config.AuthMethodPassphrase, callID: 2},
		{name: "touchid", authMethod: config.AuthMethodTouchID, callID: 3},
	}

	fixtureCases := make([]mcpAuthStatusCase, 0, len(cases))
	for _, tc := range cases {
		vaultDir := t.TempDir()
		profile := config.AgentProfile{
			Name:         "fixture",
			AllowedPaths: []string{"*"},
			ApprovalMode: config.StrPtr("none"),
		}
		srv := newTestServerWithVault(t, profile, "stdio", vaultDir)
		cfg := config.Default()
		cfg.VaultDir = vaultDir
		if err := cfg.SetAuthMethod(tc.authMethod); err != nil {
			t.Fatalf("SetAuthMethod(%s): %v", tc.authMethod, err)
		}
		srv.vault.Config = cfg
		handler := NewProtocolHandler(serverName, serverVersion, srv)
		inputs := append(append([]string{}, base...), fmt.Sprintf(
			`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"get_auth_status"}}`, tc.callID))
		outputs := make([]json.RawMessage, 0, len(inputs))
		for _, line := range inputs {
			var msg transport.Message
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				t.Fatalf("decode %s input: %v", tc.name, err)
			}
			response, err := handler.HandleMessage(context.Background(), &msg)
			if err != nil {
				t.Fatalf("handle %s: %v", tc.name, err)
			}
			if response == nil {
				continue
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatalf("marshal %s response: %v", tc.name, err)
			}
			outputs = append(outputs, encoded)
		}
		fixtureCases = append(fixtureCases, mcpAuthStatusCase{Name: tc.name, Input: inputs, Output: outputs})
	}

	root := mcpAuthStatusRepoRoot(t)
	sourceHash := mcpAuthStatusSourceHash(t, mcpAuthStatusSourceFiles)
	if got, want := sourceHash, mcpAuthStatusGitSourceHash(t, mcpAuthStatusSourceFiles); got != want {
		t.Fatalf("Go auth-status sources differ from fca3f894: got %s, want %s", got, want)
	}
	fixture := mcpAuthStatusFixture{
		SchemaVersion: 1,
		Oracle: mcpAuthStatusOracle{
			Commit: "fca3f894", CommitSHA: "fca3f89401833b5e14ec4ec74ef736b0f63bca74",
			SourceFiles: mcpAuthStatusSourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpAuthStatusGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-auth-status.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP auth-status fixture is stale; run with SYMAIRA_GENERATE_MCP_AUTH_STATUS_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func mcpAuthStatusRepoRoot(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	root, err := cmd.Output()
	if err != nil {
		t.Fatalf("find repository root: %v", err)
	}
	return string(bytes.TrimSpace(root))
}

func mcpAuthStatusSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpAuthStatusRepoRoot(t)
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read auth-status source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func mcpAuthStatusGitSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpAuthStatusRepoRoot(t)
	for _, name := range files {
		cmd := exec.Command("git", "show", "fca3f894:"+name)
		cmd.Dir = root
		data, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned auth-status source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func mcpAuthStatusGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate auth-status fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read auth-status fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}
