package server

// This focused generator runs the production registry and list-time filters.
// It is intentionally a Go test so it can call the unexported registry seam
// without adding a public compatibility API just for fixture production.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/secureui"
)

type mcpListFixture struct {
	SchemaVersion int              `json:"schema_version"`
	Oracle        mcpListOracle    `json:"oracle"`
	Catalog       []map[string]any `json:"catalog"`
	Cases         []mcpListCase    `json:"cases"`
}

type mcpListOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpListCase struct {
	Name             string           `json:"name"`
	Profile          string           `json:"profile"`
	IncludeAll       bool             `json:"include_all_tools"`
	ExposeValueTools *bool            `json:"expose_value_tools,omitempty"`
	Runtime          mcpListRuntime   `json:"runtime"`
	Tools            []map[string]any `json:"tools"`
}

type mcpListRuntime struct {
	ExecuteAPI   bool `json:"execute_api"`
	SecureInput  bool `json:"secure_input"`
	GenerateTOTP bool `json:"generate_totp"`
}

var mcpListSourceFiles = []string{
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/leanmode.go",
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/tools_execute_api_request.go",
	"internal/mcp/server/secure_input.go",
	"internal/mcp/server/tools_totp.go",
	"internal/mcp/server/server_authorize.go",
}

const mcpListPinnedSourceHash = "84035cd3f669596d81313612c00f29fc45432ea22a6cb61b0c59ddc3f811a14c"

func TestGenerateMCPListFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_LIST_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_LIST_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_LIST_FIXTURE=1 or SYMAIRA_CHECK_MCP_LIST_FIXTURE=1")
	}

	// The production registry uses host capability detection for these three
	// tools. Inject deterministic capabilities so this capture never touches a
	// keychain, vault, GUI, or real command runner.
	originalSecure := secureInputCapabilityFn
	secureInputCapabilityFn = func() secureui.Capability { return secureui.CapNone }
	t.Cleanup(func() { secureInputCapabilityFn = originalSecure })

	baselineRuntime := mcpListRuntime{GenerateTOTP: true}

	cases := []mcpListCase{
		captureMCPListCase("nil_lean", "", false, baselineRuntime, nil),
		captureMCPListCase("nil_all", "", true, baselineRuntime, nil),
	}

	secureInputCapabilityFn = func() secureui.Capability { return secureui.CapTTY }
	runtime := mcpListRuntime{ExecuteAPI: true, SecureInput: true, GenerateTOTP: true}
	for _, tier := range []string{"read-only", "standard", "admin"} {
		srv := mcpListProfile(t, tier, runtime)
		cases = append(cases,
			captureMCPListCase(tier+"_all", tier, true, runtime, srv),
			captureMCPListCase(tier+"_lean", tier, false, runtime, srv),
		)
	}
	custom := mcpListProfileWithExpose(t, "custom", runtime, nil)
	cases = append(cases,
		captureMCPListCase("custom_unset_all", "custom", true, runtime, custom),
	)
	customTrue := mcpListProfileWithExpose(t, "custom", runtime, config.BoolPtr(true))
	cases = append(cases,
		captureMCPListCase("custom_true_all", "custom", true, runtime, customTrue),
	)
	customFalse := mcpListProfileWithExpose(t, "custom", runtime, config.BoolPtr(false))
	cases = append(cases,
		captureMCPListCase("custom_false_all", "custom", true, runtime, customFalse),
	)

	sourceHash := mcpListSourceHash(t, mcpListSourceFiles)
	if sourceHash != mcpListPinnedSourceHash {
		t.Fatalf("Go MCP list sources drifted from pinned oracle: got %s, want %s", sourceHash, mcpListPinnedSourceHash)
	}
	if pinnedHash := mcpListGitSourceHash(t, mcpListSourceFiles); pinnedHash != sourceHash {
		t.Fatalf("working Go MCP list sources differ from caadd5e: got %s, want %s", sourceHash, pinnedHash)
	}
	generatorHash := mcpListGeneratorHash(t)
	fixture := mcpListFixture{
		SchemaVersion: 1,
		Oracle: mcpListOracle{
			Commit:        "fca3f894",
			CommitSHA:     "fca3f89401833b5e14ec4ec74ef736b0f63bca74",
			SourceFiles:   mcpListSourceFiles,
			SourceHash:    sourceHash,
			GeneratorHash: generatorHash,
		},
		Catalog: toolsListPayload(mcpListProfile(t, "admin", runtime)),
		Cases:   cases,
	}

	root := mcpListRepoRoot(t)
	path := filepath.Join(root, "testdata", "port", "mcp", "tool-list.json")
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP list fixture is stale; run with SYMAIRA_GENERATE_MCP_LIST_FIXTURE=1")
		}
		t.Logf("checked %s (%d bytes)", path, len(data))
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(data))
}

func captureMCPListCase(name, tier string, includeAll bool, runtime mcpListRuntime, srv *Server) mcpListCase {
	var tools []map[string]any
	if srv == nil && tier != "" {
		panic("profile required for tier case")
	}
	if srv == nil {
		tools = toolsListPayload(nil)
	} else {
		tools = toolsListPayload(srv)
	}
	if !includeAll {
		tools = filterLeanTools(tools)
	}
	var expose *bool
	if srv != nil && srv.agent != nil {
		expose = srv.agent.ExposeValueTools
	}
	return mcpListCase{Name: name, Profile: tier, IncludeAll: includeAll, ExposeValueTools: expose, Runtime: runtime, Tools: tools}
}

func mcpListProfile(t *testing.T, tier string, runtime mcpListRuntime) *Server {
	return mcpListProfileWithExpose(t, tier, runtime, config.BoolPtr(tier == "admin"))
}

func mcpListProfileWithExpose(t *testing.T, tier string, runtime mcpListRuntime, expose *bool) *Server {
	t.Helper()
	trueValue := true
	profile := config.AgentProfile{
		Name:             "fixture",
		Tier:             config.StrPtr(tier),
		CanRunCommands:   &trueValue,
		CanUseClipboard:  &trueValue,
		CanUseAutotype:   &trueValue,
		CanReadValues:    &trueValue,
		ExposeValueTools: expose,
		AllowedPaths:     []string{"*"},
		ApprovalMode:     config.StrPtr("none"),
	}
	if !runtime.ExecuteAPI {
		profile.CanRunCommands = config.BoolPtr(false)
	}
	if !runtime.GenerateTOTP {
		profile.CanUseClipboard = config.BoolPtr(false)
		profile.CanUseAutotype = config.BoolPtr(false)
		profile.CanReadValues = config.BoolPtr(false)
	}
	return newTestServerWithVault(t, profile, "stdio", "")
}

func mcpListSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(mcpListRepoRoot(t), name))
		if err != nil {
			t.Fatalf("read source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mcpListGitSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpListRepoRoot(t)
	for _, name := range files {
		cmd := exec.Command("git", "show", "fca3f894:"+name)
		cmd.Dir = root
		data, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mcpListGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func mcpListRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repository root")
		}
		dir = parent
	}
}
