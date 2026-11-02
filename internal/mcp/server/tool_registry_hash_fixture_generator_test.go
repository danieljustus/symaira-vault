package server

// TOOLHASH-001 fixture generator. It runs the production registry hash
// (ComputeToolRegistryHash over the full toolDefinitions(), exactly what
// setup.go stores in auth.CurrentToolRegistryHash) and the production
// call-time drift refusal (executeTool), and records the results for the Rust
// port. It is a Go test so it can reach the unexported registry seam without
// adding a public compatibility API (same precedent as
// mcplist_fixture_generator_test.go).
//
//	SYMAIRA_GENERATE_TOOL_REGISTRY_HASH_FIXTURE=1  write the fixture
//	SYMAIRA_CHECK_TOOL_REGISTRY_HASH_FIXTURE=1     compare, never write

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/mcp/auth"
)

type toolHashFixture struct {
	SchemaVersion int                `json:"schema_version"`
	Oracle        toolHashOracle     `json:"oracle"`
	Algorithm     string             `json:"algorithm"`
	Registry      toolHashRegistry   `json:"registry"`
	Mutations     []toolHashMutation `json:"mutations"`
	Synthetic     []toolHashSynth    `json:"synthetic"`
	Drift         []toolHashDrift    `json:"drift"`
}

type toolHashOracle struct {
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
	Note          string   `json:"note"`
}

type toolHashRegistry struct {
	ToolCount int            `json:"tool_count"`
	Hash      string         `json:"hash"`
	Tools     []toolHashTool `json:"tools"`
}

// toolHashTool is the exact hash material of one tool: input_schema_json is
// the bytes json.Marshal produced for the schema.
type toolHashTool struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	InputSchemaJSON string `json:"input_schema_json"`
	ReadOnlyHint    bool   `json:"read_only_hint"`
	DestructiveHint bool   `json:"destructive_hint"`
}

type toolHashOp struct {
	Op       string          `json:"op"`
	Tool     string          `json:"tool,omitempty"`
	Property string          `json:"property,omitempty"`
	Value    json.RawMessage `json:"value,omitempty"`
	Def      *toolHashDefIn  `json:"def,omitempty"`
}

type toolHashDefIn struct {
	Name            string         `json:"name"`
	Description     string         `json:"description"`
	InputSchema     map[string]any `json:"input_schema"`
	ReadOnlyHint    bool           `json:"read_only_hint"`
	DestructiveHint bool           `json:"destructive_hint"`
}

type toolHashMutation struct {
	Name          string       `json:"name"`
	Ops           []toolHashOp `json:"ops"`
	Hash          string       `json:"hash"`
	ChangesHash   bool         `json:"changes_hash"`
	ExpectedCount int          `json:"tool_count"`
}

type toolHashSynth struct {
	Name string          `json:"name"`
	Defs []toolHashDefIn `json:"defs"`
	Hash string          `json:"hash"`
	Why  string          `json:"why"`
}

type toolHashDrift struct {
	Name      string `json:"name"`
	TokenHash string `json:"token_hash"`
	// TokenHashIsRegistry means the token carries the registry hash itself
	// (TokenHash is then left empty in the fixture).
	TokenHashIsRegistry bool   `json:"token_hash_is_registry"`
	Drift               bool   `json:"drift"`
	AgentName           string `json:"agent_name"`
	Tool                string `json:"tool"`
	Arguments           string `json:"arguments"`
	// ResultJSON is the exact executeTool payload marshaled by encoding/json
	// (refusal or normal result).
	ResultJSON string `json:"result_json"`
	Refused    bool   `json:"refused"`
}

var toolHashSourceFiles = []string{
	"internal/mcp/auth/token.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/setup.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/toolhash.go",
}

func toolHashDefsFromRegistry() []mcp.ToolHashDef {
	defs := toolDefinitions()
	out := make([]mcp.ToolHashDef, len(defs))
	for i, d := range defs {
		out[i] = mcp.ToolHashDef{Name: d.Name, Description: d.Description, InputSchema: d.InputSchema, ReadOnlyHint: d.ReadOnlyHint, DestructiveHint: d.DestructiveHint}
	}
	return out
}

func toolHashApplyOps(t *testing.T, defs []mcp.ToolHashDef, ops []toolHashOp) []mcp.ToolHashDef {
	t.Helper()
	out := make([]mcp.ToolHashDef, len(defs))
	copy(out, defs)
	index := func(name string) int {
		for i := range out {
			if out[i].Name == name {
				return i
			}
		}
		t.Fatalf("unknown tool %q in op", name)
		return -1
	}
	for _, op := range ops {
		switch op.Op {
		case "set_description":
			var v string
			mustJSON(t, op.Value, &v)
			out[index(op.Tool)].Description = v
		case "set_read_only":
			var v bool
			mustJSON(t, op.Value, &v)
			out[index(op.Tool)].ReadOnlyHint = v
		case "set_destructive":
			var v bool
			mustJSON(t, op.Value, &v)
			out[index(op.Tool)].DestructiveHint = v
		case "set_schema_property_description":
			var v string
			mustJSON(t, op.Value, &v)
			i := index(op.Tool)
			// Deep copy through JSON so the production registry is untouched.
			raw, err := json.Marshal(out[i].InputSchema)
			if err != nil {
				t.Fatal(err)
			}
			var schema map[string]any
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatal(err)
			}
			props, _ := schema["properties"].(map[string]any)
			prop, _ := props[op.Property].(map[string]any)
			if prop == nil {
				t.Fatalf("tool %q has no property %q", op.Tool, op.Property)
			}
			prop["description"] = v
			out[i].InputSchema = schema
		case "remove_tool":
			i := index(op.Tool)
			out = append(out[:i:i], out[i+1:]...)
		case "add_tool":
			out = append(out, mcp.ToolHashDef{Name: op.Def.Name, Description: op.Def.Description, InputSchema: op.Def.InputSchema, ReadOnlyHint: op.Def.ReadOnlyHint, DestructiveHint: op.Def.DestructiveHint})
		case "reverse_order":
			for l, r := 0, len(out)-1; l < r; l, r = l+1, r-1 {
				out[l], out[r] = out[r], out[l]
			}
		default:
			t.Fatalf("unknown op %q", op.Op)
		}
	}
	return out
}

func mustJSON(t *testing.T, raw json.RawMessage, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode op value %s: %v", raw, err)
	}
}

func rawJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func toolHashDefsFromIn(in []toolHashDefIn) []mcp.ToolHashDef {
	out := make([]mcp.ToolHashDef, len(in))
	for i, d := range in {
		out[i] = mcp.ToolHashDef{Name: d.Name, Description: d.Description, InputSchema: d.InputSchema, ReadOnlyHint: d.ReadOnlyHint, DestructiveHint: d.DestructiveHint}
	}
	return out
}

func TestGenerateToolRegistryHashFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_TOOL_REGISTRY_HASH_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_TOOL_REGISTRY_HASH_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_TOOL_REGISTRY_HASH_FIXTURE=1 or SYMAIRA_CHECK_TOOL_REGISTRY_HASH_FIXTURE=1")
	}

	root := mcpListRepoRoot(t)
	base := toolHashDefsFromRegistry()
	registryHash := computeToolRegistryHashDefs(toolDefinitions())
	if registryHash != auth.CurrentToolRegistryHash {
		t.Fatalf("setup.go hash %s != recomputed %s", auth.CurrentToolRegistryHash, registryHash)
	}
	if got := mcp.ComputeToolRegistryHash(base); got != registryHash {
		t.Fatalf("ComputeToolRegistryHash mismatch: %s vs %s", got, registryHash)
	}

	sorted := make([]mcp.ToolHashDef, len(base))
	copy(sorted, base)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	tools := make([]toolHashTool, len(sorted))
	for i, d := range sorted {
		schema, err := json.Marshal(d.InputSchema)
		if err != nil {
			schema = []byte("{}")
		}
		tools[i] = toolHashTool{Name: d.Name, Description: d.Description, InputSchemaJSON: string(schema), ReadOnlyHint: d.ReadOnlyHint, DestructiveHint: d.DestructiveHint}
	}

	mutationSpecs := []struct {
		name string
		ops  []toolHashOp
		same bool
	}{
		{"reverse_order_keeps_hash", []toolHashOp{{Op: "reverse_order"}}, true},
		{"description_changed", []toolHashOp{{Op: "set_description", Tool: "get_auth_status", Value: rawJSON("Return Symaira Vault unlock authentication status (mutated)")}}, false},
		{"description_changed_with_html_chars", []toolHashOp{{Op: "set_description", Tool: "health", Value: rawJSON("Return <b>health</b> & \u2028status")}}, false},
		{"read_only_hint_flipped", []toolHashOp{{Op: "set_read_only", Tool: "get_auth_status", Value: rawJSON(false)}}, false},
		{"destructive_hint_flipped", []toolHashOp{{Op: "set_destructive", Tool: "health", Value: rawJSON(true)}}, false},
		{"schema_property_description_changed", []toolHashOp{{Op: "set_schema_property_description", Tool: "get_entry", Property: "path", Value: rawJSON("Entry path (mutated)")}}, false},
		{"tool_removed", []toolHashOp{{Op: "remove_tool", Tool: "health"}}, false},
		{"tool_added", []toolHashOp{{Op: "add_tool", Def: &toolHashDefIn{Name: "zz_added_tool", Description: "Added", InputSchema: map[string]any{"type": "object", "properties": map[string]any{}}, ReadOnlyHint: true}}}, false},
	}
	var mutations []toolHashMutation
	for _, spec := range mutationSpecs {
		mutated := toolHashApplyOps(t, base, spec.ops)
		h := mcp.ComputeToolRegistryHash(mutated)
		if (h == registryHash) != spec.same {
			t.Fatalf("mutation %s: same-hash=%v, want %v", spec.name, h == registryHash, spec.same)
		}
		mutations = append(mutations, toolHashMutation{Name: spec.name, Ops: spec.ops, Hash: h, ChangesHash: h != registryHash, ExpectedCount: len(mutated)})
	}

	synthSpecs := []struct {
		name string
		why  string
		defs []toolHashDefIn
	}{
		{
			"escaping_and_numbers",
			"json.Marshal escapes <, >, & and U+2028/U+2029 and formats float64 Go-style; descriptions are written verbatim",
			[]toolHashDefIn{
				{Name: "b_tool", Description: "desc <with> & \u2028 \u2029 chars %s %d |pipe|\nnewline", InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"z": map[string]any{"type": "number", "default": 1.5, "maximum": 1e21, "minimum": 1e-7, "x": 100.0, "neg": -0.0},
						"a": map[string]any{"description": "<>&\u2028\u2029 caf\u00e9 \u2713 \\ \"quoted\" \u0007"},
					},
					"required": []string{"z", "a"},
					"enum":     []any{1.0, 2.5, "s", nil, true},
				}, ReadOnlyHint: true, DestructiveHint: false},
				{Name: "a_tool", Description: "", InputSchema: nil, ReadOnlyHint: false, DestructiveHint: true},
				{Name: "c_tool", Description: "empty schema", InputSchema: map[string]any{}},
			},
		},
		{
			"empty_registry",
			"no tools hashes the empty byte stream",
			[]toolHashDefIn{},
		},
	}
	var synth []toolHashSynth
	for _, spec := range synthSpecs {
		synth = append(synth, toolHashSynth{Name: spec.name, Why: spec.why, Defs: spec.defs, Hash: mcp.ComputeToolRegistryHash(toolHashDefsFromIn(spec.defs))})
	}

	generatorSrc, err := os.ReadFile(filepath.Join(root, "internal/mcp/server/tool_registry_hash_fixture_generator_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	genSum := sha256.Sum256(generatorSrc)

	// Drift scenarios run through the production executeTool with a scoped
	// token in the context, exactly as the HTTP middleware supplies it.
	profile := config.AgentProfile{Name: "fixture"}
	srv := newTestServerWithVault(t, profile, "http", "")
	driftSpecs := []struct {
		name     string
		tokenSet string // "" legacy, "registry", or literal stale hash
		registry bool
		tool     string
	}{
		{"legacy_empty_hash_is_accepted", "", false, "symaira_search"},
		{"matching_hash_is_accepted", "", true, "symaira_search"},
		{"stale_hash_is_refused", "stale-hash-does-not-match", false, "symaira_search"},
		{"zero_hash_is_refused", "0000000000000000000000000000000000000000000000000000000000000000", false, "symaira_search"},
	}
	var drift []toolHashDrift
	for _, spec := range driftSpecs {
		tokenHash := spec.tokenSet
		if spec.registry {
			tokenHash = registryHash
		}
		tok := &auth.ScopedToken{TokenData: auth.TokenData{ID: "tok-fixture", Hash: "x", AllowedTools: []string{"*"}, ToolRegistryHash: tokenHash, AgentName: "fixture", CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}
		entry := toolHashDrift{Name: spec.name, TokenHash: spec.tokenSet, TokenHashIsRegistry: spec.registry, Drift: tok.IsToolRegistryDriftDetected(), AgentName: "fixture", Tool: spec.tool, Arguments: `{"intent":"auth","return":"names"}`}
		payload, execErr := srv.executeTool(auth.WithToken(context.Background(), tok), spec.tool, json.RawMessage(entry.Arguments))
		if execErr != nil {
			t.Fatalf("%s: executeTool error: %v", spec.name, execErr)
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		entry.Refused = bytes.Contains(raw, []byte("tool registry has changed"))
		entry.ResultJSON = string(raw)
		if entry.Refused != entry.Drift {
			t.Fatalf("%s: refused=%v but IsToolRegistryDriftDetected=%v (payload %s)", spec.name, entry.Refused, entry.Drift, raw)
		}
		drift = append(drift, entry)
	}

	fixture := toolHashFixture{
		SchemaVersion: 1,
		Oracle: toolHashOracle{
			SourceFiles:   toolHashSourceFiles,
			SourceHash:    mcpListSourceHash(t, toolHashSourceFiles),
			GeneratorHash: hex.EncodeToString(genSum[:]),
			Note:          "Recorded from the Go sources in this checkout; regenerate when any source file changes (a changed tool definition changes the registry hash by design).",
		},
		Algorithm: "sort defs by name; for each: fmt.Fprintf(sha256, \"%s|%s|%s|%v|%v\\n\", Name, Description, json.Marshal(InputSchema) (\"{}\" on error), ReadOnlyHint, DestructiveHint); hex digest. The hash covers the full toolDefinitions() registry (all 35 tools, not tier- or availability-filtered).",
		Registry:  toolHashRegistry{ToolCount: len(tools), Hash: registryHash, Tools: tools},
		Mutations: mutations,
		Synthetic: synth,
		Drift:     drift,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tool-registry-hash.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("tool-registry-hash fixture is stale; run with SYMAIRA_GENERATE_TOOL_REGISTRY_HASH_FIXTURE=1")
		}
		t.Logf("checked %s (%d bytes, hash %s)", path, len(data), registryHash)
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d bytes, hash %s)", path, len(data), registryHash)
}
