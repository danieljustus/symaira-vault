// Command mcpcallgen freezes the real Go protocol handler's tools/call guard
// ordering. The nil Server input is intentional: it exercises pre-initialize
// and vault-locked behavior without opening a vault or platform credential
// provider.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	mcpserver "github.com/danieljustus/symaira-vault/internal/mcp/server"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const pinnedOracleCommit = "caadd5e"

var productionSources = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/transport/transport.go",
}

type oracle struct {
	Commit       string   `json:"commit"`
	CommitSHA    string   `json:"commit_sha"`
	SourceFiles  []string `json:"source_files"`
	SourceDigest string   `json:"source_digest"`
}

type callCase struct {
	Name   string            `json:"name"`
	Input  []string          `json:"input"`
	Output []json.RawMessage `json:"output"`
}

type fixture struct {
	SchemaVersion   int        `json:"schema_version"`
	Oracle          oracle     `json:"oracle"`
	GeneratorDigest string     `json:"generator_digest"`
	ServerName      string     `json:"server_name"`
	ServerVersion   string     `json:"server_version"`
	Cases           []callCase `json:"cases"`
}

func main() {
	check := flag.Bool("check", false, "check fixture freshness")
	flag.Parse()
	rootBytes, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	must(err)
	root := strings.TrimSpace(string(rootBytes))
	commitSHA, err := provenance.Verify(root, pinnedOracleCommit, productionSources)
	must(err)
	digest, err := provenance.Digest(root, productionSources)
	must(err)
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/mcpcallgen/main.go"})
	must(err)

	const serverName = "symvault"
	const serverVersion = "0.0.0-fixture"
	cases := []struct {
		name  string
		input []string
	}{
		{"call_before_initialize", []string{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"bad"}`}},
		{"locked_call_valid_arguments", []string{
			`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"health"}}`,
		}},
		{"locked_call_invalid_params_still_locked", []string{
			`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":"bad"}`,
		}},
		{"locked_call_invalid_arguments_still_locked", []string{
			`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"health","arguments":[]}}`,
		}},
	}

	fixtureCases := make([]callCase, 0, len(cases))
	for _, tc := range cases {
		handler := mcpserver.NewProtocolHandler(serverName, serverVersion, nil)
		outputs := make([]json.RawMessage, 0, len(tc.input))
		for _, line := range tc.input {
			var msg transport.Message
			must(json.Unmarshal([]byte(line), &msg))
			response, handleErr := handler.HandleMessage(context.Background(), &msg)
			must(handleErr)
			if response == nil {
				continue
			}
			encoded, marshalErr := json.Marshal(response)
			must(marshalErr)
			outputs = append(outputs, encoded)
		}
		fixtureCases = append(fixtureCases, callCase{Name: tc.name, Input: tc.input, Output: outputs})
	}

	value := fixture{
		SchemaVersion: 1,
		Oracle: oracle{
			Commit: pinnedOracleCommit, CommitSHA: commitSHA, SourceFiles: productionSources, SourceDigest: digest,
		},
		GeneratorDigest: generatorDigest,
		ServerName:      serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	content, err := json.MarshalIndent(value, "", "  ")
	must(err)
	content = append(content, '\n')
	path := "testdata/port/mcp/tools-call.json"
	if *check {
		old, readErr := os.ReadFile(path)
		must(readErr)
		if string(old) != string(content) {
			must(fmt.Errorf("MCP tools/call fixture stale"))
		}
	} else {
		must(os.WriteFile(path, content, 0600))
	}
	fmt.Printf("PASS MCP tools/call oracle (%d cases)\n", len(fixtureCases))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
