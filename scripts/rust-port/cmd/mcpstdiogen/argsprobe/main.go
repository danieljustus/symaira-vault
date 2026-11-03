// Command argsprobe drives the real stdio transport, ProtocolHandler and a
// real tool Server (built through the exported mcpserver.New) with the
// tools/call frames given on stdin, and prints the verbatim stdout stream of
// each case.
//
// It is NOT run from the working tree. mcpstdiogen extracts the pinned oracle
// commit with `git archive`, copies this file into that tree and runs it there,
// so the bytes it records are produced by the oracle's own code and not by
// whatever the working tree has become since. Keep it dependent on exported
// APIs only: it must compile in both trees.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/config"
	mcpserver "github.com/danieljustus/symaira-vault/internal/mcp/server"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

type probeCase struct {
	Name  string `json:"name"`
	Input string `json:"input"`
}

type probeResult struct {
	Name      string `json:"name"`
	StdoutRaw string `json:"stdout_raw"`
}

func main() {
	var cases []probeCase
	if err := json.NewDecoder(os.Stdin).Decode(&cases); err != nil {
		fmt.Fprintf(os.Stderr, "decode cases: %v\n", err)
		os.Exit(2)
	}
	home, err := os.MkdirTemp("", "argsprobe-home-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "home: %v\n", err)
		os.Exit(2)
	}
	defer func() { _ = os.RemoveAll(home) }()
	// generate_template reads custom templates from $HOME and the server loads
	// policies from the user's config tree: keep both empty and disposable.
	for _, kv := range [][2]string{
		{"HOME", home}, {"XDG_CONFIG_HOME", filepath.Join(home, ".config")},
		{"XDG_DATA_HOME", filepath.Join(home, ".local", "share")},
		{"XDG_CACHE_HOME", filepath.Join(home, ".cache")},
	} {
		if err := os.Setenv(kv[0], kv[1]); err != nil {
			fmt.Fprintf(os.Stderr, "setenv: %v\n", err)
			os.Exit(2)
		}
	}

	results := make([]probeResult, 0, len(cases))
	for _, c := range cases {
		out, err := run(home, c.Input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "case %s: %v\n", c.Name, err)
			os.Exit(2)
		}
		results = append(results, probeResult{Name: c.Name, StdoutRaw: out})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(results); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(2)
	}
}

func run(home, input string) (string, error) {
	dir, err := os.MkdirTemp(home, "vault-")
	if err != nil {
		return "", err
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	approval := "none"
	cfg := &config.Config{
		DefaultAgent: "fixture",
		Agents: map[string]config.AgentProfile{
			"fixture": {AllowedPaths: []string{"*"}, ApprovalMode: &approval},
		},
	}
	v := &vault.Vault{Dir: dir, Identity: identity, Config: cfg}
	srv, err := mcpserver.New(v, "fixture", "stdio")
	if err != nil {
		return "", fmt.Errorf("new server: %w", err)
	}
	defer func() { _ = srv.Close() }()

	handler := mcpserver.NewProtocolHandler("symvault", "0.0.0-fixture", srv)
	var stdout bytes.Buffer
	tr := transport.NewStdioTransportWithIO(strings.NewReader(input), &stdout)
	if err := tr.Start(context.Background(), handler.HandleMessage); err != nil {
		return "", fmt.Errorf("transport: %w", err)
	}
	return stdout.String(), nil
}
