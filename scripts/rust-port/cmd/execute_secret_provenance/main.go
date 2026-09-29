package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const pinnedOracleCommit = "12d8c616ae98b954a9b906e0984af1613ca05fde"

var sources = []string{
	"internal/mcp/server/approval_helper.go",
	"internal/mcp/server/command_policy.go",
	"internal/mcp/server/render.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tools_execute_with_secret.go",
	"internal/mcp/server/tools_sanitize.go",
	"internal/mcp/server/tools_run.go",
	"internal/mcp/masking/sanitizer.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/apitemplates/auth.go",
	"internal/redact/detectors.go",
	"internal/redact/redact.go",
	"internal/secrets/filter.go",
	"internal/secrets/runner.go",
}

var generatorFiles = []string{
	"internal/mcp/server/mcpexecutewithsecret_fixture_generator_test.go",
	"scripts/rust-port/cmd/execute_secret_child/main.go",
	"scripts/rust-port/cmd/execute_secret_provenance/main.go",
	"scripts/rust-port/cmd/execute_secret_unicode/main.go",
	"crates/symvault-mcp/src/go_unicode_15.rs",
}

func main() {
	rootBytes, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	must(err)
	root := strings.TrimSpace(string(rootBytes))
	commitSHA, err := provenance.Verify(root, pinnedOracleCommit, sources)
	must(err)
	digest, err := provenance.Digest(root, sources)
	must(err)
	generatorDigest, err := provenance.Digest(root, generatorFiles)
	must(err)
	must(json.NewEncoder(os.Stdout).Encode(map[string]string{
		"commit_sha": commitSHA, "source_digest": digest,
		"generator_digest": generatorDigest,
	}))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
