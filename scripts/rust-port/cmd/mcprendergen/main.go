// Command mcprendergen freezes the production MCP output sanitizer.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unicode/utf8"

	"github.com/danieljustus/symaira-vault/internal/mcp/server"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

func main() {
	check := flag.Bool("check", false, "check frozen oracle")
	flag.Parse()
	rootBytes, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	must(err)
	root := strings.TrimSpace(string(rootBytes))
	const pinnedOracleCommit = "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
	sources := []string{"go.mod", "go.sum", "internal/mcp/server/render.go"}
	_, err = provenance.Verify(root, pinnedOracleCommit, sources)
	must(err)
	// Digest the enforced subset so a dependency bump does not restamp the
	// fixture; source_files still records the full claimed provenance.
	digest, err := provenance.Digest(root, provenance.EnforcedSources(sources))
	must(err)
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/mcprendergen/main.go"})
	must(err)
	inputs := []string{"", "hello\nworld\t\r", "a\x00b\x7fc", "\x1b[31mred\x1b[0m", "before\x1b[", "before\x1b[12", "a\x1bzB", "a\x1b", "a\x1béZ", "\x1b]8;;https://example.test\x1b\\link\x1b]8;;\a", "\x1b]unfinished", "\x1b]\\x\aY", "</data>", "</data key=\"x\">", "</_x></9x></é>", "</data", "--><!-- DATA_x -->", "＜／ＤＡＴＡ＞", "e\u0301\u200d\u202e</data>", "\u034fA\u00adB\ufeffC", "</a\x1b[31m>", "\u1100\u1161\u11a8", "A\u030a\u0301", "a" + strings.Repeat("\u0301", 30) + "\u0327", "a" + strings.Repeat("\u0301", 31) + "\u0327", strings.Repeat("\u0344", 20) + "\u0327"}
	type sample struct {
		Input  string `json:"input"`
		Output string `json:"output"`
	}
	samples := []sample{}
	renderer := server.NewRenderChokepoint()
	for _, input := range inputs {
		samples = append(samples, sample{input, renderer.SanitizeForMCP(input)})
	}
	// Exhaustively bind single-scalar normalization, including Unicode-version drift.
	hash := sha256.New()
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		_, err = hash.Write([]byte(renderer.SanitizeForMCP(string(r))))
		must(err)
		_, err = hash.Write([]byte{0})
		must(err)
	}
	fixture := struct {
		Commit          string   `json:"commit"`
		Sources         []string `json:"sources"`
		SourceDigest    string   `json:"source_digest"`
		GeneratorDigest string   `json:"generator_digest"`
		Cases           []sample `json:"cases"`
		ScalarDigest    string   `json:"scalar_digest"`
	}{pinnedOracleCommit, sources, digest, generatorDigest, samples, hex.EncodeToString(hash.Sum(nil))}
	data, err := json.MarshalIndent(fixture, "", "  ")
	must(err)
	data = append(data, '\n')
	const path = "testdata/port/mcp_render.json"
	if *check {
		old, readErr := os.ReadFile(path)
		must(readErr)
		if !bytes.Equal(data, old) {
			must(fmt.Errorf("MCP render fixture stale"))
		}
	} else {
		must(os.WriteFile(path, data, 0600))
	}
	fmt.Printf("PASS MCP render (%d vectors plus every Unicode scalar)\n", len(samples))
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
