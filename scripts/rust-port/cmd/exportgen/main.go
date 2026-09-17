// Command exportgen compares synthetic CSV/JSON exports with production Go.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/exporter"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const pinnedOracleCommit = "fca3f89401833b5e14ec4ec74ef736b0f63bca74"

type exportCase struct {
	Name    string                 `json:"name"`
	Entries []exporter.ExportEntry `json:"entries"`
	Mapping map[string]string      `json:"mapping"`
	JSON    string                 `json:"json"`
	CSV     string                 `json:"csv"`
	Notices string                 `json:"notices"`
}

func main() {
	check := flag.Bool("check", false, "verify fixture")
	flag.Parse()
	rootBytes, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	must(err)
	root := strings.TrimSpace(string(rootBytes))
	sources := []string{"internal/exporter/csv.go", "internal/exporter/exporter.go", "internal/exporter/json.go", "go.mod", "go.sum"}
	_, err = provenance.Verify(root, pinnedOracleCommit, sources)
	must(err)
	digest, err := provenance.Digest(root, sources)
	must(err)
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/exportgen/main.go"})
	must(err)
	cases := []exportCase{
		{Name: "empty", Entries: []exporter.ExportEntry{}},
		{Name: "escaping", Entries: []exporter.ExportEntry{{Path: " <&>\u2028", Data: map[string]any{"leading": "\u00a0space", "quote": "a\"b", "comma": "a,b", "newline": "a\r\nb", "sentinel": "\\.", "empty": "", "line": "\u2029"}}}},
		{Name: "nested", Entries: []exporter.ExportEntry{{Path: "nested", Data: map[string]any{"array": []any{"a", nil, true, []any{"b"}}, "map": map[string]any{"z": []any{"x", "y"}, "a": map[string]any{"b": "c"}}, "nil": nil, "number": 42}}}},
		{Name: "attachments", Entries: []exporter.ExportEntry{{Path: "with-files", Data: map[string]any{"file_b64_0": "c3ludGhldGlj", "chunk_count": 1, "chunk_size": 9, "name": "fixture"}}, {Path: "only-files", Data: map[string]any{"file_b64_1": "c3ludGhldGlj"}}}},
		{Name: "mapping", Entries: []exporter.ExportEntry{{Path: "first", Data: map[string]any{"username": "fixture", "field": "value"}}, {Path: "second", Data: map[string]any{"extra": "optional"}}}, Mapping: map[string]string{"username": " name", "extra": "", "field": "renamed"}},
	}
	for i := range cases {
		c := &cases[i]
		var j, v, n bytes.Buffer
		must((&exporter.JSONExporter{}).Export(&j, c.Entries, c.Mapping))
		must((&exporter.CSVExporter{NoticeWriter: &n}).Export(&v, c.Entries, c.Mapping))
		var streamed bytes.Buffer
		stream := exporter.NewJSONStream(&streamed, c.Mapping)
		for _, entry := range c.Entries {
			must(stream.WriteEntry(entry))
		}
		must(stream.Close())
		if !bytes.Equal(j.Bytes(), streamed.Bytes()) {
			must(fmt.Errorf("Go batch/stream export mismatch: %s", c.Name))
		}
		c.JSON = j.String()
		c.CSV = v.String()
		c.Notices = n.String()
	}
	fixture := struct {
		Commit          string       `json:"commit"`
		SourceFiles     []string     `json:"source_files"`
		SourceDigest    string       `json:"source_digest"`
		GeneratorDigest string       `json:"generator_digest"`
		Cases           []exportCase `json:"cases"`
	}{pinnedOracleCommit, sources, digest, generatorDigest, cases}
	encoded, err := json.MarshalIndent(fixture, "", "  ")
	must(err)
	encoded = append(encoded, '\n')
	const path = "testdata/port/sync/export.json"
	if *check {
		actual, readErr := os.ReadFile(path)
		must(readErr)
		if !bytes.Equal(actual, encoded) {
			must(fmt.Errorf("export fixture stale"))
		}
		fmt.Println("PASS export oracle (5 cases)")
		return
	}
	must(os.WriteFile(path, encoded, 0600))
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
