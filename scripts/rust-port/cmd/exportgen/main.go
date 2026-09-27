// Command exportgen compares synthetic CSV/JSON exports with production Go.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/exporter"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const pinnedOracleCommit = "fca3f89401833b5e14ec4ec74ef736b0f63bca74"

type exportCase struct {
	Name         string                 `json:"name"`
	Entries      []exporter.ExportEntry `json:"entries"`
	Mapping      map[string]string      `json:"mapping"`
	FloatFields  []string               `json:"float_fields,omitempty"`
	JSON         string                 `json:"json"`
	JSONOutcomes []string               `json:"json_outcomes,omitempty"`
	CSV          string                 `json:"csv"`
	Notices      string                 `json:"notices"`
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
	// Digest the enforced subset so a dependency bump does not restamp the
	// fixture; source_files still records the full claimed provenance.
	digest, err := provenance.Digest(root, provenance.EnforcedSources(sources))
	must(err)
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/exportgen/main.go"})
	must(err)
	cases := []exportCase{
		{Name: "empty", Entries: []exporter.ExportEntry{}},
		{Name: "escaping", Entries: []exporter.ExportEntry{{Path: " <&>\u2028", Data: map[string]any{"leading": "\u00a0space", "quote": "a\"b", "comma": "a,b", "newline": "a\r\nb", "sentinel": "\\.", "empty": "", "line": "\u2029"}}}},
		{Name: "nested", Entries: []exporter.ExportEntry{{Path: "nested", Data: map[string]any{"array": []any{"a", nil, true, []any{"b"}}, "map": map[string]any{"z": []any{"x", "y"}, "a": map[string]any{"b": "c"}}, "nil": nil, "number": 42}}}},
		{Name: "numeric-edges", Entries: []exporter.ExportEntry{{Path: "numeric", Data: map[string]any{"small_exponent": 1e-7, "decimal_boundary": 1e-6, "large_decimal": 1e20, "large_exponent": 1e21, "csv_decimal_low": 1e-4, "csv_exponent_low": 1e-5, "csv_decimal_high": 1e5, "csv_exponent_high": 1e6, "negative_zero": math.Copysign(0, -1), "integer": int64(9007199254740993), "numeric_string": "-0.0"}}}, FloatFields: []string{"small_exponent", "decimal_boundary", "large_decimal", "large_exponent", "csv_decimal_low", "csv_exponent_low", "csv_decimal_high", "csv_exponent_high", "negative_zero"}},
		{Name: "attachments", Entries: []exporter.ExportEntry{{Path: "with-files", Data: map[string]any{"file_b64_0": "c3ludGhldGlj", "chunk_count": 1, "chunk_size": 9, "name": "fixture"}}, {Path: "only-files", Data: map[string]any{"file_b64_1": "c3ludGhldGlj"}}}},
		{Name: "mapping", Entries: []exporter.ExportEntry{{Path: "first", Data: map[string]any{"username": "fixture", "field": "value"}}, {Path: "second", Data: map[string]any{"extra": "optional"}}}, Mapping: map[string]string{"username": " name", "extra": "", "field": "renamed"}},
		{Name: "mapping-collision", Entries: []exporter.ExportEntry{{Path: "collision", Data: map[string]any{"alpha": "first", "beta": "second"}}}, Mapping: map[string]string{"alpha": "same", "beta": "same"}},
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
		if c.Name != "mapping-collision" && !bytes.Equal(j.Bytes(), streamed.Bytes()) {
			must(fmt.Errorf("go batch/stream export mismatch: %s", c.Name))
		}
		c.JSON = j.String()
		if c.Name == "mapping-collision" {
			outcomes := make(map[string]struct{})
			for range 128 {
				var batch, streamOutput bytes.Buffer
				must((&exporter.JSONExporter{}).Export(&batch, c.Entries, c.Mapping))
				outcomes[batch.String()] = struct{}{}
				stream := exporter.NewJSONStream(&streamOutput, c.Mapping)
				for _, entry := range c.Entries {
					must(stream.WriteEntry(entry))
				}
				must(stream.Close())
				outcomes[streamOutput.String()] = struct{}{}
			}
			for outcome := range outcomes {
				c.JSONOutcomes = append(c.JSONOutcomes, outcome)
			}
			sort.Strings(c.JSONOutcomes)
			if len(c.JSONOutcomes) != 2 {
				must(fmt.Errorf("expected both Go mapping-collision winners, got %d", len(c.JSONOutcomes)))
			}
			c.JSON = ""
		}
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
		fmt.Printf("PASS export oracle (%d cases)\n", len(cases))
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
