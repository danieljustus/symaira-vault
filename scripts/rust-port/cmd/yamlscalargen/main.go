// Command yamlscalargen freezes how the pinned gopkg.in/yaml.v3 renders odd
// strings: the YAML the Go CLI's `--output yaml` (a yaml.v3 marshal of plain
// maps and slices) produces when a string is a map value, a map key, a
// sequence item, a nested sequence-of-maps field, a deeply nested value or the
// document root. The Rust renderer (crates/symvault-gojson/src/yaml.rs) is
// replayed against it by crates/symvault-gojson/tests/yaml_scalars.rs.
//
// The corpus is independent of any CLI build and of the host OS: it records
// what the yaml.v3 module pinned in go.mod emits, so it is verified on every
// platform (`--check` regenerates in memory and compares bytes).
//
//	go run ./scripts/rust-port/cmd/yamlscalargen --check
//	go run ./scripts/rust-port/cmd/yamlscalargen            # regenerate
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	defaultOutput = "testdata/port/cli/yaml-scalars.json"
	yamlModule    = "gopkg.in/yaml.v3"
)

var generatorFiles = []string{"scripts/rust-port/cmd/yamlscalargen/main.go"}

type provenanceBlock struct {
	Module          string   `json:"module"`
	Version         string   `json:"version"`
	GoSumLines      []string `json:"go_sum_lines"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

type row struct {
	// Name labels the group the value belongs to.
	Name  string `json:"name"`
	Value string `json:"value"`
	// Renders of the same string in six positions, exactly as yaml.Marshal
	// returned them.
	MapValue string `json:"map_value"`
	MapKey   string `json:"map_key"`
	SeqItem  string `json:"seq_item"`
	Nested   string `json:"nested"`
	Deep     string `json:"deep"`
	Root     string `json:"root"`
}

type fixture struct {
	SchemaVersion int             `json:"schema_version"`
	Provenance    provenanceBlock `json:"provenance"`
	Notes         []string        `json:"notes"`
	Rows          []row           `json:"rows"`
}

func main() {
	output := flag.String("output", defaultOutput, "fixture path relative to the repository root")
	check := flag.Bool("check", false, "fail if the fixture differs")
	flag.Parse()
	root, err := repositoryRoot()
	if err != nil {
		fatal("locate repository: %v", err)
	}
	version, sums, err := moduleVersion(root)
	if err != nil {
		fatal("%v", err)
	}
	digest, err := provenance.Digest(root, generatorFiles)
	if err != nil {
		fatal("hash generator: %v", err)
	}
	rows, err := render()
	if err != nil {
		fatal("%v", err)
	}
	content, err := marshalJSON(fixture{
		SchemaVersion: 1,
		Provenance: provenanceBlock{
			Module: yamlModule, Version: version, GoSumLines: sums,
			GeneratorFiles: generatorFiles, GeneratorDigest: digest,
		},
		Notes: []string{
			"Every string is marshalled by the pinned gopkg.in/yaml.v3 in six positions: value of a map, key of a map, item of a sequence, field of a mapping inside a sequence inside a mapping, value two mappings deep, and the document root.",
			"The renders are byte-exact yaml.Marshal output, which is what internal/cli/output does for --output yaml.",
			"Values are valid UTF-8; the CLI never marshals invalid UTF-8 as text (yaml.v3 would emit !!binary).",
		},
		Rows: rows,
	})
	if err != nil {
		fatal("marshal fixture: %v", err)
	}
	target := filepath.Join(root, filepath.FromSlash(*output))
	if *check {
		existing, err := os.ReadFile(target) // #nosec G304 -- repository fixture path
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; regenerate deliberately")
		}
		fmt.Printf("PASS yaml scalar fixture (%d values, %s %s)\n", len(rows), yamlModule, version)
		return
	}
	if err := os.WriteFile(target, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d values)\n", *output, len(rows))
}

// marshal is exactly what the CLI's output package does (yaml.Marshal).
func marshal(value any) (string, error) {
	out, err := yaml.Marshal(value)
	return string(out), err
}

func render() ([]row, error) {
	var rows []row
	for _, group := range corpus() {
		for _, value := range group.values {
			r := row{Name: group.name, Value: value}
			var err error
			for _, target := range []struct {
				dst   *string
				value any
			}{
				{&r.MapValue, map[string]string{"k": value}},
				{&r.MapKey, map[string]string{value: "v"}},
				{&r.SeqItem, []string{value}},
				{&r.Nested, map[string][]map[string]string{"list": {{"k": value}}}},
				{&r.Deep, map[string]map[string]map[string]string{"a": {"b": {"c": value}}}},
				{&r.Root, value},
			} {
				if *target.dst, err = marshal(target.value); err != nil {
					return nil, fmt.Errorf("%q: %w", value, err)
				}
			}
			rows = append(rows, r)
		}
	}
	return rows, nil
}

type group struct {
	name   string
	values []string
}

// corpus is the set of strings: everything that changes how yaml.v3 picks a
// style or spells an escape. The seed-entry notes of the CLI end up in the same
// code path (`get --print --output yaml` marshals them as map values).
func corpus() []group {
	var controls []string
	for r := rune(1); r < 0x20; r++ {
		controls = append(controls, "a"+string(r)+"b")
	}
	controls = append(controls, "a\x7fb", "\x00", "a\x00b", "a\u0080b", "a\u0085b", "a\u009fb", "a\u00a0b", "\u00a0", "a\u00adb")
	return []group{
		{"empty-and-null", []string{"", "~", "null", "Null", "NULL", "NuLL"}},
		{"bool-like", []string{"true", "True", "TRUE", "tRUE", "false", "False", "FALSE", "yes", "Yes", "YES", "no", "No", "NO", "on", "On", "ON", "off", "Off", "OFF", "y", "Y", "n", "N"}},
		{"numbers", []string{"12", "-12", "+12", "012", "08", "0x1f", "0X1F", "0o17", "0O17", "0b101", "0B11", "-0b11", "1_000", "_1", "1__0", "9223372036854775807", "9223372036854775808", "18446744073709551615", "18446744073709551616", "-9223372036854775808", "-9223372036854775809", "1.5", "1.", ".5", "-.5", "+.5", "1e3", "1E3", "1e+3", "e3", "1.5e", "1_0.5", "1:30", "1:30:00", "190:20:30.15", "1:60", "0x", "0b", "0o", "0xg", "-", "+", ".", "..", "-0", "+0", "0", "00", "1 2", "1e1000", "0e0", "0.1.2", ".inf", ".Inf", ".INF", "+.inf", "-.inf", ".nan", ".NaN", ".NAN", ".nAn", "<<", "<"}},
		{"timestamps", []string{"2026-10-31", "2026-1-2", "2026-13-01", "2026-02-30", "2026-10-31T10:00:00Z", "2026-10-31t10:00:00Z", "2026-10-31 10:00:00", "2026-10-31 10:00", "2026-10-31T10:00:00", "2026-10-31T10:00:00+02:00", "2026-10-31T10:00:00.123456789Z", "2026-10-31T25:00:00Z", "2026-10-31T1:2:3Z", "20261031", "10000-01-01", "0000-01-01", "2026-10-31x", "2026-10-31 "}},
		{"indicators", []string{"a: b", "a:", "a:b", ":", ": a", "? a", "?", "- a", "-a", "- ", "---", "--- x", "...", "... x", "-- ", "#c", "a #b", "a#b", "!tag", "&a", "*a", "|", ">", "%", "@", "`", "'", "\"", "[", "]", "{", "}", ",", "a,b", "[a]", "{a}", "a'b", "a\"b", "a\\b", "\\", "key: value", "it's: x", "x: 'y'"}},
		{"spaces-and-tabs", []string{" ", "  ", "a ", " a", " a ", "a  b", "\t", "a\tb", "\ta", "a\t", " \t", "a \t b"}},
		{"newlines", []string{"\n", "\n\n", "\n\n\n", "a\n", "a\n\n", "a\n\n\n", "\na", "\n\na", "a\nb", "a\n\nb", "a\nb\n", "a\nb\n\n", " a\nb", "a\n b", "a \nb", "a\n  b\n", "\n a", "\n\n a\n", "a\tb\nc", "a\r\nb", "a\rb", "a\r", "\r", "\r\n", "line1\nline2\n", "line1\n\nline2\n\nline3", "a\n\n", " \n", "\n ", "a\n \nb", "text:\n- not a list\n"}},
		{"controls", controls},
		{"unicode-breaks", []string{"a\u2028b", "a\u2029b", "\u2028", "\u2029", "a\u0085b", "\u0085", "a\u2028", "\u2028a", "a\u2028\nb", "a\nb\u2028c", "a \u2028b", "a\u2028 b"}},
		{"bom-and-specials", []string{"\ufeff", "\ufeffbom", "bom\ufeff", "a\ufeffb", "\ufffe", "\uffff", "a\ufffeb", "\ufffd", "a\ufffdb", "\ud7ff", "\ue000", "a\ue000b", "\u00ff", "é", "ü ö", "日本語", "a é b"}},
		{"astral", []string{"\U0001F600", "a\U0001F600b", "\U0001F600\U0001F600", "emoji \U0001F600 end", "\U00010000", "\U0010ffff", "a\U0001F600\nb", "\U0001F600: x"}},
		{"long", []string{strings.Repeat("a", 90), strings.Repeat("word ", 40), strings.Repeat("k", 130), strings.Repeat("é", 70) + ": x", strings.Repeat("line\n", 30)}},
		{"plain", []string{"a", "abc", "Val-Alpha-001", "https://example.test", "a,b", "a/b", "path/to/x", "x y z", "tru", "nul", "Yes!", "a-b", "a.b", "a_b", "1a", "a1", "0.1.2.3", "v1.2.3", "10:20", "a: ", "a:  b"}},
	}
}

func repositoryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..")), nil
}

// moduleVersion reads the pinned yaml.v3 version and its go.sum lines.
func moduleVersion(root string) (string, []string, error) {
	mod, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- repository file
	if err != nil {
		return "", nil, err
	}
	version := ""
	for _, line := range strings.Split(string(mod), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == yamlModule {
			version = fields[1]
		}
	}
	if version == "" {
		return "", nil, fmt.Errorf("go.mod does not require %s", yamlModule)
	}
	sum, err := os.ReadFile(filepath.Join(root, "go.sum")) // #nosec G304 -- repository file
	if err != nil {
		return "", nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(sum), "\n") {
		if strings.HasPrefix(line, yamlModule+" "+version) {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return "", nil, fmt.Errorf("go.sum has no entry for %s %s", yamlModule, version)
	}
	return version, lines, nil
}

func marshalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
