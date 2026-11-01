// Command gotemplategen freezes Go text/template behavior (with the repo's
// DefaultFuncMap over RenderData) for the Rust interpreter.
//
//	go run ./scripts/rust-port/cmd/gotemplategen --out testdata/port/template/gotemplate-corpus.json
//	go run ./scripts/rust-port/cmd/gotemplategen --check testdata/port/template/gotemplate-corpus.json
//	go run ./scripts/rust-port/cmd/gotemplategen --tables crates/symvault-sync/src/gotemplate/unicode_tables.rs
//
// --check re-runs the real Go text/template and byte-compares; it never writes.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"unicode/utf8"

	templatepkg "github.com/danieljustus/symaira-vault/internal/template"
)

// str carries a byte string that may not be valid UTF-8.
type str struct {
	S   string `json:"s,omitempty"`
	B64 string `json:"b64,omitempty"`
}

func mk(s string) str {
	if utf8.ValidString(s) {
		return str{S: s}
	}
	return str{B64: base64.StdEncoding.EncodeToString([]byte(s))}
}

type dataset struct {
	Name   string            `json:"name"`
	Refs   map[string]string `json:"refs"`
	Values map[string]string `json:"values"`
}

type pair struct {
	K str `json:"k"`
	V str `json:"v"`
}

// outData is the corpus form of a dataset: ordered pairs, because map keys
// (like values) may not be valid UTF-8 and JSON object keys cannot say so.
type outData struct {
	Name   str    `json:"name"`
	Refs   []pair `json:"refs"`
	Values []pair `json:"values"`
}

func pairs(m map[string]string) []pair {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := make([]pair, 0, len(keys))
	for _, k := range keys {
		out = append(out, pair{K: mk(k), V: mk(m[k])})
	}
	return out
}

func toOut(d dataset) outData {
	return outData{Name: mk(d.Name), Refs: pairs(d.Refs), Values: pairs(d.Values)}
}

type caseOut struct {
	ID     string  `json:"id"`
	Group  string  `json:"group"`
	Name   str     `json:"name"`
	Src    str     `json:"src"`
	Data   outData `json:"data"`
	Kind   string  `json:"kind"` // ok | parse_error | exec_error
	Output str     `json:"output"`
	Error  str     `json:"error"`
}

type fixture struct {
	SchemaVersion int       `json:"schema_version"`
	Oracle        oracle    `json:"oracle"`
	Funcs         []string  `json:"funcs"`
	Cases         []caseOut `json:"cases"`
	ValueCases    []valueCase `json:"value_cases"`
}

// valueCase pins ResolveRef's fmt.Sprintf("%v", v) of a JSON-decoded entry
// field (internal/template/resolver.go).
type valueCase struct {
	JSON   string `json:"json"`
	Output str    `json:"output"`
}

func valueCases() []valueCase {
	texts := []string{
		"0", "1", "-1", "-0.0", "1.0", "1.5", "0.1", "3.14159", "100000", "1000000", "123456789", "12345678901234567890", "1e21", "1e20", "1e-7", "0.000001", "0.0000001",
		"1e308", "-1e308", "1E3", "2.5e-3", "9007199254740993", "4.9e-324", "true", "false", "null", `""`, `"plain"`, `"héllo 日本"`, `"a b\nc"`,
		"[]", "{}", "[1]", "[1,2,3]", `["a","b c"]`, "[null]", "[true,false]", "[[],{}]", `[1,"a",true,null,[2,3],{"k":3}]`, "[1.5,1e21,1e-7]",
		`{"k":"v"}`, `{"b":1,"a":[1,2],"c":{"z":null,"y":"s"}}`, `{"B":1,"a":2,"é":3,"A":4}`, `{"a b":"c d"}`, `{"n":null}`,
		`{"secret":"JBSWY3DPEHPK3PXP","issuer":"Example","account":"me@example.com"}`, `{"x":{"y":{"z":[1,{"w":false}]}}}`, `["",""]`, `{"":""}`,
	}
	out := make([]valueCase, 0, len(texts))
	for _, t := range texts {
		var v any
		if err := json.Unmarshal([]byte(t), &v); err != nil {
			panic(err)
		}
		out = append(out, valueCase{JSON: t, Output: mk(fmt.Sprintf("%v", v))})
	}
	return out
}

type oracle struct {
	GoVersion       string            `json:"go_version"`
	BaseCommit      string            `json:"base_commit"`
	SourceDigest    string            `json:"source_digest"`
	GeneratorDigest string            `json:"generator_digest"`
	Sources         map[string]string `json:"sources"`
}

// render mirrors internal/template.Engine.Render after the template source
// and values are known: same FuncMap, same Parse/Execute calls, same error
// wrapping.
func render(name, src string, d dataset) (out string, kind string, err error) {
	tmpl, perr := template.New(name).Funcs(templatepkg.DefaultFuncMap()).Parse(src)
	if perr != nil {
		return "", "parse_error", fmt.Errorf("parse template %q: %w", name, perr)
	}
	data := templatepkg.RenderData{Name: d.Name, Refs: d.Refs, Values: d.Values}
	var buf strings.Builder
	if eerr := tmpl.Execute(&buf, data); eerr != nil {
		return "", "exec_error", fmt.Errorf("execute template %q: %w", name, eerr)
	}
	return buf.String(), "ok", nil
}

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

func digestFiles(root string, files []string) (string, map[string]string, error) {
	h := sha256.New()
	per := map[string]string{}
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			return "", nil, err
		}
		sum := sha256.Sum256(raw)
		per[f] = hex.EncodeToString(sum[:])
		fmt.Fprintf(h, "%s\x00%d\x00", f, len(raw))
		h.Write(raw)
	}
	return hex.EncodeToString(h.Sum(nil)), per, nil
}

var fuzzOverride []tcase

func build(baseCommit string) (fixture, error) {
	root := repoRoot()
	srcDigest, sources, err := digestFiles(root, []string{
		"internal/template/builtins.go",
		"internal/template/engine.go",
		"internal/template/funcs.go",
		"internal/template/resolver.go",
	})
	if err != nil {
		return fixture{}, err
	}
	genDigest, _, err := digestFiles(root, []string{
		"scripts/rust-port/cmd/gotemplategen/main.go",
		"scripts/rust-port/cmd/gotemplategen/cases.go",
		"scripts/rust-port/cmd/gotemplategen/tables.go",
	})
	if err != nil {
		return fixture{}, err
	}
	var funcs []string
	for name := range templatepkg.DefaultFuncMap() {
		funcs = append(funcs, name)
	}
	sortStrings(funcs)
	fx := fixture{
		SchemaVersion: 1,
		Oracle: oracle{
			GoVersion:       runtime.Version(),
			BaseCommit:      baseCommit,
			SourceDigest:    srcDigest,
			GeneratorDigest: genDigest,
			Sources:         sources,
		},
		Funcs:      funcs,
		ValueCases: valueCases(),
	}
	seen := map[string]bool{}
	cases := allCases()
	if fuzzOverride != nil {
		cases = fuzzOverride
	}
	for i, c := range cases {
		if c.id == "" {
			c.id = fmt.Sprintf("%s-%03d", c.group, i)
		}
		if seen[c.id] {
			return fixture{}, fmt.Errorf("duplicate case id %q", c.id)
		}
		seen[c.id] = true
		name := c.name
		if name == "" {
			name = "t"
		}
		out, kind, rerr := render(name, c.src, c.data)
		co := caseOut{ID: c.id, Group: c.group, Name: mk(name), Src: mk(c.src), Data: toOut(c.data), Kind: kind, Output: mk(out)}
		if rerr != nil {
			co.Error = mk(rerr.Error())
		}
		fx.Cases = append(fx.Cases, co)
	}
	return fx, nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func marshal(fx fixture) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(fx); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func main() {
	out := flag.String("out", "", "write the corpus to this path")
	check := flag.String("check", "", "re-run Go and byte-compare against this corpus (non-writing)")
	tables := flag.String("tables", "", "write the Rust unicode tables to this path")
	fuzzN := flag.Int("fuzz", 0, "with --out: write N pseudo-random cases (not the committed corpus)")
	fuzzSeed := flag.Int64("seed", 1, "seed for --fuzz")
	base := flag.String("base", "1f965f6e56f2507b9183cf30b822f58f7badb951", "base commit recorded in the fixture header")
	flag.Parse()

	switch {
	case *tables != "":
		if err := os.WriteFile(*tables, []byte(emitTables()), 0o644); err != nil { //nolint:gosec // generated source
			fatal(err)
		}
	case *out != "":
		if *fuzzN > 0 {
			fuzzOverride = fuzzCases(*fuzzSeed, *fuzzN)
		}
		fx, err := build(*base)
		if err != nil {
			fatal(err)
		}
		raw, err := marshal(fx)
		if err != nil {
			fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil { //nolint:gosec // fixture dir
			fatal(err)
		}
		if err := os.WriteFile(*out, raw, 0o644); err != nil { //nolint:gosec // fixture file
			fatal(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %d cases to %s\n", len(fx.Cases), *out)
	case *check != "":
		want, err := os.ReadFile(*check)
		if err != nil {
			fatal(err)
		}
		var header fixture
		if err := json.Unmarshal(want, &header); err != nil {
			fatal(err)
		}
		fx, err := build(header.Oracle.BaseCommit)
		if err != nil {
			fatal(err)
		}
		got, err := marshal(fx)
		if err != nil {
			fatal(err)
		}
		if !bytes.Equal(got, want) {
			reportDrift(header, fx)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "ok: %d cases byte-identical\n", len(fx.Cases))
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func reportDrift(old, fresh fixture) {
	if old.Oracle.SourceDigest != fresh.Oracle.SourceDigest {
		fmt.Fprintln(os.Stderr, "oracle source digest changed")
	}
	if old.Oracle.GeneratorDigest != fresh.Oracle.GeneratorDigest {
		fmt.Fprintln(os.Stderr, "generator digest changed")
	}
	if old.Oracle.GoVersion != fresh.Oracle.GoVersion {
		fmt.Fprintf(os.Stderr, "go version %s != %s\n", old.Oracle.GoVersion, fresh.Oracle.GoVersion)
	}
	byID := map[string]caseOut{}
	for _, c := range old.Cases {
		byID[c.ID] = c
	}
	for _, c := range fresh.Cases {
		o, ok := byID[c.ID]
		if !ok {
			fmt.Fprintf(os.Stderr, "case %s: missing from corpus\n", c.ID)
			continue
		}
		a, _ := json.Marshal(o)
		b, _ := json.Marshal(c)
		if !bytes.Equal(a, b) {
			fmt.Fprintf(os.Stderr, "case %s: drift\n  corpus: %s\n  go:     %s\n", c.ID, a, b)
		}
		delete(byID, c.ID)
	}
	for id := range byID {
		fmt.Fprintf(os.Stderr, "case %s: not produced by generator\n", id)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gotemplategen:", err)
	os.Exit(1)
}
