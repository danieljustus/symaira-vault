// Command import1passgen freezes the production 1Password and pass adapters
// into a source-provenanced fixture consumed by the Rust importer tests.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/importer"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const pinnedOracleCommit = "fca3f89401833b5e14ec4ec74ef736b0f63bca74"

type entry struct {
	Path     string         `json:"path"`
	Data     map[string]any `json:"data"`
	Warnings []string       `json:"warnings"`
}

type passFile struct {
	Path          string `json:"path"`
	Content       string `json:"content,omitempty"`
	ContentBase64 string `json:"content_base64,omitempty"`
}

type importCase struct {
	Name          string     `json:"name"`
	Kind          string     `json:"kind"`
	InputBase64   string     `json:"input_base64,omitempty"`
	Files         []passFile `json:"files,omitempty"`
	Expected      []entry    `json:"expected"`
	Failed        bool       `json:"failed"`
	ErrorContains string     `json:"error_contains,omitempty"`
}

func main() {
	check := flag.Bool("check", false, "check fixture freshness")
	flag.Parse()
	rootBytes, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	must(err)
	root := strings.TrimSpace(string(rootBytes))
	sources := []string{
		"internal/crypto/totp.go",
		"internal/importer/importer.go",
		"internal/importer/onepux.go",
		"internal/importer/pass.go",
		"internal/importer/totp.go",
		"internal/secrets/filter.go",
	}
	_, err = provenance.Verify(root, pinnedOracleCommit, sources)
	must(err)
	digest, err := provenance.Digest(root, sources)
	must(err)
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/import1passgen/main.go"})
	must(err)

	pass, err := passCase()
	must(err)
	cases := []importCase{
		pass,
		onePuxCase(),
		onePuxInvalidUTF8Case(),
		onePuxInvalidUTF8AfterEscapeCase(),
		onePuxMalformedEscapedInvalidUTF8Case(),
		onePuxInvalidUTF8OutsideStringCase(),
		onePuxInvalidFirstTOTPCase(),
		onePuxNullCase(),
		onePuxNullElementsCase(),
		onePuxDuplicateExportCase(),
		onePuxMissingExportCase(),
		onePuxMalformedCase(),
		onePuxSuffixBoundaryCase(),
		onePuxTrailingJSONCase(),
	}

	fixture := struct {
		Commit          string       `json:"commit"`
		Sources         []string     `json:"sources"`
		SourceDigest    string       `json:"source_digest"`
		GeneratorDigest string       `json:"generator_digest"`
		Cases           []importCase `json:"cases"`
	}{pinnedOracleCommit, sources, digest, generatorDigest, cases}
	content, err := json.MarshalIndent(fixture, "", "  ")
	must(err)
	content = append(content, '\n')
	path := "testdata/port/sync/onepass.json"
	if *check {
		old, err := os.ReadFile(path)
		must(err)
		if !bytes.Equal(old, content) {
			must(fmt.Errorf("1Password/pass fixture stale"))
		}
	} else {
		must(os.WriteFile(path, content, 0600))
	}
	fmt.Printf("PASS 1Password/pass oracle (%d cases)\n", len(cases))
}

func onePuxCase() importCase {
	// This exercises duplicate credential fields, title-based TOTP detection,
	// first-value selection, skipped categories, and skipped trashed items.
	payload := []byte(`{"accounts":[{"vaults":[{"items":[
{"categoryUuid":"001","title":"Work Login","details":{"loginFields":[
{"designation":"username","value":"old-user"},{"designation":"Username","value":"new-user"},
{"designation":"password","value":"old-pass"},{"designation":"PASSWORD","value":"new-pass"}],
"notesPlain":"notes","sections":[{"fields":[
{"t":"custom","title":"One-Time Password","v":{"otp":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}},
{"n":"totp","v":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}]}]},
"overview":{"urls":[{"url":"https://example.test"}],"tags":["work"]}},
{"categoryUuid":"001","title":"Trash","trashed":true},
{"categoryUuid":"webforms.generic","title":"Ignored"}
]}]}]}`)
	input := zipBytes("nested/export.json", payload)
	parser, err := importer.New(importer.Format1Password)
	must(err)
	entries, err := parser.Parse(bytes.NewReader(input))
	must(err)
	return importCase{Name: "onepux_duplicate_and_first_totp", Kind: "onepux", InputBase64: base64.StdEncoding.EncodeToString(input), Expected: convert(entries)}
}

func onePuxInvalidUTF8Case() importCase {
	payload := []byte(`{"accounts":[{"vaults":[{"items":[{"categoryUuid":"001","title":"bad`)
	payload = append(payload, 0xff)
	payload = append(payload, []byte(`title"}]}]}]}`)...)
	input := zipBytes("export.json", payload)
	parser, err := importer.New(importer.Format1Password)
	must(err)
	entries, err := parser.Parse(bytes.NewReader(input))
	must(err)
	return importCase{Name: "onepux_invalid_utf8_in_string", Kind: "onepux", InputBase64: base64.StdEncoding.EncodeToString(input), Expected: convert(entries)}
}

func onePuxInvalidUTF8AfterEscapeCase() importCase {
	payload := []byte(`{"accounts":[{"vaults":[{"items":[{"categoryUuid":"001","title":"ébad\\`)
	payload = append(payload, 0xff)
	payload = append(payload, []byte(`title"}]}]}]}`)...)
	input := zipBytes("export.json", payload)
	parser, err := importer.New(importer.Format1Password)
	must(err)
	entries, err := parser.Parse(bytes.NewReader(input))
	must(err)
	return importCase{Name: "onepux_invalid_utf8_after_escaped_backslash", Kind: "onepux", InputBase64: base64.StdEncoding.EncodeToString(input), Expected: convert(entries)}
}

func onePuxMalformedEscapedInvalidUTF8Case() importCase {
	payload := []byte(`{"accounts":[{"vaults":[{"items":[{"categoryUuid":"001","title":"ébad\`)
	payload = append(payload, 0xff)
	payload = append(payload, []byte(`title"}]}]}]}`)...)
	return onePuxErrorCase("onepux_malformed_escaped_invalid_utf8", zipBytes("export.json", payload))
}

func onePuxInvalidUTF8OutsideStringCase() importCase {
	payload := []byte(`{"accounts":`)
	payload = append(payload, 0xff)
	payload = append(payload, []byte(`}`)...)
	return onePuxErrorCase("onepux_invalid_utf8_outside_string", zipBytes("export.json", payload))
}

func onePuxMissingExportCase() importCase {
	input := zipBytes("other.json", []byte(`{}`))
	parser, err := importer.New(importer.Format1Password)
	must(err)
	_, err = parser.Parse(bytes.NewReader(input))
	if err == nil {
		must(fmt.Errorf("missing export case unexpectedly succeeded"))
	}
	return importCase{
		Name:          "onepux_missing_export",
		Kind:          "onepux",
		InputBase64:   base64.StdEncoding.EncodeToString(input),
		Expected:      []entry{},
		Failed:        true,
		ErrorContains: err.Error(),
	}
}

func onePuxInvalidFirstTOTPCase() importCase {
	payload := []byte(`{"accounts":[{"vaults":[{"items":[
{"categoryUuid":"001","title":"Invalid OTP","details":{"sections":[{"fields":[
{"n":"totp","v":"bad"},
{"n":"totp","v":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}]}]}}
]}]}]}`)
	input := zipBytes("export.json", payload)
	parser, err := importer.New(importer.Format1Password)
	must(err)
	entries, err := parser.Parse(bytes.NewReader(input))
	must(err)
	return importCase{Name: "onepux_first_invalid_totp", Kind: "onepux", InputBase64: base64.StdEncoding.EncodeToString(input), Expected: convert(entries)}
}

func onePuxNullCase() importCase {
	payload := []byte(`{"accounts":[{"vaults":[{"items":[
{"categoryUuid":"001","title":"Null Fields","details":null,"overview":null},
{"categoryUuid":"001","title":"Null Members","details":{"loginFields":null,"notesPlain":null,"sections":null},"overview":{"urls":null,"tags":null}}
]}]}]}`)
	input := zipBytes("export.json", payload)
	parser, err := importer.New(importer.Format1Password)
	must(err)
	entries, err := parser.Parse(bytes.NewReader(input))
	must(err)
	return importCase{Name: "onepux_null_fields", Kind: "onepux", InputBase64: base64.StdEncoding.EncodeToString(input), Expected: convert(entries)}
}

func onePuxNullElementsCase() importCase {
	input := zipBytes("export.json", []byte(`{"accounts":[null,{"vaults":[null,{"items":[null,{"categoryUuid":"001","title":"null elements","details":{"loginFields":[null],"sections":[null,{"fields":[null]}]},"overview":{"urls":[null],"tags":[null,"tag"]}}]}]}]}`))
	parser, err := importer.New(importer.Format1Password)
	must(err)
	entries, err := parser.Parse(bytes.NewReader(input))
	must(err)
	return importCase{Name: "onepux_null_elements", Kind: "onepux", InputBase64: base64.StdEncoding.EncodeToString(input), Expected: convert(entries)}
}

func onePuxDuplicateExportCase() importCase {
	first := []byte(`{"accounts":[{"vaults":[{"items":[{"categoryUuid":"001","title":"first"}]}]}]}`)
	second := []byte(`{"accounts":[{"vaults":[{"items":[{"categoryUuid":"001","title":"second"}]}]}]}`)
	input := zipBytesMultiple([]zipEntry{{"export.json", first}, {"nested/export.json", second}})
	parser, err := importer.New(importer.Format1Password)
	must(err)
	entries, err := parser.Parse(bytes.NewReader(input))
	must(err)
	return importCase{Name: "onepux_duplicate_export_uses_first", Kind: "onepux", InputBase64: base64.StdEncoding.EncodeToString(input), Expected: convert(entries)}
}

func onePuxMalformedCase() importCase {
	input := []byte("not a zip archive")
	return onePuxErrorCase("onepux_malformed_zip", input)
}

func onePuxSuffixBoundaryCase() importCase {
	return onePuxErrorCase("onepux_suffix_boundary", zipBytes("fooexport.json", []byte(`{}`)))
}

func onePuxTrailingJSONCase() importCase {
	return onePuxErrorCase("onepux_trailing_json", zipBytes("export.json", []byte(`{} {}`)))
}

func onePuxErrorCase(name string, input []byte) importCase {
	parser, err := importer.New(importer.Format1Password)
	must(err)
	_, err = parser.Parse(bytes.NewReader(input))
	if err == nil {
		must(fmt.Errorf("malformed zip case unexpectedly succeeded"))
	}
	errorContains := err.Error()
	switch name {
	case "onepux_malformed_zip":
		errorContains = "zip"
	case "onepux_trailing_json":
		errorContains = "parse export.json"
	case "onepux_suffix_boundary":
		errorContains = "export.json not found"
	case "onepux_malformed_escaped_invalid_utf8", "onepux_invalid_utf8_outside_string":
		errorContains = "parse export.json"
	}
	return importCase{
		Name:          name,
		Kind:          "onepux",
		InputBase64:   base64.StdEncoding.EncodeToString(input),
		Expected:      []entry{},
		Failed:        true,
		ErrorContains: errorContains,
	}
}

func passCase() (importCase, error) {
	root, err := os.MkdirTemp("", "symvault-import1passgen-")
	if err != nil {
		return importCase{}, err
	}
	defer func() { _ = os.RemoveAll(root) }()
	store := filepath.Join(root, "store")
	bin := filepath.Join(root, "bin")
	if err = os.MkdirAll(filepath.Join(store, "work"), 0700); err != nil {
		return importCase{}, err
	}
	if err = os.MkdirAll(bin, 0700); err != nil {
		return importCase{}, err
	}
	files := []passFile{
		{Path: "work/example.gpg", Content: "example-secret\nusername:  example-user\nurl: https://example.test\ncomment line\n"},
		{Path: "work/invalid.gpg", Content: "invalid-secret\notpauth://totp/example?secret=bad\n"},
		{Path: "work/slash\\name.gpg", Content: "pw\n"},
		{Path: "work/truncated-utf8.gpg", ContentBase64: base64.StdEncoding.EncodeToString([]byte("bad-\xe2\x82"))},
	}
	for _, file := range files {
		content := []byte(file.Content)
		if file.ContentBase64 != "" {
			content, err = base64.StdEncoding.DecodeString(file.ContentBase64)
			if err != nil {
				return importCase{}, err
			}
		}
		if err = os.WriteFile(filepath.Join(store, file.Path), content, 0600); err != nil {
			return importCase{}, err
		}
	}
	gpg := filepath.Join(bin, "gpg")
	// Synthetic plaintext input only: no keyring or real GPG material is touched.
	// #nosec G306 -- executable synthetic GPG fixture in private temporary directory
	if err = os.WriteFile(gpg, []byte("#!/bin/sh\ncat \"$4\"\n"), 0700); err != nil {
		return importCase{}, err
	}
	oldPath := os.Getenv("PATH")
	if err = os.Setenv("PATH", bin+string(os.PathListSeparator)+oldPath); err != nil {
		return importCase{}, err
	}
	defer func() { _ = os.Setenv("PATH", oldPath) }()
	entries, err := importer.ImportPass(store)
	if err != nil {
		return importCase{}, err
	}
	return importCase{
		Name:     "pass_adapter_recursive_and_warning",
		Kind:     "pass",
		Files:    files,
		Expected: convert(entries),
	}, nil
}

type zipEntry struct {
	name    string
	payload []byte
}

func zipBytes(name string, payload []byte) []byte {
	return zipBytesMultiple([]zipEntry{{name, payload}})
}

func zipBytesMultiple(entries []zipEntry) []byte {
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for _, entry := range entries {
		file, err := writer.Create(entry.name)
		must(err)
		_, err = io.Copy(file, bytes.NewReader(entry.payload))
		must(err)
	}
	must(writer.Close())
	return out.Bytes()
}

func convert(entries []importer.ImportedEntry) []entry {
	out := make([]entry, 0, len(entries))
	for _, item := range entries {
		out = append(out, entry{Path: item.Path, Data: item.Data, Warnings: item.Warnings})
	}
	return out
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
