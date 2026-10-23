package autotype

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateAutotypeEscapeFixture freezes the two escaping functions that
// every platform shares (autotype_common.go) from the production code. They are
// pure and host independent, so this runs on any OS. Linux tool routing and
// the focus guard are covered by scripts/rust-port/cmd/desktopgen and
// focus_fixture_generator_test.go respectively.
//
// Inputs are valid UTF-8 only: the Rust Autotype trait takes &str, so invalid
// byte sequences cannot reach the escapers there (Go would map each invalid
// byte to U+FFFD while Rust's lossy decoding maps maximal subparts, which
// differ; that boundary is documented rather than pretended equal).
func TestGenerateAutotypeEscapeFixture(t *testing.T) {
	mode := os.Getenv("SYMVAULT_AUTOTYPE_ESCAPE_FIXTURE")
	if mode == "" {
		t.Skip("set SYMVAULT_AUTOTYPE_ESCAPE_FIXTURE=write or check")
	}
	root := filepath.Join("..", "..")
	const pin = "861ad93813e3ee43c4ec989f45940d14b05b6eaf"
	files := []string{"internal/autotype/autotype_common.go"}
	hash := sha256.New()
	for _, name := range files {
		source, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		// #nosec G204 -- fixed git operation over compiled-in source paths and immutable pin
		cmd := exec.Command("git", "show", pin+":"+name)
		cmd.Dir = root
		pinned, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(source, pinned) {
			t.Fatalf("oracle source drift: %s", name)
		}
		_, _ = hash.Write([]byte(name + "\x00"))
		_, _ = hash.Write(source)
		_, _ = hash.Write([]byte{0})
	}
	generator, err := os.ReadFile("autotype_escape_fixture_generator_test.go")
	if err != nil {
		t.Fatal(err)
	}
	generatorHash := sha256.Sum256(generator)

	type testCase struct {
		Name   string `json:"name"`
		Input  string `json:"input"`
		Output string `json:"output"`
	}
	inputs := []struct{ name, input string }{
		{"empty", ""},
		{"plain", "hello"},
		{"backslash", `back\slash`},
		{"double_quote", `say "hello"`},
		{"newline", "line\nbreak"},
		{"carriage_return", "car\rriage"},
		{"tab", "tab\there"},
		{"mixed_escapes", `a\b"c\nd\re\tf`},
		{"sendkeys_metacharacters", "test{123}+^%~"},
		{"each_sendkeys_metacharacter", "+^%~{}[]"},
		{"brackets", "bracket[ and ]"},
		{"nul", "a\x00b"},
		{"other_controls_pass_through", "\x01\x07\x08\x0b\x0c\x1b\x7f"},
		{"unicode_bmp", "pässwörd ✓ 日本語"},
		{"astral", "𝄞 😀"},
		{"line_separators", "a\u2028b\u2029c"},
		{"already_escaped_look", `\\ \" \n {+} {{}`},
		{"trailing_backslash", `path\`},
		{"only_quote", `"`},
		{"only_brace", "{"},
		{"long_mixed", strings.Repeat(`a\"{+}`+"\n", 64)},
		{"single_quote_and_backtick_pass_through", "it's `x` $y"},
	}
	var apple, sendKeys []testCase
	for _, in := range inputs {
		apple = append(apple, testCase{in.name, in.input, escapeAppleScriptString(in.input)})
		sendKeys = append(sendKeys, testCase{in.name, in.input, escapeSendKeysString(in.input)})
	}
	fixture := struct {
		Commit        string     `json:"commit"`
		SourceFiles   []string   `json:"source_files"`
		SourceHash    string     `json:"source_hash"`
		GeneratorHash string     `json:"generator_hash"`
		AppleScript   []testCase `json:"apple_script"`
		SendKeys      []testCase `json:"send_keys"`
	}{pin, files, hex.EncodeToString(hash.Sum(nil)), hex.EncodeToString(generatorHash[:]), apple, sendKeys}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(fixture); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	path := filepath.Join(root, "testdata/port/platform/autotype_escape.json")
	if mode == "write" {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(existing, data) {
		t.Fatal("autotype escape fixture stale; regenerate with SYMVAULT_AUTOTYPE_ESCAPE_FIXTURE=write")
	}
}
