package autotype

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGenerateFocusFixture(t *testing.T) {
	mode := os.Getenv("SYMVAULT_FOCUS_FIXTURE")
	if mode == "" {
		t.Skip("set SYMVAULT_FOCUS_FIXTURE=write or check")
	}
	root := filepath.Join("..", "..")
	const pin = "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
	// go.mod/go.sum stay recorded as provenance but are not asserted: binding
	// them turns every dependency bump into an oracle drift failure even though
	// focus behavior is unchanged.
	allFiles := []string{"internal/autotype/focus.go", "go.mod", "go.sum"}
	files := []string{"internal/autotype/focus.go"}
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
	generator, err := os.ReadFile("focus_fixture_generator_test.go")
	if err != nil {
		t.Fatal(err)
	}
	generatorHash := sha256.Sum256(generator)
	type testCase struct {
		Name     string   `json:"name"`
		Strict   string   `json:"strict"`
		Captures []string `json:"captures"`
		Error    string   `json:"error"`
		Calls    int      `json:"calls"`
	}
	cases := []testCase{
		{Name: "stable", Captures: []string{"process:a", "process:a"}},
		{Name: "changed", Captures: []string{"process:a", "process:b"}},
		{Name: "empty_first", Captures: []string{"", "process:b"}},
		{Name: "empty_second", Captures: []string{"process:a", ""}},
		{Name: "unavailable_default", Captures: []string{"unavailable"}},
		{Name: "unavailable_zero", Strict: "0", Captures: []string{"unavailable"}},
		{Name: "unavailable_strict", Strict: "false", Captures: []string{"unavailable"}},
		{Name: "first_failed", Captures: []string{"failed"}},
		{Name: "second_failed", Captures: []string{"process:a", "failed"}},
		{Name: "second_unavailable_strict", Strict: "1", Captures: []string{"process:a", "unavailable"}},
	}
	old := captureActiveWindowFunc
	t.Cleanup(func() { captureActiveWindowFunc = old })
	for i := range cases {
		c := &cases[i]
		t.Setenv("SYMVAULT_AUTOTYPE_STRICT_FOCUS", c.Strict)
		captureActiveWindowFunc = func() (string, error) {
			value := c.Captures[c.Calls]
			c.Calls++
			switch value {
			case "unavailable":
				return "", ErrFocusUnavailable
			case "failed":
				return "", errors.New("capture failed")
			default:
				return value, nil
			}
		}
		if err := guardActiveWindow(); err != nil {
			c.Error = err.Error()
		}
	}
	fixture := struct {
		Commit        string     `json:"commit"`
		SourceFiles   []string   `json:"source_files"`
		SourceHash    string     `json:"source_hash"`
		GeneratorHash string     `json:"generator_hash"`
		Cases         []testCase `json:"cases"`
	}{pin, allFiles, hex.EncodeToString(hash.Sum(nil)), hex.EncodeToString(generatorHash[:]), cases}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata/port/platform/focus.json")
	if mode == "write" {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(existing, data) {
		t.Fatal("focus fixture stale; regenerate with SYMVAULT_FOCUS_FIXTURE=write")
	}
}
