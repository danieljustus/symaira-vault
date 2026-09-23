// mobilejsonnumgen records Go's encoding/json float64 formatting for the
// mobile Entry.Data boundary and binds the fixture to the bridge/type sources.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	outputPath = "testdata/port/ffi/mobile-json-numbers.json"
	inputJSON  = `{"fixed_negative_six":1e-6,"fixed_positive_twenty":1e20,"scientific_negative_seven":1e-7,"scientific_positive_twenty_one":1e21}`
)

type fixture struct {
	GoVersion    string            `json:"go_version"`
	SourceSHA256 map[string]string `json:"source_sha256"`
	InputJSON    string            `json:"input_json"`
	ExpectedJSON string            `json:"expected_json"`
}

func main() {
	check := flag.Bool("check", false, "verify that the checked-in Go fixture is current")
	output := flag.String("output", outputPath, "fixture path")
	flag.Parse()

	value, err := buildFixture()
	if err != nil {
		fatal("build fixture: %v", err)
	}
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fatal("marshal fixture: %v", err)
	}
	content = append(content, '\n')
	if *check {
		existing, err := os.ReadFile(*output)
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; regenerate with go run ./scripts/rust-port/cmd/mobilejsonnumgen")
		}
		fmt.Println("PASS Go mobile JSON number fixture")
		return
	}
	if err := os.WriteFile(*output, content, 0o644); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("wrote %s\n", *output)
}

func buildFixture() (fixture, error) {
	var entry vault.Entry
	if err := json.Unmarshal([]byte(`{"data":`+inputJSON+`}`), &entry); err != nil {
		return fixture{}, fmt.Errorf("decode Go Entry: %w", err)
	}
	expected, err := json.Marshal(entry.Data)
	if err != nil {
		return fixture{}, fmt.Errorf("marshal Go Entry.Data: %w", err)
	}
	sources := []string{"internal/mobilebind/mobilebind.go", "internal/vault/entry.go"}
	hashes := make(map[string]string, len(sources))
	for _, path := range sources {
		content, err := os.ReadFile(path)
		if err != nil {
			return fixture{}, fmt.Errorf("read source %s: %w", path, err)
		}
		digest := sha256.Sum256(content)
		hashes[path] = hex.EncodeToString(digest[:])
	}
	return fixture{
		GoVersion:    runtime.Version(),
		SourceSHA256: hashes,
		InputJSON:    inputJSON,
		ExpectedJSON: string(expected),
	}, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "mobilejsonnumgen: "+format+"\n", args...)
	os.Exit(1)
}
