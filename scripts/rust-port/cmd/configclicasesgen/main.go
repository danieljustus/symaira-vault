// Command configclicasesgen freezes read-only config CLI cases from the Go
// production helpers. The Rust integration test consumes this fixture as a
// language-neutral contract.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
	pinnedOracleRelease = "unreleased"
	fileMarker          = "__CONFIG__"
)

var productionSources = []string{
	"cmd/admin/config.go",
	"internal/config/dottedpath.go",
	"internal/cli/output/output.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

type expected struct {
	ExitCode       int    `json:"exit_code"`
	Stdout         string `json:"stdout,omitempty"`
	StdoutBytes    []int  `json:"stdout_bytes,omitempty"`
	StderrContains string `json:"stderr_contains,omitempty"`
}

type cliCase struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Config      string   `json:"config,omitempty"`
	ConfigBytes []int    `json:"config_bytes,omitempty"`
	Args        []string `json:"args"`
	Expected    expected `json:"expected"`
}

type fixture struct {
	SchemaVersion int       `json:"schema_version"`
	Oracle        oracle    `json:"oracle"`
	Cases         []cliCase `json:"cases"`
}

func inputs() []struct {
	name, description, config, key, output string
	args                                   []string
	quiet                                  bool
} {
	return []struct {
		name, description, config, key, output string
		args                                   []string
		quiet                                  bool
	}{
		{"get_scalar_text", "read a scalar in text mode", "vaultDir: /fixture/vault\n", "vaultDir", "text", nil, false},
		{"get_nested_bool", "read a nested boolean in text mode", "agents:\n  probe:\n    canWrite: true\n", "agents.probe.canWrite", "text", nil, false},
		{"get_complex_sequence", "render a sequence using YAML block text", "allowed:\n  - /fixture/a\n  - /fixture/b\n", "allowed", "text", nil, false},
		{"get_scalar_json", "encode a scalar result as a JSON object", "vaultDir: /fixture/vault\n", "vaultDir", "json", nil, false},
		{"get_unknown_output_is_text", "unknown output values follow the Go text path", "vaultDir: /fixture/vault\n", "vaultDir", "wat", nil, false},
		{"get_quiet", "quiet mode suppresses a successful result", "vaultDir: /fixture/vault\n", "vaultDir", "text", []string{"--quiet"}, true},
		{"list_raw", "list prints the original bytes without parsing", "vaultDir: /fixture/vault\nagents:\n  probe:\n    canWrite: true\n", "", "text", []string{"list"}, false},
		{"list_json_still_raw", "list keeps raw output even with JSON requested", "vaultDir: /fixture/vault\n", "", "json", []string{"list", "--json"}, false},
		{"list_empty", "an empty mapping is printed byte-for-byte", "{}\n", "", "text", []string{"list"}, false},
		{"missing_key", "a missing dotted key fails with a config error", "vaultDir: /fixture/vault\n", "missing.key", "text", nil, false},
		{"missing_file", "a missing config file fails with a config error", "", "vaultDir", "text", []string{"missing-file"}, false},
		{"malformed_yaml", "malformed YAML fails before lookup", "vaultDir: [\n", "vaultDir", "text", nil, false},
		{"quiet_missing_file", "quiet mode still reads a missing file and fails", "", "vaultDir", "text", []string{"missing-file", "--quiet"}, true},
	}
}

func buildCases() ([]cliCase, error) {
	cases := make([]cliCase, 0, len(inputs()))
	for _, input := range inputs() {
		args := []string{"config", "get", input.key, "--file", fileMarker}
		if len(input.args) > 0 {
			if input.args[0] == "list" {
				args = []string{"config", "list", "--file", fileMarker}
				args = append(args, input.args[1:]...)
			} else {
				args = append(args, input.args...)
			}
		}
		if input.output != "text" {
			args = append(args, "--output", input.output)
		}
		if input.quiet && (len(input.args) == 0 || input.args[0] != "--quiet") {
			args = append(args, "--quiet")
		}
		item := cliCase{Name: input.name, Description: input.description, Config: input.config, Args: args}
		if input.name == "missing_file" || input.name == "quiet_missing_file" {
			item.Args = []string{"config", "get", input.key, "--file", fileMarker + ".missing"}
			if input.quiet {
				item.Args = append(item.Args, "--quiet")
			}
			item.Expected = expected{ExitCode: 6, StderrContains: "cannot load config"}
			cases = append(cases, item)
			continue
		}
		if input.args != nil && input.args[0] == "list" {
			item.Expected = expected{ExitCode: 0}
			if !input.quiet {
				item.Expected.Stdout = input.config
			}
			cases = append(cases, item)
			continue
		}

		dir, err := os.MkdirTemp("", "configclicasesgen-")
		if err != nil {
			return nil, err
		}
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(input.config), 0o600); err != nil {
			_ = os.RemoveAll(dir)
			return nil, err
		}
		root, loadErr := configpkg.LoadConfigNode(path)
		_ = os.RemoveAll(dir)
		if loadErr != nil {
			item.Expected = expected{ExitCode: 6, StderrContains: "cannot load config"}
		} else {
			node, lookupErr := configpkg.GetConfigValue(root, input.key)
			if lookupErr != nil {
				item.Expected = expected{ExitCode: 6, StderrContains: "key"}
			} else {
				value := configpkg.NodeToString(node)
				item.Expected.ExitCode = 0
				if !input.quiet {
					if input.output == "json" {
						encoded, err := json.Marshal(map[string]string{input.key: value})
						if err != nil {
							return nil, err
						}
						item.Expected.Stdout = string(encoded) + "\n"
					} else {
						item.Expected.Stdout = value + "\n"
					}
				}
			}
		}
		cases = append(cases, item)
	}
	// The list command writes raw bytes. Keep one invalid UTF-8 case in the
	// generated corpus so a text conversion cannot silently change the file.
	raw := []byte("vaultDir: /fixture/vault\ninvalid: \xff\n")
	rawCase := cliCase{
		Name:        "list_invalid_utf8",
		Description: "list preserves invalid UTF-8 bytes",
		Args:        []string{"config", "list", "--file", fileMarker},
		Expected:    expected{ExitCode: 0, StdoutBytes: byteValues(raw)},
		ConfigBytes: byteValues(raw),
	}
	cases = append(cases, rawCase)
	return cases, nil
}

func byteValues(value []byte) []int {
	result := make([]int, len(value))
	for index, item := range value {
		result[index] = int(item)
	}
	return result
}

func main() {
	output := flag.String("output", "testdata/port/cli/config-inspect.json", "fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	flag.Parse()
	commitLabel, releaseLabel, err := resolveOracle(*check, *commit, *release)
	if err != nil {
		fatal("resolve oracle metadata: %v", err)
	}
	root, err := repositoryRoot()
	if err != nil {
		fatal("locate repository: %v", err)
	}
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	sourceDigest, err := provenance.Digest(root, sources)
	if err != nil {
		fatal("hash production sources: %v", err)
	}
	resolved, err := provenance.Verify(root, commitLabel, sources)
	if err != nil {
		fatal("verify oracle: %v", err)
	}
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/configclicasesgen/main.go"})
	if err != nil {
		fatal("hash generator: %v", err)
	}
	cases, err := buildCases()
	if err != nil {
		fatal("build cases: %v", err)
	}
	content, err := marshalJSON(fixture{1, oracle{commitLabel, resolved, releaseLabel, sources, sourceDigest, generatorDigest}, cases})
	if err != nil {
		fatal("marshal fixture: %v", err)
	}
	if *check {
		existing, err := os.ReadFile(*output)
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; regenerate deliberately")
		}
		fmt.Printf("PASS config CLI fixture (%d cases)\n", len(cases))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d cases)\n", *output, len(cases))
}

func resolveOracle(check bool, commit, release string) (string, string, error) {
	if commit != "" && commit != pinnedOracleCommit {
		return "", "", fmt.Errorf("oracle commit %q is not pinned", commit)
	}
	if release != "" && release != pinnedOracleRelease {
		return "", "", fmt.Errorf("oracle release %q is not pinned", release)
	}
	if check {
		return pinnedOracleCommit, pinnedOracleRelease, nil
	}
	if commit == "" || release == "" {
		return "", "", fmt.Errorf("--oracle-commit and --oracle-release are required")
	}
	return commit, release, nil
}

func repositoryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..")), nil
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
