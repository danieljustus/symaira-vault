// Command configclicasesgen freezes raw config list cases from the Go CLI.
// The Rust integration test consumes this fixture as a language-neutral
// contract. Expected output and exit status always come from the pinned Go
// binary, including for malformed and non-UTF-8 input.
package main

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
	pinnedOracleRelease = "unreleased"
	fileMarker          = "__CONFIG__"
)

var productionSources = []string{
	"cmd/admin/config.go",
	"internal/cli/cli.go",
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
	StdoutBytes    []int  `json:"stdout_bytes,omitempty"`
	StderrContains string `json:"stderr_contains,omitempty"`
}

type cliCase struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	ConfigBytes []int    `json:"config_bytes,omitempty"`
	WriteConfig bool     `json:"write_config"`
	DefaultPath bool     `json:"default_path,omitempty"`
	ClearHome   bool     `json:"clear_home,omitempty"`
	Args        []string `json:"args"`
	Expected    expected `json:"expected"`
}

type fixture struct {
	SchemaVersion int       `json:"schema_version"`
	Oracle        oracle    `json:"oracle"`
	Cases         []cliCase `json:"cases"`
}

type inputCase struct {
	name, description string
	config            []byte
	writeConfig       bool
	defaultPath       bool
	clearHome         bool
	args              []string
}

func inputs() []inputCase {
	return []inputCase{
		{
			name:        "list_raw",
			description: "list prints ordinary config bytes without parsing",
			config:      []byte("vaultDir: /fixture/vault\nagents:\n  probe:\n    canWrite: true\n"),
			writeConfig: true,
			args:        []string{"config", "list", "--file", fileMarker},
		},
		{
			name:        "list_crlf",
			description: "list preserves CRLF bytes",
			config:      []byte("vaultDir: /fixture/vault\r\nagents:\r\n  probe:\r\n    canWrite: true\r\n"),
			writeConfig: true,
			args:        []string{"config", "list", "--file", fileMarker},
		},
		{
			name:        "list_empty",
			description: "list preserves an empty config file",
			config:      []byte{},
			writeConfig: true,
			args:        []string{"config", "list", "--file", fileMarker},
		},
		{
			name:        "list_malformed",
			description: "list prints malformed YAML without parsing it",
			config:      []byte("vaultDir: [\n"),
			writeConfig: true,
			args:        []string{"config", "list", "--file", fileMarker},
		},
		{
			name:        "list_invalid_utf8",
			description: "list preserves invalid UTF-8 bytes",
			config:      []byte{'v', 'a', 'u', 'l', 't', 'D', 'i', 'r', ':', ' ', '/', 'f', 'i', 'x', 't', 'u', 'r', 'e', '\n', 'i', 'n', 'v', 'a', 'l', 'i', 'd', ':', ' ', 0xff, '\n'},
			writeConfig: true,
			args:        []string{"config", "list", "--file", fileMarker},
		},
		{
			name:        "list_json_flag",
			description: "list remains raw when JSON output is requested",
			config:      []byte("vaultDir: /fixture/vault\n"),
			writeConfig: true,
			args:        []string{"config", "list", "--file", fileMarker, "--json"},
		},
		{
			name:        "list_json_global_before_command",
			description: "list accepts a global JSON flag before the command",
			config:      []byte("vaultDir: /fixture/vault\n"),
			writeConfig: true,
			args:        []string{"--json", "config", "list", "--file", fileMarker},
		},
		{
			name:        "list_output_global_before_command",
			description: "list accepts a global output flag before the command",
			config:      []byte("vaultDir: /fixture/vault\n"),
			writeConfig: true,
			args:        []string{"--output", "json", "config", "list", "--file", fileMarker},
		},
		{
			name:        "list_quiet",
			description: "quiet list reads the file and suppresses stdout",
			config:      []byte("vaultDir: /fixture/vault\n"),
			writeConfig: true,
			args:        []string{"config", "list", "--file", fileMarker, "--quiet"},
		},
		{
			name:        "list_default_home",
			description: "list uses ~/.symvault/config.yaml when no file is supplied",
			config:      []byte("vaultDir: /fixture/vault\n"),
			writeConfig: true,
			defaultPath: true,
			args:        []string{"config", "list"},
		},
		{
			name:        "list_empty_file_falls_back",
			description: "an empty --file value uses the default home path",
			config:      []byte("vaultDir: /fixture/vault\n"),
			writeConfig: true,
			defaultPath: true,
			args:        []string{"config", "list", "--file="},
		},
		{
			name:        "list_missing_quiet",
			description: "quiet list still reports a missing config file",
			args:        []string{"config", "list", "--file", fileMarker + ".missing", "--quiet"},
		},
		{
			name:        "list_missing_home",
			description: "a missing home directory is a general CLI error",
			clearHome:   true,
			args:        []string{"config", "list", "--file="},
		},
	}
}

func buildCases(goBinary, root string) ([]cliCase, error) {
	cases := make([]cliCase, 0, len(inputs()))
	for _, input := range inputs() {
		tempRoot, err := os.MkdirTemp("", "configclicasesgen-")
		if err != nil {
			return nil, err
		}
		home := filepath.Join(tempRoot, "home")
		configPath := filepath.Join(tempRoot, "config.yaml")
		if input.defaultPath {
			configPath = filepath.Join(home, ".symvault", "config.yaml")
		}
		if input.writeConfig {
			if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
				_ = os.RemoveAll(tempRoot)
				return nil, err
			}
			if err := os.WriteFile(configPath, input.config, 0o600); err != nil {
				_ = os.RemoveAll(tempRoot)
				return nil, err
			}
		}
		args := make([]string, len(input.args))
		for i, arg := range input.args {
			args[i] = strings.ReplaceAll(arg, fileMarker, configPath)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, goBinary, args...)
		cmd.Dir = root
		env := os.Environ()
		env = setEnv(env, "HOME", home)
		env = setEnv(env, "USERPROFILE", home)
		env = setEnv(env, "XDG_CONFIG_HOME", filepath.Join(tempRoot, "xdg-config"))
		env = setEnv(env, "XDG_DATA_HOME", filepath.Join(tempRoot, "xdg-data"))
		env = setEnv(env, "XDG_CACHE_HOME", filepath.Join(tempRoot, "xdg-cache"))
		if input.clearHome {
			env = removeEnv(env, "HOME")
			env = removeEnv(env, "USERPROFILE")
		}
		cmd.Env = env
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		runErr := cmd.Run()
		if ctx.Err() != nil {
			cancel()
			_ = os.RemoveAll(tempRoot)
			return nil, fmt.Errorf("run oracle case %s: %w", input.name, ctx.Err())
		}
		cancel()
		exitCode := 0
		if runErr != nil {
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) {
				_ = os.RemoveAll(tempRoot)
				return nil, fmt.Errorf("run oracle case %s: %w", input.name, runErr)
			}
			exitCode = exitErr.ExitCode()
		}
		item := cliCase{
			Name:        input.name,
			Description: input.description,
			WriteConfig: input.writeConfig,
			DefaultPath: input.defaultPath,
			ClearHome:   input.clearHome,
			Args:        input.args,
			Expected: expected{
				ExitCode:       exitCode,
				StdoutBytes:    byteValues(stdout.Bytes()),
				StderrContains: errorNeedle(stderr.Bytes()),
			},
		}
		if input.writeConfig {
			item.ConfigBytes = byteValues(input.config)
		}
		cases = append(cases, item)
		_ = os.RemoveAll(tempRoot)
	}
	return cases, nil
}

func errorNeedle(stderr []byte) string {
	for _, needle := range []string{"cannot determine config file path", "cannot load config"} {
		if bytes.Contains(stderr, []byte(needle)) {
			return needle
		}
	}
	return ""
}

func byteValues(value []byte) []int {
	result := make([]int, len(value))
	for index, item := range value {
		result[index] = int(item)
	}
	return result
}

func setEnv(env []string, key, value string) []string {
	return append(removeEnv(env, key), key+"="+value)
}

func removeEnv(env []string, key string) []string {
	prefix := key + "="
	filtered := env[:0]
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func main() {
	output := flag.String("output", "testdata/port/cli/config-inspect.json", "fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	goBinary := flag.String("go-binary", "", "validated Go symvault binary used as the oracle")
	flag.Parse()
	if *goBinary == "" {
		fatal("--go-binary is required")
	}
	if err := validateGoBinary(*goBinary); err != nil {
		fatal("validate Go oracle: %v", err)
	}
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
	cases, err := buildCases(*goBinary, root)
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

func validateGoBinary(path string) error {
	const modulePath = "github.com/danieljustus/symaira-vault"
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read build metadata: %w", err)
	}
	if info.Path != modulePath || info.Main.Path != modulePath {
		return fmt.Errorf("main module %q/%q, want %q", info.Path, info.Main.Path, modulePath)
	}
	if info.GoVersion != "go1.26.6" {
		return fmt.Errorf("GoVersion %q, want go1.26.6", info.GoVersion)
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	for key, want := range map[string]string{
		"vcs.revision": pinnedOracleCommit,
		"vcs.modified": "false",
	} {
		if got := settings[key]; got != want {
			return fmt.Errorf("build setting %s=%q, want %q", key, got, want)
		}
	}
	return nil
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
