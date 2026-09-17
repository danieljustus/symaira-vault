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
	"internal/config/dottedpath.go",
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
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	ConfigBytes        []int    `json:"config_bytes,omitempty"`
	WriteConfig        bool     `json:"write_config"`
	CaptureConfigAfter bool     `json:"capture_config_after,omitempty"`
	ConfigAfterBytes   []int    `json:"config_after_bytes,omitempty"`
	DefaultPath        bool     `json:"default_path,omitempty"`
	ClearHome          bool     `json:"clear_home,omitempty"`
	Args               []string `json:"args"`
	Expected           expected `json:"expected"`
}

type fixture struct {
	SchemaVersion int       `json:"schema_version"`
	Oracle        oracle    `json:"oracle"`
	Cases         []cliCase `json:"cases"`
}

type inputCase struct {
	name, description  string
	config             []byte
	writeConfig        bool
	captureConfigAfter bool
	defaultPath        bool
	clearHome          bool
	args               []string
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
		{
			name:        "get_scalar_lexeme",
			description: "get preserves the source lexeme for scalar values",
			config:      []byte("leading: 001\ntruth: TRUE\nempty: ~\n"),
			writeConfig: true,
			args:        []string{"config", "get", "leading", "--file", fileMarker},
		},
		{
			name:        "get_nested_scalar",
			description: "get follows dotted paths through mappings",
			config:      []byte("agents:\n  probe:\n    canWrite: true\n"),
			writeConfig: true,
			args:        []string{"config", "get", "agents.probe.canWrite", "--file", fileMarker},
		},
		{
			name:        "get_bool_lexeme",
			description: "get preserves YAML boolean spelling",
			config:      []byte("truth: TRUE\n"),
			writeConfig: true,
			args:        []string{"config", "get", "truth", "--file", fileMarker},
		},
		{
			name:        "get_null_lexeme",
			description: "get preserves YAML null spelling",
			config:      []byte("empty: ~\n"),
			writeConfig: true,
			args:        []string{"config", "get", "empty", "--file", fileMarker},
		},
		{
			name:        "get_alias_lexeme",
			description: "get returns an alias node value without resolving it",
			config:      []byte("anchor: &a hello\nalias: *a\n"),
			writeConfig: true,
			args:        []string{"config", "get", "alias", "--file", fileMarker},
		},
		{
			name:        "get_quoted_anchor_alias",
			description: "get returns the name of an alias to a quoted anchor",
			config:      []byte("anchor: &quoted \"value\"\nalias: *quoted\n"),
			writeConfig: true,
			args:        []string{"config", "get", "alias", "--file", fileMarker},
		},
		{
			name:        "get_flow_mapping",
			description: "get renders a flow mapping node",
			config:      []byte("flow: {a: 1, b: two}\n"),
			writeConfig: true,
			args:        []string{"config", "get", "flow", "--file", fileMarker},
		},
		{
			name:        "get_flow_sequence",
			description: "get renders a flow sequence node",
			config:      []byte("seq: [one, two]\n"),
			writeConfig: true,
			args:        []string{"config", "get", "seq", "--file", fileMarker},
		},
		{
			name:        "get_block_scalar",
			description: "get returns the value of a literal block scalar",
			config:      []byte("block: |\n  hello\n  world\n"),
			writeConfig: true,
			args:        []string{"config", "get", "block", "--file", fileMarker},
		},
		{
			name:        "get_folded_scalar",
			description: "get returns the value of a folded block scalar",
			config:      []byte("fold: >\n  hello\n  world\n"),
			writeConfig: true,
			args:        []string{"config", "get", "fold", "--file", fileMarker},
		},
		{
			name:        "get_quoted_colon_key",
			description: "get resolves a quoted mapping key containing a colon",
			config:      []byte("\"colon:key\": value\n"),
			writeConfig: true,
			args:        []string{"config", "get", "colon:key", "--file", fileMarker},
		},
		{
			name:        "get_anchored_quoted_scalar",
			description: "get returns an anchored quoted scalar value",
			config:      []byte("anchored: &name \"quoted value\"\n"),
			writeConfig: true,
			args:        []string{"config", "get", "anchored", "--file", fileMarker},
		},
		{
			name:        "get_complex_quote_comment",
			description: "get preserves a comment marker inside a quoted scalar",
			config:      []byte("complex: \"<&> # kept\"\n"),
			writeConfig: true,
			args:        []string{"config", "get", "complex", "--file", fileMarker},
		},
		{
			name:        "get_mapping_node",
			description: "get renders a nested block mapping node",
			config:      []byte("nested:\n  a: one\n  b:\n    c: three\n"),
			writeConfig: true,
			args:        []string{"config", "get", "nested", "--file", fileMarker},
		},
		{
			name:        "get_nested_block_scalar_mapping",
			description: "get renders a mapping containing a block scalar",
			config:      []byte("nested:\n  note: |\n    line one\n    line two\n"),
			writeConfig: true,
			args:        []string{"config", "get", "nested", "--file", fileMarker},
		},
		{
			name:        "get_duplicate_sibling_comments",
			description: "get attaches comments to the selected duplicate-content sibling",
			config:      []byte("left:\n  # left comment\n  nested:\n    same: value\nright:\n  # right comment\n  nested:\n    same: value\n"),
			writeConfig: true,
			args:        []string{"config", "get", "right", "--file", fileMarker},
		},
		{
			name:        "get_colon_block_scalar_indentation",
			description: "get preserves colon-containing block scalar lines at their node indentation",
			config:      []byte("nested:\n    note: |\n        line: content\n        line two\n"),
			writeConfig: true,
			args:        []string{"config", "get", "nested", "--file", fileMarker},
		},
		{
			name:        "get_mapping_comments_anchors",
			description: "get preserves comments and anchors in a mapping node",
			config:      []byte("root:\n  # retained comment\n  anchored: &real \"value\" # trailing\n  alias: *real\n"),
			writeConfig: true,
			args:        []string{"config", "get", "root", "--file", fileMarker},
		},
		{
			name:        "get_scalar_anchor_text",
			description: "get does not treat anchor-like text inside a scalar as an anchor",
			config:      []byte("fake: \"&fake before &real\"\nanchored: &real value\n"),
			writeConfig: true,
			args:        []string{"config", "get", "fake", "--file", fileMarker},
		},
		{
			name:        "get_duplicate_anchor_names",
			description: "get reports duplicate anchor names as a YAML error",
			config:      []byte("first: &dup one\nsecond: &dup two\n"),
			writeConfig: true,
			args:        []string{"config", "get", "first", "--file", fileMarker},
		},
		{
			name:        "get_quoted_null_literal_mapping",
			description: "get preserves a quoted null-looking mapping scalar",
			config:      []byte("literal: \"null\"\n"),
			writeConfig: true,
			args:        []string{"config", "get", "literal", "--file", fileMarker},
		},
		{
			name:        "get_sequence_mapping_node",
			description: "get renders a sequence containing mappings",
			config:      []byte("items:\n  - name: one\n    enabled: true\n  - name: two\n    enabled: false\n"),
			writeConfig: true,
			args:        []string{"config", "get", "items", "--file", fileMarker},
		},
		{
			name:        "get_multidoc_first",
			description: "get reads the first YAML document",
			config:      []byte("first: one\n---\nsecond: two\n"),
			writeConfig: true,
			args:        []string{"config", "get", "first", "--file", fileMarker},
		},
		{
			name:        "get_multidoc_second_missing",
			description: "get does not read keys from a later YAML document",
			config:      []byte("first: one\n---\nsecond: two\n"),
			writeConfig: true,
			args:        []string{"config", "get", "second", "--file", fileMarker},
		},
		{
			name:               "set_existing_scalar",
			description:        "set replaces an existing scalar and preserves other fields",
			config:             []byte("a: old\nnested:\n  keep: yes\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "a", "new", "--file", fileMarker},
		},
		{
			name:               "set_nested_new",
			description:        "set creates a missing nested mapping path",
			config:             []byte("root:\n  keep: true\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "root.new", "value", "--file", fileMarker},
		},
		{
			name:               "set_overwrites_scalar_parent",
			description:        "set replaces a scalar intermediate with a mapping",
			config:             []byte("root: old\nkeep: true\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "root.child", "value", "--file", fileMarker},
		},
		{
			name:               "set_quoted_value",
			description:        "set parses a quoted YAML string value",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "\"new value\"", "--file", fileMarker},
		},
		{
			name:               "set_empty_value",
			description:        "set preserves an explicitly empty string value",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "", "--file", fileMarker},
		},
		{
			name:               "set_boolean_value",
			description:        "set parses a YAML boolean value",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "true", "--file", fileMarker},
		},
		{
			name:               "set_number_value",
			description:        "set parses and emits a YAML integer value",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "001", "--file", fileMarker},
		},
		{
			name:               "set_null_value",
			description:        "set parses a YAML null value",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "null", "--file", fileMarker},
		},
		{
			name:               "set_quoted_null_value",
			description:        "set keeps a quoted null-looking value as a string",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "\"null\"", "--file", fileMarker},
		},
		{
			name:               "set_literal_value",
			description:        "set emits a multiline YAML string as a literal scalar",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "|\n  line one\n  line two", "--file", fileMarker},
		},
		{
			name:               "set_literal_strip",
			description:        "set preserves a strip-chomping literal scalar's semantic value",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "|-\n  one", "--file", fileMarker},
		},
		{
			name:               "set_literal_clip",
			description:        "set preserves a clip-chomping literal scalar's semantic value",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "|\n  one\n", "--file", fileMarker},
		},
		{
			name:               "set_literal_keep",
			description:        "set preserves a keep-chomping literal scalar's semantic value",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "|+\n  one\n\n", "--file", fileMarker},
		},
		{
			name:               "set_literal_empty",
			description:        "set emits an empty string for an empty literal scalar",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "|\n", "--file", fileMarker},
		},
		{
			name:               "set_quiet",
			description:        "quiet set writes the value without stdout",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "new", "--file", fileMarker, "--quiet"},
		},
		{
			name:               "set_default_home",
			description:        "set uses the default home config path",
			config:             []byte("value: old\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			defaultPath:        true,
			args:               []string{"config", "set", "value", "new"},
		},
		{
			name:               "set_preserves_comments_anchors",
			description:        "set preserves comments and anchors around an edited value",
			config:             []byte("root:\n  # keep this comment\n  value: old # keep this trailing comment\n  anchored: &real text\n  alias: *real\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "root.value", "new", "--file", fileMarker},
		},
		{
			name:               "set_flow_mapping_value",
			description:        "set emits a parsed mapping value using Go YAML encoding",
			config:             []byte("value: old\nkeep: true\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "{a: 1, b: two}", "--file", fileMarker},
		},
		{
			name:               "set_flow_sequence_value",
			description:        "set emits a parsed sequence value using Go YAML encoding",
			config:             []byte("value: old\nkeep: true\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "[one, two]", "--file", fileMarker},
		},
		{
			name:               "set_malformed",
			description:        "set rejects malformed YAML without changing the file",
			config:             []byte("value: [\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "value", "new", "--file", fileMarker},
		},
		{
			name:               "set_invalid_mcp_bind",
			description:        "set writes then reports a config validation error for an invalid known field",
			config:             []byte("mcp:\n  bind: 127.0.0.1\n"),
			writeConfig:        true,
			captureConfigAfter: true,
			args:               []string{"config", "set", "mcp.bind", "", "--file", fileMarker},
		},
		{
			name:        "get_json_unescaped",
			description: "JSON get output does not HTML escape scalar strings",
			config:      []byte("special: \"<&>\"\n"),
			writeConfig: true,
			args:        []string{"config", "get", "special", "--file", fileMarker, "--json"},
		},
		{
			name:        "get_json_escape_controls",
			description: "JSON get preserves literal escape text and Unicode separators while leaving HTML characters unescaped",
			config:      []byte("special: \"\\\\u003c <>&\\u2028\"\n"),
			writeConfig: true,
			args:        []string{"config", "get", "special", "--file", fileMarker, "--json"},
		},
		{
			name:        "get_output_json",
			description: "get honors the global JSON output format",
			config:      []byte("special: \"<&>\"\n"),
			writeConfig: true,
			args:        []string{"config", "get", "special", "--file", fileMarker, "--output", "json"},
		},
		{
			name:        "get_json_before_command",
			description: "get accepts a global JSON flag before the command",
			config:      []byte("vaultDir: /fixture/vault\n"),
			writeConfig: true,
			args:        []string{"--json", "config", "get", "vaultDir", "--file", fileMarker},
		},
		{
			name:        "get_quiet",
			description: "quiet get reads and resolves a value without stdout",
			config:      []byte("vaultDir: /fixture/vault\n"),
			writeConfig: true,
			args:        []string{"config", "get", "vaultDir", "--file", fileMarker, "--quiet"},
		},
		{
			name:        "get_missing_key",
			description: "get reports the complete dotted path for a missing key",
			config:      []byte("agents:\n  probe:\n    canWrite: true\n"),
			writeConfig: true,
			args:        []string{"config", "get", "agents.probe.missing", "--file", fileMarker},
		},
		{
			name:        "get_missing_key_sibling_scope",
			description: "get does not cross a sibling mapping while resolving a path",
			config:      []byte("agents:\n  probe:\n    canWrite: true\n  other:\n    missing: false\n"),
			writeConfig: true,
			args:        []string{"config", "get", "agents.probe.missing", "--file", fileMarker},
		},
		{
			name:        "get_malformed",
			description: "get rejects malformed YAML before lookup",
			config:      []byte("vaultDir: [\n"),
			writeConfig: true,
			args:        []string{"config", "get", "vaultDir", "--file", fileMarker},
		},
		{
			name:        "get_default_home",
			description: "get uses the default home config path",
			config:      []byte("vaultDir: /fixture/vault\n"),
			writeConfig: true,
			defaultPath: true,
			args:        []string{"config", "get", "vaultDir"},
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
				return nil, cleanupCase(tempRoot, err)
			}
			if err := os.WriteFile(configPath, input.config, 0o600); err != nil {
				return nil, cleanupCase(tempRoot, err)
			}
		}
		args := make([]string, len(input.args))
		for i, arg := range input.args {
			args[i] = strings.ReplaceAll(arg, fileMarker, configPath)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		// #nosec G204 -- validateGoBinary checked the pinned, clean oracle before this command.
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
			return nil, cleanupCase(tempRoot, fmt.Errorf("run oracle case %s: %w", input.name, ctx.Err()))
		}
		cancel()
		exitCode := 0
		if runErr != nil {
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) {
				return nil, cleanupCase(tempRoot, fmt.Errorf("run oracle case %s: %w", input.name, runErr))
			}
			exitCode = exitErr.ExitCode()
		}
		item := cliCase{
			Name:               input.name,
			Description:        input.description,
			WriteConfig:        input.writeConfig,
			CaptureConfigAfter: input.captureConfigAfter,
			DefaultPath:        input.defaultPath,
			ClearHome:          input.clearHome,
			Args:               input.args,
			Expected: expected{
				ExitCode:       exitCode,
				StdoutBytes:    byteValues(stdout.Bytes()),
				StderrContains: errorNeedle(stderr.Bytes()),
			},
		}
		if input.writeConfig {
			item.ConfigBytes = byteValues(input.config)
		}
		if input.captureConfigAfter {
			after, readErr := os.ReadFile(configPath)
			if readErr != nil {
				return nil, cleanupCase(tempRoot, fmt.Errorf("read oracle case %s config after: %w", input.name, readErr))
			}
			item.ConfigAfterBytes = byteValues(after)
		}
		cases = append(cases, item)
		if err := os.RemoveAll(tempRoot); err != nil {
			return nil, fmt.Errorf("cleanup oracle case %s: %w", input.name, err)
		}
	}
	return cases, nil
}

func cleanupCase(tempRoot string, cause error) error {
	if cleanupErr := os.RemoveAll(tempRoot); cleanupErr != nil {
		return fmt.Errorf("%w (cleanup: %w)", cause, cleanupErr)
	}
	return cause
}

func errorNeedle(stderr []byte) string {
	for _, needle := range []string{"config is invalid after update", "cannot determine config file path", "cannot load config", "key ", "cannot access key"} {
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
