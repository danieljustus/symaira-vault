// Command configbytesgen freezes the CFG-003 config-bytes contract: how the
// loader treats canonical, unknown and corrupt YAML, and the modes the writer
// leaves behind.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "aa21ec4e"
	pinnedOracleRelease = "unreleased"

	// Default() derives vaultDir from the environment, and the writer emits it,
	// so both the snapshot and the canonical output would otherwise carry the
	// generating host's home directory into the fixture. Path resolution is
	// CFG-001's contract; here it is pinned to a synthetic value so this row is
	// about bytes and nothing else.
	fixtureVaultDir = "/fixture/vault"
)

var productionSources = []string{
	"internal/config/config.go",
	"internal/config/config_load.go",
	"internal/config/config_merge.go",
	"internal/config/config_save.go",
	"internal/config/config_validate.go",
	// Carries the warning texts the contract pins.
	"internal/config/warn.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

// snapshot is the implementation-neutral shape of an accepted config. It
// deliberately omits vaultDir: Default() derives that from the environment, so
// including it would bake the generating host's home directory into the
// fixture and fail anywhere else. Path resolution is CFG-001's contract.
//
// Error
// text is deliberately not part of the contract: Go's yaml.v3 and Rust's
// serde_yaml_ng word their failures differently, so the contract pins whether
// an input is rejected, not how the rejection reads.
type snapshot struct {
	DefaultAgent       string   `json:"default_agent"`
	SessionTimeout     string   `json:"session_timeout"`
	SessionMaxLifetime string   `json:"session_max_lifetime"`
	AuthMethod         string   `json:"auth_method"`
	VaultDir           string   `json:"vault_dir"`
	AgentNames         []string `json:"agent_names"`
}

type bytesCase struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Input       string    `json:"input"`
	Rejected    bool      `json:"rejected"`
	Snapshot    *snapshot `json:"snapshot,omitempty"`
	// Warnings the loader raised, in order. Both implementations emit the
	// identical texts, so unlike error messages these are part of the contract.
	Warnings []string `json:"warnings,omitempty"`
	// SavedYAML is the canonical form the writer produces for an accepted
	// input. Re-loading it must yield the same snapshot, which the round-trip
	// field records.
	SavedYAML    string `json:"saved_yaml,omitempty"`
	RoundTripsTo string `json:"round_trips_to,omitempty"`
}

// modeContract records the permissions the writer leaves behind. Unix only:
// Windows does not carry these bits, and pretending otherwise would make the
// row unverifiable there.
type modeContract struct {
	Directory string `json:"directory"`
	File      string `json:"file"`
	Platform  string `json:"platform"`
}

type fixture struct {
	SchemaVersion int          `json:"schema_version"`
	Oracle        oracle       `json:"oracle"`
	Cases         []bytesCase  `json:"cases"`
	Modes         modeContract `json:"modes"`
}

func inputs() []struct{ name, description, input string } {
	return []struct{ name, description, input string }{
		{"empty", "an empty document yields the defaults", ""},
		{"whitespace_only", "whitespace is treated as empty", "   \n\t\n"},
		{"canonical_minimal", "a minimal canonical document", "defaultAgent: custom\n"},
		{"unknown_top_level_ignored", "unknown top-level keys are ignored", "unknownTopLevel: ignored\ndefaultAgent: custom\n"},
		{"unknown_nested_ignored", "unknown nested keys are ignored", "agents:\n  custom:\n    unknownAgentField: ignored\n    canWrite: true\n"},
		{"deep_unknown_nesting", "deeply nested unknown structure is ignored", "a:\n b:\n  c:\n   d: 1\n"},

		{"unclosed_quote", "an unterminated scalar is a syntax error", "defaultAgent: \"unterminated\n"},
		{"unclosed_bracket", "an unterminated flow sequence is a syntax error", "envAllowlist: [a, b\n"},
		{"tab_indentation", "tabs cannot start a token", "agents:\n\tcustom:\n\t\tcanWrite: true\n"},
		{"bad_indentation", "inconsistent indentation is a syntax error", "agents:\n  custom:\n canWrite: true\n"},
		{"control_character", "a NUL byte is rejected outright", "defaultAgent: a\x00b\n"},
		{"duplicate_key", "a repeated mapping key is rejected", "defaultAgent: a\ndefaultAgent: b\n"},

		{"scalar_document", "a bare scalar is not a config mapping", "just-a-string\n"},
		{"sequence_document", "a sequence is not a config mapping", "- one\n- two\n"},
		{"null_document", "an explicit null yields the defaults", "null\n"},
		{"multiple_documents", "a second document is rejected, not silently dropped", "defaultAgent: a\n---\ndefaultAgent: b\n"},
		{"bom_prefixed", "a leading byte-order mark does not prevent parsing", "\ufeffdefaultAgent: a\n"},

		{"wrong_scalar_type", "a string where a bool belongs does not abort the load", "agents:\n  custom:\n    canWrite: \"yes\"\n"},
		{"negative_duration", "a negative session duration is rejected", "sessionTimeout: -5m\n"},
		{"zero_duration", "an explicitly zero session duration is rejected", "sessionTimeout: 0s\n"},
		{"negative_max_lifetime", "the rule covers sessionMaxLifetime too", "sessionMaxLifetime: -1h\n"},
		{"large_duration", "a very large duration is accepted verbatim", "sessionTimeout: 100000h\n"},
	}
}

func snapshotOf(cfg *configpkg.Config) *snapshot {
	names := make([]string, 0, len(cfg.Agents))
	for name := range cfg.Agents {
		names = append(names, name)
	}
	sort.Strings(names)
	return &snapshot{
		DefaultAgent:       cfg.DefaultAgent,
		SessionTimeout:     cfg.SessionTimeout.String(),
		SessionMaxLifetime: cfg.SessionMaxLifetime.String(),
		AuthMethod:         cfg.EffectiveAuthMethod(),
		AgentNames:         names,
	}
}

func buildCases(workDir string) ([]bytesCase, error) {
	cases := make([]bytesCase, 0, len(inputs()))
	for index, input := range inputs() {
		path := filepath.Join(workDir, fmt.Sprintf("case-%02d.yaml", index))
		if err := os.WriteFile(path, []byte(input.input), 0o600); err != nil {
			return nil, err
		}
		item := bytesCase{Name: input.name, Description: input.description, Input: input.input}

		var captured []string
		configpkg.SetWarnFunc(func(message string) { captured = append(captured, message) })
		cfg, err := configpkg.Load(path)
		configpkg.SetWarnFunc(nil)
		item.Warnings = captured

		if err != nil {
			item.Rejected = true
			cases = append(cases, item)
			continue
		}
		cfg.VaultDir = fixtureVaultDir
		item.Snapshot = snapshotOf(cfg)

		savedPath := filepath.Join(workDir, fmt.Sprintf("case-%02d-saved.yaml", index))
		if saveErr := cfg.SaveTo(savedPath); saveErr != nil {
			return nil, fmt.Errorf("save %s: %w", input.name, saveErr)
		}
		saved, err := os.ReadFile(savedPath) // #nosec G304 -- generator-owned temporary path
		if err != nil {
			return nil, err
		}
		item.SavedYAML = string(saved)

		// Re-loading the canonical form must reproduce the same snapshot.
		reloaded, err := configpkg.Load(savedPath)
		if err != nil {
			return nil, fmt.Errorf("reload %s: %w", input.name, err)
		}
		again := snapshotOf(reloaded)
		if !reflect.DeepEqual(again, item.Snapshot) {
			return nil, fmt.Errorf("case %s does not round-trip: %+v vs %+v", input.name, again, item.Snapshot)
		}
		item.RoundTripsTo = "identical_snapshot"
		cases = append(cases, item)
	}
	return cases, nil
}

func buildModes(workDir string) (modeContract, error) {
	if runtime.GOOS == "windows" {
		return modeContract{Platform: "windows-not-applicable"}, nil
	}
	nested := filepath.Join(workDir, "modes", "nested")
	path := filepath.Join(nested, "config.yaml")
	cfg := configpkg.Default()
	if err := cfg.SaveTo(path); err != nil {
		return modeContract{}, err
	}
	dirInfo, err := os.Stat(nested)
	if err != nil {
		return modeContract{}, err
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		return modeContract{}, err
	}
	return modeContract{
		Directory: fmt.Sprintf("%#o", dirInfo.Mode().Perm()),
		File:      fmt.Sprintf("%#o", fileInfo.Mode().Perm()),
		Platform:  "unix",
	}, nil
}

func main() {
	output := flag.String("output", "testdata/port/config/bytes.json", "CFG-003 fixture path")
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
		fatal("%v", err)
	}
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	sourceDigest, err := provenance.Digest(root, sources)
	if err != nil {
		fatal("hash production sources: %v", err)
	}
	resolved, err := provenance.Verify(root, commitLabel, sources)
	if err != nil {
		fatal("%v", err)
	}
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/configbytesgen/main.go"})
	if err != nil {
		fatal("hash generator: %v", err)
	}

	workDir, err := os.MkdirTemp("", "configbytesgen-")
	if err != nil {
		fatal("create work directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	cases, err := buildCases(workDir)
	if err != nil {
		fatal("build cases: %v", err)
	}
	modes, err := buildModes(workDir)
	if err != nil {
		fatal("probe modes: %v", err)
	}

	content, err := marshalJSON(fixture{
		SchemaVersion: 1,
		Oracle: oracle{
			Commit: commitLabel, CommitSHA: resolved, Release: releaseLabel,
			SourceFiles: sources, SourceDigest: sourceDigest, GeneratorDigest: generatorDigest,
		},
		Cases: cases,
		Modes: modes,
	})
	if err != nil {
		fatal("marshal fixture: %v", err)
	}
	if *check {
		existing, readErr := os.ReadFile(*output) // #nosec G304 -- explicit operator-selected fixture
		if readErr != nil {
			fatal("read fixture: %v", readErr)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; run make cfg-bytes-fixtures-generate")
		}
		fmt.Printf("PASS CFG-003 config-bytes fixture (%d cases)\n", len(cases))
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
		return "", "", fmt.Errorf("oracle commit %q is not the pinned commit %q", commit, pinnedOracleCommit)
	}
	if release != "" && release != pinnedOracleRelease {
		return "", "", fmt.Errorf("oracle release %q is not the pinned release %q", release, pinnedOracleRelease)
	}
	if check {
		return pinnedOracleCommit, pinnedOracleRelease, nil
	}
	if commit == "" || release == "" {
		return "", "", fmt.Errorf("--oracle-commit and --oracle-release are required when generating a new fixture")
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
