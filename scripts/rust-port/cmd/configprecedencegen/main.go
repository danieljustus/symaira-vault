// Command configprecedencegen freezes the CFG-002 precedence contract: how
// defaults, tier presets and explicitly present YAML fields layer.
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
	pinnedOracleCommit  = "aa21ec4e"
	pinnedOracleRelease = "unreleased"
	agentName           = "probe"
)

var productionSources = []string{
	"internal/config/config.go",
	"internal/config/config_load.go",
	"internal/config/config_merge.go",
	"internal/config/presets.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

// profile is the resolved agent profile as a consumer observes it.
//
// Go models these permissions as *bool and every consumer resolves them the
// same way — `p != nil && *p` — so an unset permission is observably false.
// The contract is therefore stated in those effective terms, which is also the
// shape Rust carries. Present records whether the agent exists at all, since
// an agent absent from the file is a different thing from one with no fields.
type profile struct {
	Present          bool     `json:"present"`
	Tier             *string  `json:"tier"`
	ApprovalMode     *string  `json:"approval_mode"`
	AllowedPaths     []string `json:"allowed_paths"`
	CanWrite         bool     `json:"can_write"`
	CanRunCommands   bool     `json:"can_run_commands"`
	CanManageConfig  bool     `json:"can_manage_config"`
	CanUseClipboard  bool     `json:"can_use_clipboard"`
	CanUseAutotype   bool     `json:"can_use_autotype"`
	CanReadValues    bool     `json:"can_read_values"`
	ExposeValueTools bool     `json:"expose_value_tools"`
	AutoUnseal       bool     `json:"auto_unseal"`
	RequireApproval  bool     `json:"require_approval"`
}

// effective mirrors how every Go consumer reads these permissions.
func effective(value *bool) bool { return value != nil && *value }

type precedenceCase struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Input       string  `json:"input"`
	Profile     profile `json:"profile"`
}

type fixture struct {
	SchemaVersion int              `json:"schema_version"`
	Oracle        oracle           `json:"oracle"`
	Cases         []precedenceCase `json:"cases"`
}

func inputs() []struct{ name, description, body string } {
	return []struct{ name, description, body string }{
		{"no_agent_entry", "an agent absent from the file has no profile at all, and no permissions", ""},
		{"empty_agent_entry", "an agent present but empty still gets the defaults", "    {}\n"},

		// The tier preset layer.
		{"tier_read_only", "a read-only tier applies its preset", "    tier: read-only\n"},
		{"tier_standard", "a standard tier applies its preset", "    tier: standard\n"},
		{"tier_admin", "an admin tier applies its preset", "    tier: admin\n"},
		{"tier_unknown", "an unrecognized tier changes nothing but is still recorded", "    tier: not-a-tier\n"},

		// Explicit fields override the tier preset.
		{"tier_admin_denies_write", "an explicit false overrides what the tier grants", "    tier: admin\n    canWrite: false\n"},
		{"tier_read_only_grants_write", "an explicit true overrides what the tier withholds", "    tier: read-only\n    canWrite: true\n"},
		{"tier_admin_drops_approval", "an explicit false overrides the tier's approval requirement", "    tier: admin\n    requireApproval: false\n"},

		// Presence, not value: an explicit zero must beat the default.
		{"explicit_false_without_tier", "an explicit false is not the same as an absent field", "    canWrite: false\n"},
		{"explicit_true_without_tier", "an explicit true without a tier", "    canWrite: true\n"},

		// exposeValueTools carries a default that only applies when neither it
		// nor tier is present.
		{"expose_default_when_neither_present", "neither tier nor exposeValueTools present", "    canWrite: true\n"},
		{"expose_explicit_false", "an explicit false suppresses the default", "    exposeValueTools: false\n"},
		{"expose_suppressed_by_tier", "a tier present suppresses the default", "    tier: read-only\n"},
		{"expose_explicit_with_tier", "an explicit value overrides the tier's", "    tier: read-only\n    exposeValueTools: true\n"},

		// allowedPaths is a slice: absent, explicitly empty and populated must
		// be distinguishable.
		{"allowed_paths_absent", "an absent list", "    canWrite: true\n"},
		{"allowed_paths_empty", "an explicitly empty list", "    allowedPaths: []\n"},
		{"allowed_paths_null", "an explicitly null list", "    allowedPaths:\n"},
		{"allowed_paths_populated", "a populated list", "    allowedPaths:\n      - /fixture/a\n      - /fixture/b\n"},

		// approvalMode is derived from requireApproval when absent.
		{"approval_mode_absent", "no approval fields at all", "    canWrite: true\n"},
		{"approval_mode_from_require_true", "requireApproval true derives the mode", "    requireApproval: true\n"},
		{"approval_mode_from_require_false", "requireApproval false derives the mode", "    requireApproval: false\n"},
		{"approval_mode_explicit_wins", "an explicit mode beats the derivation", "    approvalMode: none\n    requireApproval: true\n"},
	}
}

func snapshot(item configpkg.AgentProfile, present bool) profile {
	paths := item.AllowedPaths
	if paths == nil {
		paths = []string{}
	}
	return profile{
		Present:          present,
		Tier:             item.Tier,
		ApprovalMode:     item.ApprovalMode,
		AllowedPaths:     paths,
		CanWrite:         effective(item.CanWrite),
		CanRunCommands:   effective(item.CanRunCommands),
		CanManageConfig:  effective(item.CanManageConfig),
		CanUseClipboard:  effective(item.CanUseClipboard),
		CanUseAutotype:   effective(item.CanUseAutotype),
		CanReadValues:    effective(item.CanReadValues),
		ExposeValueTools: effective(item.ExposeValueTools),
		AutoUnseal:       effective(item.AutoUnseal),
		RequireApproval:  effective(item.RequireApproval),
	}
}

func buildCases(workDir string) ([]precedenceCase, error) {
	cases := make([]precedenceCase, 0, len(inputs()))
	for index, input := range inputs() {
		document := ""
		if input.body != "" {
			document = "agents:\n  " + agentName + ":\n" + input.body
		}
		path := filepath.Join(workDir, fmt.Sprintf("case-%02d.yaml", index))
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			return nil, err
		}
		cfg, err := configpkg.Load(path)
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", input.name, err)
		}
		item, present := cfg.Agents[agentName]
		cases = append(cases, precedenceCase{
			Name:        input.name,
			Description: input.description,
			Input:       document,
			Profile:     snapshot(item, present),
		})
	}
	return cases, nil
}

func main() {
	output := flag.String("output", "testdata/port/config/precedence.json", "CFG-002 fixture path")
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
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/configprecedencegen/main.go"})
	if err != nil {
		fatal("hash generator: %v", err)
	}

	workDir, err := os.MkdirTemp("", "configprecedencegen-")
	if err != nil {
		fatal("create work directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	cases, err := buildCases(workDir)
	if err != nil {
		fatal("build cases: %v", err)
	}
	content, err := marshalJSON(fixture{
		SchemaVersion: 1,
		Oracle: oracle{
			Commit: commitLabel, CommitSHA: resolved, Release: releaseLabel,
			SourceFiles: sources, SourceDigest: sourceDigest, GeneratorDigest: generatorDigest,
		},
		Cases: cases,
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
			fatal("fixture is stale; run make cfg-precedence-fixtures-generate")
		}
		fmt.Printf("PASS CFG-002 precedence fixture (%d cases)\n", len(cases))
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
