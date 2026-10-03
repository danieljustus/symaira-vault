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
	"time"

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
	// The writer's VaultConfig/GitConfig/ClipboardConfig field types and YAML
	// tags are part of the SaveTo contract exercised below.
	"internal/config/schema.go",
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
// Raw legacy pointers remain observable in the fixture. Rust stores a bool,
// so cross-language comparison uses RequireApprovalEffective; mode nil versus
// explicit empty remains exact.
type approvalSnapshot struct {
	ApprovalMode             *string `json:"approval_mode"`
	RequireApprovalRaw       *bool   `json:"require_approval_raw"`
	RequireApprovalEffective bool    `json:"require_approval_effective"`
}

type snapshot struct {
	Approvals          map[string]approvalSnapshot `json:"approvals"`
	DefaultAgent       string                      `json:"default_agent"`
	SessionTimeout     string                      `json:"session_timeout"`
	SessionMaxLifetime string                      `json:"session_max_lifetime"`
	AuthMethod         string                      `json:"auth_method"`
	VaultDir           string                      `json:"vault_dir"`
	AgentNames         []string                    `json:"agent_names"`
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

// writerCase records a real Go SaveTo followed by Load. The saved bytes are
// the oracle; loaded is deliberately limited to fields Rust models, while
// omittedFields documents fields that Go's SaveTo currently does not copy.
// This makes omissions visible without pretending that the Rust model has
// parity for every wider Config field.
type writerCase struct {
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	Requested     writerSnapshot `json:"requested"`
	SavedYAML     string         `json:"saved_yaml"`
	Loaded        writerSnapshot `json:"loaded"`
	OmittedFields []string       `json:"omitted_fields,omitempty"`
}

type writerSnapshot struct {
	Vault     *writerVaultSnapshot     `json:"vault,omitempty"`
	Git       *writerGitSnapshot       `json:"git,omitempty"`
	Clipboard *writerClipboardSnapshot `json:"clipboard,omitempty"`
}

type writerVaultSnapshot struct {
	Path               string   `json:"path"`
	DefaultRecipients  []string `json:"default_recipients"`
	ConfirmRemove      bool     `json:"confirm_remove"`
	AuthMethod         string   `json:"auth_method"`
	UseTouchID         bool     `json:"use_touch_id"`
	LegacyMode         *bool    `json:"legacy_mode,omitempty"`
	SearchIndex        bool     `json:"search_index"`
	SearchWorkers      int      `json:"search_workers"`
	SearchIndexCache   bool     `json:"search_index_cache"`
	ConfigCacheEntries int      `json:"config_cache_entries"`
	PseudonymizePaths  bool     `json:"pseudonymize_paths"`
	ScryptWorkFactor   int      `json:"scrypt_work_factor"`
	AutoMigrateKDF     bool     `json:"auto_migrate_kdf"`
	AutoHealZeroKey    bool     `json:"auto_heal_zero_key"`
	LastRotated        string   `json:"last_rotated"`
	FormatVersion      int      `json:"format_version"`
	Argon2idTime       int      `json:"argon2id_time"`
	Argon2idMemory     int      `json:"argon2id_memory"`
	Argon2idThreads    int      `json:"argon2id_threads"`
	ListingCacheTTL    string   `json:"listing_cache_ttl"`
	ManifestGeneration int      `json:"manifest_generation"`
	SyncMethod         string   `json:"sync_method"`
}

type writerGitSnapshot struct {
	AutoPush         bool   `json:"auto_push"`
	AutoPull         bool   `json:"auto_pull"`
	AutoPullInterval string `json:"auto_pull_interval"`
	CommitTemplate   string `json:"commit_template"`
}

type writerClipboardSnapshot struct {
	AutoClearDuration int  `json:"auto_clear_duration"`
	CopyByDefault     bool `json:"copy_by_default"`
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
	WriterCases   []writerCase `json:"writer_cases,omitempty"`
	Modes         modeContract `json:"modes"`
}

func inputs() []struct{ name, description, input string } {
	cases := []struct{ name, description, input string }{
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
		{"null_optional_sections", "null optional sections are skipped like absent sections", "vault: null\ngit: null\nmcp: null\nupdate: null\nclipboard: null\n"},
		{"multiple_documents", "a second document is rejected, not silently dropped", "defaultAgent: a\n---\ndefaultAgent: b\n"},
		{"bom_prefixed", "a leading byte-order mark does not prevent parsing", "\ufeffdefaultAgent: a\n"},

		{"wrong_scalar_type", "a string where a bool belongs does not abort the load", "agents:\n  custom:\n    canWrite: \"yes\"\n"},
		{"negative_duration", "a negative session duration is rejected", "sessionTimeout: -5m\n"},
		{"zero_duration", "an explicitly zero session duration is rejected", "sessionTimeout: 0s\n"},
		{"negative_max_lifetime", "the rule covers sessionMaxLifetime too", "sessionMaxLifetime: -1h\n"},
		{"large_duration", "a very large duration is accepted verbatim", "sessionTimeout: 100000h\n"},
		{"approval_mode_auto", "auto is accepted by Validate but rejected by Load", "agents:\n  default:\n    approvalMode: auto\n"},
		{"approval_mode_bogus", "an unknown approval mode is rejected after merge", "agents:\n  default:\n    approvalMode: bogus\n"},
		{"approval_mode_control_character", "a control character inside a mode is rejected", "agents:\n  default:\n    approvalMode: \"prompt\\u0001\"\n"},
		{"approval_mode_unicode_unrecognized", "a Unicode mode outside the accepted set is rejected", "agents:\n  default:\n    approvalMode: \"prомpt\"\n"},
		{"approval_mode_empty", "an explicit empty mode is preserved and accepted", "agents:\n  default:\n    approvalMode: \"\"\n"},
		{"approval_mode_null", "an explicit null mode clears the pointer and is accepted", "agents:\n  default:\n    approvalMode: null\n"},
		{"approval_mode_require_true", "requireApproval true derives prompt", "agents:\n  default:\n    requireApproval: true\n"},
		{"approval_mode_require_false", "requireApproval false derives none", "agents:\n  default:\n    requireApproval: false\n"},
		{"approval_mode_explicit_precedence", "an explicit mode wins over requireApproval", "agents:\n  default:\n    requireApproval: true\n    approvalMode: deny\n"},
		{"approval_mode_null_precedence", "an explicit null mode still wins over requireApproval", "agents:\n  default:\n    requireApproval: true\n    approvalMode: null\n"},
		{"approval_mode_null_legacy", "a null legacy boolean does not override the default mode", "agents:\n  default:\n    requireApproval: null\n"},
		{"custom_agent_mode_omitted", "a defined custom selected agent keeps its unset mode", "defaultAgent: custom\nagents:\n  custom:\n    canWrite: true\n"},
	}
	// Paired custom/default profiles exercise the merge boundary, including
	// explicit modes taking precedence over legacy requireApproval.
	for _, agent := range []string{"custom", "default"} {
		for modeIndex, mode := range []*string{nil, stringValue(""), stringValue("none"), stringValue("deny"), stringValue("prompt"), stringValue("auto"), stringValue("bogus"), stringValue("bad\t\u0085\u2028\u2029")} {
			for legacyIndex, legacy := range []*bool{nil, boolValue(false), boolValue(true)} {
				fields := map[string]any{}
				if mode != nil {
					fields["approvalMode"] = *mode
				}
				if legacy != nil {
					fields["requireApproval"] = *legacy
				}
				// JSON is YAML; JSON escaping keeps control characters unambiguous.
				input, err := json.Marshal(map[string]any{"agents": map[string]any{agent: fields}})
				if err != nil {
					panic(err)
				}
				cases = append(cases, struct{ name, description, input string }{
					fmt.Sprintf("approval_%s_%d_%d", agent, modeIndex, legacyIndex),
					"ordinary approval mode and legacy merge precedence", string(input) + "\n",
				})
			}
		}
	}
	return cases
}

func stringValue(value string) *string { return &value }

func boolValue(value bool) *bool { return &value }

func writerVaultSnapshotOf(v *configpkg.VaultConfig) *writerVaultSnapshot {
	if v == nil {
		return nil
	}
	snapshot := &writerVaultSnapshot{
		Path: v.Path, DefaultRecipients: append([]string(nil), v.DefaultRecipients...),
		ConfirmRemove: v.ConfirmRemove, AuthMethod: v.AuthMethod, UseTouchID: v.UseTouchID,
		LegacyMode: v.LegacyMode, SearchIndex: v.SearchIndex, SearchWorkers: v.SearchWorkers,
		SearchIndexCache: v.SearchIndexCache, ConfigCacheEntries: v.ConfigCacheEntries,
		PseudonymizePaths: v.PseudonymizePaths, ScryptWorkFactor: v.ScryptWorkFactor,
		AutoMigrateKDF: v.AutoMigrateKDF, AutoHealZeroKey: v.AutoHealZeroKey,
		FormatVersion: v.FormatVersion, Argon2idTime: v.Argon2idTime,
		Argon2idMemory: v.Argon2idMemory, Argon2idThreads: v.Argon2idThreads,
		ListingCacheTTL: v.ListingCacheTTL.String(), ManifestGeneration: v.ManifestGeneration,
	}
	if !v.LastRotated.IsZero() {
		snapshot.LastRotated = v.LastRotated.UTC().Format(time.RFC3339Nano)
	}
	if v.Sync != nil {
		snapshot.SyncMethod = v.Sync.Method
	}
	return snapshot
}

func writerGitSnapshotOf(v *configpkg.GitConfig) *writerGitSnapshot {
	if v == nil {
		return nil
	}
	return &writerGitSnapshot{AutoPush: v.AutoPush, AutoPull: v.AutoPull,
		AutoPullInterval: v.AutoPullInterval.String(), CommitTemplate: v.CommitTemplate}
}

func writerClipboardSnapshotOf(v *configpkg.ClipboardConfig) *writerClipboardSnapshot {
	if v == nil {
		return nil
	}
	return &writerClipboardSnapshot{AutoClearDuration: v.AutoClearDuration, CopyByDefault: v.CopyByDefault}
}

func buildWriterCase(workDir, name, description string, cfg *configpkg.Config, omitted []string) (writerCase, error) {
	cfg.VaultDir = fixtureVaultDir
	path := filepath.Join(workDir, name+"-saved.yaml")
	if err := cfg.SaveTo(path); err != nil {
		return writerCase{}, fmt.Errorf("save writer case %s: %w", name, err)
	}
	saved, err := os.ReadFile(path) // #nosec G304 -- generator-owned temporary path
	if err != nil {
		return writerCase{}, err
	}
	loaded, err := configpkg.Load(path)
	if err != nil {
		return writerCase{}, fmt.Errorf("reload writer case %s: %w", name, err)
	}
	return writerCase{
		Name: name, Description: description,
		Requested:     writerSnapshot{Vault: writerVaultSnapshotOf(cfg.Vault), Git: writerGitSnapshotOf(cfg.Git), Clipboard: writerClipboardSnapshotOf(cfg.Clipboard)},
		SavedYAML:     string(saved),
		Loaded:        writerSnapshot{Vault: writerVaultSnapshotOf(loaded.Vault), Git: writerGitSnapshotOf(loaded.Git), Clipboard: writerClipboardSnapshotOf(loaded.Clipboard)},
		OmittedFields: omitted,
	}, nil
}

func buildWriterCases(workDir string) ([]writerCase, error) {
	all := configpkg.Default()
	all.Vault = &configpkg.VaultConfig{
		Path: "/fixture/nested", DefaultRecipients: []string{"age1fixture"}, ConfirmRemove: true,
		AuthMethod: configpkg.AuthMethodTouchID, UseTouchID: true, LegacyMode: boolValue(false),
		SearchIndex: true, SearchWorkers: 4, SearchIndexCache: true, ConfigCacheEntries: 12,
		PseudonymizePaths: true, ScryptWorkFactor: 22, AutoMigrateKDF: true, AutoHealZeroKey: true,
		LastRotated: time.Date(2025, 6, 7, 8, 9, 10, 123456789, time.UTC), FormatVersion: 7,
		Argon2idTime: 3, Argon2idMemory: 65536, Argon2idThreads: 2,
		ListingCacheTTL: 45 * time.Minute, ManifestGeneration: 9,
		Sync: &configpkg.SyncConfig{Method: configpkg.SyncMethodICloudDrive},
	}
	first, err := buildWriterCase(workDir, "vault_all_modeled_fields", "SaveTo preserves the modeled vault and KDF fields", all,
		[]string{"vault.listing_cache_ttl", "vault.manifest_generation", "vault.sync"})
	if err != nil {
		return nil, err
	}
	falseSections := configpkg.Default()
	falseSections.Git = &configpkg.GitConfig{AutoPush: false, AutoPull: false, AutoPullInterval: 0, CommitTemplate: ""}
	falseSections.Clipboard = &configpkg.ClipboardConfig{AutoClearDuration: 0, CopyByDefault: false, PrintByDefault: false}
	second, err := buildWriterCase(workDir, "explicit_false_sections", "SaveTo writes empty sections for explicit false values", falseSections, nil)
	if err != nil {
		return nil, err
	}
	return []writerCase{first, second}, nil
}

func snapshotOf(cfg *configpkg.Config) *snapshot {
	names := make([]string, 0, len(cfg.Agents))
	for name := range cfg.Agents {
		names = append(names, name)
	}
	sort.Strings(names)
	approvals := make(map[string]approvalSnapshot, len(cfg.Agents))
	for name, agent := range cfg.Agents {
		approvals[name] = approvalSnapshot{ApprovalMode: agent.ApprovalMode,
			RequireApprovalRaw:       agent.RequireApproval,
			RequireApprovalEffective: agent.RequireApproval != nil && *agent.RequireApproval}
	}
	return &snapshot{
		Approvals:          approvals,
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
			// SaveTo omits a nil mode. Pin the two observed default-profile
			// reloads without relaxing the remaining agents or legacy state.
			expected := *item.Snapshot
			expected.Approvals = make(map[string]approvalSnapshot, len(item.Snapshot.Approvals))
			for name, approval := range item.Snapshot.Approvals {
				expected.Approvals[name] = approval
			}
			var mode string
			switch input.name {
			case "approval_mode_null":
				mode = "deny"
				item.RoundTripsTo = "null_approval_mode_defaults_to_deny"
			case "approval_mode_null_precedence":
				mode = "prompt"
				item.RoundTripsTo = "null_approval_mode_rederived_from_legacy"
			default:
				return nil, fmt.Errorf("case %s does not round-trip: %+v vs %+v", input.name, again, item.Snapshot)
			}
			approval := expected.Approvals["default"]
			approval.ApprovalMode = &mode
			expected.Approvals["default"] = approval
			if !reflect.DeepEqual(again, &expected) {
				return nil, fmt.Errorf("case %s has unexpected null-mode reload: %+v vs %+v", input.name, again, &expected)
			}
		} else {
			item.RoundTripsTo = "identical_snapshot"
		}
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
	writerCases, err := buildWriterCases(workDir)
	if err != nil {
		fatal("build writer cases: %v", err)
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
		Cases: cases, WriterCases: writerCases,
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
		fmt.Printf("PASS CFG-003 config-bytes fixture (%d cases, %d writer cases)\n", len(cases), len(writerCases))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d cases, %d writer cases)\n", *output, len(cases), len(writerCases))
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
