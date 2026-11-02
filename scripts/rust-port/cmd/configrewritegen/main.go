// Command configrewritegen freezes the CONFIG-WRITER contract: the exact bytes
// Go's Config.SaveTo leaves behind when a command loads a config.yaml,
// optionally changes it, and writes it back (agent install/upgrade/uninstall,
// remote, `config validate --fix`, `doctor --fix`).
//
// Each case is a real Go Load -> mutation -> SaveTo. The saved bytes are the
// oracle. Two top-level sections are NOT part of the byte contract because Go
// loses them on rewrite (paymentPolicies, security): the Rust port preserves
// them on purpose, and the fixture lists them as declared_differences so the
// comparison treats exactly those two sections as the difference.
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
	"strings"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "690647c5068a818a4b237738882bb20c865a134a"
	pinnedOracleRelease = "unreleased"
)

var productionSources = []string{
	"internal/config/config.go",
	"internal/config/config_load.go",
	"internal/config/config_merge.go",
	"internal/config/config_save.go",
	"internal/config/config_validate.go",
	"internal/config/schema.go",
	"internal/config/warn.go",
}

// declaredDifferences are the top-level sections Go's SaveTo drops and the
// Rust writer keeps (docs/rust-port/upstream-go-bugs.md).
var declaredDifferences = []string{"paymentPolicies", "security"}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

type rewriteCase struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Input       string `json:"input"`
	// Mutation is applied to the loaded config before SaveTo: "none" or
	// "remove_agent:<name>" (what `agent uninstall` does).
	Mutation  string `json:"mutation"`
	SavedYAML string `json:"saved_yaml"`
}

type fixture struct {
	SchemaVersion       int           `json:"schema_version"`
	Oracle              oracle        `json:"oracle"`
	DeclaredDifferences []string      `json:"declared_differences"`
	Cases               []rewriteCase `json:"cases"`
}

type input struct{ name, description, yaml string }

func lines(parts ...string) string { return strings.Join(parts, "\n") + "\n" }

const head = "vaultDir: /fixture/vault\n"

func inputs() []input {
	return []input{
		{"payment_policy_agent", "an agent bound to a payment policy keeps paymentPolicy, skillVersion and exposePaymentValues in Go's order",
			head + lines("agents:", "  bot:", "    approvalMode: prompt", "    canWrite: true", "    skillPath: /s/p", "    skillVersion: \"1.2.3\"", "    exposePaymentValues: true", "    paymentPolicy: card", "  other:", "    canWrite: false",
				"paymentPolicies:", "  card:", "    instrument: cards/visa", "    allowed_merchants: [acme, Beta]", "    max_amount:", "      per_transaction: \"10.00\"", "      per_day: \"50\"", "    currency: EUR")},
		{"all_sections", "audit, logging, security and scan_patterns around a payment-bound agent",
			head + lines("agents:", "  bot:", "    canWrite: true", "    paymentPolicy: card",
				"paymentPolicies:", "  card:", "    instrument: cards/visa", "    currency: EUR",
				"audit:", "  maxSizeMb: 50", "  maxBackups: 3", "  maxAgeDays: 7",
				"logging:", "  level: debug", "  format: json",
				"security:", "  disable_env_passphrase: true", "  allow_env_passphrase: true",
				"scan_patterns:", "  - name: aws", "    pattern: '^AKIA[A-Z0-9]{16}$'", "    description: 'AWS key: id'", "    severity: high",
				"  - name: empty")},
		{"audit_empty_mapping", "an empty audit mapping is the default section", head + "audit: {}\n"},
		{"audit_zero_size", "maxSizeMb 0 is written back as no size", head + lines("audit:", "  maxSizeMb: 0")},
		{"audit_zero_counts", "zero backups and age are written, not omitted", head + lines("audit:", "  maxSizeMb: 1", "  maxBackups: 0", "  maxAgeDays: 0")},
		{"audit_partial", "unwritten audit fields keep their defaults", head + lines("audit:", "  maxBackups: 9")},
		{"audit_negative_size", "a negative size is written as its (negative) megabyte count", head + lines("audit:", "  maxSizeMb: -3")},
		{"logging_level_only", "an unwritten logging field keeps its default", head + lines("logging:", "  level: error")},
		{"logging_blank_values", "blank level and format collapse to an empty mapping", head + lines("logging:", "  level: ''", "  format: ''")},
		{"logging_empty_mapping", "an empty logging mapping is the default section", head + "logging: {}\n"},
		{"security_flags", "security is a declared difference: Go drops it", head + lines("security:", "  disable_env_passphrase: true")},
		{"security_empty", "an empty security mapping is a declared difference", head + "security: {}\n"},
		{"scan_patterns_quoting", "scan_patterns scalars that need quoting",
			head + lines("scan_patterns:", "  - name: 'yes'", "    pattern: 123", "    description: \"a # b\"", "    severity: ''", "  - {name: n2, pattern: '[a-z]+', description: d, severity: low}")},
		{"scan_patterns_empty_list", "an empty list is not written", head + "scan_patterns: []\n"},
		{"payment_policies_only", "paymentPolicies alone is a declared difference",
			head + lines("paymentPolicies:", "  b:", "    instrument: cards/b", "  a:", "    instrument: cards/a", "    allowed_merchants: [x]", "    currency: USD", "    max_amount:", "      per_day: '5'")},
		{"agent_all_fields", "every agent field Go can write, set explicitly",
			head + lines("agents:", "  full:", "    tier: standard", "    approvalMode: prompt", "    allowedPaths: [a/*, b/c]", "    redactFields: [password]", "    perToolRedactFields:", "      get: [token]", "    canWrite: true", "    canRunCommands: true", "    canManageConfig: false", "    canUseClipboard: true", "    canUseAutotype: false", "    canReadValues: true", "    exposeValueTools: true", "    autoUnseal: true", "    requireApproval: true", "    approvalTimeout: 45s", "    allowed_tools: [vault_get, vault_list]", "    max_reads_per_hour: 11", "    max_reads_per_day: 22", "    max_secrets_in_session: 3", "    dynamicProviders:", "      aws: [a, b]", "    allowedEnvVars: [HOME]", "    allowedExecutables: [/bin/ls]", "    promptInjectionMode: wrap", "    pre_call_hooks: [/bin/pre]", "    post_call_hooks: [/bin/post]", "    skillPath: /skills/full", "    skillVersion: v9", "    exposePaymentValues: true", "    paymentPolicy: card")},
		{"agent_explicit_false_bools", "explicit false booleans on a custom agent are written back",
			head + lines("agents:", "  zero:", "    canWrite: false", "    exposeValueTools: false")},
		{"agent_remove_other", "agent uninstall keeps every other agent's fields and the unrelated sections",
			head + lines("defaultAgent: bot", "agents:", "  bot:", "    canWrite: true", "    skillVersion: '2'", "    paymentPolicy: card", "  other:", "    canWrite: true",
				"paymentPolicies:", "  card:", "    instrument: cards/visa", "audit:", "  maxSizeMb: 10", "logging:", "  level: info", "scan_patterns:", "  - name: n", "    pattern: p")},
		{"top_level_fields", "the top-level scalars, profiles and defaultProfile keep Go's order",
			lines("vaultDir: /fixture/vault", "defaultAgent: default", "sessionTimeout: 20m", "sessionMaxLifetime: 4h", "authMethod: passphrase", "profiles:", "  work:", "    vault: /fixture/work", "defaultProfile: work", "envAllowlist: [A, B]")},
		{"all_sections_modelled", "vault, git, mcp, update, clipboard together with audit and logging",
			head + lines("vault:", "  path: /fixture/v", "  search_index: true", "mcp:", "  port: 9090", "  bind: 127.0.0.1", "update:", "  cache_ttl: 12h", "clipboard:", "  auto_clear_duration: 15", "  copyByDefault: true", "git:", "  auto_push: true", "  auto_pull: true", "  commit_template: msg",
				"audit:", "  maxSizeMb: 5", "logging:", "  format: json")},
	}
}

func apply(cfg *configpkg.Config, mutation string) error {
	switch {
	case mutation == "none":
		return nil
	case strings.HasPrefix(mutation, "remove_agent:"):
		delete(cfg.Agents, strings.TrimPrefix(mutation, "remove_agent:"))
		return nil
	}
	return fmt.Errorf("unknown mutation %q", mutation)
}

func buildCases(workDir string) ([]rewriteCase, error) {
	var out []rewriteCase
	for index, in := range inputs() {
		mutations := []string{"none"}
		if in.name == "agent_remove_other" {
			mutations = []string{"remove_agent:other"}
		}
		if in.name == "payment_policy_agent" {
			mutations = append(mutations, "remove_agent:other")
		}
		for _, mutation := range mutations {
			path := filepath.Join(workDir, fmt.Sprintf("case-%02d.yaml", index))
			if err := os.WriteFile(path, []byte(in.yaml), 0o600); err != nil {
				return nil, err
			}
			configpkg.SetWarnFunc(nil)
			cfg, err := configpkg.Load(path)
			if err != nil {
				return nil, fmt.Errorf("load %s: %w", in.name, err)
			}
			if err := apply(cfg, mutation); err != nil {
				return nil, err
			}
			saved := filepath.Join(workDir, fmt.Sprintf("case-%02d-saved.yaml", index))
			if err := cfg.SaveTo(saved); err != nil {
				return nil, fmt.Errorf("save %s: %w", in.name, err)
			}
			data, err := os.ReadFile(saved) // #nosec G304 -- generator-owned temporary path
			if err != nil {
				return nil, err
			}
			name := in.name
			if mutation != "none" && in.name != "agent_remove_other" {
				name += "_" + strings.ReplaceAll(mutation, ":", "_")
			}
			out = append(out, rewriteCase{Name: name, Description: in.description, Input: in.yaml, Mutation: mutation, SavedYAML: string(data)})
		}
	}
	return out, nil
}

func main() {
	output := flag.String("output", "testdata/port/config/rewrite.json", "fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs; never writes")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	flag.Parse()

	if *commit != "" && *commit != pinnedOracleCommit {
		fatal("oracle commit %q is not the pinned commit %q", *commit, pinnedOracleCommit)
	}
	if *release != "" && *release != pinnedOracleRelease {
		fatal("oracle release %q is not the pinned release %q", *release, pinnedOracleRelease)
	}
	if !*check && (*commit == "" || *release == "") {
		fatal("--oracle-commit and --oracle-release are required when generating a new fixture")
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
	resolved, err := provenance.Verify(root, pinnedOracleCommit, sources)
	if err != nil {
		fatal("%v", err)
	}
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/configrewritegen/main.go"})
	if err != nil {
		fatal("hash generator: %v", err)
	}
	workDir, err := os.MkdirTemp("", "configrewritegen-")
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
		Oracle: oracle{Commit: pinnedOracleCommit, CommitSHA: resolved, Release: pinnedOracleRelease,
			SourceFiles: sources, SourceDigest: sourceDigest, GeneratorDigest: generatorDigest},
		DeclaredDifferences: declaredDifferences,
		Cases:               cases,
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
			fatal("fixture is stale; run make cfg-rewrite-fixtures-generate")
		}
		fmt.Printf("PASS CONFIG-WRITER rewrite fixture (%d cases)\n", len(cases))
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
