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
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

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

// tierExplicitEmptyCases are the per-tier cases that set every preset-backed
// field of a profile explicitly to an empty/false value.
var tierExplicitEmptyCases = []string{"tier_explicit_empty_read_only", "tier_explicit_empty_standard", "tier_explicit_empty_admin"}

var declaredLineDifferences = []lineDifference{
	{Side: "rust_adds", Keys: []string{"oauth"}, Block: true,
		Reason: "Go's SaveTo drops mcp.oauth (the OAuth server TTLs silently fall back to their defaults); Rust keeps it (upstream-go-bugs.md)"},
	{Side: "rust_adds", Cases: []string{"git_false_flags"}, Keys: []string{"auto_push", "auto_pull"}, Values: []string{"false"},
		Reason: "Go's omitempty drops git.auto_push/auto_pull false and the loader default is true, so an opt-out turns into an opt-in; Rust writes the false"},
	{Side: "rust_adds", Cases: []string{"clipboard_false_flag"}, Keys: []string{"copyByDefault"}, Values: []string{"false"},
		Reason: "Go's omitempty drops clipboard.copyByDefault false and the loader default is true; Rust writes the false"},
	{Side: "rust_adds", Cases: []string{"mcp_false_and_zero_values"}, Keys: []string{"port", "read_timeout", "rate_limit", "metrics_auth_required"}, Values: []string{"0", "0s", "false"},
		Reason: "Go's omitempty drops a zero port/timeout/rate limit and a false metrics_auth_required, and the loader defaults (8080, 10s, 60, true) replace them; Rust writes the operator's value"},
	{Side: "rust_adds", Cases: tierExplicitEmptyCases, Keys: []string{"allowedExecutables"}, Values: []string{"[]"},
		Reason: "Go's omitempty drops an explicit empty allowedExecutables and the next load re-applies the tier preset (standard grants curl, git, terraform, npm, node, python, python3, docker, kubectl): a rewrite widens the profile's permissions; Rust keeps the empty list (upstream-go-bugs.md 11)"},
	{Side: "rust_adds", Cases: tierExplicitEmptyCases, Keys: []string{"approvalMode"}, Values: []string{"null"},
		Reason: "Go drops an explicit approvalMode: null of a tiered profile and the next load re-applies the preset's mode (or derives one from requireApproval); Rust keeps the null so the effective profile does not change (upstream-go-bugs.md 11)"},
	{Side: "rust_adds", Cases: []string{"custom_without_can_write"}, Agents: []string{"x"}, Keys: []string{"canWrite"}, Values: []string{"false"},
		Reason: "Go holds canWrite as *bool and writes nothing for a profile that never set it; Rust holds bool and always writes canWrite, which reloads to the same false"},
	{Side: "rust_adds", Cases: []string{"mcp_dropped_by_go", "all_fields_non_zero", "git_identity", "clipboard_print_by_default"}, Keys: []string{"approval_required", "author", "email", "printByDefault"},
		Reason: "Go's SaveTo drops mcp.approval_required, git.author, git.email and clipboard.printByDefault; Rust keeps them (upstream-go-bugs.md 10)"},
	{Side: "rust_adds", Cases: []string{"mcp_dropped_by_go", "all_fields_non_zero"}, Keys: []string{"perplexity"}, Block: true,
		Reason: "Go's SaveTo drops mcp.perplexity, which turns a configured Perplexity client off; Rust keeps it (upstream-go-bugs.md 10)"},
	{Side: "go_only", Cases: []string{"custom_explicit_false_capabilities"}, Agents: []string{"x"}, Keys: []string{"canRunCommands", "canManageConfig", "canUseClipboard", "canUseAutotype", "canReadValues", "autoUnseal", "exposePaymentValues"}, Values: []string{"false"},
		Reason: "Go holds *bool: an explicit false on a custom profile is a set pointer and is written back; Rust holds bool and omits it, which reloads to the same false (a missing capability is false)"},
}

// droppedBySaveTo is the exact set of Config key paths Go reads but SaveTo
// does not write back. The probe fails when the corpus shows a different set.
var droppedBySaveTo = []string{
	"agents.*.post_call_hooks",
	"agents.*.pre_call_hooks",
	"clipboard.printByDefault",
	"envAllowlist",
	"envWhitelist",
	"git.author",
	"git.email",
	"mcp.approval_required",
	"mcp.oauth",
	"mcp.oauth.access_token_ttl",
	"mcp.oauth.refresh_token_ttl",
	"mcp.perplexity",
	"mcp.perplexity.allow_private",
	"mcp.perplexity.api_key",
	"mcp.perplexity.base_url",
	"mcp.perplexity.rate_limit_per_min",
	"paymentPolicies",
	"paymentPolicies.*.allowed_merchants",
	"paymentPolicies.*.currency",
	"paymentPolicies.*.instrument",
	"paymentPolicies.*.max_amount",
	"paymentPolicies.*.max_amount.per_day",
	"paymentPolicies.*.max_amount.per_transaction",
	"security",
	"security.allow_env_passphrase",
	"security.disable_env_passphrase",
	"vault.listing_cache_ttl",
	"vault.manifest_generation",
	"vault.sync",
	"vault.sync.method",
}

// Config key paths: the walk below is the field-coverage probe. Every yaml
// field of Config must appear in some case input; every field the corpus shows
// Go not writing back must be listed in droppedBySaveTo.
var timeType = reflect.TypeOf(time.Time{})

func joinPath(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func yamlName(f reflect.StructField) string {
	name := strings.Split(f.Tag.Get("yaml"), ",")[0]
	if name == "-" {
		return ""
	}
	return name
}

// fieldPaths lists every yaml key path of t (maps are `*`, lists `[]`).
func fieldPaths(t reflect.Type, path string, out *[]string) {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch {
	case t == timeType:
	case t.Kind() == reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if name := yamlName(t.Field(i)); name != "" {
				p := joinPath(path, name)
				*out = append(*out, p)
				fieldPaths(t.Field(i).Type, p, out)
			}
		}
	case t.Kind() == reflect.Map:
		fieldPaths(t.Elem(), path+".*", out)
	case t.Kind() == reflect.Slice:
		fieldPaths(t.Elem(), path+"[]", out)
	}
}

// presentPaths marks the key paths of t that the decoded yaml document writes.
func presentPaths(t reflect.Type, data any, path string, out map[string]bool) {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch {
	case t == timeType:
	case t.Kind() == reflect.Struct:
		node, ok := data.(map[string]any)
		if !ok {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			name := yamlName(t.Field(i))
			if name == "" {
				continue
			}
			if value, found := node[name]; found {
				p := joinPath(path, name)
				out[p] = true
				presentPaths(t.Field(i).Type, value, p, out)
			}
		}
	case t.Kind() == reflect.Map:
		if node, ok := data.(map[string]any); ok {
			for _, item := range node {
				presentPaths(t.Elem(), item, path+".*", out)
			}
		}
	case t.Kind() == reflect.Slice:
		if items, ok := data.([]any); ok {
			for _, item := range items {
				presentPaths(t.Elem(), item, path+"[]", out)
			}
		}
	}
}

// multilineStrings collects every string leaf and map key with a line break.
func multilineStrings(node any, out map[string]bool) {
	switch v := node.(type) {
	case string:
		if strings.Contains(v, "\n") {
			out[v] = true
		}
	case map[string]any:
		for key, item := range v {
			if strings.Contains(key, "\n") {
				out[key] = true
			}
			multilineStrings(item, out)
		}
	case []any:
		for _, item := range v {
			multilineStrings(item, out)
		}
	}
}

// savedIsFaithful reports whether yaml.v3 reads the saved bytes back and every
// multi-line string of the input survives unchanged.
func savedIsFaithful(input string, saved []byte) bool {
	var before, after any
	if yaml.Unmarshal([]byte(input), &before) != nil || yaml.Unmarshal(saved, &after) != nil {
		return false
	}
	// Sections Go drops by design are not part of the round trip.
	if sections, ok := before.(map[string]any); ok {
		for _, dropped := range declaredDifferences {
			delete(sections, dropped)
		}
	}
	want, got := map[string]bool{}, map[string]bool{}
	multilineStrings(before, want)
	multilineStrings(after, got)
	for text := range want {
		if !got[text] {
			return false
		}
	}
	return true
}

func documentPaths(document string, out map[string]bool) error {
	var data map[string]any
	if err := yaml.Unmarshal([]byte(document), &data); err != nil {
		return err
	}
	presentPaths(reflect.TypeOf(configpkg.Config{}), data, "", out)
	return nil
}

// coverage runs the probe: it returns every Config key path and the paths the
// corpus shows Go reading but not writing back, or an error when a field is
// never exercised or the dropped set differs from droppedBySaveTo.
func coverage(cases []rewriteCase) (fields, dropped []string, err error) {
	fieldPaths(reflect.TypeOf(configpkg.Config{}), "", &fields)
	sort.Strings(fields)
	read, written := map[string]bool{}, map[string]bool{}
	for _, c := range cases {
		if err := documentPaths(c.Input, read); err != nil {
			return nil, nil, fmt.Errorf("%s input: %w", c.Name, err)
		}
		if c.GoSavedFaithful {
			if err := documentPaths(c.SavedYAML, written); err != nil {
				return nil, nil, fmt.Errorf("%s saved: %w", c.Name, err)
			}
		}
	}
	var unexercised []string
	for _, f := range fields {
		if !read[f] {
			unexercised = append(unexercised, f)
		}
	}
	if len(unexercised) > 0 {
		return nil, nil, fmt.Errorf("fields no case input exercises: %s", strings.Join(unexercised, ", "))
	}
	for _, f := range fields {
		if !written[f] {
			dropped = append(dropped, f)
		}
	}
	if strings.Join(dropped, "\n") != strings.Join(droppedBySaveTo, "\n") {
		return nil, nil, fmt.Errorf("fields Go reads but SaveTo does not write:\n  got  %s\n  want %s",
			strings.Join(dropped, ", "), strings.Join(droppedBySaveTo, ", "))
	}
	return fields, dropped, nil
}

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
	// GoSavedFaithful is false when yaml.v3 cannot read back what its SaveTo
	// wrote, or reads back a different multi-line string (a literal block with
	// an indentation indicator inside a sequence item; a value that starts
	// with a line break). Rust writes a double-quoted scalar there instead.
	GoSavedFaithful bool `json:"go_saved_faithful"`
}

type fixture struct {
	SchemaVersion       int      `json:"schema_version"`
	Oracle              oracle   `json:"oracle"`
	DeclaredDifferences []string `json:"declared_differences"`
	// DeclaredLineDifferences are the places where the Rust writer writes more
	// than Go: every entry names the lines it may add and why.
	DeclaredLineDifferences []lineDifference `json:"declared_line_differences"`
	// Fields lists every yaml key path of Go's Config; DroppedBySaveTo the
	// ones Go reads but SaveTo does not write back (the field-coverage probe).
	Fields          []string      `json:"fields"`
	DroppedBySaveTo []string      `json:"dropped_by_save_to"`
	Cases           []rewriteCase `json:"cases"`
}

// lineDifference is a place where the Rust writer and Go's SaveTo differ on
// purpose. Side "rust_adds": Rust writes lines Go does not (data Go loses, or
// an explicit value Go's omitempty drops); side "go_only": Go writes lines Rust
// omits (an explicit false that reloads the same). A line matches when its
// trimmed text starts with "<key>:" and, if Values is set, ends with one of
// them. Cases restricts it to the named cases (empty: every case).
type lineDifference struct {
	Side  string   `json:"side"`
	Cases []string `json:"cases,omitempty"`
	// Agents restricts the difference to the named agent blocks.
	Agents []string `json:"agents,omitempty"`
	Keys   []string `json:"keys"`
	Values []string `json:"values,omitempty"`
	// Block also drops every deeper line (a nested mapping).
	Block  bool   `json:"block,omitempty"`
	Reason string `json:"reason"`
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
		{"multiline_scan_description", "a literal-block description survives agent uninstall as a literal block Go and Rust reload",
			head + lines("agents:", "  bot:", "    canWrite: true", "  other:", "    canWrite: false",
				"scan_patterns:", "  - name: aws", "    pattern: '^AKIA'", "    description: |", "      Matches AWS keys.", "      Second line.", "    severity: high")},
		{"multiline_everywhere", "multi-line strings in every string position the writer emits (map values, list items, map keys)",
			lines("vaultDir: \"/fixture/va\\nult\"", "defaultAgent: bot", "defaultProfile: work", "profiles:", "  work:", "    vault: \"/fixture/w\\nork\"",
				"vault:", "  path: \"p1\\np2\"", "  default_recipients: [\"r1\\nr2\", plain]",
				"git:", "  commit_template: \"msg\\n\\nbody\\n\"",
				"agents:", "  bot:", "    canWrite: true",
				"    allowedPaths: [\"a\\nb\", \"tail: x\", \"keep\\n\"]", "    redactFields: [\"x\\ny\\n\\n\"]",
				"    perToolRedactFields:", "      get: [\"l1\\nl2\"]", "      \"k\\nj\": [a]",
				"    dynamicProviders:", "      aws: [\"h1\\nh2\", \" lead\"]",
				"    allowedEnvVars: [\"E\\nV\"]", "    allowedExecutables: [\"/bin/a\\nb\"]", "    allowed_tools: [\"t\\nu\"]",
				"    skillPath: \"/s/p\\nq\"", "    skillVersion: \"v\\n1\"", "    paymentPolicy: card",
				"  \"two\\nlines\":", "    canWrite: false",
				"paymentPolicies:", "  card:", "    instrument: \"cards\\nvisa\"", "    allowed_merchants: [\"m1\\nm2\"]", "    currency: \"E\\nUR\"",
				"scan_patterns:", "  - name: \"n\\n1\"", "    pattern: \"p\\n1\"", "    description: \"d\\n\\n\"", "    severity: high")},
		{"all_fields_non_zero", "the field-coverage case: every yaml field of Go's Config set to a non-zero value",
			lines("vaultDir: /fixture/vault", "defaultAgent: bot", "sessionTimeout: 20m", "sessionMaxLifetime: 4h", "authMethod: touchid", "useTouchID: true",
				"profiles:", "  work:", "    vault: /fixture/work", "defaultProfile: work", "envAllowlist: [A]", "envWhitelist: [B]",
				"agents:", "  bot:", "    tier: standard", "    approvalMode: prompt", "    allowedPaths: [a/*]", "    redactFields: [password]", "    perToolRedactFields:", "      get: [token]",
				"    canWrite: true", "    canRunCommands: true", "    canManageConfig: true", "    canUseClipboard: true", "    canUseAutotype: true", "    canReadValues: true", "    exposeValueTools: true", "    autoUnseal: true", "    requireApproval: true",
				"    approvalTimeout: 45s", "    allowed_tools: [vault_get]", "    max_reads_per_hour: 11", "    max_reads_per_day: 22", "    max_secrets_in_session: 3", "    dynamicProviders:", "      aws: [a]",
				"    allowedEnvVars: [HOME]", "    allowedExecutables: [/bin/ls]", "    promptInjectionMode: wrap", "    pre_call_hooks: [/bin/pre]", "    post_call_hooks: [/bin/post]",
				"    skillPath: /skills/bot", "    skillVersion: v9", "    exposePaymentValues: true", "    paymentPolicy: card",
				"vault:", "  path: /fixture/v", "  default_recipients: [age1abc]", "  confirm_remove: true", "  authMethod: touchid", "  useTouchID: true", "  legacy_mode: true", "  search_index: true", "  search_workers: 4",
				"  search_index_cache: true", "  config_cache_entries: 100", "  pseudonymize_paths: true", "  scrypt_work_factor: 17", "  auto_migrate_kdf: true", "  auto_heal_zero_key: true", "  last_rotated: 2026-01-02T03:04:05Z",
				"  format_version: 2", "  argon2id_time: 3", "  argon2id_memory: 65536", "  argon2id_threads: 4", "  listing_cache_ttl: 5m", "  manifest_generation: 3", "  sync:", "    method: icloud-drive",
				"git:", "  commit_template: tmpl", "  author: Ann", "  email: ann@example.test", "  auto_push: true", "  auto_pull: true", "  auto_pull_interval: 30s",
				"mcp:", "  port: 9095", "  bind: 127.0.0.1", "  httpTokenFile: /tmp/t", "  otlp_endpoint: localhost:4317", "  stdio: true", "  approval_required: true", "  read_header_timeout: 6s", "  read_timeout: 7s", "  write_timeout: 8s", "  shutdown_timeout: 9s", "  approval_timeout: 10s", "  rate_limit: 11",
				"  trusted_proxy_ips: [10.0.0.1]", "  metrics_auth_required: true", "  tls_cert_file: /c", "  tls_key_file: /k", "  tls_client_ca_file: /ca", "  approval_tls_cert_file: /ac", "  approval_tls_key_file: /ak", "  mtls_enabled: true", "  allow_insecure_bind: true",
				"  oauth:", "    access_token_ttl: 2h", "    refresh_token_ttl: 3h", "  perplexity:", "    api_key: k", "    base_url: https://p.example.test", "    rate_limit_per_min: 5", "    allow_private: true",
				"update:", "  cache_ttl: 12h", "clipboard:", "  auto_clear_duration: 15", "  copyByDefault: true", "  printByDefault: true",
				"audit:", "  maxSizeMb: 50", "  maxBackups: 3", "  maxAgeDays: 7", "logging:", "  level: debug", "  format: json", "security:", "  disable_env_passphrase: true", "  allow_env_passphrase: true",
				"scan_patterns:", "  - name: aws", "    pattern: '^AKIA'", "    description: aws key", "    severity: high",
				"paymentPolicies:", "  card:", "    instrument: cards/visa", "    allowed_merchants: [acme]", "    max_amount:", "      per_transaction: \"10\"", "      per_day: \"50\"", "    currency: EUR")},
		{"tier_only_profiles", "tiered profiles hold the full preset field set",
			head + lines("agents:", "  ro:", "    tier: read-only", "  std:", "    tier: standard", "  adm:", "    tier: admin")},
		{"tier_with_overrides", "a tiered profile with overridden capabilities keeps the overrides and the preset",
			head + lines("agents:", "  ro:", "    tier: read-only", "    canWrite: true", "    canRunCommands: false", "  adm:", "    tier: admin", "    canManageConfig: false", "    requireApproval: false")},
		{"custom_explicit_false_capabilities", "explicit false capabilities on a custom profile",
			head + lines("agents:", "  x:", "    canWrite: true", "    canRunCommands: false", "    canManageConfig: false", "    canUseClipboard: false", "    canUseAutotype: false", "    canReadValues: false", "    autoUnseal: false", "    requireApproval: false", "    exposePaymentValues: false")},
		{"custom_true_capabilities", "true capabilities on a custom profile are written back, not reset by the next load",
			head + lines("agents:", "  x:", "    canWrite: true", "    canManageConfig: true", "    canUseClipboard: true", "    canUseAutotype: true", "    canReadValues: true", "    autoUnseal: true", "  claude-code:", "    canUseClipboard: true", "    canReadValues: true")},
		{"last_rotated_forms", "last_rotated written as an RFC 3339 timestamp with a fraction and an offset",
			head + lines("vault:", "  last_rotated: 2026-01-02T03:04:05.5+02:00")},
		{"last_rotated_space_form", "last_rotated in the yaml timestamp space form is normalised by Go",
			head + lines("vault:", "  last_rotated: 2026-01-02 03:04:05")},
		{"last_rotated_date_only", "last_rotated as a bare date is midnight UTC",
			head + lines("vault:", "  last_rotated: 2026-1-2")},
		{"git_false_flags", "false auto_push / auto_pull are dropped by Go's omitempty (the loader default is true)",
			head + lines("git:", "  auto_push: false", "  auto_pull: false", "  commit_template: msg")},
		{"clipboard_false_flag", "copyByDefault false is dropped by Go's omitempty (the loader default is true)",
			head + lines("clipboard:", "  auto_clear_duration: 0", "  copyByDefault: false")},
		{"mcp_false_and_zero_values", "explicit false and zero values of omitempty MCP fields",
			head + lines("mcp:", "  port: 0", "  metrics_auth_required: false", "  rate_limit: 0", "  read_timeout: 0s", "  stdio: false")},
		{"leading_break_list_item", "a list item that starts with a line break: yaml.v3's own output cannot be parsed back, Rust double-quotes it",
			head + lines("agents:", "  bot:", "    canWrite: true", "    allowedPaths: [\"\\nlead\", \" sp\\nx\", plain]")},
		{"leading_break_scan_pattern", "a scan_patterns value that starts with a line break (mapping inside a sequence item): same yaml.v3 defect",
			head + lines("scan_patterns:", "  - name: n", "    pattern: p", "    description: \"\\nlead\"", "    severity: low")},
		{"leading_break_map_value", "a value that starts with a line break loses it in yaml.v3's output (it reloads as lead\\nx); Rust double-quotes it",
			head + lines("vault:", "  path: \"\\nlead\\nx\"")},
		{"leading_space_map_value", "a value that starts with a space is a literal block with indentation indicator 4, which parses back at mapping depth 4",
			head + lines("vault:", "  path: \" lead\\nx\"", "git:", "  commit_template: \" lead\\nx\"")},
		{"mcp_full_fields", "every MCP field Go's SaveTo keeps, in Go's order (otlp_endpoint, trusted_proxy_ips, approval_tls_*)",
			head + lines("mcp:", "  port: 9091", "  bind: 0.0.0.0", "  httpTokenFile: /tmp/tok", "  otlp_endpoint: 'http://otel:4318'", "  stdio: true",
				"  read_header_timeout: 7s", "  read_timeout: 1m30s", "  write_timeout: 1.5s", "  shutdown_timeout: 2m", "  approval_timeout: 45s", "  rate_limit: 120",
				"  trusted_proxy_ips: [10.0.0.1, 192.168.0.0/24]", "  metrics_auth_required: true",
				"  tls_cert_file: /c.pem", "  tls_key_file: /k.pem", "  tls_client_ca_file: /ca.pem",
				"  approval_tls_cert_file: certs/approval-client.pem", "  approval_tls_key_file: certs/approval-client.key",
				"  mtls_enabled: true", "  allow_insecure_bind: true")},
		{"mcp_stdio_http_token_file", "stdio with an explicit httpTokenFile: Go order is port, bind, httpTokenFile, otlp_endpoint, stdio",
			head + lines("mcp:", "  stdio: true", "  httpTokenFile: /tmp/mcp-token", "  otlp_endpoint: localhost:4317", "  port: 9092", "  bind: ::1")},
		{"mcp_oauth", "mcp.oauth is a declared difference: Go's SaveTo drops it, Rust keeps it",
			head + lines("mcp:", "  port: 9093", "  oauth:", "    access_token_ttl: 2h", "    refresh_token_ttl: 90m")},
		{"mcp_dropped_by_go", "approval_required and perplexity are dropped by Go and by Rust alike",
			head + lines("mcp:", "  port: 9094", "  approval_required: true", "  perplexity:", "    api_key: pplx-secret", "    base_url: 'https://api.perplexity.ai'", "    rate_limit_per_min: 7", "    allow_private: true")},
		{"durations_go_string", "durations are written as time.Duration.String() (90s is 1m30s, 1h30m is 1h30m0s)",
			lines("vaultDir: /fixture/vault", "sessionTimeout: 90s", "sessionMaxLifetime: 1h30m", "git:", "  auto_pull_interval: 90s", "update:", "  cache_ttl: 36h30m", "mcp:", "  approval_timeout: 1h30m", "  read_timeout: 2500ms",
				"agents:", "  bot:", "    canWrite: true", "    approvalTimeout: 90s", "  other:", "    canWrite: true", "    approvalTimeout: 1h")},
		{"quoting_agent_lists", "yaml.v3 scalar style decisions for list items (plain, single, double, escapes)",
			head + lines("agents:", "  bot:", "    canWrite: true", "    allowedPaths:",
				"      - '&amp'", "      - '#c'", "      - \"2026-01-02\"", "      - \"2026-01-02T10:00:00Z\"", "      - \"\\U0001F600\"", "      - 'null'", "      - '~'", "      - '- x'", "      - \"it's\"", "      - ' lead'", "      - 'trail '",
				"      - \"tab\\there\"", "      - '1e3'", "      - '0x1F'", "      - '.inf'", "      - '1_000'", "      - 'y'", "      - 'a: b'", "      - '@at'", "      - '`tick'", "      - '%pct'", "      - '!bang'", "      - '*star'", "      - '?q'", "      - '|pipe'", "      - '>gt'", "      - '{br}'", "      - '[sq]'", "      - ',c'", "      - 'key:'", "      - 'a #b'", "      - \"caf\\u00e9\"", "      - \"bell\\a\"", "      - ''", "      - '12:30:45'", "      - ' '", "      - '---'", "      - '<<'")},
		{"quoting_scan_pattern_values", "the same style decisions for map values at another depth",
			head + lines("scan_patterns:", "  - name: '&amp'", "    pattern: '#c'", "    description: \"2026-01-02\"", "    severity: \"\\U0001F600\"")},
		{"empty_lists_in_maps", "an empty list under perToolRedactFields or dynamicProviders is written as []",
			head + lines("agents:", "  bot:", "    canWrite: true", "    perToolRedactFields:", "      get: []", "      put:", "    dynamicProviders:", "      aws: []")},
		{"approval_timeout_zero", "an explicit approvalTimeout: 0s is written back as 0s",
			head + lines("agents:", "  bot:", "    canWrite: true", "    approvalTimeout: 0s", "  other:", "    canWrite: true")},
		{"leading_break_map_key", "agent and perToolRedactFields keys that start with a line break: yaml.v3 writes them as `? |4-` and reads them back without the break, so \"\\na\\nb\" collides with \"a\\nb\"; Rust double-quotes them",
			head + lines("agents:", "  \"\\na\\nb\":", "    canWrite: true", "    perToolRedactFields:", "      \"\\nk\": [x]", "  \"a\\nb\":", "    canWrite: false")},
		{"leading_space_map_key", "an agent key that starts with a space and has a line break keeps its `? |4-` form (the indentation indicator matches at this depth)",
			head + lines("agents:", "  \" a\\nb\":", "    canWrite: true")},
		{"custom_without_can_write", "a custom profile that never sets canWrite: Go writes no canWrite, Rust writes the false",
			head + lines("agents:", "  x:", "    skillPath: /s/p")},
		{"tier_explicit_empty_read_only", "every preset-backed field of a read-only profile set explicitly to false/empty/null",
			head + tierExplicitEmpty("read-only")},
		{"tier_explicit_empty_standard", "every preset-backed field of a standard profile set explicitly to false/empty/null: dropping allowedExecutables: [] would re-grant the preset's nine executables",
			head + tierExplicitEmpty("standard")},
		{"tier_explicit_empty_admin", "every preset-backed field of an admin profile set explicitly to false/empty/null",
			head + tierExplicitEmpty("admin")},
		{"git_identity", "git.author and git.email are dropped by Go and kept by Rust",
			head + lines("git:", "  commit_template: msg", "  author: Ann", "  email: ann@example.test")},
		{"clipboard_print_by_default", "the deprecated printByDefault: Go folds it into copyByDefault and drops the key, Rust keeps it",
			head + lines("clipboard:", "  auto_clear_duration: 15", "  printByDefault: true")},
		{"all_sections_modelled", "vault, git, mcp, update, clipboard together with audit and logging",
			head + lines("vault:", "  path: /fixture/v", "  search_index: true", "mcp:", "  port: 9090", "  bind: 127.0.0.1", "update:", "  cache_ttl: 12h", "clipboard:", "  auto_clear_duration: 15", "  copyByDefault: true", "git:", "  auto_push: true", "  auto_pull: true", "  commit_template: msg",
				"audit:", "  maxSizeMb: 5", "logging:", "  format: json")},
	}
}

// tierExplicitEmpty is a profile of the given tier with every preset-backed
// field written explicitly as false/empty/null, next to a profile that
// `agent uninstall` removes.
func tierExplicitEmpty(tier string) string {
	return lines("agents:", "  bot:", "    tier: "+tier, "    approvalMode: null", "    canWrite: false", "    canRunCommands: false", "    canManageConfig: false", "    canUseClipboard: false", "    canUseAutotype: false", "    canReadValues: false", "    exposeValueTools: false", "    autoUnseal: false", "    requireApproval: false", "    allowedExecutables: []", "  other:", "    canWrite: true")
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
		if in.name == "multiline_scan_description" {
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
			faithful := savedIsFaithful(in.yaml, data)
			name := in.name
			if mutation != "none" && in.name != "agent_remove_other" {
				name += "_" + strings.ReplaceAll(mutation, ":", "_")
			}
			out = append(out, rewriteCase{Name: name, Description: in.description, Input: in.yaml, Mutation: mutation, SavedYAML: string(data), GoSavedFaithful: faithful})
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
	fields, dropped, err := coverage(cases)
	if err != nil {
		fatal("field-coverage probe: %v", err)
	}
	content, err := marshalJSON(fixture{
		SchemaVersion: 1,
		Oracle: oracle{Commit: pinnedOracleCommit, CommitSHA: resolved, Release: pinnedOracleRelease,
			SourceFiles: sources, SourceDigest: sourceDigest, GeneratorDigest: generatorDigest},
		DeclaredDifferences:     declaredDifferences,
		DeclaredLineDifferences: declaredLineDifferences,
		Fields:                  fields,
		DroppedBySaveTo:         dropped,
		Cases:                   cases,
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
