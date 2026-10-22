// Command configsectionsgen freezes the section half of the CFG-002 precedence
// contract and the deprecation warnings of CFG-003.
//
// configprecedencegen pins how defaults, tier presets and explicitly present
// agent fields layer. The loader applies the same rule to every other section
// — vault, git, mcp, update and clipboard: a section carries its own defaults
// and only the fields the document names override them, so an explicit zero or
// false beats the default while an absent field does not. This generator pins
// that presence rule, the mcp.oauth positive-only guard, the legacy-key
// fallbacks, and the warnings the loader raises for deprecated keys.
//
// clipboard.printByDefault warns once per process, so every case is loaded in
// a fresh child process; the dedicated `twice` case loads the same document two
// times in one child to pin the once-per-process behavior.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "861ad93813e3ee43c4ec989f45940d14b05b6eaf"
	pinnedOracleRelease = "unreleased"
)

var productionSources = []string{
	"internal/config/config.go",
	"internal/config/config_load.go",
	"internal/config/config_merge.go",
	"internal/config/schema.go",
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

type syncSnapshot struct {
	Method string `json:"method"`
}

type vaultSnapshot struct {
	Path               string        `json:"path"`
	DefaultRecipients  []string      `json:"default_recipients"`
	ConfirmRemove      bool          `json:"confirm_remove"`
	AuthMethod         string        `json:"auth_method"`
	UseTouchID         bool          `json:"use_touch_id"`
	LegacyMode         *bool         `json:"legacy_mode"`
	SearchIndex        bool          `json:"search_index"`
	SearchWorkers      int           `json:"search_workers"`
	SearchIndexCache   bool          `json:"search_index_cache"`
	ConfigCacheEntries int           `json:"config_cache_entries"`
	PseudonymizePaths  bool          `json:"pseudonymize_paths"`
	ScryptWorkFactor   int           `json:"scrypt_work_factor"`
	AutoMigrateKDF     bool          `json:"auto_migrate_kdf"`
	AutoHealZeroKey    bool          `json:"auto_heal_zero_key"`
	FormatVersion      int           `json:"format_version"`
	Argon2idTime       int           `json:"argon2id_time"`
	Argon2idMemory     int           `json:"argon2id_memory"`
	Argon2idThreads    int           `json:"argon2id_threads"`
	ListingCacheTTLNs  int64         `json:"listing_cache_ttl_ns"`
	ManifestGeneration int           `json:"manifest_generation"`
	Sync               *syncSnapshot `json:"sync"`
}

type gitSnapshot struct {
	AutoPush           bool   `json:"auto_push"`
	AutoPull           bool   `json:"auto_pull"`
	AutoPullIntervalNs int64  `json:"auto_pull_interval_ns"`
	CommitTemplate     string `json:"commit_template"`
}

type oauthSnapshot struct {
	AccessTokenTTLNs  int64 `json:"access_token_ttl_ns"`
	RefreshTokenTTLNs int64 `json:"refresh_token_ttl_ns"`
}

type mcpSnapshot struct {
	Port                int            `json:"port"`
	Bind                string         `json:"bind"`
	Stdio               bool           `json:"stdio"`
	HTTPTokenFile       string         `json:"http_token_file"`
	ReadHeaderTimeoutNs int64          `json:"read_header_timeout_ns"`
	ReadTimeoutNs       int64          `json:"read_timeout_ns"`
	WriteTimeoutNs      int64          `json:"write_timeout_ns"`
	ShutdownTimeoutNs   int64          `json:"shutdown_timeout_ns"`
	ApprovalTimeoutNs   int64          `json:"approval_timeout_ns"`
	RateLimit           int            `json:"rate_limit"`
	MetricsAuthRequired bool           `json:"metrics_auth_required"`
	TLSCertFile         string         `json:"tls_cert_file"`
	TLSKeyFile          string         `json:"tls_key_file"`
	TLSClientCAFile     string         `json:"tls_client_ca_file"`
	MTLSEnabled         bool           `json:"mtls_enabled"`
	AllowInsecureBind   bool           `json:"allow_insecure_bind"`
	OAuth               *oauthSnapshot `json:"oauth"`
}

type updateSnapshot struct {
	CacheTTLNs int64 `json:"cache_ttl_ns"`
}

type clipboardSnapshot struct {
	AutoClearDuration int  `json:"auto_clear_duration"`
	CopyByDefault     bool `json:"copy_by_default"`
}

// snapshot is the observable result of loading one document. Absent sections
// are null: Go leaves the pointer nil, and consumers branch on that.
type snapshot struct {
	AuthMethod          string             `json:"auth_method"`
	EffectiveAuthMethod string             `json:"effective_auth_method"`
	Vault               *vaultSnapshot     `json:"vault"`
	Git                 *gitSnapshot       `json:"git"`
	MCP                 *mcpSnapshot       `json:"mcp"`
	Update              *updateSnapshot    `json:"update"`
	Clipboard           *clipboardSnapshot `json:"clipboard"`
}

// load is one Load of the document: the warnings it raised and, when it was
// accepted, what it resolved to.
type load struct {
	Warnings []string  `json:"warnings"`
	Rejected bool      `json:"rejected"`
	Snapshot *snapshot `json:"snapshot"`
}

type sectionCase struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Input       string `json:"input"`
	// Loads holds the results of loading Input that many times in one process.
	Loads []load `json:"loads"`
}

type fixture struct {
	SchemaVersion int           `json:"schema_version"`
	Oracle        oracle        `json:"oracle"`
	Cases         []sectionCase `json:"cases"`
}

type input struct {
	name, description, body string
	loads                   int
}

func inputs() []input {
	cases := []input{
		// An absent or null section stays nil: no defaults are invented.
		{"no_sections", "no section present at all", "defaultAgent: default\n", 1},
		{"sections_null", "every section explicitly null stays absent", "vault:\ngit:\nmcp:\nupdate:\nclipboard:\n", 1},
		{"sections_empty", "an empty section takes its full set of defaults", "vault: {}\ngit: {}\nmcp: {}\nupdate: {}\nclipboard: {}\n", 1},

		// git: presence, not value.
		{"git_explicit_false", "explicit false beats a true default", "git:\n  auto_push: false\n  auto_pull: false\n", 1},
		{"git_explicit_zero_interval", "an explicit zero duration beats the ten second default", "git:\n  auto_pull_interval: 0s\n", 1},
		{"git_explicit_empty_template", "an explicit empty template beats the default text", "git:\n  commit_template: \"\"\n", 1},
		{"git_partial", "unnamed fields keep their defaults", "git:\n  auto_pull_interval: 45s\n", 1},
		{"git_wrong_type", "a scalar where a boolean is required is rejected", "git:\n  auto_push: maybe\n", 1},
		{"git_scalar_section", "a scalar where a section is required is rejected", "git: nope\n", 1},

		// update.
		{"update_explicit_zero", "an explicit zero TTL beats the default", "update:\n  cache_ttl: 0s\n", 1},
		{"update_explicit", "an explicit TTL", "update:\n  cache_ttl: 90m\n", 1},

		// clipboard: auto_clear_duration carries no omitempty on purpose.
		{"clipboard_zero_auto_clear", "an explicit zero disables the timer", "clipboard:\n  auto_clear_duration: 0\n", 1},
		{"clipboard_auto_clear", "an explicit duration", "clipboard:\n  auto_clear_duration: 5\n", 1},
		{"clipboard_copy_false", "an explicit false beats the true default", "clipboard:\n  copyByDefault: false\n", 1},
		{"clipboard_print_by_default_false", "the deprecated key is honored, and warns", "clipboard:\n  printByDefault: false\n", 1},
		{"clipboard_print_by_default_true", "the deprecated key set true", "clipboard:\n  printByDefault: true\n", 1},
		{"clipboard_copy_wins_over_print", "copyByDefault present suppresses the deprecated key and its warning", "clipboard:\n  copyByDefault: true\n  printByDefault: false\n", 1},
		{"clipboard_print_by_default_twice", "the deprecation warning fires once per process", "clipboard:\n  printByDefault: false\n", 2},

		// mcp.
		{"mcp_explicit_zero_port", "an explicit zero port beats the default", "mcp:\n  port: 0\n", 1},
		{"mcp_stdio", "an explicit boolean", "mcp:\n  stdio: true\n", 1},
		{"mcp_metrics_auth_false", "an explicit false beats the true default", "mcp:\n  metrics_auth_required: false\n", 1},
		{"mcp_rate_limit_zero", "an explicit zero rate limit beats the default", "mcp:\n  rate_limit: 0\n", 1},
		{"mcp_empty_token_file", "an explicit empty token file beats the auto default", "mcp:\n  httpTokenFile: \"\"\n", 1},
		{"mcp_timeouts", "the five explicit timeouts", "mcp:\n  read_header_timeout: 1s\n  read_timeout: 2s\n  write_timeout: 3s\n  shutdown_timeout: 4s\n  approval_timeout: 5s\n", 1},
		{"mcp_tls", "tls and mtls fields", "mcp:\n  tls_cert_file: /fixture/c.pem\n  tls_key_file: /fixture/k.pem\n  tls_client_ca_file: /fixture/ca.pem\n  mtls_enabled: true\n  allow_insecure_bind: true\n", 1},
		{"mcp_empty_bind", "an explicitly empty bind is rejected", "mcp:\n  bind: \"\"\n", 1},
		{"mcp_oauth_absent", "an mcp section without oauth keeps the default TTLs", "mcp:\n  port: 9000\n", 1},
		{"mcp_oauth_empty", "an empty oauth section keeps the default TTLs", "mcp:\n  oauth: {}\n", 1},
		{"mcp_oauth_null", "a null oauth section keeps the default TTLs", "mcp:\n  oauth:\n", 1},
		{"mcp_oauth_explicit", "both TTLs set", "mcp:\n  oauth:\n    access_token_ttl: 1h\n    refresh_token_ttl: 2h\n", 1},
		{"mcp_oauth_partial", "one TTL set keeps the other default", "mcp:\n  oauth:\n    access_token_ttl: 1h\n", 1},
		{"mcp_oauth_zero_ignored", "a zero TTL is ignored: the guard is positive-only", "mcp:\n  oauth:\n    access_token_ttl: 0s\n    refresh_token_ttl: 0s\n", 1},
		{"mcp_oauth_negative_ignored", "a negative TTL is ignored too", "mcp:\n  oauth:\n    access_token_ttl: -1h\n    refresh_token_ttl: -2h\n", 1},
		{"mcp_approval_required_true", "the deprecated key warns", "mcp:\n  approval_required: true\n", 1},
		{"mcp_approval_required_false", "false is the zero value and does not warn", "mcp:\n  approval_required: false\n", 1},

		// vault.
		{"vault_search_index_false", "an explicit false beats the true default", "vault:\n  search_index: false\n", 1},
		{"vault_scrypt_zero", "an explicit zero beats the default of 18", "vault:\n  scrypt_work_factor: 0\n", 1},
		{"vault_heal_false", "an explicit false beats the true default", "vault:\n  auto_heal_zero_key: false\n", 1},
		{"vault_format_zero", "an explicit zero beats the default of 1", "vault:\n  format_version: 0\n", 1},
		{"vault_numbers", "explicit numeric fields", "vault:\n  search_workers: 4\n  config_cache_entries: 16\n  argon2id_time: 2\n  argon2id_memory: 65536\n  argon2id_threads: 4\n", 1},
		{"vault_booleans", "explicit boolean fields", "vault:\n  confirm_remove: true\n  search_index_cache: true\n  pseudonymize_paths: true\n  auto_migrate_kdf: true\n", 1},
		{"vault_path", "an explicit path", "vault:\n  path: /fixture/other\n", 1},
		{"vault_recipients_list", "a populated recipient list", "vault:\n  default_recipients:\n    - age1aaa\n    - age1bbb\n", 1},
		{"vault_recipients_empty", "an explicitly empty recipient list", "vault:\n  default_recipients: []\n", 1},
		{"vault_recipients_null", "a null recipient list keeps the default", "vault:\n  default_recipients:\n", 1},
		{"vault_legacy_true", "legacy_mode true", "vault:\n  legacy_mode: true\n", 1},
		{"vault_legacy_false", "legacy_mode false is retained, not dropped", "vault:\n  legacy_mode: false\n", 1},
		{"vault_legacy_null", "legacy_mode null stays unset", "vault:\n  legacy_mode:\n", 1},
		{"vault_sync_icloud", "an explicit sync method", "vault:\n  sync:\n    method: icloud-drive\n", 1},
		{"vault_sync_empty", "an empty sync block is propagated", "vault:\n  sync: {}\n", 1},
		{"vault_sync_unknown", "an unknown sync method is carried verbatim", "vault:\n  sync:\n    method: carrier-pigeon\n", 1},
		{"vault_listing_cache_ttl", "listing_cache_ttl is read from the document", "vault:\n  listing_cache_ttl: 5m\n", 1},
		{"vault_manifest_generation", "manifest_generation is read from the document", "vault:\n  manifest_generation: 7\n", 1},

		// authMethod crosses the vault section and the top level.
		{"auth_vault_touchid", "vault.authMethod alone selects touchid", "vault:\n  authMethod: touchid\n", 1},
		{"auth_vault_alias", "vault.authMethod accepts an alias", "vault:\n  authMethod: touch-id\n", 1},
		{"auth_vault_use_touch_id", "vault.useTouchID alone selects touchid", "vault:\n  useTouchID: true\n", 1},
		{"auth_top_beats_vault", "top-level authMethod wins over the vault block", "authMethod: passphrase\nvault:\n  authMethod: touchid\n", 1},
		{"auth_top_touchid", "top-level touchid", "authMethod: touchid\n", 1},
		{"auth_top_use_touch_id", "a top-level useTouchID true selects touchid when authMethod is unwritten", "useTouchID: true\n", 1},
		{"auth_top_use_touch_id_false", "a top-level useTouchID false selects nothing", "useTouchID: false\n", 1},
		{"auth_top_passphrase_with_use_touch_id", "an explicit authMethod wins over useTouchID", "authMethod: passphrase\nuseTouchID: true\n", 1},
		{"auth_top_touchid_with_vault_section", "a vault block without its own method does not inherit the top-level one", "authMethod: touchid\nvault: {}\n", 1},
		{"auth_use_touch_id_then_vault_passphrase", "the vault block's method overrides a top-level useTouchID", "useTouchID: true\nvault:\n  authMethod: passphrase\n", 1},
		{"auth_vault_empty_method_feeds_nothing", "an explicitly empty vault.authMethod feeds nothing upward", "useTouchID: true\nvault:\n  authMethod: \"\"\n  useTouchID: true\n", 1},
		{"auth_vault_method_and_flag", "vault.authMethod present suppresses the vault.useTouchID fallback", "vault:\n  authMethod: passphrase\n  useTouchID: true\n", 1},
		{"auth_top_invalid", "an invalid top-level authMethod is accepted and ignored by the Go merge", "authMethod: retina\n", 1},
		{"auth_vault_invalid", "an invalid vault.authMethod is rejected or carried", "vault:\n  authMethod: retina\n", 1},

		// Deprecated top-level key and its precedence over the new name.
		{"env_whitelist_warns", "envWhitelist warns", "envWhitelist:\n  - HOME\n", 1},
		{"env_whitelist_empty_warns", "an empty non-null envWhitelist still warns", "envWhitelist: []\n", 1},
		{"env_whitelist_null_silent", "a null envWhitelist does not warn", "envWhitelist:\n", 1},
		{"env_allowlist_silent", "envAllowlist does not warn", "envAllowlist:\n  - HOME\n", 1},
		{"env_both_warn", "both keys present: the deprecated one warns", "envAllowlist:\n  - HOME\nenvWhitelist:\n  - PATH\n", 1},

		// An explicit null is present: Go decodes it to the zero value and the
		// merge applies it, so it beats the default just as an explicit zero does.
		{"git_null_bool", "a null boolean is present and decodes to false", "git:\n  auto_push:\n", 1},
		{"git_null_interval", "a null duration is present and decodes to zero", "git:\n  auto_pull_interval:\n", 1},
		{"git_null_template", "a null string is present and decodes to empty", "git:\n  commit_template:\n", 1},
		{"update_null_ttl", "a null TTL is present and decodes to zero", "update:\n  cache_ttl:\n", 1},
		{"clipboard_null_auto_clear", "a null integer is present and decodes to zero", "clipboard:\n  auto_clear_duration:\n", 1},
		{"clipboard_null_copy", "a null copyByDefault is present, so the deprecated key is ignored", "clipboard:\n  copyByDefault:\n  printByDefault: true\n", 1},
		{"clipboard_null_print", "a null printByDefault is present: it warns and decodes to false", "clipboard:\n  printByDefault:\n", 1},
		{"mcp_null_port", "a null port is present and decodes to zero", "mcp:\n  port:\n", 1},
		{"mcp_null_bind", "a null bind is present and decodes to empty, which is rejected", "mcp:\n  bind:\n", 1},
		{"mcp_null_approval_required", "a null approval_required does not warn", "mcp:\n  approval_required:\n", 1},
		{"vault_null_search_index", "a null boolean is present and decodes to false", "vault:\n  search_index:\n", 1},
		{"vault_null_path", "a null string is present and decodes to empty", "vault:\n  path:\n", 1},
		{"vault_null_scrypt", "a null integer is present and decodes to zero", "vault:\n  scrypt_work_factor:\n", 1},
		{"env_whitelist_scalar", "a scalar where a list is required is rejected", "envWhitelist: HOME\n", 1},
		{"env_allowlist_scalar", "a scalar where a list is required is rejected", "envAllowlist: HOME\n", 1},

		// Several warnings at once: order is part of the contract.
		{"all_warnings_order", "envWhitelist, then mcp, then clipboard", "clipboard:\n  printByDefault: true\nmcp:\n  approval_required: true\nenvWhitelist:\n  - HOME\n", 1},
		{"warning_then_rejection", "a warning raised before a rejection is still emitted", "envWhitelist:\n  - HOME\nmcp:\n  bind: \"\"\n", 1},
	}
	return cases
}

func snapshotOf(cfg *configpkg.Config) *snapshot {
	out := &snapshot{
		AuthMethod:          cfg.AuthMethod,
		EffectiveAuthMethod: cfg.EffectiveAuthMethod(),
	}
	if v := cfg.Vault; v != nil {
		recipients := v.DefaultRecipients
		if recipients == nil {
			recipients = []string{}
		}
		vs := &vaultSnapshot{
			Path: v.Path, DefaultRecipients: recipients, ConfirmRemove: v.ConfirmRemove,
			AuthMethod: v.AuthMethod, UseTouchID: v.UseTouchID, LegacyMode: v.LegacyMode,
			SearchIndex: v.SearchIndex, SearchWorkers: v.SearchWorkers, SearchIndexCache: v.SearchIndexCache,
			ConfigCacheEntries: v.ConfigCacheEntries, PseudonymizePaths: v.PseudonymizePaths,
			ScryptWorkFactor: v.ScryptWorkFactor, AutoMigrateKDF: v.AutoMigrateKDF,
			AutoHealZeroKey: v.AutoHealZeroKey, FormatVersion: v.FormatVersion,
			Argon2idTime: v.Argon2idTime, Argon2idMemory: v.Argon2idMemory, Argon2idThreads: v.Argon2idThreads,
			ListingCacheTTLNs: int64(v.ListingCacheTTL), ManifestGeneration: v.ManifestGeneration,
		}
		if v.Sync != nil {
			vs.Sync = &syncSnapshot{Method: v.Sync.Method}
		}
		out.Vault = vs
	}
	if g := cfg.Git; g != nil {
		out.Git = &gitSnapshot{
			AutoPush: g.AutoPush, AutoPull: g.AutoPull,
			AutoPullIntervalNs: int64(g.AutoPullInterval), CommitTemplate: g.CommitTemplate,
		}
	}
	if m := cfg.MCP; m != nil {
		ms := &mcpSnapshot{
			Port: m.Port, Bind: m.Bind, Stdio: m.Stdio, HTTPTokenFile: m.HTTPTokenFile,
			ReadHeaderTimeoutNs: int64(m.ReadHeaderTimeout), ReadTimeoutNs: int64(m.ReadTimeout),
			WriteTimeoutNs: int64(m.WriteTimeout), ShutdownTimeoutNs: int64(m.ShutdownTimeout),
			ApprovalTimeoutNs: int64(m.ApprovalTimeout), RateLimit: m.RateLimit,
			MetricsAuthRequired: m.MetricsAuthRequired, TLSCertFile: m.TLSCertFile,
			TLSKeyFile: m.TLSKeyFile, TLSClientCAFile: m.TLSClientCAFile,
			MTLSEnabled: m.MTLSEnabled, AllowInsecureBind: m.AllowInsecureBind,
		}
		if m.OAuth != nil {
			ms.OAuth = &oauthSnapshot{
				AccessTokenTTLNs:  int64(m.OAuth.AccessTokenTTL),
				RefreshTokenTTLNs: int64(m.OAuth.RefreshTokenTTL),
			}
		}
		out.MCP = ms
	}
	if u := cfg.Update; u != nil {
		out.Update = &updateSnapshot{CacheTTLNs: int64(u.CacheTTL)}
	}
	if c := cfg.Clipboard; c != nil {
		out.Clipboard = &clipboardSnapshot{AutoClearDuration: c.AutoClearDuration, CopyByDefault: c.CopyByDefault}
	}
	return out
}

// runChild loads path `count` times in this process and prints the results.
// It runs in a fresh process per case so the once-per-process warning guard
// starts closed for every case.
func runChild(path string, count int) error {
	loads := make([]load, 0, count)
	for range count {
		var captured []string
		configpkg.SetWarnFunc(func(message string) { captured = append(captured, message) })
		cfg, err := configpkg.Load(path)
		configpkg.SetWarnFunc(nil)
		item := load{Warnings: captured}
		if item.Warnings == nil {
			item.Warnings = []string{}
		}
		if err != nil {
			item.Rejected = true
		} else {
			item.Snapshot = snapshotOf(cfg)
		}
		loads = append(loads, item)
	}
	return json.NewEncoder(os.Stdout).Encode(loads)
}

func buildCases(workDir string) ([]sectionCase, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	all := inputs()
	cases := make([]sectionCase, 0, len(all))
	for index, in := range all {
		path := filepath.Join(workDir, fmt.Sprintf("case-%02d.yaml", index))
		if err := os.WriteFile(path, []byte(in.body), 0o600); err != nil {
			return nil, err
		}
		cmd := exec.Command(self, "--child", path, "--child-loads", fmt.Sprint(in.loads)) // #nosec G204 -- re-executes this generator
		cmd.Env = []string{"HOME=" + workDir, "XDG_CONFIG_HOME=" + filepath.Join(workDir, "cfg"), "XDG_DATA_HOME=" + filepath.Join(workDir, "data"), "XDG_CACHE_HOME=" + filepath.Join(workDir, "cache")}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("case %s: %w: %s", in.name, err, stderr.String())
		}
		var loads []load
		if err := json.Unmarshal(stdout.Bytes(), &loads); err != nil {
			return nil, fmt.Errorf("case %s: %w", in.name, err)
		}
		cases = append(cases, sectionCase{Name: in.name, Description: in.description, Input: in.body, Loads: loads})
	}
	return cases, nil
}

func main() {
	output := flag.String("output", "testdata/port/config/sections.json", "CFG-002/003 sections fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	child := flag.String("child", "", "internal: load this file and print the results")
	childLoads := flag.Int("child-loads", 1, "internal: how many times to load it")
	flag.Parse()

	if *child != "" {
		if err := runChild(*child, *childLoads); err != nil {
			fatal("child: %v", err)
		}
		return
	}

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
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/configsectionsgen/main.go"})
	if err != nil {
		fatal("hash generator: %v", err)
	}

	workDir, err := os.MkdirTemp("", "configsectionsgen-")
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
			fatal("fixture is stale; run make cfg-sections-fixtures-generate")
		}
		fmt.Printf("PASS CFG-002/003 sections fixture (%d cases)\n", len(cases))
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
