// Command configgen derives configuration and platform seam fixtures from the
// production Go loaders and helpers. It never hand-writes expected behavior.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/clipboard"
	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/secureui"
)

const (
	pinnedOracleCommit  = "caadd5e"
	pinnedOracleRelease = "v0.22.1"
)

var productionSources = []string{
	"internal/config/config.go",
	"internal/config/config_load.go",
	"internal/config/config_merge.go",
	"internal/config/config_save.go",
	"internal/config/config_validate.go",
	"internal/config/paths.go",
	"internal/config/presets.go",
	"internal/clipboard/clipboard.go",
	"internal/secureui/secureui.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

type fixture struct {
	SchemaVersion int            `json:"schema_version"`
	Oracle        oracle         `json:"oracle"`
	Cases         []configCase   `json:"cases"`
	PlatformCases []platformCase `json:"platform_cases"`
}

type configCase struct {
	Name      string          `json:"name"`
	Input     string          `json:"input"`
	Expected  *configSnapshot `json:"expected,omitempty"`
	SavedYAML string          `json:"saved_yaml,omitempty"`
	Error     string          `json:"error,omitempty"`
}

type configSnapshot struct {
	VaultDir         string                   `json:"vault_dir"`
	DefaultAgent     string                   `json:"default_agent"`
	SessionTimeoutNS int64                    `json:"session_timeout_ns"`
	MaxLifetimeNS    int64                    `json:"session_max_lifetime_ns"`
	AuthMethod       string                   `json:"auth_method"`
	UseTouchID       bool                     `json:"use_touch_id"`
	Agents           map[string]agentSnapshot `json:"agents"`
	MCPPort          int                      `json:"mcp_port,omitempty"`
	MCPBind          string                   `json:"mcp_bind,omitempty"`
}

type agentSnapshot struct {
	ApprovalMode    string   `json:"approval_mode"`
	AllowedPaths    []string `json:"allowed_paths"`
	CanWrite        bool     `json:"can_write"`
	CanRunCommands  bool     `json:"can_run_commands"`
	ExposeValues    bool     `json:"expose_value_tools"`
	AutoUnseal      bool     `json:"auto_unseal"`
	RequireApproval bool     `json:"require_approval"`
	SkillPath       string   `json:"skill_path"`
}

type platformCase struct {
	Name           string `json:"name"`
	Input          string `json:"input"`
	Expected       string `json:"expected"`
	ErrorClass     string `json:"error_class,omitempty"`
	NativeEvidence string `json:"native_evidence"`
}

func buildOracle(root string, commit string, release string) (oracle, error) {
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	sourceDigest, err := digestFiles(root, sources)
	if err != nil {
		return oracle{}, fmt.Errorf("hash config/platform sources: %w", err)
	}
	generatorDigest, err := digestFiles(root, []string{"scripts/rust-port/cmd/configgen/main.go"})
	if err != nil {
		return oracle{}, fmt.Errorf("hash config generator: %w", err)
	}
	return oracle{Commit: commit, Release: release, SourceFiles: sources, SourceDigest: sourceDigest, GeneratorDigest: generatorDigest}, nil
}

func digestFiles(root string, names []string) (string, error) {
	h := sha256.New()
	for _, name := range names {
		content, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return "", err
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(content)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func repositoryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate config generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..")), nil
}

func resolveOracle(check bool, commit, release string) (string, string, error) {
	if commit != "" && commit != pinnedOracleCommit {
		return "", "", fmt.Errorf("oracle commit %q is not pinned to %q", commit, pinnedOracleCommit)
	}
	if release != "" && release != pinnedOracleRelease {
		return "", "", fmt.Errorf("oracle release %q is not pinned to %q", release, pinnedOracleRelease)
	}
	if check {
		return pinnedOracleCommit, pinnedOracleRelease, nil
	}
	if commit == "" || release == "" {
		return "", "", fmt.Errorf("--oracle-commit and --oracle-release are required when generating")
	}
	return commit, release, nil
}

func buildConfigCases(root string) []configCase {
	inputs := []struct{ name, text string }{
		{"defaults", ""},
		{"explicit_presence", "vaultDir: /fixture/vault\ndefaultAgent: custom\nsessionTimeout: 30m\nsessionMaxLifetime: 2h\nauthMethod: touchid\nuseTouchID: false\nagents:\n  custom:\n    canWrite: true\n    canRunCommands: true\n    exposeValueTools: false\n    requireApproval: true\n    approvalMode: prompt\n    allowedPaths: [work/*]\nmcp:\n  port: 9090\n  bind: 0.0.0.0\n"},
		{"field_presence_override", "authMethod: passphrase\nuseTouchID: true\nagents:\n  custom:\n    canWrite: false\n    requireApproval: false\n"},
		{"unknown_fields_ignored", "unknownTopLevel: ignored\nagents:\n  custom:\n    unknownAgentField: ignored\n    canWrite: true\n"},
		{"invalid_empty_bind", "mcp:\n  bind: \"\"\n"},
		{"invalid_duration", "sessionTimeout: not-a-duration\n"},
	}

	result := make([]configCase, 0, len(inputs))
	for _, input := range inputs {
		path := filepath.Join(root, input.name, "config.yaml")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			panic(err)
		}
		if err := os.WriteFile(path, []byte(input.text), 0o600); err != nil {
			panic(err)
		}
		cfg, err := configpkg.Load(path)
		item := configCase{Name: input.name, Input: input.text}
		if err != nil {
			item.Error = err.Error()
			result = append(result, item)
			continue
		}
		snapshot := snapshotConfig(cfg, root)
		item.Expected = &snapshot
		savedPath := filepath.Join(root, input.name, "saved.yaml")
		if err := cfg.SaveTo(savedPath); err != nil {
			panic(fmt.Errorf("save %s: %w", input.name, err))
		}
		saved, err := os.ReadFile(savedPath)
		if err != nil {
			panic(err)
		}
		item.SavedYAML = normalize(string(saved), root)
		result = append(result, item)
	}
	return result
}

func snapshotConfig(cfg *configpkg.Config, root string) configSnapshot {
	agents := make(map[string]agentSnapshot, len(cfg.Agents))
	names := make([]string, 0, len(cfg.Agents))
	for name := range cfg.Agents {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := cfg.Agents[name]
		agents[name] = agentSnapshot{
			ApprovalMode:    valueString(p.ApprovalMode),
			AllowedPaths:    append([]string(nil), p.AllowedPaths...),
			CanWrite:        valueBool(p.CanWrite),
			CanRunCommands:  valueBool(p.CanRunCommands),
			ExposeValues:    valueBool(p.ExposeValueTools),
			AutoUnseal:      valueBool(p.AutoUnseal),
			RequireApproval: valueBool(p.RequireApproval),
			SkillPath:       valueString(p.SkillPath),
		}
	}
	result := configSnapshot{
		VaultDir:         normalize(cfg.VaultDir, root),
		DefaultAgent:     cfg.DefaultAgent,
		SessionTimeoutNS: int64(cfg.SessionTimeout),
		MaxLifetimeNS:    int64(cfg.SessionMaxLifetime),
		AuthMethod:       cfg.EffectiveAuthMethod(),
		UseTouchID:       cfg.UseTouchID != nil && *cfg.UseTouchID,
		Agents:           agents,
	}
	if cfg.MCP != nil {
		result.MCPPort = cfg.MCP.Port
		result.MCPBind = cfg.MCP.Bind
	}
	return result
}

func valueString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
func valueBool(v *bool) bool { return v != nil && *v }
func normalize(value, root string) string {
	return strings.ReplaceAll(value, root, "/fixture/root")
}

func buildPlatformCases() []platformCase {
	cases := []platformCase{
		{Name: "format_description_path_field", Input: "description+path+field", Expected: secureui.FormatPrompt(secureui.PromptRequest{Description: "A description", Path: "entry", Field: "password"}), NativeEvidence: "injected-only; native secure UI unavailable to this fixture"},
		{Name: "format_description_only", Input: "description", Expected: secureui.FormatPrompt(secureui.PromptRequest{Description: "A description"}), NativeEvidence: "injected-only; native secure UI unavailable to this fixture"},
	}
	for _, expected := range []bool{false, true} {
		read := func() (string, error) {
			if expected {
				return "secret", nil
			}
			return "different", nil
		}
		err := clipboard.VerifyCleared("secret", read)
		item := platformCase{Name: "clipboard_verify_unchanged", Input: fmt.Sprintf("expected_absent=secret/current_matches=%t", expected), NativeEvidence: "injected-only; clipboard OS backend not exercised"}
		if err != nil {
			item.ErrorClass = "not_cleared"
			item.Expected = "error"
		} else {
			item.Expected = "ok"
		}
		cases = append(cases, item)
	}
	return cases
}

func marshalFixture(value fixture) []byte {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(content, '\n')
}

func main() {
	configOutput := flag.String("config-output", "testdata/port/config/contract.json", "configuration fixture output")
	platformOutput := flag.String("platform-output", "testdata/port/platform/contract.json", "platform fixture output")
	check := flag.Bool("check", false, "check instead of writing")
	commit := flag.String("oracle-commit", "", "pinned Go oracle commit")
	release := flag.String("oracle-release", "", "pinned Go oracle release")
	flag.Parse()
	oracleCommit, oracleRelease, err := resolveOracle(*check, *commit, *release)
	if err != nil {
		fatal("resolve oracle: %v", err)
	}
	root, err := repositoryRoot()
	if err != nil {
		fatal("locate root: %v", err)
	}
	meta, err := buildOracle(root, oracleCommit, oracleRelease)
	if err != nil {
		fatal("build provenance: %v", err)
	}
	tmp, err := os.MkdirTemp("", "symvault-config-fixture-")
	if err != nil {
		fatal("temporary root: %v", err)
	}
	defer os.RemoveAll(tmp)
	oldHome, oldConfig, oldData, oldCache := os.Getenv("HOME"), os.Getenv("XDG_CONFIG_HOME"), os.Getenv("XDG_DATA_HOME"), os.Getenv("XDG_CACHE_HOME")
	defer func() {
		_ = os.Setenv("HOME", oldHome)
		_ = os.Setenv("XDG_CONFIG_HOME", oldConfig)
		_ = os.Setenv("XDG_DATA_HOME", oldData)
		_ = os.Setenv("XDG_CACHE_HOME", oldCache)
	}()
	_ = os.Setenv("HOME", filepath.Join(tmp, "home"))
	_ = os.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))
	_ = os.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	_ = os.Setenv("XDG_CACHE_HOME", filepath.Join(tmp, "cache"))
	value := fixture{SchemaVersion: 1, Oracle: meta, Cases: buildConfigCases(tmp)}
	platform := fixture{SchemaVersion: 1, Oracle: meta, PlatformCases: buildPlatformCases()}
	configContent := marshalFixture(value)
	platformContent := marshalFixture(platform)
	if err := writeOrCheck(*configOutput, configContent, *check); err != nil {
		fatal("configuration fixture: %v", err)
	}
	if err := writeOrCheck(*platformOutput, platformContent, *check); err != nil {
		fatal("platform fixture: %v", err)
	}
	if *check {
		fmt.Printf("PASS config/platform fixtures (%d config, %d platform cases)\n", len(value.Cases), len(platform.PlatformCases))
	} else {
		fmt.Printf("WROTE %s and %s\n", *configOutput, *platformOutput)
	}
}

func writeOrCheck(path string, expected []byte, check bool) error {
	if check {
		existing, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if !bytes.Equal(existing, expected) {
			return fmt.Errorf("%s is stale; run make config-session-fixtures-generate", path)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, expected, 0o600)
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
