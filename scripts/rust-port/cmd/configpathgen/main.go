// Command configpathgen freezes the pure CFG-001 path-resolution contract.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
)

const (
	pinnedOracleCommit  = "fc9eddc0"
	pinnedOracleRelease = "unreleased"

	// fixtureHome is a synthetic home directory. It is never touched on disk and
	// deliberately does not resemble any real user's home.
	fixtureHome = "/fixture/home/probe"
)

var productionSources = []string{
	"internal/config/config.go",
	"internal/config/paths.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

// environment mirrors config.PathEnvironment. Values are slash-separated
// logical paths; see the note on expected.
type environment struct {
	Home             string `json:"home,omitempty"`
	XDGConfigHome    string `json:"xdg_config_home,omitempty"`
	XDGDataHome      string `json:"xdg_data_home,omitempty"`
	XDGCacheHome     string `json:"xdg_cache_home,omitempty"`
	VaultOverride    string `json:"vault_override,omitempty"`
	LegacyDirExists  bool   `json:"legacy_dir_exists,omitempty"`
	XDGDataDirExists bool   `json:"xdg_data_dir_exists,omitempty"`
}

// expected holds slash-separated logical paths. The contract pins the
// resolution logic, not the host separator: a generator run on Windows would
// otherwise emit backslashes and the fixture would stop being comparable
// across platforms. Both implementations normalise to slashes before
// comparing.
type expected struct {
	ConfigDir  string `json:"config_dir"`
	DataDir    string `json:"data_dir"`
	CacheDir   string `json:"cache_dir"`
	LegacyDir  string `json:"legacy_dir"`
	Migrated   bool   `json:"migrated"`
	ConfigPath string `json:"config_path"`
	AuditDir   string `json:"audit_dir"`
	CachePath  string `json:"cache_path"`
}

type pathCase struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Environment environment `json:"environment"`
	Expected    expected    `json:"expected"`
}

type fixture struct {
	SchemaVersion int        `json:"schema_version"`
	Oracle        oracle     `json:"oracle"`
	Cases         []pathCase `json:"cases"`
}

func caseInputs() []struct {
	name, description string
	env               environment
} {
	return []struct {
		name, description string
		env               environment
	}{
		{"new_install_xdg_only", "no legacy directory: XDG exclusively", environment{Home: fixtureHome}},
		{"legacy_install_reads_legacy", "legacy present, XDG data absent: read from legacy", environment{Home: fixtureHome, LegacyDirExists: true}},
		{"post_migration_prefers_xdg", "both present: prefer XDG and report migrated", environment{Home: fixtureHome, LegacyDirExists: true, XDGDataDirExists: true}},
		{"xdg_data_without_legacy", "XDG data present, no legacy: not a migration", environment{Home: fixtureHome, XDGDataDirExists: true}},
		{"explicit_xdg_values", "explicit XDG values win over the defaults", environment{Home: fixtureHome, XDGConfigHome: "/x/cfg", XDGDataHome: "/x/data", XDGCacheHome: "/x/cache"}},
		{"empty_xdg_values_fall_back", "set-but-empty XDG values fall back exactly like unset ones", environment{Home: fixtureHome, XDGConfigHome: "", XDGDataHome: "", XDGCacheHome: ""}},
		{"explicit_xdg_with_legacy_install", "a legacy install still reports the XDG cache directory", environment{Home: fixtureHome, XDGConfigHome: "/x/cfg", XDGCacheHome: "/x/cache", LegacyDirExists: true}},
		{"vault_override_replaces_data_dir", "SYMVAULT_VAULT replaces only the data directory", environment{Home: fixtureHome, VaultOverride: "/elsewhere/vault"}},
		{"vault_override_is_trimmed", "surrounding whitespace is trimmed", environment{Home: fixtureHome, VaultOverride: "  /elsewhere/vault  "}},
		{"vault_override_tilde_expands", "a leading ~/ expands against home", environment{Home: fixtureHome, VaultOverride: "~/vaults/work"}},
		{"vault_override_bare_tilde", "a bare ~ resolves to home", environment{Home: fixtureHome, VaultOverride: "~"}},
		{"vault_override_blank_is_ignored", "a whitespace-only override is ignored", environment{Home: fixtureHome, VaultOverride: "   "}},
		{"vault_override_overrides_legacy_data_dir", "the override also replaces a legacy data directory", environment{Home: fixtureHome, LegacyDirExists: true, VaultOverride: "/elsewhere/vault"}},
		{"no_home_yields_zero_resolver", "an undeterminable home yields a zero resolver", environment{XDGConfigHome: "/x/cfg"}},
	}
}

func buildCases() []pathCase {
	inputs := caseInputs()
	cases := make([]pathCase, 0, len(inputs))
	for _, input := range inputs {
		resolver := configpkg.ResolvePaths(configpkg.PathEnvironment{
			Home:             filepath.FromSlash(input.env.Home),
			XDGConfigHome:    filepath.FromSlash(input.env.XDGConfigHome),
			XDGDataHome:      filepath.FromSlash(input.env.XDGDataHome),
			XDGCacheHome:     filepath.FromSlash(input.env.XDGCacheHome),
			VaultOverride:    input.env.VaultOverride,
			LegacyDirExists:  input.env.LegacyDirExists,
			XDGDataDirExists: input.env.XDGDataDirExists,
		})
		cases = append(cases, pathCase{
			Name:        input.name,
			Description: input.description,
			Environment: input.env,
			Expected: expected{
				ConfigDir:  filepath.ToSlash(resolver.ConfigDir),
				DataDir:    filepath.ToSlash(resolver.DataDir),
				CacheDir:   filepath.ToSlash(resolver.CacheDir),
				LegacyDir:  filepath.ToSlash(resolver.LegacyDir),
				Migrated:   resolver.Migrated,
				ConfigPath: filepath.ToSlash(resolver.ConfigPath()),
				AuditDir:   filepath.ToSlash(resolver.AuditDir()),
				CachePath:  filepath.ToSlash(resolver.CachePath()),
			},
		})
	}
	return cases
}

func main() {
	output := flag.String("output", "testdata/port/config/paths.json", "CFG-001 fixture path")
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
	meta, err := buildOracle(root, commitLabel, releaseLabel)
	if err != nil {
		fatal("build oracle: %v", err)
	}
	content, err := marshalJSON(fixture{SchemaVersion: 1, Oracle: meta, Cases: buildCases()})
	if err != nil {
		fatal("marshal fixture: %v", err)
	}
	if *check {
		existing, readErr := os.ReadFile(*output) // #nosec G304 -- explicit operator-selected fixture
		if readErr != nil {
			fatal("read fixture: %v", readErr)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; run make cfg-fixtures-generate")
		}
		fmt.Printf("PASS CFG-001 path fixture (%d cases)\n", len(buildCases()))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d cases)\n", *output, len(buildCases()))
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

// buildOracle verifies that the working tree's production sources are
// byte-identical to the claimed oracle commit's immutable blobs. The generator
// can only execute the code compiled into it, so claiming a commit is only
// honest when that code is exactly that commit's code.
func buildOracle(root, commit, release string) (oracle, error) {
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	sourceDigest, err := digestFiles(root, sources)
	if err != nil {
		return oracle{}, fmt.Errorf("hash production sources: %w", err)
	}
	resolved, pinnedDigest, err := pinnedSourceDigest(root, commit, sources)
	if err != nil {
		return oracle{}, err
	}
	if pinnedDigest != sourceDigest {
		return oracle{}, fmt.Errorf(
			"oracle provenance mismatch: working tree digest %s does not match commit %s (%s) digest %s; "+
				"the generator would execute code that is not the claimed oracle",
			sourceDigest, commit, resolved, pinnedDigest)
	}
	generatorDigest, err := digestFiles(root, []string{"scripts/rust-port/cmd/configpathgen/main.go"})
	if err != nil {
		return oracle{}, fmt.Errorf("hash generator: %w", err)
	}
	return oracle{
		Commit:          commit,
		CommitSHA:       resolved,
		Release:         release,
		SourceFiles:     sources,
		SourceDigest:    sourceDigest,
		GeneratorDigest: generatorDigest,
	}, nil
}

func pinnedSourceDigest(root, commit string, sources []string) (string, string, error) {
	if commit == "" {
		return "", "", fmt.Errorf("oracle commit is required for provenance verification")
	}
	resolvedRaw, err := gitOutput(root, "rev-parse", "--verify", "--end-of-options", commit+"^{commit}")
	if err != nil {
		return "", "", fmt.Errorf("resolve oracle commit %q: %w", commit, err)
	}
	resolved := strings.TrimSpace(string(resolvedRaw))
	hash := sha256.New()
	for _, name := range sources {
		content, err := gitOutput(root, "cat-file", "blob", resolved+":"+name)
		if err != nil {
			return "", "", fmt.Errorf("read %s at %s: %w", name, resolved, err)
		}
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(content)
		_, _ = hash.Write([]byte{0})
	}
	return resolved, hex.EncodeToString(hash.Sum(nil)), nil
}

func gitOutput(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...) // #nosec G204 -- fixed subcommands over a validated repository root
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %v: %w: %s", args, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func digestFiles(root string, files []string) (string, error) {
	hash := sha256.New()
	for _, name := range files {
		path := name
		if root != "" && !filepath.IsAbs(name) {
			path = filepath.Join(root, name)
		}
		content, err := os.ReadFile(path) // #nosec G304 -- fixed production/generator inputs
		if err != nil {
			return "", err
		}
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(content)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
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
