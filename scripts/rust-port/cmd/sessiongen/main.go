// Command sessiongen freezes the session CLI's error and empty-state
// contracts from the pinned Go executable. Cases deliberately avoid a real
// vault and keyring: authorization tests belong to the platform-native suite.
package main

import (
	"bytes"
	"context"
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
	vaultMarker         = "__VAULT__"
	rootMarker          = "__ROOT__"
)

var productionSources = []string{
	"cmd/auth/auth.go",
	"cmd/auth/lock.go",
	"cmd/auth/unlock.go",
	"internal/cli/cli.go",
	"internal/cli/passphrase_env.go",
	"internal/cli/terminal.go",
	"internal/session/session.go",
	"internal/cli/unlock.go",
	"internal/cli/vault.go",
	"internal/cli/vaultpath.go",
	"internal/config/config.go",
	"internal/config/config_load.go",
	"internal/config/config_merge.go",
	"internal/config/config_validate.go",
	"internal/config/paths.go",
	"internal/config/schema.go",
	"internal/session/biometric.go",
	"internal/session/guisession_darwin.go",
	"internal/session/guisession_nondarwin.go",
	"internal/session/keyring.go",
	"internal/session/memory_init.go",
	"internal/session/memory_keyring.go",
	"internal/session/oskeyring.go",
	"internal/session/oskeyring_unavailable.go",
	"internal/session/secure_bytes.go",
	"internal/session/touchid_darwin.go",
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
	StderrBytes    []int  `json:"stderr_bytes,omitempty"`
	StderrContains string `json:"stderr_contains,omitempty"`
}

type sessionCase struct {
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	ConfigBytes     []int             `json:"config_bytes,omitempty"`
	RootConfigBytes []int             `json:"root_config_bytes,omitempty"`
	Initialized     bool              `json:"initialized,omitempty"`
	VaultDir        string            `json:"vault_dir,omitempty"`
	DisableVaultEnv bool              `json:"disable_vault_env,omitempty"`
	Args            []string          `json:"args"`
	Env             map[string]string `json:"env,omitempty"`
	Expected        expected          `json:"expected"`
}

type fixture struct {
	SchemaVersion int           `json:"schema_version"`
	Oracle        oracle        `json:"oracle"`
	Cases         []sessionCase `json:"cases"`
}

func inputs() []sessionCase {
	initializedConfig := bytesToInts([]byte("vaultDir: /fixture/vault\nauthMethod: passphrase\n"))
	return []sessionCase{
		{Name: "lock_uninitialized", Description: "lock refuses a missing initialized vault", Args: []string{"--vault", vaultMarker, "lock"}},
		{Name: "unlock_check_uninitialized", Description: "unlock check validates initialization before session state", Args: []string{"--vault", vaultMarker, "unlock", "--check"}},
		{Name: "auth_status_uninitialized", Description: "auth status validates initialization before reporting cache state", Args: []string{"--vault", vaultMarker, "auth", "status"}},
		{Name: "unlock_check_missing_session", Description: "unlock check reports a missing cached session", Initialized: true, ConfigBytes: initializedConfig, Args: []string{"--vault", vaultMarker, "unlock", "--check"}},
		{Name: "lock_initialized", Description: "lock clears an initialized vault without a cached session", Initialized: true, ConfigBytes: initializedConfig, Args: []string{"--vault", vaultMarker, "lock"}},
		{Name: "auth_status_invalid_config", Description: "auth status reports malformed vault configuration", Initialized: true, ConfigBytes: bytesToInts([]byte("authMethod: [\n")), Args: []string{"--vault", vaultMarker, "auth", "status"}},
		{Name: "auth_status_initialized", Description: "auth status renders a memory fallback status in CI", Initialized: true, ConfigBytes: initializedConfig, Args: []string{"--vault", vaultMarker, "auth", "status", "--json"}},
		{Name: "auth_status_env_initialized", Description: "auth status resolves an initialized vault from SYMVAULT_VAULT", Initialized: true, ConfigBytes: initializedConfig, Args: []string{"auth", "status", "--json"}},
		{Name: "auth_status_profile_initialized", Description: "auth status resolves an initialized named profile", Initialized: true, ConfigBytes: initializedConfig, RootConfigBytes: bytesToInts([]byte("profiles:\n  fixture:\n    vault: __PROFILE_VAULT__\n")), VaultDir: "profile-vault", DisableVaultEnv: true, Args: []string{"--profile", "fixture", "auth", "status", "--json"}},
		{Name: "auth_status_default_profile_initialized", Description: "auth status resolves an initialized default profile", Initialized: true, ConfigBytes: initializedConfig, RootConfigBytes: bytesToInts([]byte("defaultProfile: fixture\nprofiles:\n  fixture:\n    vault: __PROFILE_VAULT__\n")), VaultDir: "profile-vault", DisableVaultEnv: true, Args: []string{"auth", "status", "--json"}},
		{Name: "auth_status_default_invalid_config", Description: "default path resolution ignores malformed resolver config and loads the data vault", Initialized: true, ConfigBytes: initializedConfig, RootConfigBytes: bytesToInts([]byte("authMethod: [\n")), VaultDir: "home/.local/share/symaira-vault", DisableVaultEnv: true, Args: []string{"auth", "status", "--json"}},
		{Name: "auth_status_json_escape", Description: "auth status uses Go JSON escaping for a vault path containing HTML-sensitive and line-separator characters", Initialized: true, ConfigBytes: initializedConfig, VaultDir: "special-<&>-\u2028", Args: []string{"--vault", vaultMarker, "auth", "status", "--json"}},
		{Name: "unlock_check_ttl_fraction", Description: "unlock parses a leading-dot Go duration before checking the session", Initialized: true, ConfigBytes: initializedConfig, Args: []string{"--vault", vaultMarker, "unlock", "--check", "--ttl", ".5s"}},
		{Name: "unlock_check_ttl_trailing_fraction", Description: "unlock accepts a Go duration with a trailing decimal point", Initialized: true, ConfigBytes: initializedConfig, Args: []string{"--vault", vaultMarker, "unlock", "--check", "--ttl", "1.s"}},
		{Name: "unlock_check_ttl_micro_sign", Description: "unlock accepts both Go microsecond spellings", Initialized: true, ConfigBytes: initializedConfig, Args: []string{"--vault", vaultMarker, "unlock", "--check", "--ttl", "1μs"}},
		{Name: "unlock_check_ttl_zero", Description: "unlock treats a zero override as the configured TTL", Initialized: true, ConfigBytes: initializedConfig, Args: []string{"--vault", vaultMarker, "unlock", "--check", "--ttl", "0s"}},
		{Name: "unlock_check_ttl_negative", Description: "unlock treats a negative override as the configured TTL", Initialized: true, ConfigBytes: initializedConfig, Args: []string{"--vault", vaultMarker, "unlock", "--check", "--ttl=-1m"}},
		{Name: "unlock_check_ttl_invalid", Description: "unlock rejects a duration without a unit before checking the vault", Initialized: true, ConfigBytes: initializedConfig, Args: []string{"--vault", vaultMarker, "unlock", "--check", "--ttl", "15"}},
	}
}

func buildCases(goBinary, root string) ([]sessionCase, error) {
	cases := make([]sessionCase, 0, len(inputs()))
	for _, input := range inputs() {
		tempRoot, err := os.MkdirTemp("", "sessiongen-")
		if err != nil {
			return nil, err
		}
		vaultDir := input.VaultDir
		if vaultDir == "" {
			vaultDir = "missing-vault"
		}
		vault := filepath.Join(tempRoot, filepath.FromSlash(vaultDir))
		profileVault := filepath.Join(tempRoot, "profile-vault")
		if input.Initialized {
			if err := os.MkdirAll(vault, 0o700); err != nil {
				_ = os.RemoveAll(tempRoot)
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(vault, "identity.age"), []byte("fixture identity"), 0o600); err != nil {
				_ = os.RemoveAll(tempRoot)
				return nil, err
			}
			config := make([]byte, len(input.ConfigBytes))
			for i, value := range input.ConfigBytes {
				config[i] = byte(value)
			}
			if err := os.WriteFile(filepath.Join(vault, "config.yaml"), config, 0o600); err != nil {
				_ = os.RemoveAll(tempRoot)
				return nil, err
			}
		}
		if len(input.RootConfigBytes) > 0 {
			rootConfig := make([]byte, len(input.RootConfigBytes))
			for i, value := range input.RootConfigBytes {
				rootConfig[i] = byte(value)
			}
			rootConfig = bytes.ReplaceAll(rootConfig, []byte("__PROFILE_VAULT__"), []byte(profileVault))
			configPath := filepath.Join(tempRoot, "home", ".config", "symaira-vault", "config.yaml")
			if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
				_ = os.RemoveAll(tempRoot)
				return nil, err
			}
			if err := os.WriteFile(configPath, rootConfig, 0o600); err != nil {
				_ = os.RemoveAll(tempRoot)
				return nil, err
			}
		}
		args := make([]string, len(input.Args))
		for i, arg := range input.Args {
			args[i] = strings.ReplaceAll(arg, vaultMarker, vault)
		}
		commandEnv := make([]string, 0, len(os.Environ())+4)
		for _, item := range os.Environ() {
			if strings.HasPrefix(item, "SYMVAULT_VAULT=") || strings.HasPrefix(item, "SYMVAULT_PROFILE=") || strings.HasPrefix(item, "HOME=") || strings.HasPrefix(item, "USERPROFILE=") {
				continue
			}
			commandEnv = append(commandEnv, item)
		}
		commandEnv = append(commandEnv, "CI=1", "HOME="+filepath.Join(tempRoot, "home"), "USERPROFILE="+filepath.Join(tempRoot, "home"))
		if !input.DisableVaultEnv {
			commandEnv = append(commandEnv, "SYMVAULT_VAULT="+vault)
		}
		for key, value := range input.Env {
			value = strings.ReplaceAll(value, vaultMarker, vault)
			value = strings.ReplaceAll(value, "__PROFILE_VAULT__", profileVault)
			commandEnv = append(commandEnv, key+"="+value)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		command := exec.CommandContext(ctx, goBinary, args...) // #nosec G204 -- validated oracle binary and fixed cases
		command.Dir = root
		command.Env = commandEnv
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		runErr := command.Run()
		if ctx.Err() != nil {
			cancel()
			_ = os.RemoveAll(tempRoot)
			return nil, fmt.Errorf("run oracle case %s: %w", input.Name, ctx.Err())
		}
		cancel()
		exitCode := 0
		if runErr != nil {
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) {
				_ = os.RemoveAll(tempRoot)
				return nil, fmt.Errorf("run oracle case %s: %w", input.Name, runErr)
			}
			exitCode = exitErr.ExitCode()
		}
		input.Expected = expected{
			ExitCode:       exitCode,
			StdoutBytes:    bytesToInts(normalizeOutput(stdout.Bytes(), tempRoot)),
			StderrBytes:    bytesToInts(normalizeOutput(stderr.Bytes(), tempRoot)),
			StderrContains: errorNeedle(stderr.Bytes()),
		}
		if input.Name != "lock_initialized" {
			input.Expected.StderrBytes = nil
		}
		cases = append(cases, input)
		_ = os.RemoveAll(tempRoot)
	}
	return cases, nil
}

func normalizeOutput(output []byte, tempRoot string) []byte {
	// Replace only the random root. Keeping the path suffix in the fixture
	// proves JSON escaping for hostile bytes such as <&> and U+2028/U+2029.
	return bytes.ReplaceAll(output, []byte(tempRoot), []byte(rootMarker))
}

func errorNeedle(stderr []byte) string {
	for _, needle := range []string{"vault not initialized", "not initialized", "load config", "no active session"} {
		if bytes.Contains(bytes.ToLower(stderr), []byte(needle)) {
			return needle
		}
	}
	return ""
}

func bytesToInts(value []byte) []int {
	result := make([]int, len(value))
	for i, item := range value {
		result[i] = int(item)
	}
	return result
}

func main() {
	output := flag.String("output", "testdata/port/cli/session.json", "fixture path")
	check := flag.Bool("check", false, "fail if fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit")
	release := flag.String("oracle-release", "", "Go oracle release")
	goBinary := flag.String("go-binary", "", "validated Go symvault binary")
	flag.Parse()
	if *goBinary == "" {
		fatal("--go-binary is required")
	}
	root, err := repositoryRoot()
	if err != nil {
		fatal("locate repository: %v", err)
	}
	commitLabel, releaseLabel := pinnedOracleCommit, pinnedOracleRelease
	if *commit != "" && *commit != commitLabel || *release != "" && *release != releaseLabel {
		fatal("oracle metadata is not pinned")
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
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/sessiongen/main.go"})
	if err != nil {
		fatal("hash generator: %v", err)
	}
	cases, err := buildCases(*goBinary, root)
	if err != nil {
		fatal("build cases: %v", err)
	}
	content, err := json.MarshalIndent(fixture{1, oracle{commitLabel, resolved, releaseLabel, sources, sourceDigest, generatorDigest}, cases}, "", "  ")
	if err != nil {
		fatal("marshal fixture: %v", err)
	}
	content = append(content, '\n')
	if *check {
		existing, err := os.ReadFile(*output)
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; regenerate deliberately")
		}
		fmt.Printf("PASS session CLI fixture (%d cases)\n", len(cases))
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

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
