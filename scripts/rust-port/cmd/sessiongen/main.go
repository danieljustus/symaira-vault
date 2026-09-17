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
	pinnedOracleCommit  = "4373522deb8891d850b6028ac7ef5c9b401f3156"
	pinnedOracleRelease = "unreleased"
	vaultMarker         = "__VAULT__"
)

var productionSources = []string{
	"cmd/auth/auth.go",
	"cmd/auth/lock.go",
	"cmd/auth/unlock.go",
	"internal/cli/cli.go",
	"internal/session/session.go",
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

type sessionCase struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Args        []string `json:"args"`
	Expected    expected `json:"expected"`
}

type fixture struct {
	SchemaVersion int           `json:"schema_version"`
	Oracle        oracle        `json:"oracle"`
	Cases         []sessionCase `json:"cases"`
}

func inputs() []sessionCase {
	return []sessionCase{
		{Name: "lock_uninitialized", Description: "lock refuses a missing initialized vault", Args: []string{"--vault", vaultMarker, "lock"}},
		{Name: "unlock_check_uninitialized", Description: "unlock check validates initialization before session state", Args: []string{"--vault", vaultMarker, "unlock", "--check"}},
		{Name: "auth_status_uninitialized", Description: "auth status validates initialization before reporting cache state", Args: []string{"--vault", vaultMarker, "auth", "status"}},
	}
}

func buildCases(goBinary, root string) ([]sessionCase, error) {
	cases := make([]sessionCase, 0, len(inputs()))
	for _, input := range inputs() {
		tempRoot, err := os.MkdirTemp("", "sessiongen-")
		if err != nil {
			return nil, err
		}
		vault := filepath.Join(tempRoot, "missing-vault")
		args := make([]string, len(input.Args))
		for i, arg := range input.Args {
			args[i] = strings.ReplaceAll(arg, vaultMarker, vault)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		command := exec.CommandContext(ctx, goBinary, args...) // #nosec G204 -- validated oracle binary and fixed cases
		command.Dir = root
		command.Env = append(os.Environ(), "SYMVAULT_VAULT="+vault)
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
		input.Expected = expected{ExitCode: exitCode, StdoutBytes: bytesToInts(stdout.Bytes()), StderrContains: errorNeedle(stderr.Bytes())}
		cases = append(cases, input)
		_ = os.RemoveAll(tempRoot)
	}
	return cases, nil
}

func errorNeedle(stderr []byte) string {
	for _, needle := range []string{"vault not initialized", "not initialized"} {
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
