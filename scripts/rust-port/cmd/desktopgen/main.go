// Command desktopgen freezes the Linux half of PLATFORM-001 (#1244).
//
// It drives the production Go code with fake desktop tools on a disposable
// PATH and records what the code actually executed:
//
//   - internal/clipboard.NewSystemClipboard on Linux is the atotto/clipboard
//     backend. Its tool selection (wl-copy/wl-paste, xclip, xsel, Termux,
//     clip.exe+powershell.exe) happens in that package's init(), from PATH and
//     WAYLAND_DISPLAY, so each scenario runs in a re-executed child process.
//   - internal/autotype.NewLinuxAutotype routes text through xdotool, wtype or
//     ydotool on stdin and runs the focus guard first.
//
// The Windows autotype constants (PowerShell wrapper and foreground probe) are
// not executed here; they are extracted from the pinned source with go/parser
// and labeled as such in the fixture.
//
// No real clipboard, display, keychain or credential is touched. The tools are
// POSIX shell scripts that only write into a scratch directory. The generator
// refuses to run anywhere but Linux because the production code under test is
// GOOS=linux; `make desktop-linux-fixtures-check` runs it in a Linux container
// on other hosts.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	defaultOutput = "testdata/port/platform/desktop_linux.json"
	generatorPath = "scripts/rust-port/cmd/desktopgen"
)

// pinnedOracleCommit is the commit whose blobs must equal the working-tree
// production sources below. It is the base the slice started from.
const pinnedOracleCommit = "861ad93813e3ee43c4ec989f45940d14b05b6eaf"

// productionSources are the behavior-bearing Go files under test.
var productionSources = []string{
	"internal/autotype/autotype_common.go",
	"internal/autotype/autotype_linux.go",
	"internal/autotype/autotype_windows.go",
	"internal/autotype/focus.go",
	"internal/autotype/focus_linux.go",
	"internal/autotype/focus_windows.go",
	"internal/autotype/interface.go",
	"internal/autotype/provider.go",
	"internal/clipboard/clipboard.go",
	"internal/clipboard/interface.go",
	"internal/clipboard/provider.go",
	"internal/clipboard/system_clipboard.go",
	"internal/secrets/filter.go",
}

// generatorSources are hashed into generator_digest.
var generatorSources = []string{
	generatorPath + "/main.go",
	generatorPath + "/scenarios.go",
	generatorPath + "/scripts.go",
	generatorPath + "/clipboard.go",
	generatorPath + "/autotype_linux.go",
	generatorPath + "/autotype_other.go",
	generatorPath + "/windows.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
	Dependency      string   `json:"dependency"`
}

type fixture struct {
	SchemaVersion int    `json:"schema_version"`
	Oracle        oracle `json:"oracle"`
	Note          string `json:"note"`
	// ScriptPlaceholders documents the substitutions Rust must apply to the
	// templates in FakeTools to reproduce the Go scenarios with real processes.
	ScriptPlaceholders []string          `json:"script_placeholders"`
	FakeTools          map[string]string `json:"fake_tools"`
	// AutotypeEnvWhitelist is Go's secrets.DefaultWhitelist(): the only
	// environment names a Linux/Windows autotype tool receives.
	AutotypeEnvWhitelist []string         `json:"autotype_env_whitelist"`
	Clipboard            []clipboardCase  `json:"clipboard_cases"`
	Autotype             []autotypeCase   `json:"autotype_cases"`
	WindowsExtracts      []windowsExtract `json:"windows_extracted_not_executed"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == childFlag {
		os.Exit(runChild(os.Args[2:]))
	}
	output := flag.String("output", defaultOutput, "fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", pinnedOracleCommit, "Go oracle commit")
	provenanceOnly := flag.Bool("provenance-only", false, "verify the working-tree sources against the oracle commit on any host, then exit")
	hostVerified := flag.Bool("provenance-host-verified", false, "skip the git blob comparison because the caller already ran -provenance-only on the host (containers whose git cannot read this worktree)")
	flag.Parse()
	if *provenanceOnly {
		if err := verifyProvenance(*commit); err != nil {
			fmt.Fprintln(os.Stderr, "desktopgen:", err)
			os.Exit(1)
		}
		fmt.Println("PASS oracle provenance: working-tree sources equal", *commit)
		return
	}
	if err := run(*output, *check, *commit, *hostVerified); err != nil {
		fmt.Fprintln(os.Stderr, "desktopgen:", err)
		os.Exit(1)
	}
}

func verifyProvenance(commit string) error {
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	_, err = provenance.Verify(root, commit, sources)
	return err
}

func run(output string, check bool, commit string, hostVerified bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("must run on Linux (GOOS=%s): the production backends are Linux-only; use `make desktop-linux-fixtures-check`", runtime.GOOS)
	}
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	sourceDigest, err := provenance.Digest(root, sources)
	if err != nil {
		return fmt.Errorf("hash production sources: %w", err)
	}
	resolved := commit
	if !hostVerified {
		resolved, err = provenance.Verify(root, commit, sources)
		if err != nil {
			return err
		}
	} else if len(commit) != 40 {
		return errors.New("-provenance-host-verified requires a full 40-character oracle commit")
	}
	generators := append([]string(nil), generatorSources...)
	sort.Strings(generators)
	generatorDigest, err := provenance.Digest(root, generators)
	if err != nil {
		return fmt.Errorf("hash generator: %w", err)
	}
	dep, err := dependencyRecord(root)
	if err != nil {
		return err
	}
	f, err := buildFixture()
	if err != nil {
		return err
	}
	win, err := extractWindowsConstants(root)
	if err != nil {
		return err
	}
	f.WindowsExtracts = win
	f.Oracle = oracle{
		Commit: commit, CommitSHA: resolved, Release: "unreleased",
		SourceFiles: sources, SourceDigest: sourceDigest,
		GeneratorDigest: generatorDigest, Dependency: dep,
	}
	content, err := marshalJSON(f)
	if err != nil {
		return err
	}
	path := output
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	if check {
		existing, err := os.ReadFile(path) // #nosec G304 -- fixed fixture path under the repository root
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, content) {
			return fmt.Errorf("%s is stale; regenerate with `make desktop-linux-fixtures-generate`", output)
		}
		fmt.Printf("PASS PLATFORM-001 Linux desktop fixture (%d clipboard, %d autotype cases)\n", len(f.Clipboard), len(f.Autotype))
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o600)
}

// dependencyRecord pins the third-party clipboard backend whose init() the
// clipboard scenarios exercise, by version and go.sum hashes.
func dependencyRecord(root string) (string, error) {
	sum, err := os.ReadFile(filepath.Join(root, "go.sum")) // #nosec G304 -- fixed repository file
	if err != nil {
		return "", err
	}
	var lines []string
	for _, line := range strings.Split(string(sum), "\n") {
		if strings.HasPrefix(line, "github.com/atotto/clipboard v") {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return "", errors.New("go.sum has no github.com/atotto/clipboard entry")
	}
	return strings.Join(lines, "; "), nil
}

func marshalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func repositoryRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("repository root (go.mod) not found")
		}
		dir = parent
	}
}
