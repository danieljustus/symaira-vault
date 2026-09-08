// Command storereopen runs the executable Go↔Rust storage reopen contract.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"filippo.io/age"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	oracleCommit  = "caadd5e"
	oracleRelease = "v0.22.1"
	identityText  = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL"
)

type fixture struct {
	SchemaVersion int     `json:"schema_version"`
	Oracle        oracle  `json:"oracle"`
	Cases         []caseV `json:"cases"`
}

type oracle struct {
	Commit  string `json:"commit"`
	Release string `json:"release"`
}

type caseV struct {
	Name          string          `json:"name"`
	Path          string          `json:"path"`
	Entry         json.RawMessage `json:"entry,omitempty"`
	StoragePath   string          `json:"storage_path"`
	ReadDirection string          `json:"read_direction"`
}

type projection struct {
	Path           string         `json:"path"`
	Data           map[string]any `json:"data"`
	Classification int            `json:"classification"`
	Canary         bool           `json:"canary"`
}

func defaultFixture() fixture {
	return fixture{
		SchemaVersion: 1,
		Oracle:        oracle{Commit: oracleCommit, Release: oracleRelease},
		Cases: []caseV{
			{
				Name:          "go_to_rust_read",
				Path:          "go-created",
				StoragePath:   "entries/go-created.age",
				ReadDirection: "go_write_rust_read",
			},
			{
				Name:          "rust_to_go_read",
				Path:          "rust-created",
				Entry:         json.RawMessage(`{"path":"rust-created","data":{"token":"rust-fixture-token","enabled":true},"meta":{},"secret_meta":{}}`),
				StoragePath:   "entries/rust-created.age",
				ReadDirection: "rust_write_go_read",
			},
		},
	}
}

func validateFixture(value fixture) error {
	if value.SchemaVersion != 1 || value.Oracle.Commit != oracleCommit || value.Oracle.Release != oracleRelease {
		return errors.New("reopen fixture provenance changed")
	}
	if len(value.Cases) != 2 {
		return fmt.Errorf("reopen case cardinality %d, want 2", len(value.Cases))
	}
	wantNames := []string{"go_to_rust_read", "rust_to_go_read"}
	wantPaths := []string{"go-created", "rust-created"}
	wantStorage := []string{"entries/go-created.age", "entries/rust-created.age"}
	for i, item := range value.Cases {
		if item.Name != wantNames[i] || item.Path != wantPaths[i] || item.StoragePath != wantStorage[i] || item.ReadDirection == "" {
			return fmt.Errorf("reopen case %d changed", i)
		}
	}
	if len(value.Cases[1].Entry) == 0 {
		return errors.New("rust write case has no entry input")
	}
	var entry vaultpkg.Entry
	if err := json.Unmarshal(value.Cases[1].Entry, &entry); err != nil {
		return fmt.Errorf("rust write entry: %w", err)
	}
	if entry.Path != value.Cases[1].Path || len(entry.Data) != 2 {
		return errors.New("rust write entry shape changed")
	}
	return nil
}

func confinedFixturePath(path string) (string, error) {
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) {
		return "", errors.New("fixture path must be relative")
	}
	root, err := filepath.Abs("testdata/port/store")
	if err != nil {
		return "", err
	}
	absolute, err := filepath.Abs(clean)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, absolute)
	if err != nil {
		return "", err
	}
	if relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("fixture path escapes testdata/port/store")
	}
	return absolute, nil
}

func writeFixture(path string) error {
	safePath, err := confinedFixturePath(path)
	if err != nil {
		return err
	}
	value := defaultFixture()
	if validateErr := validateFixture(value); validateErr != nil {
		return validateErr
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(safePath), 0o750); err != nil {
		return err
	}
	return os.WriteFile(safePath, data, 0o600)
}

func readFixture(path string) (fixture, error) {
	safePath, err := confinedFixturePath(path)
	if err != nil {
		return fixture{}, err
	}
	// #nosec G304 -- confinedFixturePath restricts reads to the contract fixture tree.
	data, err := os.ReadFile(safePath)
	if err != nil {
		return fixture{}, err
	}
	var value fixture
	if err := json.Unmarshal(data, &value); err != nil {
		return fixture{}, err
	}
	if err := validateFixture(value); err != nil {
		return fixture{}, err
	}
	return value, nil
}

func fixedIdentity() (*age.X25519Identity, error) {
	return age.ParseX25519Identity(identityText)
}

func runRust(binary, root string, args ...string) ([]byte, error) {
	cmd := exec.Command(binary, args...)
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("rust %v: %w: %s", args, err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("rust %v: %w", args, err)
	}
	if stderr.Len() != 0 {
		return nil, fmt.Errorf("rust %v wrote unexpected stderr", args)
	}
	return output, nil
}

func project(entry *vaultpkg.Entry) projection {
	return projection{Path: entry.Path, Data: entry.Data, Classification: int(entry.Classification), Canary: entry.Canary}
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func runDifferential(binary string, value fixture) error {
	absoluteBinary, err := filepath.Abs(binary)
	if err != nil {
		return err
	}
	binary = absoluteBinary
	identity, err := fixedIdentity()
	if err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "symvault-store-reopen-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(root) }()
	legacy := false
	cfg := vaultconfig.Default()
	cfg.VaultDir = root
	cfg.Vault = &vaultconfig.VaultConfig{FormatVersion: 2, LegacyMode: &legacy, SearchIndex: false}
	if initErr := vaultpkg.Init(root, identity, cfg); initErr != nil {
		return fmt.Errorf("go init: %w", initErr)
	}
	if writeErr := os.WriteFile(filepath.Join(root, "recipients.txt"), []byte(identity.Recipient().String()+"\n"), 0o600); writeErr != nil {
		return writeErr
	}
	goEntry := &vaultpkg.Entry{Path: value.Cases[0].Path, Data: map[string]any{
		"username": "go-fixture-user",
		"token":    "go-fixture-token",
	}}
	if writeErr := vaultpkg.WriteEntry(root, goEntry.Path, goEntry, identity); writeErr != nil {
		return fmt.Errorf("go write: %w", writeErr)
	}
	goWritten, err := vaultpkg.ReadEntry(root, goEntry.Path, identity)
	if err != nil {
		return fmt.Errorf("go reopen: %w", err)
	}
	readOutput, err := runRust(binary, root, "--action", "read", "--root", root, "--path", value.Cases[0].Path)
	if err != nil {
		return err
	}
	var rustRead vaultpkg.Entry
	if decodeErr := json.Unmarshal(readOutput, &rustRead); decodeErr != nil {
		return fmt.Errorf("decode rust read: %w", decodeErr)
	}
	if !reflect.DeepEqual(project(&rustRead), project(goWritten)) {
		return fmt.Errorf("Go→Rust reopen projection mismatch: path=%q/%q keys=%v/%v classification=%d/%d canary=%t/%t", rustRead.Path, goWritten.Path, sortedKeys(rustRead.Data), sortedKeys(goWritten.Data), rustRead.Classification, goWritten.Classification, rustRead.Canary, goWritten.Canary)
	}

	entryFile := filepath.Join(root, "rust-entry.json")
	if writeErr := os.WriteFile(entryFile, value.Cases[1].Entry, 0o600); writeErr != nil {
		return writeErr
	}
	if _, runErr := runRust(binary, root, "--action", "write", "--root", root, "--path", value.Cases[1].Path, "--entry-file", entryFile); runErr != nil {
		return runErr
	}
	goRead, err := vaultpkg.ReadEntry(root, value.Cases[1].Path, identity)
	if err != nil {
		return fmt.Errorf("go read: %w", err)
	}
	var expected vaultpkg.Entry
	if err := json.Unmarshal(value.Cases[1].Entry, &expected); err != nil {
		return err
	}
	if !reflect.DeepEqual(project(goRead), project(&expected)) {
		return fmt.Errorf("Rust→Go reopen projection mismatch")
	}
	if _, err := os.Stat(filepath.Join(root, value.Cases[1].StoragePath)); err != nil {
		return fmt.Errorf("rust storage path: %w", err)
	}
	return nil
}

func main() {
	fixturePath := flag.String("fixture", "testdata/port/store/reopen.json", "reopen fixture path")
	generate := flag.Bool("generate", false, "write the deterministic contract fixture")
	run := flag.Bool("run", false, "run the Go↔Rust differential")
	rustBinary := flag.String("rust-binary", "", "path to the Rust store-reopen example")
	flag.Parse()
	if *generate {
		if err := writeFixture(*fixturePath); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL generate reopen fixture:", err)
			os.Exit(1)
		}
		fmt.Println("WROTE", *fixturePath)
		return
	}
	value, err := readFixture(*fixturePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL reopen fixture:", err)
		os.Exit(1)
	}
	if !*run {
		fmt.Println("PASS reopen fixture (2 cases)")
		return
	}
	if *rustBinary == "" {
		fmt.Fprintln(os.Stderr, "FAIL differential: --rust-binary is required")
		os.Exit(2)
	}
	if err := runDifferential(*rustBinary, value); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL Go↔Rust reopen:", err)
		os.Exit(1)
	}
	fmt.Println("PASS Go↔Rust reopen (2 cases)")
}
