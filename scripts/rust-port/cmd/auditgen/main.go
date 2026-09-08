// Command auditgen freezes deterministic keyed audit-chain vectors for the
// staged Rust store port.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

	auditpkg "github.com/danieljustus/symaira-vault/internal/audit"
)

const (
	pinnedOracleCommit  = "caadd5e"
	pinnedOracleRelease = "v0.22.1"
	fixtureKeyHex       = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	fixtureAgent        = "fixture-agent"
	keyringEnv          = "SYMVAULT_TEST_KEYRING"
)

var oracleSourceFiles = []string{
	"internal/audit/audit.go",
	"internal/audit/audit_hmac_test.go",
	"internal/audit/keystore.go",
}

var generatorFiles = []string{
	"scripts/rust-port/cmd/auditgen/main.go",
	"scripts/rust-port/cmd/auditgen/main_test.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

type fixture struct {
	SchemaVersion int           `json:"schema_version"`
	Oracle        oracle        `json:"oracle"`
	KeyHex        string        `json:"key_hex"`
	Entries       []entryVector `json:"entries"`
}

type entryVector struct {
	Entry         auditpkg.LogEntry `json:"entry"`
	CanonicalJSON string            `json:"canonical_json"`
	HMAC          string            `json:"hmac"`
	Line          string            `json:"line"`
}

func rootDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate auditgen")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

func digestFiles(root string, names []string, pinned bool) (string, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	hash := sha256.New()
	for _, name := range sorted {
		var (
			data []byte
			err  error
		)
		if pinned {
			data, err = exec.Command("git", "-C", root, "show", pinnedOracleCommit+":"+name).Output() // #nosec G204 -- executable and revision are fixed; name comes from a compile-time list.
		} else {
			data, err = os.ReadFile(filepath.Join(root, name)) // #nosec G304 -- names come from a compile-time list.
		}
		if err != nil {
			return "", fmt.Errorf("digest %s: %w", name, err)
		}
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(data)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func authoritativeOracle(root string) (oracle, error) {
	pinnedDigest, err := digestFiles(root, oracleSourceFiles, true)
	if err != nil {
		return oracle{}, fmt.Errorf("hash pinned audit oracle: %w", err)
	}
	currentDigest, err := digestFiles(root, oracleSourceFiles, false)
	if err != nil {
		return oracle{}, fmt.Errorf("hash current audit oracle: %w", err)
	}
	if currentDigest != pinnedDigest {
		return oracle{}, fmt.Errorf("current audit oracle differs from pinned commit %s; advance the oracle before regenerating", pinnedOracleCommit)
	}
	generatorDigest, err := digestFiles(root, generatorFiles, false)
	if err != nil {
		return oracle{}, fmt.Errorf("hash audit generator: %w", err)
	}
	return oracle{
		Commit:          pinnedOracleCommit,
		Release:         pinnedOracleRelease,
		SourceFiles:     append([]string(nil), oracleSourceFiles...),
		SourceDigest:    pinnedDigest,
		GeneratorFiles:  append([]string(nil), generatorFiles...),
		GeneratorDigest: generatorDigest,
	}, nil
}

func resolveOracle(check bool, commit, release string) error {
	if commit != "" && commit != pinnedOracleCommit {
		return fmt.Errorf("oracle commit %q is not the pinned commit %q", commit, pinnedOracleCommit)
	}
	if release != "" && release != pinnedOracleRelease {
		return fmt.Errorf("oracle release %q is not the pinned release %q", release, pinnedOracleRelease)
	}
	if !check && (commit == "" || release == "") {
		return errors.New("--oracle-commit and --oracle-release are required when generating a new fixture")
	}
	return nil
}

func fixedEntries() []auditpkg.LogEntry {
	return []auditpkg.LogEntry{
		{
			Timestamp: "2024-01-15T10:30:00Z",
			Agent:     fixtureAgent,
			Action:    "get",
			Path:      "secret/api-key",
			Field:     "password",
			Transport: "stdio",
			DurMs:     17,
			OK:        true,
		},
		{
			Timestamp:   "2024-01-15T10:30:01Z",
			Agent:       fixtureAgent,
			Action:      "set",
			Path:        "secret/api-key",
			Field:       "password",
			Transport:   "http",
			Reason:      "write_denied",
			ShareID:     "share-1",
			FromAgent:   fixtureAgent,
			ToAgent:     "other-agent",
			ShareAction: "share_request",
			TokenID:     "tok_1",
			RequestID:   "req_1",
			SessionID:   "sess_1",
			OK:          false,
		},
		{
			Timestamp: "2024-01-15T10:30:02Z",
			Agent:     fixtureAgent,
			Action:    "list",
			ArgvHash:  "argv-hash",
			OK:        true,
		},
	}
}

func buildFixture(root string) (fixture, error) {
	meta, err := authoritativeOracle(root)
	if err != nil {
		return fixture{}, err
	}
	key, err := hex.DecodeString(fixtureKeyHex)
	if err != nil {
		return fixture{}, fmt.Errorf("decode fixture key: %w", err)
	}

	dir, err := os.MkdirTemp("", "symvault-auditgen-")
	if err != nil {
		return fixture{}, fmt.Errorf("create isolated audit directory: %w", err)
	}
	defer os.RemoveAll(dir) // #nosec G304 -- dir is the generator's private temporary directory.

	if err := os.WriteFile(filepath.Join(dir, "audit-hmac-key"), key, 0o600); err != nil {
		return fixture{}, fmt.Errorf("seed fixture HMAC key: %w", err)
	}

	restoreConfig := configureDeterministicAudit()
	logger, err := auditpkg.New(fixtureAgent, dir, nil)
	if err != nil {
		restoreConfig()
		return fixture{}, fmt.Errorf("open production audit logger: %w", err)
	}
	for _, entry := range fixedEntries() {
		if err := logger.LogEntry(entry); err != nil {
			_ = logger.Close()
			restoreConfig()
			return fixture{}, fmt.Errorf("write production audit entry: %w", err)
		}
	}
	if err := logger.Close(); err != nil {
		restoreConfig()
		return fixture{}, fmt.Errorf("close production audit logger: %w", err)
	}
	restoreConfig()

	logPath := filepath.Join(dir, "audit-"+fixtureAgent+".log")
	result, err := auditpkg.VerifyLog(logPath, key)
	if err != nil {
		return fixture{}, fmt.Errorf("verify generated audit chain: %w", err)
	}
	if !result.Valid || result.Total != len(fixedEntries()) || result.Verified != len(fixedEntries()) || result.Tampered != 0 || result.Legacy != 0 || result.FirstBadIdx != -1 {
		return fixture{}, fmt.Errorf("generated audit chain did not verify: %+v", result)
	}

	data, err := os.ReadFile(logPath) // #nosec G304 -- logPath is inside the generator's private temp directory.
	if err != nil {
		return fixture{}, fmt.Errorf("read generated audit log: %w", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	entries := make([]entryVector, 0, len(lines))
	for i, line := range lines {
		if line == "" {
			continue
		}
		var entry auditpkg.LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return fixture{}, fmt.Errorf("decode generated entry %d: %w", i, err)
		}
		storedHMAC := entry.HMAC
		entry.HMAC = ""
		canonical, err := json.Marshal(entry)
		if err != nil {
			return fixture{}, fmt.Errorf("marshal canonical entry %d: %w", i, err)
		}
		entries = append(entries, entryVector{
			Entry:         entry,
			CanonicalJSON: string(canonical),
			HMAC:          storedHMAC,
			Line:          line,
		})
	}
	return fixture{SchemaVersion: 1, Oracle: meta, KeyHex: fixtureKeyHex, Entries: entries}, nil
}

func configureDeterministicAudit() func() {
	const (
		maxSizeEnv = "SYMVAULT_AUDIT_MAX_SIZE_MB"
		maxBackups = "SYMVAULT_AUDIT_MAX_BACKUPS"
		maxAgeDays = "SYMVAULT_AUDIT_MAX_AGE_DAYS"
	)
	type environmentValue struct {
		value string
		set   bool
	}
	previous := make(map[string]environmentValue, 3)
	for _, name := range []string{maxSizeEnv, maxBackups, maxAgeDays} {
		value, set := os.LookupEnv(name)
		previous[name] = environmentValue{value: value, set: set}
		_ = os.Unsetenv(name)
	}
	auditpkg.SetConfig(&auditpkg.Config{MaxFileSize: 1 << 30, MaxBackups: 5, MaxAgeDays: 36500})
	return func() {
		for name, previousValue := range previous {
			if previousValue.set {
				_ = os.Setenv(name, previousValue.value)
			} else {
				_ = os.Unsetenv(name)
			}
		}
		auditpkg.ReloadConfig()
	}
}

func marshalFixture(value fixture) ([]byte, error) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func validateFixture(value fixture, expected oracle) error {
	if value.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema_version %d", value.SchemaVersion)
	}
	if value.Oracle.Commit != expected.Commit || value.Oracle.Release != expected.Release ||
		value.Oracle.SourceDigest != expected.SourceDigest || value.Oracle.GeneratorDigest != expected.GeneratorDigest ||
		!sameStrings(value.Oracle.SourceFiles, expected.SourceFiles) || !sameStrings(value.Oracle.GeneratorFiles, expected.GeneratorFiles) {
		return errors.New("audit fixture provenance changed; regenerate from the pinned Go oracle")
	}
	if value.KeyHex != fixtureKeyHex || len(value.Entries) != len(fixedEntries()) {
		return errors.New("audit fixture key or entry cardinality changed")
	}
	for i, entry := range value.Entries {
		if entry.Entry.Agent != fixtureAgent || entry.HMAC == "" || entry.Line == "" || entry.CanonicalJSON == "" {
			return fmt.Errorf("audit fixture entry %d is incomplete", i)
		}
	}
	return nil
}

func checkFixture(root, path string) error {
	expected, err := buildFixture(root)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is the explicit fixture selected by the caller.
	if err != nil {
		return fmt.Errorf("read audit fixture: %w", err)
	}
	var actual fixture
	if err := json.Unmarshal(data, &actual); err != nil {
		return fmt.Errorf("decode audit fixture: %w", err)
	}
	if err := validateFixture(actual, expected.Oracle); err != nil {
		return err
	}
	expectedBytes, err := marshalFixture(expected)
	if err != nil {
		return fmt.Errorf("marshal expected audit fixture: %w", err)
	}
	if !bytes.Equal(data, expectedBytes) {
		return errors.New("audit fixture is stale; run make audit-fixtures-generate")
	}
	return nil
}

func reexecWithMemoryKeyring() error {
	env := make([]string, 0, len(os.Environ())+1)
	prefix := keyringEnv + "="
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, prefix) {
			env = append(env, value)
		}
	}
	env = append(env, prefix+"memory")
	command := exec.Command(os.Args[0], os.Args[1:]...) // #nosec G204 -- re-executes this fixed generator binary.
	command.Env = env
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

func run() {
	output := flag.String("output", "testdata/port/audit/chain.json", "audit fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit")
	release := flag.String("oracle-release", "", "Go oracle release")
	flag.Parse()

	if err := resolveOracle(*check, *commit, *release); err != nil {
		fatal("resolve oracle metadata: %v", err)
	}
	root := rootDir()
	if *check {
		if err := checkFixture(root, *output); err != nil {
			fatal("%v", err)
		}
		fmt.Println("PASS audit fixture (3 entries)")
		return
	}
	value, err := buildFixture(root)
	if err != nil {
		fatal("generate audit fixture: %v", err)
	}
	content, err := marshalFixture(value)
	if err != nil {
		fatal("marshal audit fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create audit fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write audit fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d entries)\n", *output, len(value.Entries))
}

func main() {
	if os.Getenv(keyringEnv) != "memory" {
		if err := reexecWithMemoryKeyring(); err != nil {
			fatal("start isolated generator: %v", err)
		}
		return
	}
	run()
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
