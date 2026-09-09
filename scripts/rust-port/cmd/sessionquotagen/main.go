// Command sessionquotagen derives session and persistent quota fixtures from
// the production Go managers. Expected values come from public package paths.
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
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/policy"
	"github.com/danieljustus/symaira-vault/internal/quotas"
	"github.com/danieljustus/symaira-vault/internal/session"
)

const (
	pinnedOracleCommit  = "caadd5e"
	pinnedOracleRelease = "v0.22.1"
)

var productionSources = []string{
	"internal/session/session.go",
	"internal/session/keyring.go",
	"internal/session/memory_keyring.go",
	"internal/quotas/counter.go",
	"internal/quotas/lock_unix.go",
	"internal/quotas/lock_windows.go",
	"internal/policy/ratelimit.go",
	"internal/policy/ratelimit_transition.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
	GOOS            string   `json:"goos"`
}

type sessionFixture struct {
	SchemaVersion int           `json:"schema_version"`
	Oracle        oracle        `json:"oracle"`
	Cases         []sessionCase `json:"cases"`
}

type sessionCase struct {
	Name       string   `json:"name"`
	Operations []string `json:"operations"`
	Expected   string   `json:"expected"`
	ErrorClass string   `json:"error_class,omitempty"`
}

type quotaFixture struct {
	SchemaVersion int           `json:"schema_version"`
	Oracle        oracle        `json:"oracle"`
	Cases         []quotaCase   `json:"cases"`
	Wrapper       []wrapperCase `json:"wrapper_cases"`
}

type quotaCase struct {
	Name          string         `json:"name"`
	Operations    []string       `json:"operations"`
	Counts        map[string]int `json:"counts"`
	AfterReset    map[string]int `json:"after_reset"`
	RawAfterWrite string         `json:"raw_after_write"`
	RawAfterReset string         `json:"raw_after_reset"`
	DirMode       uint32         `json:"dir_mode"`
	FileMode      uint32         `json:"file_mode"`
	ClosedCheck   [2]int         `json:"closed_check"`
}

type wrapperCase struct {
	Name          string `json:"name"`
	UnknownBefore bool   `json:"unknown_before"`
	HasAfterSet   bool   `json:"has_after_set"`
	FirstAllow    bool   `json:"first_allow"`
	SecondAllow   bool   `json:"second_allow"`
	OtherAllow    bool   `json:"other_agent_allow"`
	HasAfterClean bool   `json:"has_after_cleanup"`
}

// fakeKeyring is deliberately only a transport double; all session decisions
// and encryption remain in internal/session.Manager.
type fakeKeyring struct{ values map[string]string }

func (f *fakeKeyring) Get(key string) (string, error) {
	v, ok := f.values[key]
	if !ok {
		return "", session.ErrKeyringNotFound
	}
	return v, nil
}
func (f *fakeKeyring) Set(key, value string) error { f.values[key] = value; return nil }
func (f *fakeKeyring) Delete(key string) error     { delete(f.values, key); return nil }

func buildSessionFixture(meta oracle) sessionFixture {
	v := "fixture-vault"
	key := "symvault:" + v + "|session"
	now := time.Now().UTC().Format(time.RFC3339Nano)
	cases := make([]sessionCase, 0, 5)
	missing := &fakeKeyring{values: map[string]string{}}
	_, err := session.NewManager(missing, nil).LoadPassphrase(v)
	cases = append(cases, resultCase("missing", []string{"load_passphrase"}, err))

	backend := &fakeKeyring{values: map[string]string{}}
	manager := session.NewManager(backend, nil)
	err = manager.SavePassphrase(v, []byte("fixture-secret"), time.Hour)
	if err != nil {
		panic(err)
	}
	value, err := manager.LoadPassphrase(v)
	if err != nil || string(value) != "fixture-secret" {
		panic(fmt.Errorf("session round trip: %w", err))
	}
	cases = append(cases, sessionCase{Name: "encrypted_round_trip", Operations: []string{"save_passphrase", "load_passphrase"}, Expected: "fixture-secret"})

	legacyBytes, err := json.Marshal(map[string]any{"saved_at": now, "last_access": now, "passphrase": "legacy", "ttl_ns": int64(3600000000000)})
	if err != nil {
		panic(err)
	}
	legacy := &fakeKeyring{values: map[string]string{key: string(legacyBytes)}}
	_, err = session.NewManager(legacy, nil).LoadPassphrase(v)
	cases = append(cases, resultCase("legacy_plaintext", []string{"load_passphrase"}, err))

	expired := &fakeKeyring{values: map[string]string{key: `{"saved_at":"2000-01-01T00:00:00Z","last_access":"2000-01-01T00:00:00Z","ttl_ns":1,"encrypted_passphrase":"x","nonce":"x"}`}}
	_, err = session.NewManager(expired, nil).LoadPassphrase(v)
	cases = append(cases, resultCase("expired", []string{"load_passphrase"}, err))

	malformed := &fakeKeyring{values: map[string]string{key: "not-json"}}
	_, err = session.NewManager(malformed, nil).LoadPassphrase(v)
	cases = append(cases, resultCase("malformed", []string{"load_passphrase"}, err))
	_ = meta
	return sessionFixture{SchemaVersion: 1, Oracle: meta, Cases: cases}
}

func resultCase(name string, ops []string, err error) sessionCase {
	item := sessionCase{Name: name, Operations: ops}
	if err == nil {
		item.Expected = "ok"
		return item
	}
	item.Expected = "error"
	switch {
	case errors.Is(err, session.ErrLegacyPlaintextSession):
		item.ErrorClass = "legacy_plaintext"
	case strings.Contains(err.Error(), "expired"):
		item.ErrorClass = "expired"
	case strings.Contains(err.Error(), "malformed"), strings.Contains(err.Error(), "decode"):
		item.ErrorClass = "malformed"
	case errors.Is(err, session.ErrKeyringNotFound):
		item.ErrorClass = "not_found"
	default:
		item.ErrorClass = "other"
	}
	return item
}

func buildQuotaFixture(meta oracle, root string) quotaFixture {
	dir := filepath.Join(root, "quota")
	q, err := quotas.New(dir)
	if err != nil {
		panic(err)
	}
	first, err := q.Increment("read_entry")
	if err != nil {
		panic(err)
	}
	second, err := q.Increment("read_entry")
	if err != nil {
		panic(err)
	}
	other, err := q.Increment("write_entry")
	if err != nil {
		panic(err)
	}
	if second != 2 || other != 1 {
		panic(fmt.Errorf("quota increments = %d,%d", second, other))
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".quotas.json"))
	if err != nil {
		panic(err)
	}
	ok, current := q.Check("read_entry", 2)
	if ok || current != 2 {
		panic(fmt.Errorf("quota check = %v,%d", ok, current))
	}
	q.Reset()
	rawReset, err := os.ReadFile(filepath.Join(dir, ".quotas.json"))
	if err != nil {
		panic(err)
	}
	_, _ = q.Increment("after_reset")
	closeErr := q.Close()
	if closeErr != nil {
		panic(fmt.Errorf("close quota counter: %w", closeErr))
	}
	closedOK, closedCurrent := q.Check("after_reset", 10)
	info, err := os.Stat(filepath.Join(dir, ".quotas.json"))
	if err != nil {
		panic(err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		panic(err)
	}
	return quotaFixture{
		SchemaVersion: 1, Oracle: meta,
		Cases:   []quotaCase{{Name: "persistent_counter", Operations: []string{"new", "increment", "check", "reset", "close"}, Counts: map[string]int{"read_entry": first + 1, "write_entry": other}, AfterReset: map[string]int{"after_reset": 1}, RawAfterWrite: string(raw), RawAfterReset: string(rawReset), DirMode: uint32(dirInfo.Mode().Perm()), FileMode: uint32(info.Mode().Perm()), ClosedCheck: [2]int{boolInt(closedOK), closedCurrent}}},
		Wrapper: []wrapperCase{buildWrapperCase()},
	}
}

func buildWrapperCase() wrapperCase {
	rl := policy.NewAgentRateLimiter()
	unknown := rl.Allow("unknown")
	rl.SetLimits("agent-a", 1, 1)
	first := rl.Allow("agent-a")
	second := rl.Allow("agent-a")
	other := rl.Allow("agent-b")
	has := rl.HasLimits("agent-a")
	rl.Cleanup()
	return wrapperCase{Name: "public_registry", UnknownBefore: unknown, HasAfterSet: has, FirstAllow: first, SecondAllow: second, OtherAllow: other, HasAfterClean: rl.HasLimits("agent-a")}
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func buildOracle(root, commit, release string) (oracle, error) {
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	digest, err := digestFiles(root, sources)
	if err != nil {
		return oracle{}, err
	}
	generator, err := digestFiles(root, []string{"scripts/rust-port/cmd/sessionquotagen/main.go"})
	if err != nil {
		return oracle{}, err
	}
	return oracle{Commit: commit, Release: release, SourceFiles: sources, SourceDigest: digest, GeneratorDigest: generator, GOOS: runtime.GOOS}, nil
}
func digestFiles(root string, names []string) (string, error) {
	h := sha256.New()
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return "", err
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(b)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func repositoryRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}
func resolve(check bool, commit, release string) (string, string, error) {
	if commit != "" && commit != pinnedOracleCommit {
		return "", "", fmt.Errorf("oracle commit is not pinned")
	}
	if release != "" && release != pinnedOracleRelease {
		return "", "", fmt.Errorf("oracle release is not pinned")
	}
	if check {
		return pinnedOracleCommit, pinnedOracleRelease, nil
	}
	if commit == "" || release == "" {
		return "", "", fmt.Errorf("oracle metadata is required")
	}
	return commit, release, nil
}
func marshal(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}
func writeOrCheck(path string, content []byte, check bool) error {
	if check {
		existing, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, content) {
			return fmt.Errorf("%s is stale; run make config-session-fixtures-generate", path)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o600)
}

func main() {
	outputSession := flag.String("session-output", "testdata/port/session/contract.json", "session fixture")
	outputQuota := flag.String("quota-output", "testdata/port/quotas/contract.json", "quota fixture")
	check := flag.Bool("check", false, "check fixtures")
	commit := flag.String("oracle-commit", "", "pinned oracle commit")
	release := flag.String("oracle-release", "", "pinned oracle release")
	flag.Parse()
	c, r, err := resolve(*check, *commit, *release)
	if err != nil {
		fatal("resolve oracle: %v", err)
	}
	root := repositoryRoot()
	meta, err := buildOracle(root, c, r)
	if err != nil {
		fatal("provenance: %v", err)
	}
	tmp, err := os.MkdirTemp("", "symvault-session-quota-")
	if err != nil {
		fatal("temp root: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	sessionContent := marshal(buildSessionFixture(meta))
	quotaContent := marshal(buildQuotaFixture(meta, tmp))
	if err := writeOrCheck(*outputSession, sessionContent, *check); err != nil {
		fatal("session fixture: %v", err)
	}
	if err := writeOrCheck(*outputQuota, quotaContent, *check); err != nil {
		fatal("quota fixture: %v", err)
	}
	if *check {
		fmt.Println("PASS session/quota fixtures")
	} else {
		fmt.Printf("WROTE %s and %s\n", *outputSession, *outputQuota)
	}
}
func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
