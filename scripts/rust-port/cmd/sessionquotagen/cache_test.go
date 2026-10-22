package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCacheFixtureCoversTheLifecycleDeterministically(t *testing.T) {
	first, err := buildCacheFixture(repositoryRoot())
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildCacheFixture(repositoryRoot())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatal("cache fixture differs between two generator runs")
	}
	if len(first.Scenarios) != 22 || len(first.Concurrency) != 3 {
		t.Fatalf("scenarios=%d concurrency=%d", len(first.Scenarios), len(first.Concurrency))
	}
	if first.Storage.Backend != "keyring" || first.Storage.OnDiskFiles != 0 || len(first.Storage.FilesystemImports) != 0 {
		t.Fatalf("storage contract = %+v", first.Storage)
	}
	results := map[string]bool{}
	for _, sc := range first.Scenarios {
		for _, step := range sc.Steps {
			if step.Expect.Result != "" {
				results[step.Expect.Result] = true
			}
		}
	}
	for _, want := range []string{"ok", "not_found", "expired", "expired_zero_ttl", "expired_no_data", "malformed", "legacy_plaintext", "decrypt_failed", "wrap_key_missing", "wrap_key_invalid", "keyring_unavailable"} {
		if !results[want] {
			t.Errorf("no scenario observes result class %q", want)
		}
	}
}

func TestClassifyMapsOracleErrors(t *testing.T) {
	wrapped := func(message string) error { return errors.New(message) }
	for message, want := range map[string]string{
		"session expired for vault v: TTL is zero or negative":      "expired_zero_ttl",
		"session expired for vault v: no passphrase data available": "expired_no_data",
		"identity cache expired for vault v: last activity x":       "expired",
		"load wrap key: wrap key not found":                         "wrap_key_missing",
		"load wrap key: wrap key has invalid length: got 1":         "wrap_key_invalid",
		"load wrap key: decode wrap key: illegal base64":            "wrap_key_invalid",
		"decode session: invalid character":                         "malformed",
		"decode identity: invalid character":                        "malformed",
		"decrypt session: decrypt: message authentication failed":   "decrypt_failed",
	} {
		if got := classify(wrapped(message)); got != want {
			t.Errorf("classify(%q) = %q, want %q", message, got, want)
		}
	}
	if classify(nil) != "ok" || classify(fmt.Errorf("x: %w", errCacheFault)) != "keyring_unavailable" {
		t.Fatal("nil and wrapped fault classification")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("an unclassified error must not be frozen into the fixture")
		}
	}()
	classify(errors.New("unknown failure"))
}

func TestCacheKeyringFaultsAreAccountScoped(t *testing.T) {
	k := newCacheKeyring()
	k.putRaw("session", "value")
	k.setFault(cacheFault{Get: true, Accounts: []string{"identity"}})
	if got, err := k.Get(cacheVaultKey + "session"); err != nil || got != "value" {
		t.Fatalf("unfaulted account: %q %v", got, err)
	}
	if _, err := k.Get(cacheVaultKey + "identity"); !errors.Is(err, errCacheFault) {
		t.Fatalf("faulted account: %v", err)
	}
	k.setFault(cacheFault{Set: true, Delete: true})
	if err := k.Set(cacheVaultKey+"session", "x"); !errors.Is(err, errCacheFault) {
		t.Fatalf("set fault: %v", err)
	}
	if err := k.Delete(cacheVaultKey + "session"); !errors.Is(err, errCacheFault) {
		t.Fatalf("delete fault: %v", err)
	}
	if got, ok := k.raw("session"); !ok || got != "value" {
		t.Fatal("faults must leave the stored value intact")
	}
	k.dropRaw("session")
	if _, ok := k.raw("session"); ok {
		t.Fatal("dropRaw did not remove")
	}
}

func TestFilesystemImportsReportsBannedPackages(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "internal", "session")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	clean := "package session\n\nimport (\n\t\"errors\"\n)\n"
	dirty := "package session\n\nimport (\n\t\"os\"\n\t\"io/ioutil\"\n)\n"
	for name, body := range map[string]string{"session.go": dirty, "keyring.go": clean, "memory_keyring.go": clean} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := filesystemImports(root)
	if err != nil || strings.Join(got, ",") != "io/ioutil,os" {
		t.Fatalf("imports = %v, %v", got, err)
	}
	if _, err := filesystemImports(t.TempDir()); err == nil {
		t.Fatal("missing sources must be an error")
	}
}

func TestScopeEnvironmentRestoresPreviousValues(t *testing.T) {
	t.Setenv("HOME", "/original-home")
	scratch := t.TempDir()
	restore := scopeEnvironment(scratch)
	if os.Getenv("HOME") != scratch || os.Getenv("TMPDIR") != scratch {
		t.Fatal("environment was not scoped to the scratch root")
	}
	restore()
	if os.Getenv("HOME") != "/original-home" {
		t.Fatalf("HOME = %q after restore", os.Getenv("HOME"))
	}
}

func TestConcurrencyRunnerRejectsViolations(t *testing.T) {
	c := concurrencyCases()[0]
	c.Permitted = map[string][]string{"load_passphrase": {"not_found"}, "load_identity": {"ok"}, "peek_identity": {"ok"}}
	if _, err := runConcurrency(c); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("a result outside the permitted set must fail, got %v", err)
	}
	c = concurrencyCases()[0]
	c.ProbeExpected = map[string]bool{"is_session_expired": true, "is_identity_expired": false}
	if _, err := runConcurrency(c); err == nil {
		t.Fatal("a wrong probe answer must fail")
	}
	c = concurrencyCases()[0]
	c.FinalPresent = []string{"session"}
	if _, err := runConcurrency(c); err == nil || !strings.Contains(err.Error(), "final entries") {
		t.Fatalf("wrong final entries must fail, got %v", err)
	}
	c = concurrencyCases()[0]
	c.FinalResult = []string{"not_found"}
	if _, err := runConcurrency(c); err == nil || !strings.Contains(err.Error(), "final load") {
		t.Fatalf("wrong final load must fail, got %v", err)
	}
}

func TestRunScenarioRejectsUnknownOperations(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("unknown operation must panic")
		}
	}()
	runScenario(cacheScenario{Name: "bad", Backend: "memory", Steps: []cacheStep{{Op: "nonsense"}}})
}
