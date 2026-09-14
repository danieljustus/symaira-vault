package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeArchivePath(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", ".."} {
		if _, err := safeArchivePath(name); err == nil {
			t.Errorf("safeArchivePath(%q) accepted traversal", name)
		}
	}
	for _, name := range []string{"internal/config/config.go", "internal/config/../config/config.go"} {
		if _, err := safeArchivePath(name); err != nil {
			t.Errorf("safeArchivePath(%q): %v", name, err)
		}
	}
}

func TestSandboxEnvIncludesWindowsAndXDGIsolation(t *testing.T) {
	env := sandboxEnv(filepath.Join("/sandbox", "root"))
	joined := strings.Join(env, "\x00")
	for _, want := range []string{"HOME=/sandbox/root/home", "XDG_CONFIG_HOME=/sandbox/root/config", "TMP=/sandbox/root/tmp", "TEMP=/sandbox/root/tmp", "GOCACHE=/sandbox/root/gocache"} {
		if !strings.Contains(joined, want) {
			t.Errorf("sandbox environment missing %q", want)
		}
	}
}

func TestSandboxNormalizationPreservesUserValues(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"default_profile": "user-/tmp/sandbox-value",
		"profiles":        map[string]any{},
		"saved":           "vaultDir: /tmp/sandbox-value\ndefaultProfile: user-/tmp/sandbox-value\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := snapshotWithSaved(raw, strings.ReplaceAll("vaultDir: /tmp/sandbox-value\ndefaultProfile: user-/tmp/sandbox-value\n", "/tmp/sandbox-value", "/fixture/root"))
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte("user-/fixture/root")) {
		t.Fatal("declared saved field was not normalized")
	}
	if bytes.Contains(encoded, []byte("default_profile\\\":\\\"user-/fixture/root")) {
		t.Fatal("arbitrary user value was normalized")
	}
}

func TestGeneratorRepeatabilityAndCleanup(t *testing.T) {
	output := filepath.Join("testdata", "port", ".config-profile-generator-test.json")
	t.Cleanup(func() { _ = os.Remove(filepath.Join(repositoryRootForTest(), output)) })
	before := tempArtifactNames(t)
	run := func() {
		cmd := exec.Command("go", "run", ".", "--oracle-commit", pinnedOracleCommit, "--oracle-release", pinnedOracleRelease, "--output", output)
		cmd.Dir = "."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generator: %v\n%s", err, out)
		}
	}
	run()
	first, err := os.ReadFile(filepath.Join(repositoryRootForTest(), output))
	if err != nil {
		t.Fatal(err)
	}
	run()
	second, err := os.ReadFile(filepath.Join(repositoryRootForTest(), output))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("generator output is not repeatable")
	}
	after := tempArtifactNames(t)
	for name := range after {
		if !before[name] {
			t.Errorf("temporary oracle artifact leaked: %s", name)
		}
	}
}

func repositoryRootForTest() string {
	root, _ := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	return root
}

func tempArtifactNames(t *testing.T) map[string]bool {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]bool)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "config-profile-") {
			out[entry.Name()] = true
		}
	}
	return out
}
