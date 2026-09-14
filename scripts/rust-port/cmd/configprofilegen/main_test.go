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
			t.Errorf("accepted %q", name)
		}
	}
}

func TestNormalizationPreservesUserValues(t *testing.T) {
	for _, path := range []string{`/tmp/sandbox/data/symaira-vault`, `C:\Temp\sandbox\data\symaira-vault`} {
		input := "vaultDir: " + path + "\ndefaultProfile: " + path + "\nprofiles:\n    user:\n        vault: " + path + "\n"
		raw, err := json.Marshal(map[string]any{"saved": input, "default_profile": path})
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Saved string `json:"saved"`
		}
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		normalized := normalizeSaved(decoded.Saved, path)
		want := strings.Replace(input, "vaultDir: "+path, "vaultDir: /fixture/root/data/symaira-vault", 1)
		if normalized != want {
			t.Fatalf("unexpected normalization: %q", normalized)
		}
		snapshot := snapshotWithSaved(raw, normalized)
		if snapshot["default_profile"] != path {
			t.Fatal("user value changed")
		}
	}
}

func TestGeneratorRepeatabilityMutationAndCleanup(t *testing.T) {
	sandbox := t.TempDir()
	t.Setenv("TMPDIR", sandbox)
	t.Setenv("TMP", sandbox)
	t.Setenv("TEMP", sandbox)
	oracleRoot := filepath.Join(sandbox, "oracle")
	if err := os.Mkdir(oracleRoot, 0700); err != nil {
		t.Fatal(err)
	}
	archiveOracle(repositoryRoot(), oracleRoot)
	writeOracleHelper(oracleRoot)
	first := runOracle(oracleRoot)
	second := runOracle(oracleRoot)
	a, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFixture(a, b); err != nil {
		t.Fatal(err)
	}
	if len(first) != 14 {
		t.Fatalf("got %d cases", len(first))
	}
	seen := map[string]bool{}
	for _, c := range first {
		if seen[c.Name] {
			t.Fatal("duplicate case")
		}
		seen[c.Name] = true
	}
	second[0].Input += "mutated"
	mutated, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, mutated) || validateFixture(a, mutated) == nil {
		t.Fatal("real validator accepted mutation")
	}
	entries, err := os.ReadDir(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "oracle" {
			t.Fatal("sandbox leak")
		}
	}
}

func TestPinnedGoDoesNotRequireNamedShim(t *testing.T) {
	binary := pinnedGoBinary()
	cmd := exec.Command(binary, "version")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Fields(string(out))[2] != requiredGoVersion {
		t.Fatal("wrong Go")
	}
}
