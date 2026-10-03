package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeFixture(t *testing.T, value fixture) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store.json")
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBuildStoreFixtureHasExactCoverage(t *testing.T) {
	value, err := build(rootDir())
	if err != nil {
		t.Fatal(err)
	}
	expected, err := authoritative(rootDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := validate(value, expected); err != nil {
		t.Fatal(err)
	}
	if value.Vaults[0].Layout != "fresh" || value.Vaults[1].Layout != "legacy" {
		t.Fatal("layout order changed")
	}
}

func TestVerifyRejectsOmittedOrTamperedVectors(t *testing.T) {
	root := rootDir()
	value, err := build(root)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"vault", func(v *fixture) { v.Vaults = v.Vaults[:1] }},
		{"entry", func(v *fixture) { v.Vaults[0].Entries = v.Vaults[0].Entries[:2] }},
		{"file", func(v *fixture) { v.Vaults[0].Files = v.Vaults[0].Files[:5] }},
		{"metadata", func(v *fixture) { v.Oracle.SourceDigest = "0" + v.Oracle.SourceDigest[1:] }},
		{"source inventory", func(v *fixture) {
			v.Oracle.SourceFiles = append([]string(nil), v.Oracle.SourceFiles...)
			v.Oracle.SourceFiles[0] = "changed.go"
		}},
		{"generator inventory", func(v *fixture) {
			v.Oracle.GeneratorFiles = append([]string(nil), v.Oracle.GeneratorFiles...)
			v.Oracle.GeneratorFiles[0] = "changed.go"
		}},
		{"malformed", func(v *fixture) { v.Malformed = v.Malformed[:2] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := value
			mutated.Vaults = append([]vaultFixture(nil), value.Vaults...)
			mutated.Vaults[0].Entries = append([]entryFixture(nil), value.Vaults[0].Entries...)
			mutated.Vaults[0].Files = append([]fileFixture(nil), value.Vaults[0].Files...)
			tc.mutate(&mutated)
			if err := verify(root, writeFixture(t, mutated)); err == nil {
				t.Fatal("verify accepted tampered or omitted vector")
			}
		})
	}
}

func TestRefreshProvenanceOnlyPreservesPayloadAndRejectsEscape(t *testing.T) {
	root := rootDir()
	data, err := os.ReadFile(filepath.Join(root, "testdata", "port", "store", "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	var original fixture
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatal(err)
	}
	t.Run("payload", func(t *testing.T) {
		path := writeFixture(t, original)
		if err := refreshProvenanceOnly(root, path); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var refreshed fixture
		if err := json.Unmarshal(after, &refreshed); err != nil {
			t.Fatal(err)
		}
		if err := verify(root, path); err != nil {
			t.Fatal(err)
		}
		refreshed.Oracle.GeneratorFiles = original.Oracle.GeneratorFiles
		refreshed.Oracle.GeneratorDigest = original.Oracle.GeneratorDigest
		if !reflect.DeepEqual(refreshed, original) {
			t.Fatal("provenance refresh changed payload or source provenance")
		}
	})
	t.Run("source-drift", func(t *testing.T) {
		mutated := original
		mutated.Oracle.SourceDigest = "invalid-source-digest"
		path := writeFixture(t, mutated)
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := refreshProvenanceOnly(root, path); err == nil {
			t.Fatal("refresh accepted changed source provenance")
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("rejected refresh modified the fixture")
		}
	})
	t.Run("symlink-escape", func(t *testing.T) {
		outside := writeFixture(t, original)
		before, err := os.ReadFile(outside)
		if err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "store.json")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := refreshProvenanceOnly(root, link); err == nil {
			t.Fatal("refresh followed a symlink outside the fixture root")
		}
		after, err := os.ReadFile(outside)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("rejected refresh changed the outside fixture")
		}
	})
}
