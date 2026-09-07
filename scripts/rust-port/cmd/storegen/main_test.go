package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
