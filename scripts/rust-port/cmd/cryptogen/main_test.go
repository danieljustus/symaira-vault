package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeFixtureForTest(t *testing.T, value fixture) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "age-kdf.json")
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBuildCryptoFixtureHasAuthoritativeProvenanceAndExactCoverage(t *testing.T) {
	root := rootDir()
	value, err := build(root)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := authoritativeOracle(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFixture(value, expected); err != nil {
		t.Fatal(err)
	}
	if len(value.Oracle.SourceFiles) != 5 {
		t.Fatalf("oracle source files = %d, want 5", len(value.Oracle.SourceFiles))
	}
	for _, name := range value.Oracle.SourceFiles {
		if name == "internal/crypto/interop.go" {
			t.Fatal("new interop seam was mislabeled as pinned oracle source")
		}
	}
	if len(value.Oracle.GeneratorFiles) != 3 {
		t.Fatalf("generator files = %d, want 3", len(value.Oracle.GeneratorFiles))
	}
}

func TestVerifyRejectsTamperedAuthoritativeMetadata(t *testing.T) {
	root := rootDir()
	value, err := build(root)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"commit", func(v *fixture) { v.Oracle.Commit = "tampered" }},
		{"release", func(v *fixture) { v.Oracle.Release = "v0.0.0" }},
		{"source_digest", func(v *fixture) { v.Oracle.SourceDigest = "0" + v.Oracle.SourceDigest[1:] }},
		{"generator_digest", func(v *fixture) { v.Oracle.GeneratorDigest = "0" + v.Oracle.GeneratorDigest[1:] }},
		{"source_files", func(v *fixture) { v.Oracle.SourceFiles[0] = "internal/crypto/interop.go" }},
		{"generator_files", func(v *fixture) { v.Oracle.GeneratorFiles[0] = "internal/crypto/age.go" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := value
			mutated.Oracle.SourceFiles = append([]string(nil), value.Oracle.SourceFiles...)
			mutated.Oracle.GeneratorFiles = append([]string(nil), value.Oracle.GeneratorFiles...)
			tc.mutate(&mutated)
			if err := verify(root, writeFixtureForTest(t, mutated)); err == nil {
				t.Fatal("verify accepted tampered authoritative metadata")
			}
		})
	}
}

func TestVerifyRejectsOmittedRequiredCases(t *testing.T) {
	root := rootDir()
	value, err := build(root)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"identity", func(v *fixture) { v.Identities = v.Identities[:2] }},
		{"age", func(v *fixture) { v.AgeCases = v.AgeCases[:1] }},
		{"malformed", func(v *fixture) { v.MalformedCases = v.MalformedCases[:2] }},
		{"limit", func(v *fixture) { v.LimitCases = v.LimitCases[:8] }},
		{"wrong_passphrase", func(v *fixture) { v.WrongPassphraseCases = v.WrongPassphraseCases[:2] }},
		{"migration", func(v *fixture) { v.MigrationCases = v.MigrationCases[:2] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := value
			tc.mutate(&mutated)
			if err := verify(root, writeFixtureForTest(t, mutated)); err == nil {
				t.Fatal("verify accepted omitted required case")
			}
		})
	}
}

func TestVerifyRejectsOmittedOrTamperedReencryptFamilies(t *testing.T) {
	root := rootDir()
	value, err := build(root)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"reencrypt", func(v *fixture) { v.ReencryptCases = v.ReencryptCases[:1] }},
		{"reencrypt_all", func(v *fixture) { v.ReencryptAllCases = v.ReencryptAllCases[:1] }},
		{"reencrypt_tamper", func(v *fixture) { v.ReencryptCases[0].Name = "tampered" }},
		{"reencrypt_all_tamper", func(v *fixture) { v.ReencryptAllCases[0].Name = "tampered" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := value
			tc.mutate(&mutated)
			if err := verify(root, writeFixtureForTest(t, mutated)); err == nil {
				t.Fatal("verify accepted omitted or tampered re-encryption family")
			}
		})
	}
}

func TestVerifyReencryptCasesRejectsEmpty(t *testing.T) {
	if err := verifyReencryptCases(nil); err == nil {
		t.Fatal("verifyReencryptCases accepted empty input")
	}
	if err := verifyReencryptAllCases(nil, nil); err == nil {
		t.Fatal("verifyReencryptAllCases accepted empty input")
	}
}
