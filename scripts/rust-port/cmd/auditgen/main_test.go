package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFixture(t *testing.T, value fixture) string {
	t.Helper()
	content, err := marshalFixture(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "chain.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveOracleRejectsTamperedMetadata(t *testing.T) {
	if err := resolveOracle(true, "tampered", pinnedOracleRelease); err == nil {
		t.Fatal("expected tampered commit rejection")
	}
	if err := resolveOracle(true, pinnedOracleCommit, "v0.0.0"); err == nil {
		t.Fatal("expected tampered release rejection")
	}
	if err := resolveOracle(false, "", pinnedOracleRelease); err == nil {
		t.Fatal("expected missing generation commit rejection")
	}
	if err := resolveOracle(true, "", ""); err != nil {
		t.Fatalf("check mode should use pinned metadata: %v", err)
	}
}

func TestBuildFixtureIsDeterministicAndProductionVerified(t *testing.T) {
	root := rootDir()
	first, err := buildFixture(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildFixture(root)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := marshalFixture(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := marshalFixture(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("audit fixture generation is not deterministic")
	}
	if first.SchemaVersion != 1 || first.KeyHex != fixtureKeyHex || len(first.Entries) != 3 {
		t.Fatalf("fixture shape = schema %d, key %q, entries %d", first.SchemaVersion, first.KeyHex, len(first.Entries))
	}
	if len(first.Oracle.SourceDigest) != 64 || len(first.Oracle.GeneratorDigest) != 64 {
		t.Fatalf("incomplete provenance: %#v", first.Oracle)
	}
	for i, entry := range first.Entries {
		if entry.Entry.Kid != "630dcd29" {
			t.Fatalf("entry %d kid = %q, want production fingerprint", i, entry.Entry.Kid)
		}
		if len(entry.HMAC) != 64 || entry.HMAC != strings.ToLower(entry.HMAC) {
			t.Fatalf("entry %d HMAC = %q", i, entry.HMAC)
		}
	}
}

func TestCheckRejectsProvenanceAndFixtureDrift(t *testing.T) {
	root := rootDir()
	value, err := buildFixture(root)
	if err != nil {
		t.Fatal(err)
	}
	expected := value.Oracle
	if err := validateFixture(value, expected); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"source_digest", func(v *fixture) { v.Oracle.SourceDigest = strings.Repeat("0", 64) }},
		{"generator_digest", func(v *fixture) { v.Oracle.GeneratorDigest = strings.Repeat("0", 64) }},
		{"entry", func(v *fixture) { v.Entries[1].Entry.Action = "tampered-action" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mutated := value
			mutated.Entries = append([]entryVector(nil), value.Entries...)
			tc.mutate(&mutated)
			path := writeFixture(t, mutated)
			if err := checkFixture(root, path); err == nil {
				t.Fatal("check accepted tampered fixture")
			}
		})
	}
}

func TestFixtureJSONRoundTripPreservesEntryVectors(t *testing.T) {
	value, err := buildFixture(rootDir())
	if err != nil {
		t.Fatal(err)
	}
	content, err := marshalFixture(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded fixture
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, mustMarshalFixture(t, decoded)) {
		t.Fatal("fixture JSON round trip changed bytes")
	}
}

func mustMarshalFixture(t *testing.T, value fixture) []byte {
	t.Helper()
	content, err := marshalFixture(value)
	if err != nil {
		t.Fatal(err)
	}
	return content
}
