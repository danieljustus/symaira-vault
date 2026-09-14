package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestFixturePathIsBounded(t *testing.T) {
	root := rootDir()
	if got, err := fixturePath(root, "testdata/port/pairing/contract.json"); err != nil || got != filepath.Join("pairing", "contract.json") {
		t.Fatalf("fixture path = %q, %v", got, err)
	}
	for _, path := range []string{"../outside.json", "testdata/port/../outside.json", filepath.Join(root, "outside.json")} {
		if _, err := fixturePath(root, path); err == nil {
			t.Fatalf("fixture path %q unexpectedly accepted", path)
		}
	}
}

// The pairing oracle must be free of wall-clock and randomness: expiry is
// expressed through pairing.TokenTTL and no case reads time.Now, so two runs
// have to agree byte for byte. If this ever fails, the fixture's --check gate
// would be intermittently red rather than meaningful.
func TestPinnedPairingOracleIsRepeatable(t *testing.T) {
	first, err := runOracle(rootDir())
	if err != nil {
		t.Fatalf("first pinned oracle run: %v", err)
	}
	second, err := runOracle(rootDir())
	if err != nil {
		t.Fatalf("second pinned oracle run: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("oracle case count changed between runs: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID || first[i].Seam != second[i].Seam {
			t.Fatalf("oracle case identity changed at %d: %q vs %q", i, first[i].ID, second[i].ID)
		}
		if !bytes.Equal(first[i].Input, second[i].Input) {
			t.Fatalf("oracle input changed between runs for %s: %s vs %s", first[i].ID, first[i].Input, second[i].Input)
		}
		if !bytes.Equal(first[i].Expected, second[i].Expected) {
			t.Fatalf("oracle expected output changed between runs for %s: %s vs %s", first[i].ID, first[i].Expected, second[i].Expected)
		}
	}
}

// Provenance must be read from the pinned commit, not from the working tree:
// a generator that digests whatever is checked out cannot detect oracle drift.
func TestSourceDigestComesFromThePinnedCommit(t *testing.T) {
	root := rootDir()
	meta, err := metadata(root)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if meta.Commit != oracleCommit || meta.Release != oracleRelease {
		t.Fatalf("oracle pin = %q/%q, want %q/%q", meta.Commit, meta.Release, oracleCommit, oracleRelease)
	}
	pinned, err := digest(root, meta.SourceFiles, true)
	if err != nil {
		t.Fatalf("pinned digest: %v", err)
	}
	if pinned != meta.SourceDigest {
		t.Fatalf("metadata source digest %q is not the pinned digest %q", meta.SourceDigest, pinned)
	}
	for _, name := range []string{"cmd/device.go", "internal/pairing/token.go", "internal/pairing/devicesession.go"} {
		found := false
		for _, have := range meta.SourceFiles {
			if have == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("source file %q is not bound into the provenance digest", name)
		}
	}
}

// Mutating any single expectation must make validate reject the fixture; a
// comparison that silently passes is worse than no comparison at all.
func TestValidateRejectsAMutatedExpectation(t *testing.T) {
	root := rootDir()
	fixtures, err := openFixtureRoot(root)
	if err != nil {
		t.Fatalf("open fixture root: %v", err)
	}
	// Registered first so it runs last: t.Cleanup is LIFO and runs after the
	// test function returns, so a deferred Close here would shut the root
	// before the restore below could write through it, leaving the fixture
	// mutated on disk.
	t.Cleanup(func() { _ = fixtures.Close() })

	const path = "pairing/contract.json"
	if err := validate(root, fixtures, path); err != nil {
		t.Fatalf("baseline fixture does not validate: %v", err)
	}

	original, err := fixtures.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := fixtures.WriteFile(path, original, 0600); err != nil {
			t.Fatalf("restore fixture: %v", err)
		}
	})

	var fixture Fixture
	if err := json.Unmarshal(original, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("fixture holds no cases")
	}
	fixture.Cases[0].Expected = json.RawMessage(`{"mutated":true}`)
	mutated, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal mutated fixture: %v", err)
	}
	if err := fixtures.WriteFile(path, append(mutated, '\n'), 0600); err != nil {
		t.Fatalf("write mutated fixture: %v", err)
	}
	if err := validate(root, fixtures, path); err == nil {
		t.Fatal("validate accepted a mutated expectation")
	}
}
