package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveOracleRejectsTamperedMetadata(t *testing.T) {
	if _, err := resolveOracle(true, "tampered", pinnedOracleRelease); err == nil {
		t.Fatal("expected tampered commit rejection")
	}
	if _, err := resolveOracle(true, pinnedOracleCommit, "v0.0.0"); err == nil {
		t.Fatal("expected tampered release rejection")
	}
	got, err := resolveOracle(true, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Commit != pinnedOracleCommit || got.Release != pinnedOracleRelease {
		t.Fatalf("check metadata = %#v", got)
	}
}

func TestQuotaCheckRejectsProvenanceDrift(t *testing.T) {
	meta := oracle{Commit: "test", Release: "v0.0.0", SourceDigest: strings.Repeat("a", 64), GeneratorDigest: strings.Repeat("b", 64)}
	expected, err := marshal(buildFixture(meta))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{meta.SourceDigest, meta.GeneratorDigest} {
		tampered := bytes.Replace(expected, []byte(field), []byte(strings.Repeat("0", len(field))), 1)
		path := filepath.Join(t.TempDir(), "fixture.json")
		if err := os.WriteFile(path, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := checkFixture(path, expected); err == nil {
			t.Fatalf("check accepted tampered provenance field %q", field)
		}
	}
}

func TestBuildFixtureIsDeterministicAndCoversQuotaBoundaries(t *testing.T) {
	meta := oracle{Commit: "test", Release: "v0.0.0"}
	first, err := marshal(buildFixture(meta))
	if err != nil {
		t.Fatal(err)
	}
	second, err := marshal(buildFixture(meta))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("quota fixture generation is not deterministic")
	}

	fixture := buildFixture(meta)
	if fixture.SchemaVersion != 1 || len(fixture.Cases) != 7 {
		t.Fatalf("fixture = schema %d, %d cases; want schema 1 and 7 cases", fixture.SchemaVersion, len(fixture.Cases))
	}
	wantNames := []string{
		"refill_fractional", "daily_rollover", "capacity_clamp", "rejection",
		"boundaries", "negative_hour_limit", "negative_day_limit",
	}
	for i, want := range wantNames {
		if fixture.Cases[i].Name != want {
			t.Fatalf("case %d = %q, want %q", i, fixture.Cases[i].Name, want)
		}
		if len(fixture.Cases[i].Transitions) < 3 {
			t.Fatalf("case %q has %d transitions, want at least 3", want, len(fixture.Cases[i].Transitions))
		}
	}

	boundary := fixture.Cases[4].Transitions
	if boundary[len(boundary)-2].Result.Allowed {
		t.Fatal("3599-second boundary unexpectedly allowed")
	}
	if !boundary[len(boundary)-1].Result.Allowed {
		t.Fatal("3600-second boundary unexpectedly rejected")
	}
}
