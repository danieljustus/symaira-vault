package main

import (
	"bytes"
	"testing"
)

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
	if fixture.SchemaVersion != 1 || len(fixture.Cases) != 5 {
		t.Fatalf("fixture = schema %d, %d cases; want schema 1 and 5 cases", fixture.SchemaVersion, len(fixture.Cases))
	}
	wantNames := []string{"refill_fractional", "daily_rollover", "capacity_clamp", "rejection", "boundaries"}
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
