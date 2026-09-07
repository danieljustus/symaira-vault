package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildPolicyFixtureIsDeterministic(t *testing.T) {
	first, err := buildPolicyFixture("test", "v0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildPolicyFixture("test", "v0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := marshalJSON(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := marshalJSON(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("policy fixture generation is not deterministic")
	}
}

func TestBuildPolicyFixtureCoversPureBranches(t *testing.T) {
	fixture, err := buildPolicyFixture("test", "v0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(fixture.ValidationCases) < 8 {
		t.Fatalf("validation cases = %d, want at least 8", len(fixture.ValidationCases))
	}
	if len(fixture.TimeRangeCases) < 10 {
		t.Fatalf("time range cases = %d, want at least 10", len(fixture.TimeRangeCases))
	}
	if len(fixture.EvaluationCases) < 15 {
		t.Fatalf("evaluation cases = %d, want at least 15", len(fixture.EvaluationCases))
	}
	if len(fixture.TierPresetCases) != 4 {
		t.Fatalf("tier preset cases = %d, want 4", len(fixture.TierPresetCases))
	}
	valid, invalid := 0, 0
	for _, item := range fixture.ValidationCases {
		if item.Valid {
			valid++
		} else if item.Error != "" {
			invalid++
		}
	}
	if valid == 0 || invalid == 0 {
		t.Fatalf("validation partition = valid %d invalid %d", valid, invalid)
	}
}

func TestPolicyFixtureDriftNegativeControl(t *testing.T) {
	fixture, err := buildPolicyFixture("test", "v0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	content, err := marshalJSON(fixture)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(content, []byte(fixture.Oracle.SourceDigest), []byte(strings.Repeat("0", len(fixture.Oracle.SourceDigest))), 1)
	if bytes.Equal(content, tampered) {
		t.Fatal("negative control did not change the fixture")
	}
	var decoded policyFixture
	if err := json.Unmarshal(tampered, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Oracle.SourceDigest == fixture.Oracle.SourceDigest {
		t.Fatal("tampered provenance unexpectedly matched")
	}
}
