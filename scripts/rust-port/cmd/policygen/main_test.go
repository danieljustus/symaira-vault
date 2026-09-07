package main

import (
	"bytes"
	"encoding/json"
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

func TestPolicyFixtureEvaluationCoverageIsIsolated(t *testing.T) {
	fixture, err := buildPolicyFixture("test", "v0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEvaluationCoverage(fixture.EvaluationPolicy, fixture.EvaluationCases, fixture.EmptyEngineCases); err != nil {
		t.Fatal(err)
	}
	for _, item := range fixture.EvaluationCases {
		if item.RuleName == "" {
			t.Fatalf("evaluation case %q has no isolated rule", item.Name)
		}
		if item.Name != "allowed_tool_empty_name" && item.Context.ToolName == "" {
			t.Fatalf("evaluation case %q relies on an implicit empty tool name", item.Name)
		}
	}
}

func TestPolicyCheckRejectsProvenanceDrift(t *testing.T) {
	fixture, err := buildPolicyFixture("test", "v0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	expected, err := marshalJSON(fixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{fixture.Oracle.SourceDigest, fixture.Oracle.GeneratorDigest} {
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
