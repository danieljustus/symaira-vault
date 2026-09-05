package main

import (
	"bytes"
	"reflect"
	"testing"
)

func TestBuildFixtureIsDeterministic(t *testing.T) {
	meta := oracle{Commit: "test", Release: "v0.0.0"}
	first, err := marshalFixture(buildFixture(meta))
	if err != nil {
		t.Fatal(err)
	}
	second, err := marshalFixture(buildFixture(meta))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("error fixture generation is not deterministic")
	}
}

func TestBuildFixtureCoversStableTaxonomy(t *testing.T) {
	fixture := buildFixture(oracle{Commit: "test", Release: "test"})
	wantExitCodes := []namedInt{
		{"success", 0}, {"general", 1}, {"not_found", 2}, {"not_initialized", 3},
		{"locked", 4}, {"permission_denied", 5}, {"config", 6}, {"doctor_warn", 7},
		{"doctor_fail", 8}, {"invalid_input", 9}, {"usage", 9}, {"update_available", 10},
	}
	if !reflect.DeepEqual(fixture.ExitCodes, wantExitCodes) {
		t.Fatalf("exit codes = %#v, want %#v", fixture.ExitCodes, wantExitCodes)
	}
	wantKinds := []namedInt{{"none", 0}, {"not_found", 1}, {"field_not_found", 2}, {"read_failed", 3}, {"write_failed", 4}}
	if !reflect.DeepEqual(fixture.ErrorKinds, wantKinds) {
		t.Fatalf("error kinds = %#v, want %#v", fixture.ErrorKinds, wantKinds)
	}
	if len(fixture.CorekitReverse) != 7 {
		t.Fatalf("corekit reverse mappings = %d, want 7", len(fixture.CorekitReverse))
	}
	wantCases := []string{
		"new", "not_found", "field_not_found", "read_failed", "read_failed_nil",
		"write_failed", "write_failed_nil", "not_initialized", "new_vault_not_initialized",
		"locked", "permission_denied", "invalid_input", "config_error", "internal",
		"already_exists", "custom_hint", "sentinel_priority",
	}
	gotCases := make([]string, len(fixture.Cases))
	for i, item := range fixture.Cases {
		gotCases[i] = item.Name
	}
	if !reflect.DeepEqual(gotCases, wantCases) {
		t.Fatalf("error cases = %#v, want %#v", gotCases, wantCases)
	}
}
