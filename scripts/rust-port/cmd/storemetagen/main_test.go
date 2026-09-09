package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	vault "github.com/danieljustus/symaira-vault/internal/vault"
)

const testCommit = "fe098b917a72125207bc711915f8daa791d1658f"

func TestMakeFixtureRejectsArbitraryOracleCommit(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := makeFixture(root, "081db728c695ad2b9572e73c6fb63fd0f34bf100", "unreleased"); err == nil {
		t.Fatal("arbitrary oracle commit was accepted")
	}
}

func TestCheckFixtureRejectsChangedProvenanceDigest(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	value, err := makeFixture(root, testCommit, "unreleased")
	if err != nil {
		t.Fatal(err)
	}
	value.Oracle.GeneratorDigest = "0000000000000000000000000000000000000000000000000000000000000000"
	data, err := fixtureBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "metadata.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkFixture(root, path, testCommit, "unreleased"); err == nil {
		t.Fatal("changed generator digest was accepted")
	}
}

func TestFixtureKeepsPendingWriteOutsideEntryWireInput(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	value, err := makeFixture(root, testCommit, "unreleased")
	if err != nil {
		t.Fatal(err)
	}
	var input vault.Entry
	if err := json.Unmarshal(value.Vectors[0].Input, &input); err != nil {
		t.Fatal(err)
	}
	if value.Vectors[0].PendingWrite == nil {
		t.Fatal("pending write was not retained in the generator model")
	}
	wire, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(wire) == "" || string(wire) == "null" {
		t.Fatal("entry input was not serialized")
	}
	var fields map[string]any
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["pending_write"]; ok {
		t.Fatal("runtime-only pending write leaked into Entry wire input")
	}
}
