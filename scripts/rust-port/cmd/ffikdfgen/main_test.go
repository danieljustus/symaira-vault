package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedGoKDFMigrationFixture(t *testing.T) {
	root := rootDir()
	data, err := os.ReadFile(filepath.Join(root, "testdata/port/ffi/kdf-migration.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value fixture
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	if err := verify(root, value); err != nil {
		t.Fatalf("Go migration no longer matches the pinned fixture: %v", err)
	}
	value.SchemaVersion = 0
	if err := verify(root, value); err == nil {
		t.Fatal("a stale fixture schema was accepted")
	}
}

func TestGeneratedKDFEnvelopeRoundTripsAndRejectsCorruption(t *testing.T) {
	root := rootDir()
	value, err := build(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(root, value); err != nil {
		t.Fatalf("new Go envelope did not migrate and reopen: %v", err)
	}
	value.Ciphertext = "not-base64"
	if err := verify(root, value); err == nil {
		t.Fatal("corrupt identity ciphertext was accepted")
	}
}
