package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFixturePathIsBounded(t *testing.T) {
	root := rootDir()
	if got, err := fixturePath(root, "testdata/port/sync/sync.json"); err != nil || got != filepath.Join("sync", "sync.json") {
		t.Fatalf("fixture path = %q, %v", got, err)
	}
	for _, path := range []string{"../outside.json", "testdata/port/../outside.json", filepath.Join(root, "outside.json")} {
		if _, err := fixturePath(root, path); err == nil {
			t.Fatalf("fixture path %q unexpectedly accepted", path)
		}
	}
}

func TestPinnedSyncOracleIsRepeatable(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The frozen v0.22.1 Go oracle writes filepath-native tar member names
		// and its restore path rejects those backslashes. Current backup output
		// is covered by TestCreateBackup_NormalizesTarMemberSeparators; do not
		// pretend the historical oracle has Windows parity it never had.
		t.Skip("frozen Go oracle archive case is not portable on Windows")
	}
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
			t.Fatalf("oracle case identity changed at %d: %#v vs %#v", i, first[i], second[i])
		}
		firstInput, err := json.Marshal(first[i].Input)
		if err != nil {
			t.Fatalf("marshal first input %s: %v", first[i].ID, err)
		}
		secondInput, err := json.Marshal(second[i].Input)
		if err != nil {
			t.Fatalf("marshal second input %s: %v", second[i].ID, err)
		}
		if !bytes.Equal(firstInput, secondInput) {
			t.Fatalf("oracle input changed between runs for %s: %s vs %s", first[i].ID, firstInput, secondInput)
		}
		firstExpected, err := json.Marshal(first[i].Expected)
		if err != nil {
			t.Fatalf("marshal first expected %s: %v", first[i].ID, err)
		}
		secondExpected, err := json.Marshal(second[i].Expected)
		if err != nil {
			t.Fatalf("marshal second expected %s: %v", second[i].ID, err)
		}
		if !bytes.Equal(firstExpected, secondExpected) {
			t.Fatalf("oracle expected output changed between runs for %s: %s vs %s", first[i].ID, firstExpected, secondExpected)
		}
	}
}
