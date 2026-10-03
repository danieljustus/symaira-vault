package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
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
	assertRepeatableCases(t, []string{"GIT-001-local", "GIT-002-local-bare", "GIT-003-conflict", "IO-001-imports", "IO-002-export", "IO-003-portable-intake"})
}

func TestPinnedSyncArchiveContract(t *testing.T) {
	if runtime.GOOS != "windows" {
		assertRepeatableCases(t, []string{"IO-002-archive"})
		return
	}
	// sync-windows-archive-exception-v1: execute the real detached historical
	// writer/reader pair and require its precise nested-member rejection.
	_, err := runOracleCases(rootDir(), []string{"IO-002-archive"})
	if err == nil || !strings.Contains(err.Error(), `panic: archive contains unsafe path: entries\item.age`) {
		t.Fatalf("historical Windows archive exception changed: %v", err)
	}
	t.Log("sync-windows-archive-exception-v1: actual v0.22.1 nested-member rejection observed; successful historical archive parity remains unproven")
}

func TestObservationSelectionRejectsUnknownAndDuplicateCases(t *testing.T) {
	for _, ids := range [][]string{{"unknown"}, {"IO-002-archive", "IO-002-archive"}} {
		if _, err := runOracleCases("not-a-checkout", ids); err == nil || !strings.Contains(err.Error(), "unknown or duplicate") {
			t.Fatalf("selection %v did not fail before opening a checkout: %v", ids, err)
		}
	}
}

func assertRepeatableCases(t *testing.T, selected []string) {
	t.Helper()
	first, err := runOracleCases(rootDir(), selected)
	if err != nil {
		t.Fatalf("first pinned oracle run: %v", err)
	}
	second, err := runOracleCases(rootDir(), selected)
	if err != nil {
		t.Fatalf("second pinned oracle run: %v", err)
	}
	if len(first) != len(selected) {
		t.Fatalf("selected %d observations but executed %d", len(selected), len(first))
	}
	seen := make(map[string]bool)
	for _, c := range first {
		seen[c.ID] = true
	}
	for _, id := range selected {
		if !seen[id] {
			t.Fatalf("selected observation %s did not execute", id)
		}
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
