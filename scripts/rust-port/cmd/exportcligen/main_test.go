package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeAuditLogReplacesOnlyPerWriteValues(t *testing.T) {
	input := `{"ts":"2026-10-31T07:36:10Z","agent":"","action":"export","kid":"3f14a3c3","hmac":"77cf","ok":true}` + "\n" +
		`{"ts":"2026-10-31T07:49:03Z","agent":"","action":"expose_plaintext","path":"a/b","field":"password","kid":"6cff","hmac":"15a8","argv_hash":"a4ae","ok":true}` + "\n"
	got, err := normalizeAuditLog([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"action":"export","agent":"","hmac":"<hmac>","kid":"<kid>","ok":true,"ts":"<ts>"}` + "\n" +
		`{"action":"expose_plaintext","agent":"","argv_hash":"<argv_hash>","field":"password","hmac":"<hmac>","kid":"<kid>","ok":true,"path":"a/b","ts":"<ts>"}` + "\n"
	if string(got) != want {
		t.Fatalf("normalized audit log:\n%s\nwant:\n%s", got, want)
	}
	// A differing non-volatile field must survive normalization.
	other, err := normalizeAuditLog([]byte(strings.Replace(input, `"agent":""`, `"agent":"symvault"`, 1)))
	if err != nil || bytes.Equal(other, got) {
		t.Fatalf("agent difference was normalized away: %v", err)
	}
	if _, err := normalizeAuditLog([]byte("not json\n")); err == nil {
		t.Fatal("malformed audit line accepted")
	}
}

func TestExpandOuterKeepsJSONAndExpandsOnlyOuterContainers(t *testing.T) {
	value := map[string]any{
		"cases": []any{map[string]any{
			"id":   "x",
			"tree": []any{map[string]any{"path": "a,b", "mode": 384}, map[string]any{"path": "c\"d"}},
			"none": []any{},
		}},
	}
	var compact bytes.Buffer
	enc := json.NewEncoder(&compact)
	if err := enc.Encode(value); err != nil {
		t.Fatal(err)
	}
	out := expandOuter(bytes.TrimSuffix(compact.Bytes(), []byte("\n")), expandDepth)
	var roundTrip any
	if err := json.Unmarshal(out, &roundTrip); err != nil {
		t.Fatalf("expanded output is not JSON: %v\n%s", err, out)
	}
	back, _ := json.Marshal(roundTrip)
	want, _ := json.Marshal(value)
	if !bytes.Equal(back, want) {
		t.Fatalf("round trip changed the value:\n%s\n%s", back, want)
	}
	// Tree nodes (depth 4) stay on one line each.
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, `a,b`) && !strings.Contains(line, "384") {
			t.Fatalf("a node was split across lines: %q\n%s", line, out)
		}
	}
	lines := strings.Count(string(out), "\n")
	if lines < 6 || lines > 14 {
		t.Fatalf("unexpected expansion: %d lines\n%s", lines, out)
	}
}

func TestDeltaReportsNewChangedAndRemovedNodes(t *testing.T) {
	before := []Node{{Path: "a", Kind: "file", Size: 1, SHA256: "x"}, {Path: "b", Kind: "file", Size: 1, SHA256: "y"}, {Path: "c", Kind: "dir"}}
	after := []Node{{Path: "a", Kind: "file", Size: 1, SHA256: "x"}, {Path: "b", Kind: "file", Size: 2, SHA256: "z"}, {Path: "d", Kind: "dir"}}
	changed, removed := delta(before, after)
	if len(changed) != 2 || changed[0].Path != "b" || changed[1].Path != "d" {
		t.Fatalf("changed: %+v", changed)
	}
	if len(removed) != 1 || removed[0] != "c" {
		t.Fatalf("removed: %v", removed)
	}
}

func TestCaseIDsAreUniqueAndEveryCommandIsCovered(t *testing.T) {
	seeds := map[string][]FileSpec{
		"empty":   {{Path: "vault", Kind: "dir", Mode: 0o700}},
		"entries": {{Path: "vault", Kind: "dir", Mode: 0o700}},
	}
	cases, err := buildCases(seeds)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	commands := map[string]bool{}
	for _, c := range cases {
		if seen[c.ID] {
			t.Fatalf("duplicate id %s", c.ID)
		}
		seen[c.ID] = true
		if len(c.Steps) == 0 {
			t.Fatalf("%s has no steps", c.ID)
		}
		for _, step := range c.Steps {
			for _, arg := range step.Argv {
				commands[arg] = true
			}
		}
	}
	for _, command := range []string{"export", "backup", "restore", "--exclude-git", "--mapping", "--format", "--output", "--yes", "-y"} {
		if !commands[command] {
			t.Errorf("no case uses %s", command)
		}
	}
}

func TestResolveOracleRejectsAnUnpinnedCommit(t *testing.T) {
	if _, _, err := resolveOracle(true, "deadbeef", ""); err == nil {
		t.Fatal("unpinned commit accepted")
	}
	if commit, release, err := resolveOracle(true, "", ""); err != nil || commit != pinnedOracleCommit || release != pinnedOracleRelease {
		t.Fatalf("check mode: %q %q %v", commit, release, err)
	}
	if _, _, err := resolveOracle(false, "", ""); err == nil {
		t.Fatal("generation without --oracle-commit accepted")
	}
}
